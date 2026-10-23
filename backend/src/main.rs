mod audit;
mod auth;
mod config;
mod credentials;
mod crypto;
mod error;
mod keybackup;
mod keys;
mod ledger;
mod security;
mod timestamp;
mod users;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderName, HeaderValue},
    middleware,
    routing::{get, post},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use tower_http::{
    compression::CompressionLayer, set_header::SetResponseHeaderLayer, trace::TraceLayer,
};

use config::Config;
use security::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub cfg: Arc<Config>,
    pub limiter: Arc<RateLimiter>,
    /// Held while a timestamping pass runs, so passes in this process never overlap.
    pub ts_lock: Arc<tokio::sync::Mutex<()>>,
}

const DEMO_USERS: [(&str, &str); 5] = [
    ("faculty@university.edu", "faculty"),
    ("examcell@university.edu", "exam_cell"),
    ("registrar@university.edu", "registrar"),
    ("admin@university.edu", "university_admin"),
    ("auditor@university.edu", "auditor"),
];

async fn seed_demo_users(st: &AppState) -> Result<(), error::AppError> {
    let Some(password) = &st.cfg.seed_password else {
        return Ok(());
    };
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&st.db)
        .await?;
    if count > 0 {
        return Ok(());
    }
    let hash = auth::hash_password(password)?;
    for (email, role) in DEMO_USERS {
        sqlx::query("INSERT INTO users (id, email, password_hash, role) VALUES ($1,$2,$3,$4)")
            .bind(uuid::Uuid::new_v4())
            .bind(email)
            .bind(&hash)
            .bind(role)
            .execute(&st.db)
            .await?;
    }
    tracing::warn!("seeded demo users from SEED_DEMO_PASSWORD; unset it in production");
    Ok(())
}

pub fn router(st: AppState) -> Router {
    let public = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/verify/:id", get(credentials::verify))
        .route("/api/v1/credentials/:id/qr", get(credentials::qr))
        .route("/api/v1/ledger/verify", get(ledger::verify_chain))
        .route(
            "/api/v1/ledger/blocks/:height/timestamp",
            get(timestamp::show),
        )
        .route(
            "/api/v1/ledger/blocks/:height/timestamp.tsq",
            get(timestamp::raw_request),
        )
        .route(
            "/api/v1/ledger/blocks/:height/timestamp.tsr",
            get(timestamp::raw_response),
        );

    let reads = Router::new()
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/credentials", get(credentials::list))
        .route("/api/v1/credentials/:id", get(credentials::get))
        .route("/api/v1/keys", get(keys::list))
        .route("/api/v1/ledger/blocks", get(ledger::blocks))
        .route("/api/v1/audit", get(audit::list))
        .route("/api/v1/users", get(users::list));

    let writes = Router::new()
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/password", post(users::change_password))
        .route("/api/v1/users", post(users::create))
        .route("/api/v1/users/:id/role", post(users::set_role))
        .route("/api/v1/users/:id/active", post(users::set_active))
        .route("/api/v1/users/:id/password", post(users::reset_password))
        .route("/api/v1/credentials", post(credentials::create))
        .route(
            "/api/v1/credentials/:id/approve",
            post(credentials::approve),
        )
        .route("/api/v1/credentials/:id/reject", post(credentials::reject))
        .route("/api/v1/credentials/:id/revoke", post(credentials::revoke))
        .route("/api/v1/keys/:role/rotate", post(keys::rotate))
        .route("/api/v1/keys/:id/revoke", post(keys::revoke))
        .route("/api/v1/ledger/seal", post(ledger::seal))
        .route("/api/v1/ledger/timestamp", post(timestamp::run_now))
        .route_layer(middleware::from_fn_with_state(
            st.clone(),
            security::replay_guard,
        ));

    let h = |name: &'static str, v: &'static str| {
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static(name),
            HeaderValue::from_static(v),
        )
    };
    Router::new()
        .merge(public)
        .merge(reads)
        .merge(writes)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn_with_state(
            st.clone(),
            security::global_rate_limit,
        ))
        .layer(h("x-content-type-options", "nosniff"))
        .layer(h("x-frame-options", "DENY"))
        .layer(h("referrer-policy", "no-referrer"))
        .layer(h(
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(st)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| !keybackup::is_command(a)) {
        eprintln!("{}", keybackup::USAGE);
        std::process::exit(2);
    }
    let cli = !args.is_empty();
    let logs = tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
    );
    // Commands print their result on stdout, so logs must not share it.
    if cli {
        logs.with_writer(std::io::stderr).init();
    } else {
        logs.init();
    }

    let cfg = Config::from_env()?;
    let mut attempts = 0;
    let db = loop {
        match PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&cfg.database_url)
            .await
        {
            Ok(p) => break p,
            Err(e) if attempts < 15 => {
                attempts += 1;
                tracing::warn!(error = %e, "database not ready, retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e.into()),
        }
    };
    sqlx::migrate!("./migrations").run(&db).await?;

    // Recovery commands must work even when the server itself would refuse to start.
    if cli {
        return Ok(keybackup::cli(&db, &cfg.enc_key, &args).await?);
    }

    let st = AppState {
        db,
        cfg: Arc::new(cfg),
        limiter: Arc::new(RateLimiter::default()),
        ts_lock: Arc::new(tokio::sync::Mutex::new(())),
    };
    keys::ensure_initial_keys(&st).await?;
    keys::verify_stored_keys(&st).await?;
    credentials::backfill_events(&st).await?;
    users::bootstrap_admin(&st).await?;
    seed_demo_users(&st).await?;
    let (user_count,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&st.db)
        .await?;
    if user_count == 0 {
        tracing::warn!(
            "no users exist, so nobody can sign in; set BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD and restart"
        );
    }

    if let Some(tsa) = &st.cfg.tsa {
        timestamp::preflight(tsa).await?;
        tracing::info!(url = %tsa.url, "anchoring sealed blocks to an external timestamp authority");
        tokio::spawn(timestamp::run_forever(st.clone()));
    }

    let listener = tokio::net::TcpListener::bind(&st.cfg.bind).await?;
    tracing::info!(addr = %st.cfg.bind, "listening");
    axum::serve(
        listener,
        router(st).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
