#[cfg(test)]
mod api_tests;
mod audit;
mod auth;
mod config;
mod credentials;
mod crypto;
mod error;
mod keybackup;
mod keys;
mod ledger;
mod metrics;
mod page;
mod reset;
mod security;
mod sessions;
mod timestamp;
mod totp;
mod users;
mod webauthn;

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
    /// The latest whole-chain verification, shared by everyone who asks within its lifetime.
    pub chain_cache: ChainCache,
}

pub type ChainCache =
    Arc<tokio::sync::Mutex<Option<(std::time::Instant, Arc<ledger::ChainSummary>)>>>;

/// Advisory-lock id that serialises first-start initialisation across instances.
const INIT_LOCK: i64 = 0x4143_5653_0001;

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
        .route("/health", get(metrics::health))
        .route("/ready", get(metrics::ready))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/reset-password", post(reset::redeem))
        .route("/api/v1/auth/login/mfa", post(totp::login))
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
        .route("/api/v1/auth/sessions", get(sessions::list))
        .route("/api/v1/auth/totp", get(totp::status))
        .route("/api/v1/credentials", get(credentials::list))
        .route("/api/v1/credentials/:id", get(credentials::get))
        .route(
            "/api/v1/credentials/:id/personal-challenge",
            get(credentials::personal_challenge),
        )
        .route("/api/v1/keys", get(keys::list))
        .route("/api/v1/ledger/blocks", get(ledger::blocks))
        .route("/api/v1/audit", get(audit::list))
        .route("/api/v1/users", get(users::list))
        .route("/api/v1/me/keys", get(webauthn::my_keys))
        .route("/api/v1/users/:id/keys", get(webauthn::user_keys));

    let writes = Router::new()
        .route("/api/v1/auth/logout", post(auth::logout))
        .route(
            "/api/v1/auth/sessions/revoke-others",
            post(sessions::revoke_others),
        )
        .route("/api/v1/auth/sessions/:id/revoke", post(sessions::revoke))
        .route(
            "/api/v1/users/:id/sessions/revoke",
            post(sessions::revoke_user),
        )
        .route("/api/v1/users/:id/reset-link", post(reset::issue))
        .route("/api/v1/auth/totp/setup", post(totp::setup))
        .route("/api/v1/auth/totp/enable", post(totp::enable))
        .route("/api/v1/auth/totp/disable", post(totp::disable))
        .route(
            "/api/v1/auth/totp/recovery-codes",
            post(totp::regenerate_codes),
        )
        .route("/api/v1/users/:id/totp/reset", post(totp::admin_reset))
        .route("/api/v1/auth/password", post(users::change_password))
        .route("/api/v1/users", post(users::create))
        .route("/api/v1/me/keys/options", post(webauthn::key_options))
        .route("/api/v1/me/keys", post(webauthn::key_register))
        .route(
            "/api/v1/users/:id/keys/enroll",
            post(webauthn::allow_enrollment),
        )
        .route("/api/v1/user-keys/:id/retire", post(webauthn::retire))
        .route("/api/v1/user-keys/:id/revoke", post(webauthn::revoke))
        .route("/api/v1/users/:id/role", post(users::set_role))
        .route("/api/v1/users/:id/active", post(users::set_active))
        .route("/api/v1/users/:id/password", post(users::reset_password))
        .route("/api/v1/credentials", post(credentials::create))
        .route(
            "/api/v1/credentials/:id/approve",
            post(credentials::approve),
        )
        .route("/api/v1/credentials/:id/reject", post(credentials::reject))
        .route(
            "/api/v1/credentials/:id/reissue",
            post(credentials::reissue),
        )
        .route(
            "/api/v1/credentials/:id/countersign",
            post(credentials::countersign),
        )
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
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|req: &axum::http::Request<_>| {
                    // The route template, never the real path or query: ids and hashes stay out of the logs.
                    let route = req
                        .extensions()
                        .get::<axum::extract::MatchedPath>()
                        .map_or("unmatched", axum::extract::MatchedPath::as_str);
                    let id = req
                        .headers()
                        .get("x-request-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-");
                    // Health checks run every few seconds; they are only logged when debugging.
                    if matches!(route, "/health" | "/ready") {
                        tracing::debug_span!("http", request_id = %id, method = %req.method(), route = %route)
                    } else {
                        tracing::info_span!("http", request_id = %id, method = %req.method(), route = %route)
                    }
                })
                .on_response(
                    |resp: &axum::http::Response<_>, took: Duration, span: &tracing::Span| {
                        if !span.is_disabled() {
                            tracing::info!(parent: span, status = resp.status().as_u16(), took_ms = took.as_millis() as u64, "request finished");
                        }
                    },
                ),
        )
        .layer(middleware::from_fn(metrics::track))
        .layer(middleware::from_fn(metrics::request_id))
        .with_state(st)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| !keybackup::is_command(a)) {
        eprintln!("{}", keybackup::USAGE);
        std::process::exit(2);
    }
    let cli = !args.is_empty();
    let logs = tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
    );
    // LOG_FORMAT=json writes one JSON object per line, for log shippers. Commands print their result on
    // stdout, so their logs must not share it.
    let json = std::env::var("LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"));
    match (json, cli) {
        (true, true) => logs.json().with_writer(std::io::stderr).init(),
        (true, false) => logs.json().init(),
        (false, true) => logs.with_writer(std::io::stderr).init(),
        (false, false) => logs.init(),
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
        chain_cache: Arc::default(),
    };
    tokio::spawn(security::cleanup_forever(st.db.clone()));
    tokio::spawn(sessions::purge_forever(st.db.clone()));
    // Instances started together (replicas, a rolling restart) must not race to create the first keys and
    // users: whoever holds this lock initialises, the others wait and then find it done. The lock lives as
    // long as this transaction, so it is released even if initialisation fails.
    let init_lock = {
        let mut tx = st.db.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(INIT_LOCK)
            .execute(&mut *tx)
            .await?;
        tx
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
    init_lock.commit().await?;

    if let Some(tsa) = &st.cfg.tsa {
        timestamp::preflight(tsa).await?;
        tracing::info!(url = %tsa.url, "anchoring sealed blocks to an external timestamp authority");
        tokio::spawn(timestamp::run_forever(st.clone()));
    }

    if let Some(addr) = st.cfg.metrics_bind.clone() {
        let app = Router::new()
            .route("/metrics", get(metrics::render))
            .with_state(st.clone());
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!(%addr, "serving metrics");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!(error = %e, "metrics listener stopped");
            }
        });
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
