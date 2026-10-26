//! Health, readiness, request ids and Prometheus metrics.
//!
//! Metrics are served on their own listener (`METRICS_BIND`), never on the public port, so the reverse proxy and
//! the internet cannot reach them. Labels only ever hold route templates (`/api/v1/credentials/:id`), the kind
//! of a rate limit or an audit action: nothing a client can choose, so the number of series stays small and no
//! identifier ends up in a metrics system.
use std::{sync::OnceLock, time::Instant};

use axum::{
    extract::{MatchedPath, Request, State},
    http::{header, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::AppState;

struct Metrics {
    registry: Registry,
    requests: IntCounterVec,
    seconds: HistogramVec,
    audit: IntCounterVec,
    limited: IntCounterVec,
}

fn metrics() -> &'static Metrics {
    static M: OnceLock<Metrics> = OnceLock::new();
    M.get_or_init(|| {
        let registry = Registry::new();
        let requests = IntCounterVec::new(
            Opts::new("acvs_http_requests_total", "HTTP requests handled"),
            &["method", "route", "status"],
        )
        .unwrap();
        let seconds = HistogramVec::new(
            HistogramOpts::new(
                "acvs_http_request_duration_seconds",
                "Time to answer an HTTP request",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["route"],
        )
        .unwrap();
        let audit = IntCounterVec::new(
            Opts::new(
                "acvs_audit_events_total",
                "Audit events written, by action (logins, approvals, revocations, ...)",
            ),
            &["action"],
        )
        .unwrap();
        let limited = IntCounterVec::new(
            Opts::new(
                "acvs_rate_limited_total",
                "Requests refused by a rate limit, by kind of limit",
            ),
            &["limit"],
        )
        .unwrap();
        for c in [&requests, &audit, &limited] {
            registry.register(Box::new(c.clone())).unwrap();
        }
        registry.register(Box::new(seconds.clone())).unwrap();
        Metrics {
            registry,
            requests,
            seconds,
            audit,
            limited,
        }
    })
}

pub fn audit_event(action: &str) {
    metrics().audit.with_label_values(&[action]).inc();
}

pub fn rate_limited(kind: &str) {
    metrics().limited.with_label_values(&[kind]).inc();
}

/// Counts and times every request, labelled with the route template.
pub async fn track(req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str)
        .to_string();
    let method = req.method().as_str().to_string();
    let start = Instant::now();
    let resp = next.run(req).await;
    let m = metrics();
    m.requests
        .with_label_values(&[&method, &route, resp.status().as_str()])
        .inc();
    m.seconds
        .with_label_values(&[&route])
        .observe(start.elapsed().as_secs_f64());
    resp
}

static REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Gives every request an id that appears in the logs and in the response, so one failing request can be found.
/// An id sent by the proxy is kept if it is short and plain; anything else is replaced.
pub async fn request_id(mut req: Request, next: Next) -> Response {
    let given = req
        .headers()
        .get(&REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            (8..=64).contains(&v.len())
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
        .map(str::to_string);
    let id = given.unwrap_or_else(|| Uuid::new_v4().to_string());
    let value = HeaderValue::from_str(&id).expect("ids are plain ASCII");
    req.headers_mut().insert(REQUEST_ID.clone(), value.clone());
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(REQUEST_ID.clone(), value);
    resp
}

/// Liveness: the process is up and serving. Deliberately cheap and independent of the database.
pub async fn health() -> &'static str {
    "ok"
}

/// Readiness: the database answers. A load balancer should stop sending traffic to an instance that fails this.
pub async fn ready(State(st): State<AppState>) -> (StatusCode, Json<Value>) {
    let ok = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&st.db),
    )
    .await
    .is_ok_and(|r| r.is_ok());
    if ok {
        (StatusCode::OK, Json(json!({ "status": "ready" })))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "database unavailable" })),
        )
    }
}

fn gauge(out: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
    ));
}

/// Values read from the database at scrape time.
async fn database_gauges(st: &AppState, out: &mut String) {
    let q = async {
        let by_status: Vec<(String, i64)> =
            sqlx::query_as("SELECT status, count(*) FROM credentials GROUP BY status")
                .fetch_all(&st.db)
                .await?;
        let (height, last_ts): (i64, i64) =
            sqlx::query_as("SELECT coalesce(max(height), 0), coalesce(max(ts), 0) FROM blocks")
                .fetch_one(&st.db)
                .await?;
        let (unsealed, unstamped, sessions): (i64, i64, i64) = sqlx::query_as(
            "SELECT
               (SELECT count(*) FROM credentials WHERE status = 'issued' AND block_height IS NULL),
               (SELECT count(*) FROM blocks b WHERE NOT EXISTS (SELECT 1 FROM block_timestamps t WHERE t.block_height = b.height)),
               (SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > now())",
        )
        .fetch_one(&st.db)
        .await?;
        Ok::<_, sqlx::Error>((by_status, height, last_ts, unsealed, unstamped, sessions))
    };
    match tokio::time::timeout(std::time::Duration::from_secs(3), q).await {
        Ok(Ok((by_status, height, last_ts, unsealed, unstamped, sessions))) => {
            gauge(
                out,
                "acvs_db_up",
                "1 when the database answered the scrape",
                1,
            );
            out.push_str(
                "# HELP acvs_credentials Credentials by status\n# TYPE acvs_credentials gauge\n",
            );
            for (status, n) in by_status {
                out.push_str(&format!("acvs_credentials{{status=\"{status}\"}} {n}\n"));
            }
            gauge(out, "acvs_ledger_height", "Number of sealed blocks", height);
            let age = if last_ts > 0 {
                chrono::Utc::now().timestamp() - last_ts
            } else {
                0
            };
            gauge(
                out,
                "acvs_ledger_last_block_age_seconds",
                "Seconds since the newest block was sealed (0 when none)",
                age,
            );
            gauge(
                out,
                "acvs_credentials_waiting_for_seal",
                "Issued credentials not yet anchored in a block",
                unsealed,
            );
            gauge(
                out,
                "acvs_blocks_without_external_timestamp",
                "Sealed blocks that have no outside time-stamp token yet",
                unstamped,
            );
            gauge(
                out,
                "acvs_active_sessions",
                "Sessions that are neither revoked nor expired",
                sessions,
            );
        }
        _ => gauge(
            out,
            "acvs_db_up",
            "1 when the database answered the scrape",
            0,
        ),
    }
    gauge(
        out,
        "acvs_db_pool_connections",
        "Open database connections",
        st.db.size(),
    );
    gauge(
        out,
        "acvs_db_pool_idle_connections",
        "Idle database connections",
        st.db.num_idle(),
    );
}

pub async fn render(State(st): State<AppState>) -> impl IntoResponse {
    let mut buf = Vec::new();
    TextEncoder::new()
        .encode(&metrics().registry.gather(), &mut buf)
        .expect("metrics encode");
    let mut out = String::from_utf8(buf).unwrap_or_default();
    out.push_str(&format!(
        "# HELP acvs_build_info Always 1; the version is in the label\n# TYPE acvs_build_info gauge\nacvs_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));
    database_gauges(&st, &mut out).await;
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
}
