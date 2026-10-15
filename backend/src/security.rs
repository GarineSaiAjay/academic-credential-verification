use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::Response,
};
use chrono::Utc;

use crate::{auth::client_ip, error::AppError, AppState};

/// Fixed-window in-memory limiter. Single-instance only; use a shared store to scale out.
#[derive(Default)]
pub struct RateLimiter(Mutex<HashMap<String, (Instant, u32)>>);

impl RateLimiter {
    pub fn check(&self, key: &str, limit: u32, window_secs: u64) -> bool {
        let mut map = self.0.lock().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(window_secs);
        if map.len() > 50_000 {
            map.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = map.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= limit
    }
}

pub async fn global_rate_limit(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let ip = client_ip(req.headers(), peer, st.cfg.trust_proxy);
    if !st.limiter.check(&format!("global:{ip}"), 240, 60) {
        return Err(AppError::TooMany);
    }
    Ok(next.run(req).await)
}

/// Requires a fresh timestamp (±60s) and a never-before-seen nonce on state-changing requests.
pub async fn replay_guard(
    State(st): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let h = req.headers();
    let nonce = h.get("x-nonce").and_then(|v| v.to_str().ok()).unwrap_or("");
    let ts: i64 = h
        .get("x-timestamp")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if !(16..=64).contains(&nonce.len())
        || !nonce.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(AppError::BadRequest("missing or malformed X-Nonce".into()));
    }
    if (Utc::now().timestamp() - ts).abs() > 60 {
        return Err(AppError::BadRequest(
            "X-Timestamp missing or outside the allowed window".into(),
        ));
    }
    sqlx::query("DELETE FROM nonces WHERE used_at < now() - interval '5 minutes'")
        .execute(&st.db)
        .await?;
    let inserted = sqlx::query("INSERT INTO nonces (nonce) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(nonce)
        .execute(&st.db)
        .await?
        .rows_affected();
    if inserted == 0 {
        return Err(AppError::Conflict("replayed request rejected".into()));
    }
    Ok(next.run(req).await)
}
