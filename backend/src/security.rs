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
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::{
    auth::{self, client_ip},
    error::AppError,
    AppState,
};

/// Process-local fixed-window counter. It is only a first line of defence (see `hit`): it sheds floods without
/// touching the database, and it keeps limiting if the database is unavailable.
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

/// The answer to "may this request go ahead?".
pub struct Hit {
    pub allowed: bool,
    /// Seconds until the current window ends (only meaningful when not allowed).
    pub retry_after: u64,
}

/// The local pre-filter allows this many times the real limit, so it only ever stops floods.
const LOCAL_FACTOR: u32 = 5;
/// The shared counter must answer quickly or the local one decides: a slow database must not stall requests.
const SHARED_TIMEOUT: Duration = Duration::from_millis(250);

/// Seconds until the window that started at `start` ends, never less than one.
pub fn retry_after(start: i64, window_secs: u64, now: i64) -> u64 {
    (start + window_secs as i64 - now).max(1) as u64
}

/// Counts one hit for `key` in a fixed window shared by every backend instance. Returns the hits so far in the
/// window, the window's start and the database's current time (so instances never disagree about windows).
async fn shared_hit(
    db: &PgPool,
    key: &str,
    window_secs: u64,
) -> Result<(i64, i64, i64), sqlx::Error> {
    let (hits, start, now): (i32, i64, i64) = sqlx::query_as(
        "INSERT INTO rate_limits AS r (key, window_start, hits)
         VALUES ($1, (floor(extract(epoch FROM now()) / $2) * $2)::bigint, 1)
         ON CONFLICT (key) DO UPDATE SET
             hits = CASE WHEN r.window_start = EXCLUDED.window_start THEN r.hits + 1 ELSE 1 END,
             window_start = EXCLUDED.window_start
         RETURNING hits, window_start, floor(extract(epoch FROM now()))::bigint",
    )
    .bind(key)
    .bind(window_secs as f64)
    .fetch_one(db)
    .await?;
    Ok((i64::from(hits), start, now))
}

/// Counts one hit for `key` and says whether it is within `limit` per `window_secs`. Exact across all
/// instances and across restarts (the counter lives in Postgres); degrades to a per-process count if the
/// database is slow or down.
pub async fn hit(st: &AppState, key: &str, limit: u32, window_secs: u64) -> Hit {
    if !st.limiter.check(
        &format!("pre:{key}"),
        limit.saturating_mul(LOCAL_FACTOR),
        window_secs,
    ) {
        return Hit {
            allowed: false,
            retry_after: window_secs,
        };
    }
    match tokio::time::timeout(SHARED_TIMEOUT, shared_hit(&st.db, key, window_secs)).await {
        Ok(Ok((hits, start, now))) => Hit {
            allowed: hits <= i64::from(limit),
            retry_after: retry_after(start, window_secs, now),
        },
        other => {
            tracing::warn!(
                error = %match other { Ok(Err(e)) => e.to_string(), _ => "timed out".into() },
                "shared rate limiter unavailable; limiting per process"
            );
            Hit {
                allowed: st
                    .limiter
                    .check(&format!("fallback:{key}"), limit, window_secs),
                retry_after: window_secs,
            }
        }
    }
}

/// Key for an account's failed-login counter: a hash, so attacker-chosen emails cannot bloat the table with
/// long keys and no address is stored in clear.
pub fn account_key(email: &str) -> String {
    let digest = Sha256::digest(format!("ACVS-ACCOUNT-v1|{email}").as_bytes());
    format!("acct:{}", hex::encode(&digest[..16]))
}

/// If this account has used up its failed-login budget, how many seconds until it may try again.
pub async fn account_blocked(st: &AppState, email: &str) -> Option<u64> {
    let rate = &st.cfg.rate;
    let window = rate.login_account_window_secs;
    let row = sqlx::query_as::<_, (i32, i64, i64)>(
        "SELECT hits, window_start, floor(extract(epoch FROM now()))::bigint FROM rate_limits
         WHERE key = $1 AND window_start = (floor(extract(epoch FROM now()) / $2) * $2)::bigint",
    )
    .bind(account_key(email))
    .bind(window as f64)
    .fetch_optional(&st.db);
    // If the database is slow the login proceeds (and fails on its own if the database is really down).
    match tokio::time::timeout(SHARED_TIMEOUT, row).await {
        Ok(Ok(Some((hits, start, now)))) if hits >= rate.login_account_failures as i32 => {
            Some(retry_after(start, window, now))
        }
        _ => None,
    }
}

/// Records one failed login against an account.
pub async fn account_failure(st: &AppState, email: &str) {
    let window = st.cfg.rate.login_account_window_secs;
    match tokio::time::timeout(
        SHARED_TIMEOUT,
        shared_hit(&st.db, &account_key(email), window),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "could not record a failed login"),
        Err(_) => tracing::warn!("recording a failed login timed out"),
    }
}

/// Deletes counters whose window ended long ago, now and then.
pub async fn cleanup_forever(db: PgPool) {
    loop {
        match sqlx::query("DELETE FROM rate_limits WHERE window_start < floor(extract(epoch FROM now()))::bigint - 86400")
            .execute(&db)
            .await
        {
            Ok(r) if r.rows_affected() > 0 => {
                tracing::info!(rows = r.rows_affected(), "removed expired rate-limit counters");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "rate-limit cleanup failed"),
        }
        tokio::time::sleep(Duration::from_secs(600)).await;
    }
}

pub async fn global_rate_limit(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Signed-in users have a budget of their own, so people sharing an office address do not starve each
    // other. The token's signature is checked first: an invented token gets no bucket and counts against the
    // client address like any anonymous request.
    let (key, limit) = match auth::verified_subject(req.headers(), &st.cfg.jwt_secret) {
        Some(user) => (format!("user:{user}"), st.cfg.rate.user_per_min),
        None => {
            let ip = client_ip(req.headers(), peer, &st.cfg.trusted_proxies);
            (format!("ip:{ip}"), st.cfg.rate.ip_per_min)
        }
    };
    let h = hit(&st, &key, limit, 60).await;
    if !h.allowed {
        return Err(AppError::TooMany(h.retry_after));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_counts_down_and_is_never_zero() {
        assert_eq!(retry_after(1000, 60, 1010), 50);
        assert_eq!(retry_after(1000, 60, 1059), 1);
        assert_eq!(retry_after(1000, 60, 1060), 1);
        assert_eq!(retry_after(1000, 60, 2000), 1);
    }

    #[test]
    fn account_keys_are_stable_hashed_and_distinct() {
        let a = account_key("ada@university.edu");
        assert_eq!(a, account_key("ada@university.edu"));
        assert_ne!(a, account_key("grace@university.edu"));
        assert!(a.starts_with("acct:") && a.len() == 5 + 32);
        assert!(!a.contains("ada") && !a.contains('@'));
    }

    #[test]
    fn local_counter_limits_within_a_window_and_per_key() {
        let l = RateLimiter::default();
        assert!((0..3).all(|_| l.check("a", 3, 60)));
        assert!(!l.check("a", 3, 60), "the fourth is refused");
        assert!(l.check("b", 3, 60), "other keys are independent");
    }
}
