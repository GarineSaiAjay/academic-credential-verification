//! Password reset for people who cannot sign in.
//!
//! There is no e-mail service in this stack, so an administrator, who knows the person, issues a one-time link
//! and hands it over. The token is random, valid for one hour, usable once, and stored only as a hash. Redeeming
//! it sets a new password and signs the account out everywhere; it does not bypass a second factor.

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    audit,
    auth::{self, client_ip, AuthUser, Role},
    error::{AppError, Res},
    security,
    users::check_password_for,
    AppState,
};

const VALID_MINUTES: i64 = 60;

fn digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Administrator issues a reset link for another user. Any earlier unused link for that user stops working.
pub async fn issue(
    State(st): State<AppState>,
    user: AuthUser,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin])?;
    if id == user.id {
        return Err(AppError::BadRequest(
            "use change password for your own account".into(),
        ));
    }
    let (email, active): (String, bool) =
        sqlx::query_as("SELECT email, active FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.db)
            .await?
            .ok_or_else(|| AppError::NotFound("no such user".into()))?;
    if !active {
        return Err(AppError::BadRequest(
            "the account is deactivated; reactivate it first".into(),
        ));
    }
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    let expires: DateTime<Utc> = Utc::now() + Duration::minutes(VALID_MINUTES);

    let mut tx = st.db.begin().await?;
    sqlx::query(
        "UPDATE password_resets SET used_at = now() WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO password_resets (id, user_id, token_hash, created_by, expires_at) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(id)
    .bind(digest(&token))
    .bind(user.id)
    .bind(expires)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    audit::actor_log(
        &st.db,
        &user,
        "PASSWORD_RESET_ISSUED",
        "user",
        &id.to_string(),
        json!({ "email": email, "expires_at": expires }),
    )
    .await;
    Ok(Json(json!({
        "email": email,
        "token": token,
        "path": format!("/#/reset/{token}"),
        "expires_at": expires,
    })))
}

#[derive(Deserialize)]
pub struct RedeemBody {
    token: String,
    new_password: String,
}

/// Public: whoever holds a valid token sets the account's password.
pub async fn redeem(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(b): Json<RedeemBody>,
) -> Res<Json<Value>> {
    let ip = client_ip(&headers, peer, &st.cfg.trusted_proxies);
    let hit = security::hit(&st, &format!("reset:{ip}"), 10, 60).await;
    if !hit.allowed {
        return Err(AppError::TooMany(hit.retry_after));
    }
    let bad = || {
        AppError::BadRequest("this reset link is not valid, has expired or was already used".into())
    };
    if b.token.len() > 200 {
        return Err(bad());
    }

    let mut tx = st.db.begin().await?;
    // Marking it used and reading who it belongs to is one statement, so two requests cannot both succeed.
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "UPDATE password_resets r SET used_at = now()
         FROM users u
         WHERE r.token_hash = $1 AND r.used_at IS NULL AND r.expires_at > now() AND u.id = r.user_id AND u.active
         RETURNING u.id, u.email",
    )
    .bind(digest(&b.token))
    .fetch_optional(&mut *tx)
    .await?;
    let (id, email) = row.ok_or_else(bad)?;
    // The transaction rolls back if the password is refused, so a weak choice does not use up the link.
    check_password_for(&b.new_password, Some(&email))?;
    let hash = auth::hash_password(&b.new_password)?;
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(id)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    audit::log(
        &st.db,
        Some(id),
        Some(&email),
        "PASSWORD_RESET_USED",
        Some("user"),
        Some(&id.to_string()),
        json!({ "ip": ip }),
    )
    .await;
    Ok(Json(json!({ "ok": true, "email": email })))
}
