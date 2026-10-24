//! Listing and revoking sessions, and removing the ones nobody can use any more.

use std::time::Duration;

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    audit,
    auth::{AuthUser, Role},
    error::{AppError, Res},
    AppState,
};

/// How long a finished (expired or revoked) session row is kept before it is deleted.
const KEEP_DAYS: i32 = 7;

#[derive(Serialize, sqlx::FromRow)]
struct SessionInfo {
    id: Uuid,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    ip: Option<String>,
    user_agent: Option<String>,
}

#[derive(Serialize)]
struct SessionView {
    #[serde(flatten)]
    s: SessionInfo,
    current: bool,
}

/// The signed-in user's own live sessions, newest first.
pub async fn list(State(st): State<AppState>, user: AuthUser) -> Res<Json<Value>> {
    let rows: Vec<SessionInfo> = sqlx::query_as(
        "SELECT id, created_at, expires_at, ip, user_agent FROM sessions
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
         ORDER BY created_at DESC LIMIT 200",
    )
    .bind(user.id)
    .fetch_all(&st.db)
    .await?;
    let sessions: Vec<SessionView> = rows
        .into_iter()
        .map(|s| SessionView {
            current: s.id == user.session,
            s,
        })
        .collect();
    Ok(Json(json!({ "sessions": sessions })))
}

/// Signs one of the user's own other sessions out. (To end this one, log out.)
pub async fn revoke(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Res<Json<Value>> {
    if id == user.session {
        return Err(AppError::BadRequest(
            "that is the session you are using; log out instead".into(),
        ));
    }
    // The user id in the condition means nobody can revoke someone else's session by guessing its id.
    let done = sqlx::query(
        "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(user.id)
    .execute(&st.db)
    .await?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound("no such active session".into()));
    }
    audit::actor_log(
        &st.db,
        &user,
        "SESSION_REVOKED",
        "session",
        &id.to_string(),
        json!({}),
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

/// Signs the user out everywhere except here.
pub async fn revoke_others(State(st): State<AppState>, user: AuthUser) -> Res<Json<Value>> {
    let done = sqlx::query(
        "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL",
    )
    .bind(user.id)
    .bind(user.session)
    .execute(&st.db)
    .await?;
    audit::actor_log(
        &st.db,
        &user,
        "SESSIONS_REVOKED",
        "user",
        &user.id.to_string(),
        json!({ "count": done.rows_affected() }),
    )
    .await;
    Ok(Json(json!({ "revoked": done.rows_affected() })))
}

/// An administrator signs another user out everywhere (a lost laptop, a suspected compromise).
pub async fn revoke_user(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin])?;
    if id == user.id {
        return Err(AppError::BadRequest(
            "use 'sign out other sessions' for your own account".into(),
        ));
    }
    let (email,): (String,) = sqlx::query_as("SELECT email FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| AppError::NotFound("no such user".into()))?;
    let done = sqlx::query(
        "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&st.db)
    .await?;
    audit::actor_log(
        &st.db,
        &user,
        "USER_SESSIONS_REVOKED",
        "user",
        &id.to_string(),
        json!({ "email": email, "count": done.rows_affected() }),
    )
    .await;
    Ok(Json(json!({ "revoked": done.rows_affected() })))
}

/// Deletes sessions that expired or were revoked more than a week ago.
pub async fn purge(db: &PgPool) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "DELETE FROM sessions
         WHERE least(expires_at, coalesce(revoked_at, expires_at)) < now() - make_interval(days => $1)",
    )
    .bind(KEEP_DAYS)
    .execute(db)
    .await
    .map(|r| r.rows_affected())
}

pub async fn purge_forever(db: PgPool) {
    loop {
        match purge(&db).await {
            Ok(n) if n > 0 => tracing::info!(rows = n, "removed finished sessions"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "session cleanup failed"),
        }
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
