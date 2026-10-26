use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::{AuthUser, Role},
    error::Res,
    AppState,
};

/// Best-effort: a failing audit write is logged but never blocks the request.
pub async fn log(
    db: &PgPool,
    actor: Option<Uuid>,
    email: Option<&str>,
    action: &str,
    rtype: Option<&str>,
    rid: Option<&str>,
    details: Value,
) {
    crate::metrics::audit_event(action);
    let r = sqlx::query(
        "INSERT INTO audit_logs (action, actor_id, actor_email, resource_type, resource_id, details) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(action).bind(actor).bind(email).bind(rtype).bind(rid).bind(details)
    .execute(db)
    .await;
    if let Err(e) = r {
        tracing::error!(error = %e, action, "audit write failed");
    }
}

pub async fn actor_log(
    db: &PgPool,
    u: &AuthUser,
    action: &str,
    rtype: &str,
    rid: &str,
    details: Value,
) {
    log(
        db,
        Some(u.id),
        Some(&u.email),
        action,
        Some(rtype),
        Some(rid),
        details,
    )
    .await;
}

#[derive(Serialize, sqlx::FromRow)]
struct Entry {
    id: i64,
    action: String,
    actor: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    details: Option<Value>,
    at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
pub struct Page {
    limit: Option<i64>,
    /// Older entries only: the `next` value of the previous page (an entry id).
    before: Option<i64>,
    /// Only this action, for example LOGIN_FAILED.
    action: Option<String>,
    /// Deep offsets get slower the further they go; prefer `before`. Kept for old clients, capped.
    offset: Option<i64>,
}

pub async fn list(
    State(st): State<AppState>,
    user: AuthUser,
    Query(p): Query<Page>,
) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin, Role::Auditor])?;
    let limit = crate::page::limit(p.limit, 100, 500);
    let mut rows: Vec<Entry> = sqlx::query_as(
        "SELECT id, action, actor_email AS actor, resource_type, resource_id, details, created_at AS at
         FROM audit_logs
         WHERE ($1::bigint IS NULL OR id < $1) AND ($2::text IS NULL OR action = $2)
         ORDER BY id DESC LIMIT $3 OFFSET $4",
    )
    .bind(p.before)
    .bind(p.action)
    .bind(limit + 1)
    .bind(p.offset.unwrap_or(0).clamp(0, 10_000))
    .fetch_all(&st.db)
    .await?;
    let next = (rows.len() as i64 > limit).then(|| {
        rows.truncate(limit as usize);
        rows.last().map_or(0, |e| e.id)
    });
    Ok(Json(json!({ "logs": rows, "next": next })))
}
