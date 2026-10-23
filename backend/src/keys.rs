use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::{
    audit,
    auth::{AuthUser, Role},
    crypto,
    error::{AppError, Res},
    AppState,
};

pub const KEY_ROLES: [&str; 4] = ["faculty", "exam_cell", "registrar", "university"];

async fn insert_key<'e>(e: impl PgExecutor<'e>, enc: &[u8; 32], role: &str) -> Res<Uuid> {
    let (seed, public) = crypto::new_keypair();
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO signing_keys (id, role, public_key, private_key_enc, status) VALUES ($1,$2,$3,$4,'active')")
        .bind(id).bind(role).bind(public).bind(crypto::seal(enc, &seed))
        .execute(e).await?;
    Ok(id)
}

/// Creates a stage's first key on a fresh install. A stage that already has keys but none active
/// (its key was revoked and not yet rotated) is left alone, so a restart cannot undo the revocation.
pub async fn ensure_initial_keys(st: &AppState) -> Res<()> {
    for role in KEY_ROLES {
        let any: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM signing_keys WHERE role = $1 LIMIT 1")
                .bind(role)
                .fetch_optional(&st.db)
                .await?;
        if any.is_some() {
            let active: Option<(Uuid,)> =
                sqlx::query_as("SELECT id FROM signing_keys WHERE role = $1 AND status = 'active'")
                    .bind(role)
                    .fetch_optional(&st.db)
                    .await?;
            if active.is_none() {
                tracing::warn!(
                    role,
                    "no active signing key (revoked?); rotate one to resume signing"
                );
            }
            continue;
        }
        insert_key(&st.db, &st.cfg.enc_key, role).await?;
        tracing::info!(role, "generated initial signing key");
    }
    Ok(())
}

/// Fails startup when ENCRYPTION_KEY cannot open the stored active keys, so a lost or changed key
/// shows up immediately with a recovery hint instead of at the first signature.
pub async fn verify_stored_keys(st: &AppState) -> Res<()> {
    let rows: Vec<(String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT role, public_key, private_key_enc FROM signing_keys WHERE status = 'active' ORDER BY role",
    )
    .fetch_all(&st.db)
    .await?;
    let bad: Vec<&str> = rows
        .iter()
        .filter(|(_, public, blob)| {
            !crypto::open(&st.cfg.enc_key, blob)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .is_some_and(|seed| &crypto::public_from_seed(&seed) == public)
        })
        .map(|(role, _, _)| role.as_str())
        .collect();
    if bad.is_empty() {
        return Ok(());
    }
    Err(AppError::Internal(format!(
        "ENCRYPTION_KEY cannot decrypt the stored active signing key(s) for: {}. \
         If the key was lost or changed, restore them from a key backup with `server key-restore` (see README)",
        bad.join(", ")
    )))
}

/// Active key for a stage. Fails closed if the stage's key was revoked and not yet rotated.
pub async fn active_signer(st: &AppState, role: &str) -> Res<(Uuid, [u8; 32])> {
    let row: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT id, private_key_enc FROM signing_keys WHERE role = $1 AND status = 'active'",
    )
    .bind(role)
    .fetch_optional(&st.db)
    .await?;
    let (id, blob) = row.ok_or_else(|| {
        AppError::Conflict(format!("no active '{role}' signing key; rotate one first"))
    })?;
    let seed = crypto::open(&st.cfg.enc_key, &blob)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| {
            AppError::Internal("cannot decrypt signing key (wrong ENCRYPTION_KEY?)".into())
        })?;
    Ok((id, seed))
}

#[derive(Serialize, sqlx::FromRow)]
struct KeyInfo {
    id: Uuid,
    role: String,
    public_key: String,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    revoke_reason: Option<String>,
    signatures: i64,
}

pub async fn list(State(st): State<AppState>, user: AuthUser) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin, Role::Auditor])?;
    let rows: Vec<KeyInfo> = sqlx::query_as(
        "SELECT k.id, k.role, k.public_key, k.status, k.created_at, k.revoked_at, k.revoke_reason,
                (SELECT count(*) FROM approvals a WHERE a.key_id = k.id) + (SELECT count(*) FROM blocks b WHERE b.key_id = k.id) AS signatures
         FROM signing_keys k ORDER BY k.role, k.created_at DESC",
    ).fetch_all(&st.db).await?;
    Ok(Json(json!({ "keys": rows })))
}

pub async fn rotate(
    State(st): State<AppState>,
    user: AuthUser,
    Path(role): Path<String>,
) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin])?;
    if !KEY_ROLES.contains(&role.as_str()) {
        return Err(AppError::BadRequest("unknown key role".into()));
    }
    let mut tx = st.db.begin().await?;
    sqlx::query("UPDATE signing_keys SET status = 'retired' WHERE role = $1 AND status = 'active'")
        .bind(&role)
        .execute(&mut *tx)
        .await?;
    let id = insert_key(&mut *tx, &st.cfg.enc_key, &role).await?;
    tx.commit().await?;
    audit::actor_log(
        &st.db,
        &user,
        "KEY_ROTATED",
        "signing_key",
        &id.to_string(),
        json!({ "role": role }),
    )
    .await;
    Ok(Json(json!({ "id": id, "role": role, "status": "active" })))
}

#[derive(Deserialize)]
pub struct RevokeBody {
    reason: String,
}

pub async fn revoke(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(b): Json<RevokeBody>,
) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin])?;
    let reason = b.reason.trim();
    if !(3..=500).contains(&reason.chars().count()) {
        return Err(AppError::BadRequest(
            "reason must be 3-500 characters".into(),
        ));
    }
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE signing_keys SET status = 'revoked', revoked_at = now(), revoke_reason = $2
         WHERE id = $1 AND status <> 'revoked' RETURNING role",
    )
    .bind(id)
    .bind(reason)
    .fetch_optional(&st.db)
    .await?;
    let (role,) =
        row.ok_or_else(|| AppError::NotFound("key not found or already revoked".into()))?;
    audit::actor_log(
        &st.db,
        &user,
        "KEY_REVOKED",
        "signing_key",
        &id.to_string(),
        json!({ "role": role, "reason": reason }),
    )
    .await;
    Ok(Json(
        json!({ "id": id, "role": role, "status": "revoked", "note": "credentials signed by this key now verify as INVALID; rotate the role key and reissue" }),
    ))
}
