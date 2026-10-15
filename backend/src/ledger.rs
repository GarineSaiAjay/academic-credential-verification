use axum::{extract::State, Json};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    audit,
    auth::{AuthUser, Role},
    credentials::CredRow,
    crypto::{self, merkle, Step},
    error::{AppError, Res},
    keys, AppState,
};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(FromRow)]
struct Block {
    height: i64,
    prev_hash: String,
    merkle_root: String,
    leaves: Value,
    ts: i64,
    block_hash: String,
    signature: String,
    key_id: Uuid,
}

fn block_hash(height: i64, prev: &str, root: &str, ts: i64, n: usize) -> String {
    crypto::sha256_hex(format!("ACVS-BLOCK-v1|{height}|{prev}|{root}|{ts}|{n}").as_bytes())
}

impl Block {
    fn leaves(&self) -> Vec<String> {
        serde_json::from_value(self.leaves.clone()).unwrap_or_default()
    }
    /// Checks hash, Merkle root and signature; returns (ok, key_status).
    async fn check(&self, db: &PgPool) -> Res<(bool, String)> {
        let leaves = self.leaves();
        let (public, status): (String, String) =
            sqlx::query_as("SELECT public_key, status FROM signing_keys WHERE id = $1")
                .bind(self.key_id)
                .fetch_one(db)
                .await?;
        let ok = merkle::root(&leaves).as_deref() == Some(self.merkle_root.as_str())
            && block_hash(
                self.height,
                &self.prev_hash,
                &self.merkle_root,
                self.ts,
                leaves.len(),
            ) == self.block_hash
            && crypto::verify(&public, &self.signature, self.block_hash.as_bytes())
            && status != "revoked";
        Ok((ok, status))
    }
}

#[derive(Serialize)]
pub struct Anchor {
    pub height: i64,
    pub block_hash: String,
    pub merkle_root: String,
    pub leaf_index: i32,
    pub proof: Vec<Step>,
    pub timestamp: i64,
    pub ok: bool,
}

pub async fn anchor_for(db: &PgPool, c: &CredRow) -> Res<Option<Anchor>> {
    let (Some(height), Some(index)) = (c.block_height, c.leaf_index) else {
        return Ok(None);
    };
    let b: Block = sqlx::query_as("SELECT * FROM blocks WHERE height = $1")
        .bind(height)
        .fetch_one(db)
        .await?;
    let leaves = b.leaves();
    let proof = merkle::proof(&leaves, index as usize).unwrap_or_default();
    let (block_ok, _) = b.check(db).await?;
    let ok = block_ok
        && leaves.get(index as usize) == Some(&c.credential_hash)
        && merkle::verify(&c.credential_hash, &proof, &b.merkle_root);
    Ok(Some(Anchor {
        height,
        block_hash: b.block_hash,
        merkle_root: b.merkle_root,
        leaf_index: index,
        proof,
        timestamp: b.ts,
        ok,
    }))
}

/// Seals all issued, not-yet-anchored credentials into one signed, hash-linked block.
pub async fn seal(State(st): State<AppState>, user: AuthUser) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin])?;
    let (key_id, seed) = keys::active_signer(&st, "university").await?;

    let mut tx = st.db.begin().await?;
    sqlx::query("LOCK TABLE blocks IN EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    let pending: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, credential_hash FROM credentials WHERE status = 'issued' AND block_height IS NULL ORDER BY created_at, id FOR UPDATE",
    ).fetch_all(&mut *tx).await?;
    if pending.is_empty() {
        return Err(AppError::Conflict(
            "no issued credentials are waiting to be anchored".into(),
        ));
    }
    let last: Option<(i64, String)> =
        sqlx::query_as("SELECT height, block_hash FROM blocks ORDER BY height DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
    let (height, prev) = last.map_or((1, GENESIS.to_string()), |(h, bh)| (h + 1, bh));

    let leaves: Vec<String> = pending.iter().map(|(_, h)| h.clone()).collect();
    let root = merkle::root(&leaves).ok_or_else(|| AppError::Internal("merkle root".into()))?;
    let ts = chrono::Utc::now().timestamp();
    let hash = block_hash(height, &prev, &root, ts, leaves.len());
    let signature = crypto::sign(&seed, hash.as_bytes());

    sqlx::query("INSERT INTO blocks (height, prev_hash, merkle_root, leaves, ts, block_hash, signature, key_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(height).bind(&prev).bind(&root).bind(json!(leaves)).bind(ts).bind(&hash).bind(&signature).bind(key_id)
        .execute(&mut *tx).await?;
    for (i, (id, _)) in pending.iter().enumerate() {
        sqlx::query("UPDATE credentials SET block_height = $2, leaf_index = $3 WHERE id = $1")
            .bind(id)
            .bind(height)
            .bind(i as i32)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    audit::actor_log(
        &st.db,
        &user,
        "BLOCK_SEALED",
        "block",
        &height.to_string(),
        json!({ "credentials": leaves.len(), "merkle_root": root }),
    )
    .await;
    Ok(Json(
        json!({ "height": height, "block_hash": hash, "merkle_root": root, "credentials": leaves.len() }),
    ))
}

pub async fn blocks(State(st): State<AppState>, _user: AuthUser) -> Res<Json<Value>> {
    let rows: Vec<Block> = sqlx::query_as("SELECT * FROM blocks ORDER BY height DESC LIMIT 100")
        .fetch_all(&st.db)
        .await?;
    let pending: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM credentials WHERE status = 'issued' AND block_height IS NULL",
    )
    .fetch_one(&st.db)
    .await?;
    Ok(Json(json!({
        "pending_unanchored": pending.0,
        "blocks": rows.iter().map(|b| json!({
            "height": b.height, "prev_hash": b.prev_hash, "merkle_root": b.merkle_root, "block_hash": b.block_hash,
            "timestamp": b.ts, "credentials": b.leaves().len(),
        })).collect::<Vec<_>>(),
    })))
}

/// Public: re-verifies the entire chain (linkage, hashes, Merkle roots, signatures, leaf integrity).
pub async fn verify_chain(State(st): State<AppState>) -> Res<Json<Value>> {
    let rows: Vec<Block> = sqlx::query_as("SELECT * FROM blocks ORDER BY height")
        .fetch_all(&st.db)
        .await?;
    let mut prev = GENESIS.to_string();
    let mut report = vec![];
    let mut all_ok = true;
    for (i, b) in rows.iter().enumerate() {
        let (block_ok, key_status) = b.check(&st.db).await?;
        let linked = b.prev_hash == prev && b.height == i as i64 + 1;
        let leaves = b.leaves();
        let stored: Vec<(String,)> = sqlx::query_as(
            "SELECT credential_hash FROM credentials WHERE block_height = $1 ORDER BY leaf_index",
        )
        .bind(b.height)
        .fetch_all(&st.db)
        .await?;
        let leaves_ok = stored
            .iter()
            .map(|(h,)| h.as_str())
            .eq(leaves.iter().map(String::as_str));
        let ok = block_ok && linked && leaves_ok;
        all_ok &= ok;
        report.push(json!({ "height": b.height, "ok": ok, "linked": linked, "block_ok": block_ok, "leaves_match_credentials": leaves_ok, "key_status": key_status }));
        prev = b.block_hash.clone();
    }
    Ok(Json(
        json!({ "ok": all_ok, "length": rows.len(), "blocks": report }),
    ))
}
