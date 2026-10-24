use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    audit,
    auth::{AuthUser, Role},
    credentials::CredRow,
    crypto::{self, merkle, Step},
    error::{AppError, Res},
    keys, page, timestamp, AppState,
};

/// A block holds at most this many credentials, so one seal can never build an unbounded block. The rest wait
/// for the next seal.
const MAX_PER_BLOCK: i64 = 10_000;

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

pub fn block_hash(height: i64, prev: &str, root: &str, ts: i64, n: usize) -> String {
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
    /// Proof from an external time-stamping authority, if the block has one yet.
    pub external_timestamp: Option<Value>,
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
    let external_timestamp = timestamp::summary(db, b.height, &b.block_hash).await?;
    Ok(Some(Anchor {
        height,
        block_hash: b.block_hash,
        merkle_root: b.merkle_root,
        leaf_index: index,
        proof,
        timestamp: b.ts,
        external_timestamp,
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
        "SELECT id, credential_hash FROM credentials WHERE status = 'issued' AND block_height IS NULL ORDER BY created_at, id LIMIT $1 FOR UPDATE",
    ).bind(MAX_PER_BLOCK).fetch_all(&mut *tx).await?;
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
    // The chain just grew: the next public check must look at it.
    *st.chain_cache.lock().await = None;

    if st.cfg.tsa.is_some() {
        let st = st.clone();
        tokio::spawn(async move {
            timestamp::timestamp_pending(&st).await;
        });
    }

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

#[derive(Deserialize)]
pub struct BlocksQuery {
    limit: Option<i64>,
    /// Blocks below this height only: the `next` value of the previous page.
    before: Option<i64>,
}

/// One page of blocks, newest first.
pub async fn blocks(
    State(st): State<AppState>,
    _user: AuthUser,
    Query(q): Query<BlocksQuery>,
) -> Res<Json<Value>> {
    let limit = page::limit(q.limit, 50, 200);
    let mut rows: Vec<Block> = sqlx::query_as(
        "SELECT * FROM blocks WHERE ($1::bigint IS NULL OR height < $1) ORDER BY height DESC LIMIT $2",
    )
    .bind(q.before)
    .bind(limit + 1)
    .fetch_all(&st.db)
    .await?;
    let next = (rows.len() as i64 > limit).then(|| {
        rows.truncate(limit as usize);
        rows.last().map_or(0, |b| b.height)
    });
    let pending: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM credentials WHERE status = 'issued' AND block_height IS NULL",
    )
    .fetch_one(&st.db)
    .await?;
    let heights: Vec<i64> = rows.iter().map(|b| b.height).collect();
    let stamps: HashMap<i64, (chrono::DateTime<chrono::Utc>, String, String)> =
        sqlx::query_as::<_, (i64, chrono::DateTime<chrono::Utc>, String, String)>(
            "SELECT block_height, gen_time, tsa_url, imprint FROM block_timestamps WHERE block_height = ANY($1)",
        )
        .bind(&heights)
        .fetch_all(&st.db)
        .await?
        .into_iter()
        .map(|(h, t, u, i)| (h, (t, u, i)))
        .collect();
    let blocks: Vec<Value> = rows
        .iter()
        .map(|b| {
            json!({
                "height": b.height, "prev_hash": b.prev_hash, "merkle_root": b.merkle_root, "block_hash": b.block_hash,
                "timestamp": b.ts, "credentials": b.leaves().len(),
                "external_timestamp": stamps.get(&b.height).map(|(time, tsa, imprint)| json!({ "time": time, "tsa": tsa, "imprint_ok": *imprint == b.block_hash })),
            })
        })
        .collect();
    Ok(Json(json!({
        "pending_unanchored": pending.0,
        "timestamping": st.cfg.tsa.as_ref().map(|t| json!({ "url": t.url })),
        "blocks": blocks,
        "next": next,
    })))
}

/// Result of checking the whole chain. Only failures are kept, so it stays small however long the chain is.
pub struct ChainSummary {
    length: i64,
    failed_total: i64,
    /// Heights of the first failing blocks (at most 100).
    failed: Vec<i64>,
    checked_at: i64,
}

/// Blocks checked per round trip to the database when walking the whole chain.
const CHECK_PAGE: i64 = 500;

/// Checks up to `limit` consecutive blocks starting at height `from`: linkage, hash, Merkle root, signature,
/// that the credentials stored for the block are exactly its leaves, and the outside timestamp. Uses a fixed
/// number of queries however many blocks that is. Returns each block's report and the height to continue from.
async fn check_range(db: &PgPool, from: i64, limit: i64) -> Res<(Vec<(bool, Value)>, Option<i64>)> {
    let mut rows: Vec<Block> =
        sqlx::query_as("SELECT * FROM blocks WHERE height >= $1 ORDER BY height LIMIT $2")
            .bind(from)
            .bind(limit + 1)
            .fetch_all(db)
            .await?;
    let next = (rows.len() as i64 > limit).then(|| {
        rows.truncate(limit as usize);
        rows.last().map_or(0, |b| b.height + 1)
    });
    if rows.is_empty() {
        return Ok((vec![], None));
    }
    // What the first block of the page must link back to.
    let mut prev: Option<String> = if from <= 1 {
        Some(GENESIS.to_string())
    } else {
        sqlx::query_scalar("SELECT block_hash FROM blocks WHERE height = $1")
            .bind(from - 1)
            .fetch_optional(db)
            .await?
    };
    let heights: Vec<i64> = rows.iter().map(|b| b.height).collect();
    let key_ids: Vec<Uuid> = rows.iter().map(|b| b.key_id).collect();
    let keys: HashMap<Uuid, (String, String)> = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT id, public_key, status FROM signing_keys WHERE id = ANY($1)",
    )
    .bind(&key_ids)
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|(id, k, s)| (id, (k, s)))
    .collect();
    let mut stored: HashMap<i64, Vec<String>> = HashMap::new();
    for (h, hash) in sqlx::query_as::<_, (i64, String)>(
        "SELECT block_height, credential_hash FROM credentials WHERE block_height = ANY($1) ORDER BY block_height, leaf_index",
    )
    .bind(&heights)
    .fetch_all(db)
    .await?
    {
        stored.entry(h).or_default().push(hash);
    }
    let stamps: HashMap<i64, String> = sqlx::query_as::<_, (i64, String)>(
        "SELECT block_height, imprint FROM block_timestamps WHERE block_height = ANY($1)",
    )
    .bind(&heights)
    .fetch_all(db)
    .await?
    .into_iter()
    .collect();

    let mut reports = Vec::with_capacity(rows.len());
    let mut expected_height = from;
    for b in &rows {
        let leaves = b.leaves();
        let (public, key_status) = keys.get(&b.key_id).cloned().unwrap_or_default();
        let block_ok = merkle::root(&leaves).as_deref() == Some(b.merkle_root.as_str())
            && block_hash(b.height, &b.prev_hash, &b.merkle_root, b.ts, leaves.len())
                == b.block_hash
            && crypto::verify(&public, &b.signature, b.block_hash.as_bytes())
            && key_status != "revoked";
        let linked = prev.as_deref() == Some(b.prev_hash.as_str()) && b.height == expected_height;
        let leaves_ok = stored.get(&b.height).map_or(&[][..], Vec::as_slice) == leaves.as_slice();
        // A stored timestamp must be about this very block; a block without one is merely not stamped yet.
        let stamp = match stamps.get(&b.height) {
            None => "none",
            Some(i) if *i == b.block_hash => "ok",
            Some(_) => "mismatch",
        };
        let ok = block_ok && linked && leaves_ok && stamp != "mismatch";
        reports.push((ok, json!({ "height": b.height, "ok": ok, "linked": linked, "block_ok": block_ok, "leaves_match_credentials": leaves_ok, "key_status": key_status, "external_timestamp": stamp })));
        prev = Some(b.block_hash.clone());
        expected_height = b.height + 1;
    }
    Ok((reports, next))
}

async fn check_all(db: &PgPool) -> Res<ChainSummary> {
    let (mut from, mut length, mut failed_total, mut failed) = (1, 0, 0, vec![]);
    loop {
        let (reports, next) = check_range(db, from, CHECK_PAGE).await?;
        for (ok, report) in &reports {
            length += 1;
            if !ok {
                failed_total += 1;
                if failed.len() < 100 {
                    failed.push(report["height"].as_i64().unwrap_or_default());
                }
            }
        }
        match next {
            Some(n) => from = n,
            None => break,
        }
    }
    Ok(ChainSummary {
        length,
        failed_total,
        failed,
        checked_at: chrono::Utc::now().timestamp(),
    })
}

/// The whole-chain result, recomputed at most once per `CHAIN_VERIFY_CACHE_SECS` however many people ask, and
/// whenever a block is sealed. Concurrent callers wait for one computation instead of each doing their own.
async fn chain_summary(st: &AppState) -> Res<(Arc<ChainSummary>, bool)> {
    let ttl = Duration::from_secs(st.cfg.chain_cache_secs);
    let mut cache = st.chain_cache.lock().await;
    if let Some((at, summary)) = cache.as_ref() {
        if at.elapsed() < ttl {
            return Ok((summary.clone(), true));
        }
    }
    let summary = Arc::new(check_all(&st.db).await?);
    *cache = Some((Instant::now(), summary.clone()));
    Ok((summary, false))
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    /// First block of the per-block report (default 1).
    from: Option<i64>,
    /// Blocks in the per-block report (default 100, at most 500).
    limit: Option<i64>,
}

/// Public: re-verifies the whole chain (linkage, hashes, Merkle roots, signatures, leaf integrity, outside
/// timestamps). `ok`, `length` and `failed_blocks` always describe the whole chain; `blocks` is a window of
/// per-block reports, and `next_from` is where to continue.
pub async fn verify_chain(
    State(st): State<AppState>,
    Query(q): Query<VerifyQuery>,
) -> Res<Json<Value>> {
    let (summary, cached) = chain_summary(&st).await?;
    let from = q.from.unwrap_or(1).max(1);
    let (reports, next_from) = check_range(&st.db, from, page::limit(q.limit, 100, 500)).await?;
    Ok(Json(json!({
        "ok": summary.failed_total == 0,
        "length": summary.length,
        "failed_total": summary.failed_total,
        "failed_blocks": summary.failed,
        "checked_at": summary.checked_at,
        "cached": cached,
        "from": from,
        "next_from": next_from,
        "blocks": reports.into_iter().map(|(_, r)| r).collect::<Vec<_>>(),
    })))
}
