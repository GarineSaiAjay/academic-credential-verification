use std::io::Cursor;

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

use crate::{
    audit,
    auth::{AuthUser, Role},
    crypto,
    error::{AppError, Res},
    keys, AppState,
};

pub const STAGES: [&str; 4] = ["faculty", "exam_cell", "registrar", "university"];

#[derive(FromRow, Clone)]
pub struct CredRow {
    pub id: Uuid,
    pub student_id: String,
    pub student_name: String,
    pub program: String,
    pub graduation_date: NaiveDate,
    pub gpa: Option<String>,
    pub honors: Option<String>,
    pub credential_hash: String,
    pub status: String,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoke_reason: Option<String>,
    pub block_height: Option<i64>,
    pub leaf_index: Option<i32>,
}

const CRED_COLS: &str = "id, student_id, student_name, program, graduation_date, gpa, honors, credential_hash, status, created_by, created_at, revoked_at, revoke_reason, block_height, leaf_index";

#[derive(FromRow)]
pub struct ApprovalRow {
    pub role: String,
    pub signature: String,
    pub signed_at: DateTime<Utc>,
    pub key_id: Uuid,
    pub public_key: String,
    pub key_status: String,
}

/// A signed rejection or revocation, with the key that signed it.
#[derive(FromRow)]
pub struct EventRow {
    pub kind: String,
    pub stage: String,
    pub reason: String,
    pub ts: i64,
    pub legacy: bool,
    pub created_at: DateTime<Utc>,
    pub signature: String,
    pub key_id: Uuid,
    pub public_key: String,
    pub key_status: String,
}

pub struct Termination {
    pub row: EventRow,
    /// Right stage for the kind, signature verifies, and the signing key has not been revoked.
    pub valid: bool,
}

impl EventRow {
    fn evaluate(self, c: &CredRow) -> Termination {
        let stage_ok = match self.kind.as_str() {
            "revoked" => self.stage == "university",
            "rejected" => matches!(
                self.stage.as_str(),
                "exam_cell" | "registrar" | "university"
            ),
            _ => false,
        };
        let valid = stage_ok
            && self.key_status != "revoked"
            && crypto::verify(
                &self.public_key,
                &self.signature,
                &crypto::event_message(
                    c.id,
                    &self.kind,
                    &self.stage,
                    &c.credential_hash,
                    &self.reason,
                    self.ts,
                    self.legacy,
                ),
            );
        Termination { row: self, valid }
    }

    fn view(&self, valid: bool) -> Value {
        json!({
            "kind": self.kind, "stage": self.stage, "reason": self.reason, "at": self.created_at,
            "legacy": self.legacy, "valid": valid, "key_id": self.key_id,
        })
    }
}

async fn fetch_event<'e>(
    e: impl PgExecutor<'e>,
    id: Uuid,
    c: &CredRow,
) -> Res<Option<Termination>> {
    let row: Option<EventRow> = sqlx::query_as(
        "SELECT ev.kind, ev.stage, ev.reason, ev.ts, ev.legacy, ev.created_at, ev.signature, ev.key_id,
                k.public_key, k.status AS key_status
         FROM credential_events ev JOIN signing_keys k ON k.id = ev.key_id WHERE ev.credential_id = $1",
    )
    .bind(id)
    .fetch_optional(e)
    .await?;
    Ok(row.map(|r| r.evaluate(c)))
}

/// The status column must agree with the signed event: a final status needs a valid event of that kind,
/// and an event needs the matching status. Anything else means the column or the event was tampered with.
pub fn termination_ok(c: &CredRow, t: Option<&Termination>) -> bool {
    match t {
        None => !matches!(c.status.as_str(), "revoked" | "rejected"),
        Some(t) => t.valid && t.row.kind == c.status,
    }
}

impl CredRow {
    /// Recomputes the content hash from the stored fields (detects any database tampering).
    pub fn recompute_hash(&self) -> String {
        content_hash(
            self.id,
            &self.student_id,
            &self.student_name,
            &self.program,
            self.graduation_date,
            self.gpa.as_deref(),
            self.honors.as_deref(),
        )
    }
}

fn content_hash(
    id: Uuid,
    student_id: &str,
    name: &str,
    program: &str,
    date: NaiveDate,
    gpa: Option<&str>,
    honors: Option<&str>,
) -> String {
    crypto::canonical_hash(&json!({
        "v": 1, "id": id.to_string(), "student_id": student_id, "student_name": name,
        "program": program, "graduation_date": date.to_string(), "gpa": gpa, "honors": honors,
    }))
}

async fn fetch_approvals<'e>(e: impl PgExecutor<'e>, id: Uuid) -> Res<Vec<ApprovalRow>> {
    Ok(sqlx::query_as(
        "SELECT a.role, a.signature, a.signed_at, a.key_id, k.public_key, k.status AS key_status
         FROM approvals a JOIN signing_keys k ON k.id = a.key_id WHERE a.credential_id = $1 ORDER BY a.signed_at, a.id",
    ).bind(id).fetch_all(e).await?)
}

#[derive(Serialize)]
pub struct SigView {
    pub role: String,
    pub valid: bool,
    pub key_id: Uuid,
    pub key_status: String,
    pub public_key: String,
    pub signed_at: DateTime<Utc>,
}

pub struct Evaluation {
    pub hash_ok: bool,
    pub order_ok: bool,
    pub status_ok: bool,
    pub sigs: Vec<SigView>,
}

impl Evaluation {
    pub fn sigs_ok(&self) -> bool {
        self.sigs
            .iter()
            .all(|s| s.valid && s.key_status != "revoked")
    }
    pub fn intact(&self) -> bool {
        self.hash_ok && self.order_ok && self.status_ok && self.sigs_ok()
    }
}

pub fn evaluate(c: &CredRow, rows: &[ApprovalRow]) -> Evaluation {
    let expected = match c.status.as_str() {
        "pending_exam_cell" => Some(1),
        "pending_registrar" => Some(2),
        "pending_university" => Some(3),
        "issued" => Some(4),
        _ => None,
    };
    Evaluation {
        hash_ok: c.recompute_hash() == c.credential_hash,
        order_ok: rows
            .iter()
            .enumerate()
            .all(|(i, a)| STAGES.get(i) == Some(&a.role.as_str())),
        status_ok: expected.is_none_or(|n| rows.len() == n),
        sigs: rows
            .iter()
            .map(|a| SigView {
                role: a.role.clone(),
                valid: crypto::verify(
                    &a.public_key,
                    &a.signature,
                    &crypto::approval_message(c.id, &a.role, &c.credential_hash),
                ),
                key_id: a.key_id,
                key_status: a.key_status.clone(),
                public_key: a.public_key.clone(),
                signed_at: a.signed_at,
            })
            .collect(),
    }
}

/// A signed event decides the outcome, whatever the mutable status column says. A final status with no
/// valid event behind it is treated as tampering.
pub fn verdict(c: &CredRow, ev: &Evaluation, t: Option<&Termination>) -> &'static str {
    match (c.status.as_str(), t) {
        (_, Some(t)) if !t.valid => "INVALID",
        (_, Some(t)) if t.row.kind == "revoked" => "REVOKED",
        (_, Some(_)) if ev.hash_ok && ev.order_ok && ev.sigs_ok() => "REJECTED",
        (_, Some(_)) => "INVALID",
        ("revoked" | "rejected", None) => "INVALID",
        _ if !ev.intact() => "INVALID",
        ("issued", None) => "VALID",
        _ => "PENDING",
    }
}

#[derive(Deserialize)]
pub struct CreateBody {
    student_id: String,
    student_name: String,
    program: String,
    graduation_date: String,
    gpa: Option<String>,
    honors: Option<String>,
}

fn clean(field: &str, v: &str, max: usize) -> Res<String> {
    let v = v.trim();
    if v.is_empty() || v.chars().count() > max || v.chars().any(char::is_control) {
        return Err(AppError::BadRequest(format!(
            "{field} is required (max {max} chars, no control characters)"
        )));
    }
    Ok(v.to_string())
}

fn clean_opt(field: &str, v: Option<String>, max: usize) -> Res<Option<String>> {
    v.filter(|s| !s.trim().is_empty())
        .map(|s| clean(field, &s, max))
        .transpose()
}

pub async fn create(
    State(st): State<AppState>,
    user: AuthUser,
    Json(b): Json<CreateBody>,
) -> Res<(StatusCode, Json<Value>)> {
    user.require(&[Role::Faculty])?;
    let student_id = clean("student_id", &b.student_id, 64)?;
    let name = clean("student_name", &b.student_name, 200)?;
    let program = clean("program", &b.program, 200)?;
    let gpa = clean_opt("gpa", b.gpa, 10)?;
    let honors = clean_opt("honors", b.honors, 100)?;
    let date = NaiveDate::parse_from_str(b.graduation_date.trim(), "%Y-%m-%d")
        .map_err(|_| AppError::BadRequest("graduation_date must be YYYY-MM-DD".into()))?;

    let id = Uuid::new_v4();
    let hash = content_hash(
        id,
        &student_id,
        &name,
        &program,
        date,
        gpa.as_deref(),
        honors.as_deref(),
    );
    let (key_id, seed) = keys::active_signer(&st, "faculty").await?;
    let signature = crypto::sign(&seed, &crypto::approval_message(id, "faculty", &hash));

    let mut tx = st.db.begin().await?;
    sqlx::query(
        "INSERT INTO credentials (id, student_id, student_name, program, graduation_date, gpa, honors, credential_hash, status, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending_exam_cell',$9)",
    ).bind(id).bind(&student_id).bind(&name).bind(&program).bind(date).bind(&gpa).bind(&honors).bind(&hash).bind(user.id)
    .execute(&mut *tx).await?;
    sqlx::query("INSERT INTO approvals (id, credential_id, role, approver_id, key_id, signature) VALUES ($1,$2,'faculty',$3,$4,$5)")
        .bind(Uuid::new_v4()).bind(id).bind(user.id).bind(key_id).bind(&signature)
        .execute(&mut *tx).await?;
    tx.commit().await?;

    audit::actor_log(
        &st.db,
        &user,
        "CREDENTIAL_CREATED",
        "credential",
        &id.to_string(),
        json!({ "hash": hash }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "credential_hash": hash, "status": "pending_exam_cell" })),
    ))
}

#[derive(Deserialize)]
pub struct ListQuery {
    status: Option<String>,
}

pub async fn list(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<ListQuery>,
) -> Res<Json<Value>> {
    let own_only = user.role == Role::Faculty;
    let rows: Vec<CredRow> = sqlx::query_as(&format!(
        "SELECT {CRED_COLS} FROM credentials WHERE ($1::uuid IS NULL OR created_by = $1) AND ($2::text IS NULL OR status = $2)
         ORDER BY created_at DESC LIMIT 200"
    ))
    .bind(own_only.then_some(user.id))
    .bind(q.status)
    .fetch_all(&st.db).await?;
    Ok(Json(json!({ "credentials": rows.iter().map(|c| json!({
        "id": c.id, "student_id": c.student_id, "student_name": c.student_name, "program": c.program,
        "status": c.status, "created_at": c.created_at,
    })).collect::<Vec<_>>() })))
}

async fn load(st: &AppState, user: &AuthUser, id: Uuid) -> Res<CredRow> {
    let c: CredRow = sqlx::query_as(&format!(
        "SELECT {CRED_COLS} FROM credentials WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    if user.role == Role::Faculty && c.created_by != user.id {
        return Err(AppError::NotFound("not found".into()));
    }
    Ok(c)
}

fn full_view(c: &CredRow, ev: &Evaluation, t: Option<&Termination>) -> Value {
    json!({
        "id": c.id, "student_id": c.student_id, "student_name": c.student_name, "program": c.program,
        "graduation_date": c.graduation_date, "gpa": c.gpa, "honors": c.honors,
        "credential_hash": c.credential_hash, "status": c.status, "created_at": c.created_at,
        "revoked_at": c.revoked_at, "revoke_reason": c.revoke_reason,
        "block_height": c.block_height, "leaf_index": c.leaf_index,
        "verdict": verdict(c, ev, t), "signatures": ev.sigs,
        "termination": t.map(|t| t.row.view(t.valid)),
        "checks": { "hash_ok": ev.hash_ok, "order_ok": ev.order_ok, "status_ok": ev.status_ok, "signatures_ok": ev.sigs_ok(), "termination_ok": termination_ok(c, t) },
    })
}

pub async fn get(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Res<Json<Value>> {
    let c = load(&st, &user, id).await?;
    let ev = evaluate(&c, &fetch_approvals(&st.db, id).await?);
    let t = fetch_event(&st.db, id, &c).await?;
    Ok(Json(full_view(&c, &ev, t.as_ref())))
}

/// (stage that must sign next, status after signing)
fn next_stage(status: &str, role: Role) -> Option<(&'static str, &'static str)> {
    match (status, role) {
        ("pending_exam_cell", Role::ExamCell) => Some(("exam_cell", "pending_registrar")),
        ("pending_registrar", Role::Registrar) => Some(("registrar", "pending_university")),
        ("pending_university", Role::UniversityAdmin) => Some(("university", "issued")),
        _ => None,
    }
}

async fn lock(tx: &mut sqlx::PgConnection, id: Uuid) -> Res<CredRow> {
    Ok(sqlx::query_as(&format!(
        "SELECT {CRED_COLS} FROM credentials WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_one(tx)
    .await?)
}

/// A credential that already has a signed rejection or revocation can never be acted on again.
async fn ensure_open(tx: &mut sqlx::PgConnection, id: Uuid) -> Res<()> {
    let ended: Option<(String,)> =
        sqlx::query_as("SELECT kind FROM credential_events WHERE credential_id = $1")
            .bind(id)
            .fetch_optional(tx)
            .await?;
    match ended {
        None => Ok(()),
        Some((kind,)) => Err(AppError::Conflict(format!("credential is already {kind}"))),
    }
}

/// Signs a rejection or revocation with the stage's key and stores it, in the caller's transaction.
async fn record_event(
    st: &AppState,
    tx: &mut sqlx::PgConnection,
    c: &CredRow,
    kind: &str,
    stage: &str,
    reason: &str,
    actor: Uuid,
) -> Res<()> {
    let (key_id, seed) = keys::active_signer(st, stage).await?;
    let ts = Utc::now().timestamp();
    let signature = crypto::sign(
        &seed,
        &crypto::event_message(c.id, kind, stage, &c.credential_hash, reason, ts, false),
    );
    sqlx::query(
        "INSERT INTO credential_events (credential_id, kind, stage, reason, actor_id, key_id, signature, ts)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(c.id)
    .bind(kind)
    .bind(stage)
    .bind(reason)
    .bind(actor)
    .bind(key_id)
    .bind(signature)
    .bind(ts)
    .execute(tx)
    .await?;
    Ok(())
}

pub async fn approve(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Res<Json<Value>> {
    let mut tx = st.db.begin().await?;
    let c = lock(&mut tx, id).await?;
    let (stage, next) = next_stage(&c.status, user.role).ok_or_else(|| {
        AppError::Conflict(format!(
            "credential is '{}'; your role cannot sign it now",
            c.status
        ))
    })?;

    ensure_open(&mut tx, id).await?;
    let prior = fetch_approvals(&mut *tx, id).await?;
    if !evaluate(&c, &prior).intact() {
        return Err(AppError::Conflict(
            "integrity check failed on existing signatures; refusing to co-sign".into(),
        ));
    }
    let (key_id, seed) = keys::active_signer(&st, stage).await?;
    let signature = crypto::sign(
        &seed,
        &crypto::approval_message(id, stage, &c.credential_hash),
    );
    sqlx::query("INSERT INTO approvals (id, credential_id, role, approver_id, key_id, signature) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(Uuid::new_v4()).bind(id).bind(stage).bind(user.id).bind(key_id).bind(signature)
        .execute(&mut *tx).await?;
    sqlx::query("UPDATE credentials SET status = $2 WHERE id = $1")
        .bind(id)
        .bind(next)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    audit::actor_log(
        &st.db,
        &user,
        "CREDENTIAL_SIGNED",
        "credential",
        &id.to_string(),
        json!({ "stage": stage, "status": next }),
    )
    .await;
    Ok(Json(json!({ "id": id, "status": next })))
}

#[derive(Deserialize)]
pub struct ReasonBody {
    reason: String,
}

fn reason(b: &ReasonBody) -> Res<String> {
    clean("reason", &b.reason, 500)
}

pub async fn reject(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(b): Json<ReasonBody>,
) -> Res<Json<Value>> {
    let reason = reason(&b)?;
    let mut tx = st.db.begin().await?;
    let c = lock(&mut tx, id).await?;
    let (stage, _) = next_stage(&c.status, user.role).ok_or_else(|| {
        AppError::Conflict(format!(
            "credential is '{}'; your role cannot reject it now",
            c.status
        ))
    })?;
    ensure_open(&mut tx, id).await?;
    sqlx::query("UPDATE credentials SET status = 'rejected', revoke_reason = $2 WHERE id = $1")
        .bind(id)
        .bind(&reason)
        .execute(&mut *tx)
        .await?;
    record_event(&st, &mut tx, &c, "rejected", stage, &reason, user.id).await?;
    tx.commit().await?;
    audit::actor_log(
        &st.db,
        &user,
        "CREDENTIAL_REJECTED",
        "credential",
        &id.to_string(),
        json!({ "reason": reason }),
    )
    .await;
    Ok(Json(json!({ "id": id, "status": "rejected" })))
}

pub async fn revoke(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(b): Json<ReasonBody>,
) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin])?;
    let reason = reason(&b)?;
    let mut tx = st.db.begin().await?;
    let c = lock(&mut tx, id).await?;
    if c.status != "issued" {
        return Err(AppError::Conflict(
            "only issued credentials can be revoked".into(),
        ));
    }
    ensure_open(&mut tx, id).await?;
    sqlx::query("UPDATE credentials SET status = 'revoked', revoked_at = now(), revoke_reason = $2 WHERE id = $1")
        .bind(id)
        .bind(&reason)
        .execute(&mut *tx)
        .await?;
    record_event(&st, &mut tx, &c, "revoked", "university", &reason, user.id).await?;
    tx.commit().await?;
    audit::actor_log(
        &st.db,
        &user,
        "CREDENTIAL_REVOKED",
        "credential",
        &id.to_string(),
        json!({ "reason": reason }),
    )
    .await;
    Ok(Json(json!({ "id": id, "status": "revoked" })))
}

/// Signs events for credentials that were rejected or revoked before events existed (or whose event was
/// lost), so they keep their verdict instead of reading as tampered. Safe to run on every start.
pub async fn backfill_events(st: &AppState) -> Res<()> {
    type Orphan = (
        Uuid,
        String,
        String,
        Option<DateTime<Utc>>,
        Option<String>,
        i64,
    );
    let rows: Vec<Orphan> = sqlx::query_as(
        "SELECT c.id, c.credential_hash, c.status, c.revoked_at, c.revoke_reason,
                (SELECT count(*) FROM approvals a WHERE a.credential_id = c.id)
         FROM credentials c
         WHERE c.status IN ('revoked','rejected')
           AND NOT EXISTS (SELECT 1 FROM credential_events e WHERE e.credential_id = c.id)",
    )
    .fetch_all(&st.db)
    .await?;
    for (id, hash, status, revoked_at, why, approvals) in rows {
        // A rejection happened at the first stage that had not signed yet.
        let stage = match (status.as_str(), STAGES.get(approvals as usize)) {
            ("revoked", _) => "university",
            (_, Some(stage)) if *stage != "faculty" => stage,
            _ => continue,
        };
        let reason = why.unwrap_or_else(|| "(no reason recorded)".into());
        let ts = revoked_at.unwrap_or_else(Utc::now).timestamp();
        let (key_id, seed) = match keys::active_signer(st, stage).await {
            Ok(k) => k,
            Err(_) => {
                tracing::warn!(%id, stage, "cannot sign a missing credential event: no usable '{stage}' key");
                continue;
            }
        };
        let signature = crypto::sign(
            &seed,
            &crypto::event_message(id, &status, stage, &hash, &reason, ts, true),
        );
        let inserted = sqlx::query(
            "INSERT INTO credential_events (credential_id, kind, stage, reason, key_id, signature, ts, legacy)
             VALUES ($1,$2,$3,$4,$5,$6,$7,true) ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(&status)
        .bind(stage)
        .bind(&reason)
        .bind(key_id)
        .bind(signature)
        .bind(ts)
        .execute(&st.db)
        .await?
        .rows_affected();
        if inserted == 1 {
            audit::log(
                &st.db,
                None,
                None,
                "EVENT_BACKFILLED",
                Some("credential"),
                Some(&id.to_string()),
                json!({ "kind": status, "stage": stage }),
            )
            .await;
            tracing::warn!(%id, kind = %status, "signed a missing credential event");
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    h: Option<String>,
}

/// Public, unauthenticated verification: recomputes everything from stored data.
pub async fn verify(
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<VerifyQuery>,
) -> Res<Json<Value>> {
    let c: CredRow = sqlx::query_as(&format!(
        "SELECT {CRED_COLS} FROM credentials WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    let ev = evaluate(&c, &fetch_approvals(&st.db, id).await?);
    let t = fetch_event(&st.db, id, &c).await?;
    let anchor = crate::ledger::anchor_for(&st.db, &c).await?;
    let qr_match =
        q.h.as_deref()
            .filter(|h| h.len() >= 8)
            .map(|h| c.credential_hash.starts_with(&h.to_lowercase()));
    let mut verdict = verdict(&c, &ev, t.as_ref());
    if verdict == "VALID" && anchor.as_ref().is_some_and(|a| !a.ok) {
        verdict = "INVALID";
    }
    Ok(Json(json!({
        "verdict": verdict,
        "credential": {
            "id": c.id, "student_name": c.student_name, "program": c.program, "graduation_date": c.graduation_date,
            "gpa": c.gpa, "honors": c.honors, "status": c.status, "credential_hash": c.credential_hash,
            // Shown from the signed event when there is one, not from the editable columns.
            "revoked_at": t.as_ref().filter(|t| t.row.kind == "revoked").map(|t| t.row.created_at),
            "revoke_reason": t.as_ref().map(|t| t.row.reason.as_str()),
        },
        "termination": t.as_ref().map(|t| t.row.view(t.valid)),
        "checks": { "hash_ok": ev.hash_ok, "order_ok": ev.order_ok, "status_ok": ev.status_ok, "signatures_ok": ev.sigs_ok(), "termination_ok": termination_ok(&c, t.as_ref()) },
        "signatures": ev.sigs,
        "anchor": anchor,
        "qr_hash_match": qr_match,
    })))
}

pub async fn qr(State(st): State<AppState>, Path(id): Path<Uuid>) -> Res<impl IntoResponse> {
    let (hash,): (String,) =
        sqlx::query_as("SELECT credential_hash FROM credentials WHERE id = $1")
            .bind(id)
            .fetch_one(&st.db)
            .await?;
    let url = format!("{}/#/verify/{}/{}", st.cfg.public_base_url, id, &hash[..16]);
    let code =
        qrcode::QrCode::new(url.as_bytes()).map_err(|e| AppError::Internal(e.to_string()))?;
    let img = code
        .render::<image::Luma<u8>>()
        .min_dimensions(320, 320)
        .build();
    let mut png = Vec::new();
    img.write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok((
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        png,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(status: &str) -> CredRow {
        CredRow {
            id: Uuid::nil(),
            student_id: "S".into(),
            student_name: "Ada".into(),
            program: "BSc".into(),
            graduation_date: NaiveDate::from_ymd_opt(2025, 5, 15).unwrap(),
            gpa: None,
            honors: None,
            credential_hash: "ab".repeat(32),
            status: status.into(),
            created_by: Uuid::nil(),
            created_at: Utc::now(),
            revoked_at: None,
            revoke_reason: None,
            block_height: None,
            leaf_index: None,
        }
    }

    fn ev(intact: bool) -> Evaluation {
        Evaluation {
            hash_ok: intact,
            order_ok: true,
            status_ok: true,
            sigs: vec![],
        }
    }

    fn event(kind: &str, stage: &str, seed: &[u8; 32], reason: &str, key_status: &str) -> EventRow {
        let c = cred(kind);
        let ts = 1_700_000_000;
        EventRow {
            kind: kind.into(),
            stage: stage.into(),
            reason: reason.into(),
            ts,
            legacy: false,
            created_at: Utc::now(),
            signature: crypto::sign(
                seed,
                &crypto::event_message(c.id, kind, stage, &c.credential_hash, reason, ts, false),
            ),
            key_id: Uuid::nil(),
            public_key: crypto::public_from_seed(seed),
            key_status: key_status.into(),
        }
    }

    #[test]
    fn a_genuine_event_is_valid_and_tampering_breaks_it() {
        let (seed, _) = crypto::new_keypair();
        let c = cred("revoked");
        assert!(
            event("revoked", "university", &seed, "error", "active")
                .evaluate(&c)
                .valid
        );

        let mut edited = event("revoked", "university", &seed, "error", "active");
        edited.reason = "a different reason".into();
        assert!(!edited.evaluate(&c).valid, "reason is signed");

        let mut later = event("revoked", "university", &seed, "error", "active");
        later.ts += 1;
        assert!(!later.evaluate(&c).valid, "time is signed");

        let mut other_card = cred("revoked");
        other_card.credential_hash = "cd".repeat(32);
        assert!(
            !event("revoked", "university", &seed, "error", "active")
                .evaluate(&other_card)
                .valid,
            "bound to the credential's content hash"
        );

        let (other_seed, _) = crypto::new_keypair();
        let mut forged = event("revoked", "university", &other_seed, "error", "active");
        forged.public_key = crypto::public_from_seed(&seed);
        assert!(!forged.evaluate(&c).valid, "signed by someone else");
    }

    #[test]
    fn stage_must_fit_the_kind_and_the_key_must_be_trusted() {
        let (seed, _) = crypto::new_keypair();
        assert!(
            !event("revoked", "registrar", &seed, "r", "active")
                .evaluate(&cred("revoked"))
                .valid
        );
        assert!(
            !event("rejected", "faculty", &seed, "r", "active")
                .evaluate(&cred("rejected"))
                .valid
        );
        assert!(
            event("rejected", "registrar", &seed, "r", "active")
                .evaluate(&cred("rejected"))
                .valid
        );
        assert!(
            !event("revoked", "university", &seed, "r", "revoked")
                .evaluate(&cred("revoked"))
                .valid
        );
        assert!(
            event("revoked", "university", &seed, "r", "retired")
                .evaluate(&cred("revoked"))
                .valid
        );
    }

    #[test]
    fn verdicts_follow_the_signed_event_not_the_status_column() {
        let (seed, _) = crypto::new_keypair();
        let good = |kind: &str, stage: &str| {
            let c = cred(kind);
            event(kind, stage, &seed, "why", "active").evaluate(&c)
        };
        let bad = |kind: &str| {
            let mut t = good(kind, "university");
            t.valid = false;
            t
        };
        // (status column, event, content intact) -> verdict
        let table: Vec<(&str, Option<Termination>, bool, &str)> = vec![
            ("issued", None, true, "VALID"),
            ("issued", None, false, "INVALID"),
            ("pending_registrar", None, true, "PENDING"),
            (
                "revoked",
                Some(good("revoked", "university")),
                true,
                "REVOKED",
            ),
            (
                "revoked",
                Some(good("revoked", "university")),
                false,
                "REVOKED",
            ),
            // someone set the column back to "issued" but could not remove the signed revocation
            (
                "issued",
                Some(good("revoked", "university")),
                true,
                "REVOKED",
            ),
            // revoked/rejected written into the column with no signed event behind it
            ("revoked", None, true, "INVALID"),
            ("rejected", None, true, "INVALID"),
            ("revoked", Some(bad("revoked")), true, "INVALID"),
            (
                "rejected",
                Some(good("rejected", "registrar")),
                true,
                "REJECTED",
            ),
            (
                "rejected",
                Some(good("rejected", "registrar")),
                false,
                "INVALID",
            ),
            (
                "pending_registrar",
                Some(good("rejected", "registrar")),
                true,
                "REJECTED",
            ),
        ];
        for (status, t, intact, want) in table {
            let c = cred(status);
            assert_eq!(
                verdict(&c, &ev(intact), t.as_ref()),
                want,
                "{status} intact={intact}"
            );
        }
    }

    #[test]
    fn termination_consistency() {
        let (seed, _) = crypto::new_keypair();
        let t = |kind: &str, stage: &str| {
            event(kind, stage, &seed, "r", "active").evaluate(&cred(kind))
        };
        assert!(termination_ok(&cred("issued"), None));
        assert!(termination_ok(
            &cred("revoked"),
            Some(&t("revoked", "university"))
        ));
        assert!(!termination_ok(&cred("revoked"), None));
        assert!(!termination_ok(
            &cred("issued"),
            Some(&t("revoked", "university"))
        ));
        assert!(!termination_ok(
            &cred("rejected"),
            Some(&t("revoked", "university"))
        ));
    }
}
