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

pub fn verdict(c: &CredRow, ev: &Evaluation) -> &'static str {
    match c.status.as_str() {
        "revoked" => "REVOKED",
        _ if !ev.intact() => "INVALID",
        "issued" => "VALID",
        "rejected" => "REJECTED",
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

fn full_view(c: &CredRow, ev: &Evaluation) -> Value {
    json!({
        "id": c.id, "student_id": c.student_id, "student_name": c.student_name, "program": c.program,
        "graduation_date": c.graduation_date, "gpa": c.gpa, "honors": c.honors,
        "credential_hash": c.credential_hash, "status": c.status, "created_at": c.created_at,
        "revoked_at": c.revoked_at, "revoke_reason": c.revoke_reason,
        "block_height": c.block_height, "leaf_index": c.leaf_index,
        "verdict": verdict(c, ev), "signatures": ev.sigs,
        "checks": { "hash_ok": ev.hash_ok, "order_ok": ev.order_ok, "status_ok": ev.status_ok, "signatures_ok": ev.sigs_ok() },
    })
}

pub async fn get(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Res<Json<Value>> {
    let c = load(&st, &user, id).await?;
    let ev = evaluate(&c, &fetch_approvals(&st.db, id).await?);
    Ok(Json(full_view(&c, &ev)))
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
    next_stage(&c.status, user.role).ok_or_else(|| {
        AppError::Conflict(format!(
            "credential is '{}'; your role cannot reject it now",
            c.status
        ))
    })?;
    sqlx::query("UPDATE credentials SET status = 'rejected', revoke_reason = $2 WHERE id = $1")
        .bind(id)
        .bind(&reason)
        .execute(&mut *tx)
        .await?;
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
    let n = sqlx::query("UPDATE credentials SET status = 'revoked', revoked_at = now(), revoke_reason = $2 WHERE id = $1 AND status = 'issued'")
        .bind(id).bind(&reason).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(AppError::Conflict(
            "only issued credentials can be revoked".into(),
        ));
    }
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
    let anchor = crate::ledger::anchor_for(&st.db, &c).await?;
    let qr_match =
        q.h.as_deref()
            .filter(|h| h.len() >= 8)
            .map(|h| c.credential_hash.starts_with(&h.to_lowercase()));
    let mut verdict = verdict(&c, &ev);
    if verdict == "VALID" && anchor.as_ref().is_some_and(|a| !a.ok) {
        verdict = "INVALID";
    }
    Ok(Json(json!({
        "verdict": verdict,
        "credential": {
            "id": c.id, "student_name": c.student_name, "program": c.program, "graduation_date": c.graduation_date,
            "gpa": c.gpa, "honors": c.honors, "status": c.status, "credential_hash": c.credential_hash,
            "revoked_at": c.revoked_at, "revoke_reason": c.revoke_reason,
        },
        "checks": { "hash_ok": ev.hash_ok, "order_ok": ev.order_ok, "status_ok": ev.status_ok, "signatures_ok": ev.sigs_ok() },
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
