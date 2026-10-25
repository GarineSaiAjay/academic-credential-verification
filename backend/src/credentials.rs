use std::io::Cursor;

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

use crate::{
    audit,
    auth::{AuthUser, Role},
    crypto,
    error::{AppError, Res},
    keys, page, webauthn, AppState,
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
    /// The credential this one replaces (part of the signed content hash).
    pub supersedes: Option<Uuid>,
}

const CRED_COLS: &str = "id, student_id, student_name, program, graduation_date, gpa, honors, credential_hash, status, created_by, created_at, revoked_at, revoke_reason, block_height, leaf_index, supersedes";

#[derive(FromRow)]
pub struct ApprovalRow {
    pub role: String,
    pub signature: String,
    pub signed_at: DateTime<Utc>,
    pub key_id: Uuid,
    pub public_key: String,
    pub key_status: String,
    // The approver's personal countersignature, when there is one.
    pub cs_key_id: Option<Uuid>,
    pub cs_rp_id: Option<String>,
    pub cs_origin: Option<String>,
    pub cs_auth: Option<Vec<u8>>,
    pub cs_client: Option<Vec<u8>>,
    pub cs_sig: Option<Vec<u8>>,
    pub uk_public_key: Option<Vec<u8>>,
    pub uk_status: Option<String>,
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

/// Everything the content hash covers. Credentials that replace another use hash version 2, which also
/// covers the id of the credential they replace; ordinary ones keep the original version-1 hash.
pub struct Content<'a> {
    pub id: Uuid,
    pub student_id: &'a str,
    pub student_name: &'a str,
    pub program: &'a str,
    pub graduation_date: NaiveDate,
    pub gpa: Option<&'a str>,
    pub honors: Option<&'a str>,
    pub supersedes: Option<Uuid>,
}

impl Content<'_> {
    pub fn hash(&self) -> String {
        let mut v = json!({
            "v": 1, "id": self.id.to_string(), "student_id": self.student_id, "student_name": self.student_name,
            "program": self.program, "graduation_date": self.graduation_date.to_string(),
            "gpa": self.gpa, "honors": self.honors,
        });
        if let Some(old) = self.supersedes {
            v["v"] = 2.into();
            v["supersedes"] = old.to_string().into();
        }
        crypto::canonical_hash(&v)
    }
}

impl CredRow {
    fn content(&self) -> Content<'_> {
        Content {
            id: self.id,
            student_id: &self.student_id,
            student_name: &self.student_name,
            program: &self.program,
            graduation_date: self.graduation_date,
            gpa: self.gpa.as_deref(),
            honors: self.honors.as_deref(),
            supersedes: self.supersedes,
        }
    }

    /// Recomputes the content hash from the stored fields (detects any database tampering).
    pub fn recompute_hash(&self) -> String {
        self.content().hash()
    }
}

async fn fetch_approvals<'e>(e: impl PgExecutor<'e>, id: Uuid) -> Res<Vec<ApprovalRow>> {
    Ok(sqlx::query_as(
        "SELECT a.role, a.signature, a.signed_at, a.key_id, k.public_key, k.status AS key_status,
                cs.user_key_id AS cs_key_id, cs.rp_id AS cs_rp_id, cs.origin AS cs_origin,
                cs.authenticator_data AS cs_auth, cs.client_data_json AS cs_client, cs.signature AS cs_sig,
                uk.public_key AS uk_public_key, uk.status AS uk_status
         FROM approvals a JOIN signing_keys k ON k.id = a.key_id
         LEFT JOIN approval_countersigs cs ON cs.approval_id = a.id
         LEFT JOIN user_keys uk ON uk.id = cs.user_key_id
         WHERE a.credential_id = $1 ORDER BY a.signed_at, a.id",
    ).bind(id).fetch_all(e).await?)
}

/// A person's countersignature on an approval, with everything needed to re-verify it independently.
#[derive(Serialize)]
pub struct PersonalView {
    pub valid: bool,
    pub key_id: Uuid,
    /// First bytes of the SHA-256 of the public key: identifies the key without naming its owner.
    pub fingerprint: String,
    pub key_status: String,
    /// base64url DER SubjectPublicKeyInfo (P-256).
    pub public_key: String,
    pub rp_id: String,
    pub origin: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct SigView {
    pub role: String,
    pub valid: bool,
    pub key_id: Uuid,
    pub key_status: String,
    pub public_key: String,
    pub signed_at: DateTime<Utc>,
    pub personal: Option<PersonalView>,
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
    /// Every personal countersignature that is present verifies and uses a key that is not revoked.
    /// A missing one is not an error here: it is a policy the deployment enforces when approving.
    pub fn personal_ok(&self) -> bool {
        self.sigs
            .iter()
            .all(|s| s.personal.as_ref().is_none_or(|p| p.valid))
    }
    pub fn intact(&self) -> bool {
        self.hash_ok && self.order_ok && self.status_ok && self.sigs_ok() && self.personal_ok()
    }
}

fn personal_view(c: &CredRow, a: &ApprovalRow) -> Option<PersonalView> {
    let key_id = a.cs_key_id?;
    let (spki, auth, client, sig) = (
        a.uk_public_key.clone().unwrap_or_default(),
        a.cs_auth.clone().unwrap_or_default(),
        a.cs_client.clone().unwrap_or_default(),
        a.cs_sig.clone().unwrap_or_default(),
    );
    let (rp_id, origin) = (
        a.cs_rp_id.clone().unwrap_or_default(),
        a.cs_origin.clone().unwrap_or_default(),
    );
    let key_status = a.uk_status.clone().unwrap_or_default();
    let valid = key_status != "revoked"
        && webauthn::check_assertion(
            &spki,
            &crypto::approval_challenge(c.id, &a.role, &c.credential_hash),
            &rp_id,
            &origin,
            &auth,
            &client,
            &sig,
        )
        .is_ok();
    Some(PersonalView {
        valid,
        key_id,
        fingerprint: hex::encode(&Sha256::digest(&spki)[..8]),
        key_status,
        public_key: webauthn::enc(&spki),
        rp_id,
        origin,
        authenticator_data: webauthn::enc(&auth),
        client_data_json: webauthn::enc(&client),
        signature: webauthn::enc(&sig),
    })
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
                personal: personal_view(c, a),
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
        (_, Some(_)) if ev.hash_ok && ev.order_ok && ev.sigs_ok() && ev.personal_ok() => "REJECTED",
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

/// Validated credential fields.
struct Fields {
    student_id: String,
    student_name: String,
    program: String,
    graduation_date: NaiveDate,
    gpa: Option<String>,
    honors: Option<String>,
}

fn parse_fields(b: CreateBody) -> Res<Fields> {
    Ok(Fields {
        student_id: clean("student_id", &b.student_id, 64)?,
        student_name: clean("student_name", &b.student_name, 200)?,
        program: clean("program", &b.program, 200)?,
        gpa: clean_opt("gpa", b.gpa, 10)?,
        honors: clean_opt("honors", b.honors, 100)?,
        graduation_date: NaiveDate::parse_from_str(b.graduation_date.trim(), "%Y-%m-%d")
            .map_err(|_| AppError::BadRequest("graduation_date must be YYYY-MM-DD".into()))?,
    })
}

/// Inserts a credential with the faculty stage's signature, in the caller's transaction.
/// Returns its id and content hash.
async fn insert_credential(
    st: &AppState,
    tx: &mut sqlx::PgConnection,
    user: &AuthUser,
    f: &Fields,
    supersedes: Option<Uuid>,
) -> Res<(Uuid, String)> {
    let id = Uuid::new_v4();
    let hash = Content {
        id,
        student_id: &f.student_id,
        student_name: &f.student_name,
        program: &f.program,
        graduation_date: f.graduation_date,
        gpa: f.gpa.as_deref(),
        honors: f.honors.as_deref(),
        supersedes,
    }
    .hash();
    let (key_id, seed) = keys::active_signer(st, "faculty").await?;
    let signature = crypto::sign(&seed, &crypto::approval_message(id, "faculty", &hash));
    sqlx::query(
        "INSERT INTO credentials (id, student_id, student_name, program, graduation_date, gpa, honors, credential_hash, status, created_by, supersedes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending_exam_cell',$9,$10)",
    ).bind(id).bind(&f.student_id).bind(&f.student_name).bind(&f.program).bind(f.graduation_date).bind(&f.gpa).bind(&f.honors).bind(&hash).bind(user.id).bind(supersedes)
    .execute(&mut *tx).await?;
    sqlx::query("INSERT INTO approvals (id, credential_id, role, approver_id, key_id, signature) VALUES ($1,$2,'faculty',$3,$4,$5)")
        .bind(Uuid::new_v4()).bind(id).bind(user.id).bind(key_id).bind(&signature)
        .execute(tx).await?;
    Ok((id, hash))
}

pub async fn create(
    State(st): State<AppState>,
    user: AuthUser,
    Json(b): Json<CreateBody>,
) -> Res<(StatusCode, Json<Value>)> {
    user.require(&[Role::Faculty])?;
    let fields = parse_fields(b)?;
    let mut tx = st.db.begin().await?;
    let (id, hash) = insert_credential(&st, &mut tx, &user, &fields, None).await?;
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

/// The most credentials one import may carry.
pub const BULK_MAX: usize = 500;

#[derive(Deserialize)]
pub struct BulkBody {
    /// Not called "credentials": the WAF reads a JSON key like that as a request for a file of secrets.
    items: Vec<CreateBody>,
}

/// Creates up to `BULK_MAX` credentials, each signed as faculty, in one transaction: either every row is
/// accepted or none is, and a rejected row is named by its position (1 = the first).
pub async fn create_bulk(
    State(st): State<AppState>,
    user: AuthUser,
    Json(b): Json<BulkBody>,
) -> Res<(StatusCode, Json<Value>)> {
    user.require(&[Role::Faculty])?;
    if b.items.is_empty() {
        return Err(AppError::BadRequest("no credentials to import".into()));
    }
    if b.items.len() > BULK_MAX {
        return Err(AppError::BadRequest(format!(
            "at most {BULK_MAX} credentials per import"
        )));
    }
    let mut parsed = Vec::with_capacity(b.items.len());
    for (i, row) in b.items.into_iter().enumerate() {
        parsed.push(parse_fields(row).map_err(|e| match e {
            AppError::BadRequest(m) => AppError::BadRequest(format!("row {}: {m}", i + 1)),
            other => other,
        })?);
    }
    let mut tx = st.db.begin().await?;
    let mut made = Vec::with_capacity(parsed.len());
    for f in &parsed {
        made.push(insert_credential(&st, &mut tx, &user, f, None).await?);
    }
    tx.commit().await?;

    for (id, hash) in &made {
        audit::actor_log(
            &st.db,
            &user,
            "CREDENTIAL_CREATED",
            "credential",
            &id.to_string(),
            json!({ "hash": hash, "bulk": true }),
        )
        .await;
    }
    let ids: Vec<Uuid> = made.iter().map(|(id, _)| *id).collect();
    Ok((
        StatusCode::CREATED,
        Json(json!({ "created": ids.len(), "ids": ids, "status": "pending_exam_cell" })),
    ))
}

#[derive(Deserialize)]
pub struct ListQuery {
    status: Option<String>,
    student_id: Option<String>,
    limit: Option<i64>,
    /// The `next` value of the previous page.
    before: Option<String>,
}

/// One page of credentials, newest first. `next` is the cursor for the following page, or null at the end.
pub async fn list(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<ListQuery>,
) -> Res<Json<Value>> {
    let own_only = user.role == Role::Faculty;
    let limit = page::limit(q.limit, 50, 200);
    let (before_at, before_id) = match q.before.as_deref() {
        Some(c) => {
            let (at, id) = page::decode(c)?;
            (Some(at), Some(id))
        }
        None => (None, None),
    };
    let mut rows: Vec<CredRow> = sqlx::query_as(&format!(
        "SELECT {CRED_COLS} FROM credentials
         WHERE ($1::uuid IS NULL OR created_by = $1)
           AND ($2::text IS NULL OR status = $2)
           AND ($3::text IS NULL OR student_id = $3)
           AND ($4::timestamptz IS NULL OR (created_at, id) < ($4, $5))
         ORDER BY created_at DESC, id DESC LIMIT $6"
    ))
    .bind(own_only.then_some(user.id))
    .bind(q.status)
    .bind(
        q.student_id
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    )
    .bind(before_at)
    .bind(before_id)
    .bind(limit + 1)
    .fetch_all(&st.db)
    .await?;
    let next = (rows.len() as i64 > limit).then(|| {
        rows.truncate(limit as usize);
        let last = rows.last().expect("a full page is not empty");
        page::encode(last.created_at, last.id)
    });
    Ok(Json(json!({ "credentials": rows.iter().map(|c| json!({
        "id": c.id, "student_id": c.student_id, "student_name": c.student_name, "program": c.program,
        "status": c.status, "created_at": c.created_at,
    })).collect::<Vec<_>>(), "next": next })))
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
        "checks": { "hash_ok": ev.hash_ok, "order_ok": ev.order_ok, "status_ok": ev.status_ok, "signatures_ok": ev.sigs_ok(), "personal_signatures_ok": ev.personal_ok(), "termination_ok": termination_ok(c, t) },
    })
}

pub async fn get(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Res<Json<Value>> {
    load(&st, &user, id).await?; // faculty only see their own credentials
    let (c, ev, t) = load_core(&st, id).await?;
    let mut view = full_view(&c, &ev, t.as_ref());
    view["supersedes"] = json!(c.supersedes);
    view["superseded_by"] = json!(successor(&st, id).await?);
    let approvers: Vec<(String, String)> = sqlx::query_as(
        "SELECT a.role, u.email FROM approvals a JOIN users u ON u.id = a.approver_id WHERE a.credential_id = $1 ORDER BY a.signed_at",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    view["approvers"] = json!(approvers
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>());
    Ok(Json(view))
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

#[derive(Deserialize, Default)]
struct ApproveBody {
    /// The approver's personal signature over this approval (see `webauthn`).
    webauthn: Option<webauthn::AssertionIn>,
}

/// An empty body means "no options"; anything else must be valid JSON.
fn parse_body<T: serde::de::DeserializeOwned + Default>(body: &Bytes) -> Res<T> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    serde_json::from_slice(body)
        .map_err(|e| AppError::BadRequest(format!("invalid request body: {e}")))
}

pub async fn approve(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Res<Json<Value>> {
    let ApproveBody { webauthn: personal } = parse_body(&body)?;
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
    if st.cfg.require_personal {
        if personal.is_none() {
            return Err(AppError::Conflict(
                "this deployment requires a personal signature (your security key) on every approval".into(),
            ));
        }
        if prior.iter().any(|p| p.cs_key_id.is_none()) {
            return Err(AppError::Conflict(
                "an earlier approval still lacks its signer's personal signature; they must add it first".into(),
            ));
        }
    }
    let (key_id, seed) = keys::active_signer(&st, stage).await?;
    let signature = crypto::sign(
        &seed,
        &crypto::approval_message(id, stage, &c.credential_hash),
    );
    let approval_id = Uuid::new_v4();
    sqlx::query("INSERT INTO approvals (id, credential_id, role, approver_id, key_id, signature) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(approval_id).bind(id).bind(stage).bind(user.id).bind(key_id).bind(signature)
        .execute(&mut *tx).await?;
    if let Some(a) = &personal {
        let challenge = crypto::approval_challenge(id, stage, &c.credential_hash);
        webauthn::countersign(&st, &mut tx, &user, approval_id, &challenge, a).await?;
    }
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
        json!({ "stage": stage, "status": next, "personal_signature": personal.is_some() }),
    )
    .await;
    Ok(Json(json!({ "id": id, "status": next })))
}

#[derive(Deserialize)]
pub struct CountersignBody {
    webauthn: webauthn::AssertionIn,
}

/// Adds the caller's personal signature to an approval they already made (for example the faculty member's
/// own creation, which has no separate signing step).
pub async fn countersign(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(b): Json<CountersignBody>,
) -> Res<Json<Value>> {
    let mut tx = st.db.begin().await?;
    let c = lock(&mut tx, id).await?;
    let (approval_id, role) = unsigned_own_approval(&mut tx, id, user.id)
        .await?
        .ok_or_else(|| {
            AppError::Conflict(
                "you have no approval on this credential that still needs a personal signature"
                    .into(),
            )
        })?;
    let challenge = crypto::approval_challenge(id, &role, &c.credential_hash);
    webauthn::countersign(&st, &mut tx, &user, approval_id, &challenge, &b.webauthn).await?;
    tx.commit().await?;
    audit::actor_log(
        &st.db,
        &user,
        "APPROVAL_COUNTERSIGNED",
        "credential",
        &id.to_string(),
        json!({ "stage": role }),
    )
    .await;
    Ok(Json(json!({ "id": id, "stage": role })))
}

async fn unsigned_own_approval(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
    user_id: Uuid,
) -> Res<Option<(Uuid, String)>> {
    Ok(sqlx::query_as(
        "SELECT a.id, a.role FROM approvals a
         LEFT JOIN approval_countersigs cs ON cs.approval_id = a.id
         WHERE a.credential_id = $1 AND a.approver_id = $2 AND cs.approval_id IS NULL
         ORDER BY a.signed_at LIMIT 1",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(tx)
    .await?)
}

/// What the caller's authenticator should be asked to sign next on this credential, and with which keys.
pub async fn personal_challenge(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Res<Json<Value>> {
    let c = load(&st, &user, id).await?;
    let mut conn = st.db.acquire().await?;
    let ended: Option<(String,)> =
        sqlx::query_as("SELECT kind FROM credential_events WHERE credential_id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    let next = if ended.is_none() {
        next_stage(&c.status, user.role).map(|(stage, _)| ("approve", stage.to_string()))
    } else {
        None
    };
    let (purpose, stage) = match next {
        Some(n) => n,
        None => match unsigned_own_approval(&mut conn, id, user.id).await? {
            Some((_, role)) => ("countersign", role),
            None => {
                return Err(AppError::NotFound(
                    "there is nothing for you to sign here".into(),
                ))
            }
        },
    };
    let allow = webauthn::allowed_credentials(&st, user.id).await?;
    Ok(Json(json!({
        "purpose": purpose,
        "stage": stage,
        "challenge": webauthn::enc(&crypto::approval_challenge(id, &stage, &c.credential_hash)),
        "rp_id": st.cfg.webauthn.rp_id,
        "allow": allow,
        "required": st.cfg.require_personal,
    })))
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

/// Everything verification concludes about one credential.
pub struct Assessment {
    pub ev: Evaluation,
    pub term: Option<Termination>,
    pub anchor: Option<crate::ledger::Anchor>,
    pub verdict: &'static str,
}

/// Reads a credential, its approvals and its final event in ONE database snapshot. Without it, a verification
/// racing an approval could read the old status next to the new approval and report a spurious INVALID.
async fn load_core(st: &AppState, id: Uuid) -> Res<(CredRow, Evaluation, Option<Termination>)> {
    let mut tx = st.db.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let c: CredRow = sqlx::query_as(&format!(
        "SELECT {CRED_COLS} FROM credentials WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let ev = evaluate(&c, &fetch_approvals(&mut *tx, id).await?);
    let term = fetch_event(&mut *tx, id, &c).await?;
    tx.commit().await?;
    Ok((c, ev, term))
}

async fn assess(st: &AppState, id: Uuid) -> Res<(CredRow, Assessment)> {
    let (c, ev, term) = load_core(st, id).await?;
    let anchor = crate::ledger::anchor_for(&st.db, &c).await?;
    let mut verdict = verdict(&c, &ev, term.as_ref());
    if verdict == "VALID" && anchor.as_ref().is_some_and(|a| !a.ok) {
        verdict = "INVALID";
    }
    Ok((
        c,
        Assessment {
            ev,
            term,
            anchor,
            verdict,
        },
    ))
}

/// The credential that replaced this one (the latest, if it was re-issued more than once) and its verdict.
async fn successor(st: &AppState, id: Uuid) -> Res<Option<Value>> {
    let next: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM credentials WHERE supersedes = $1 ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    let Some((next,)) = next else {
        return Ok(None);
    };
    let (c, a) = assess(st, next).await?;
    Ok(Some(
        json!({ "id": next, "verdict": a.verdict, "status": c.status }),
    ))
}

/// Only credentials that are dead (revoked or rejected) or invalid can be replaced; a valid or pending
/// one must first be revoked or finished.
fn can_reissue(verdict: &str) -> bool {
    matches!(verdict, "REVOKED" | "REJECTED" | "INVALID")
}

#[derive(Deserialize, Default)]
pub struct ReissueBody {
    student_id: Option<String>,
    student_name: Option<String>,
    program: Option<String>,
    graduation_date: Option<String>,
    gpa: Option<String>,
    honors: Option<String>,
}

/// Replaces a revoked, rejected or invalid credential with a new one that points back at it. Fields left
/// out are copied from the old credential, but only if its stored content still passes its integrity check.
/// The new credential is signed by the faculty stage and then goes through every stage again, because every
/// signature is bound to a credential's id and content hash.
pub async fn reissue(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(b): Json<ReissueBody>,
) -> Res<(StatusCode, Json<Value>)> {
    user.require(&[Role::Faculty])?;
    load(&st, &user, id).await?; // faculty only see their own credentials
    let (old, a) = assess(&st, id).await?;
    if !can_reissue(a.verdict) {
        return Err(AppError::Conflict(format!(
            "credential is {}; only a revoked, rejected or invalid credential can be re-issued",
            a.verdict
        )));
    }
    let trusted = a.ev.hash_ok;
    let pick = |name: &str, given: Option<String>, stored: &str| -> Res<String> {
        match (given, trusted) {
            (Some(v), _) => Ok(v),
            (None, true) => Ok(stored.to_string()),
            (None, false) => Err(AppError::BadRequest(format!(
                "this credential's stored content fails its integrity check, so '{name}' cannot be copied; supply every field"
            ))),
        }
    };
    let optional = |given: Option<String>, stored: &Option<String>| -> Option<String> {
        match (given, trusted) {
            (Some(v), _) => Some(v),
            (None, true) => stored.clone(),
            (None, false) => None,
        }
    };
    let fields = parse_fields(CreateBody {
        student_id: pick("student_id", b.student_id, &old.student_id)?,
        student_name: pick("student_name", b.student_name, &old.student_name)?,
        program: pick("program", b.program, &old.program)?,
        graduation_date: pick(
            "graduation_date",
            b.graduation_date,
            &old.graduation_date.to_string(),
        )?,
        gpa: optional(b.gpa, &old.gpa),
        honors: optional(b.honors, &old.honors),
    })?;

    let mut tx = st.db.begin().await?;
    lock(&mut tx, id).await?;
    let live: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM credentials WHERE supersedes = $1 AND status NOT IN ('rejected','revoked') LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((live,)) = live {
        return Err(AppError::Conflict(format!(
            "already re-issued as {live}; revoke or reject that one first"
        )));
    }
    let (new_id, hash) = insert_credential(&st, &mut tx, &user, &fields, Some(id)).await?;
    tx.commit().await?;

    audit::actor_log(
        &st.db,
        &user,
        "CREDENTIAL_REISSUED",
        "credential",
        &new_id.to_string(),
        json!({ "replaces": id, "was": a.verdict, "hash": hash }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({ "id": new_id, "replaces": id, "credential_hash": hash, "status": "pending_exam_cell" }),
        ),
    ))
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
    let (
        c,
        Assessment {
            ev,
            term: t,
            anchor,
            verdict,
        },
    ) = assess(&st, id).await?;
    let qr_match =
        q.h.as_deref()
            .filter(|h| h.len() >= 8)
            .map(|h| c.credential_hash.starts_with(&h.to_lowercase()));
    Ok(Json(json!({
        "verdict": verdict,
        "credential": {
            "id": c.id, "student_name": c.student_name, "program": c.program, "graduation_date": c.graduation_date,
            "gpa": c.gpa, "honors": c.honors, "status": c.status, "credential_hash": c.credential_hash,
            // Shown from the signed event when there is one, not from the editable columns.
            "revoked_at": t.as_ref().filter(|t| t.row.kind == "revoked").map(|t| t.row.created_at),
            "revoke_reason": t.as_ref().map(|t| t.row.reason.as_str()),
        },
        "supersedes": c.supersedes,
        "superseded_by": successor(&st, id).await?,
        "termination": t.as_ref().map(|t| t.row.view(t.valid)),
        "checks": { "hash_ok": ev.hash_ok, "order_ok": ev.order_ok, "status_ok": ev.status_ok, "signatures_ok": ev.sigs_ok(), "personal_signatures_ok": ev.personal_ok(), "termination_ok": termination_ok(&c, t.as_ref()) },
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

    #[test]
    fn each_stage_can_only_be_signed_by_its_role_in_order() {
        use Role::*;
        let all = [Faculty, ExamCell, Registrar, UniversityAdmin, Auditor];
        let table = [
            (
                "pending_exam_cell",
                ExamCell,
                "exam_cell",
                "pending_registrar",
            ),
            (
                "pending_registrar",
                Registrar,
                "registrar",
                "pending_university",
            ),
            (
                "pending_university",
                UniversityAdmin,
                "university",
                "issued",
            ),
        ];
        for (status, role, stage, next) in table {
            for r in all {
                let got = next_stage(status, r);
                if r == role {
                    assert_eq!(got, Some((stage, next)), "{status} by {r:?}");
                } else {
                    assert_eq!(got, None, "{status} by {r:?}");
                }
            }
        }
        for status in ["issued", "revoked", "rejected", "nonsense"] {
            assert!(
                all.iter().all(|r| next_stage(status, *r).is_none()),
                "{status}"
            );
        }
    }

    #[test]
    fn only_finished_unhappy_credentials_can_be_replaced() {
        for v in ["REVOKED", "REJECTED", "INVALID"] {
            assert!(can_reissue(v), "{v}");
        }
        for v in ["VALID", "PENDING", ""] {
            assert!(!can_reissue(v), "{v}");
        }
    }

    #[test]
    fn a_status_needs_exactly_as_many_approvals() {
        let approval = |role: &str| ApprovalRow {
            role: role.into(),
            signature: String::new(),
            signed_at: Utc::now(),
            key_id: Uuid::nil(),
            public_key: String::new(),
            key_status: "active".into(),
            cs_key_id: None,
            cs_rp_id: None,
            cs_origin: None,
            cs_auth: None,
            cs_client: None,
            cs_sig: None,
            uk_public_key: None,
            uk_status: None,
        };
        let mut c = cred("pending_registrar");
        c.credential_hash = c.recompute_hash();
        let rows = [approval("faculty"), approval("exam_cell")];
        assert!(evaluate(&c, &rows).status_ok);
        assert!(evaluate(&c, &rows).order_ok);
        assert!(
            !evaluate(&c, &rows[..1]).status_ok,
            "one approval is too few"
        );
        let swapped = [approval("exam_cell"), approval("faculty")];
        assert!(!evaluate(&c, &swapped).order_ok, "stages out of order");
        c.status = "issued".into();
        assert!(!evaluate(&c, &rows).status_ok, "issued needs all four");
    }

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
            supersedes: None,
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
    fn content_hash_v1_is_unchanged_and_v2_covers_the_link() {
        let id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let old = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let content = Content {
            id,
            student_id: "S-1",
            student_name: "Ada",
            program: "BSc",
            graduation_date: NaiveDate::from_ymd_opt(2025, 5, 15).unwrap(),
            gpa: Some("3.9"),
            honors: None,
            supersedes: None,
        };
        // Computed by hand from the canonical form (sorted keys, no whitespace), so credentials issued before
        // re-issuing existed keep verifying.
        let v1 = r#"{"gpa":"3.9","graduation_date":"2025-05-15","honors":null,"id":"11111111-1111-1111-1111-111111111111","program":"BSc","student_id":"S-1","student_name":"Ada","v":1}"#;
        assert_eq!(content.hash(), crypto::sha256_hex(v1.as_bytes()));

        let linked = Content {
            supersedes: Some(old),
            ..content
        };
        let v2 = r#"{"gpa":"3.9","graduation_date":"2025-05-15","honors":null,"id":"11111111-1111-1111-1111-111111111111","program":"BSc","student_id":"S-1","student_name":"Ada","supersedes":"22222222-2222-2222-2222-222222222222","v":2}"#;
        assert_eq!(linked.hash(), crypto::sha256_hex(v2.as_bytes()));

        // Editing the link on a stored row breaks its hash.
        let mut row = cred("pending_exam_cell");
        row.id = id;
        row.credential_hash = row.recompute_hash();
        assert_eq!(row.recompute_hash(), row.credential_hash);
        row.supersedes = Some(old);
        assert_ne!(row.recompute_hash(), row.credential_hash);
    }

    #[test]
    fn only_dead_or_invalid_credentials_can_be_reissued() {
        for v in ["REVOKED", "REJECTED", "INVALID"] {
            assert!(can_reissue(v), "{v}");
        }
        for v in ["VALID", "PENDING"] {
            assert!(!can_reissue(v), "{v}");
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
