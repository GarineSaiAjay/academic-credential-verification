//! Personal signing keys.
//!
//! The stage keys on the server prove that *a* holder of a role approved something. They cannot prove which
//! person did, because the server holds them and could sign for anyone. A personal key fixes that: it is a
//! WebAuthn credential (passkey or hardware security key) whose private half never leaves the person's
//! authenticator. The server stores only the public key and verifies signatures made with it.
//!
//! An approval keeps its stage-key signature and can carry the approver's countersignature over the same
//! approval message. The authenticator's raw output is stored unchanged, so anyone can re-verify it.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use chrono::{DateTime, Duration, Utc};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgConnection};
use uuid::Uuid;

use crate::{
    audit,
    auth::{AuthUser, Role},
    error::{AppError, Res},
    AppState,
};

type R<T> = Result<T, String>;

const MAX_ACTIVE_KEYS: i64 = 10;
const CHALLENGE_MINUTES: i64 = 5;

pub fn b64(s: &str) -> R<Vec<u8>> {
    B64.decode(s).map_err(|_| "not valid base64url".to_string())
}

pub fn enc(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin")]
    cross_origin: Option<bool>,
}

fn check_client_data(raw: &[u8], kind: &str, challenge: &[u8], origin: &str) -> R<()> {
    let cd: ClientData =
        serde_json::from_slice(raw).map_err(|_| "clientDataJSON is malformed".to_string())?;
    if cd.kind != kind {
        return Err(format!("wrong ceremony type '{}'", cd.kind));
    }
    if B64.decode(&cd.challenge).ok().as_deref() != Some(challenge) {
        return Err("challenge does not match what was asked to be signed".into());
    }
    if cd.origin != origin {
        return Err(format!("origin '{}' is not '{origin}'", cd.origin));
    }
    if cd.cross_origin == Some(true) {
        return Err("signed from a cross-origin frame".into());
    }
    Ok(())
}

/// Parses a DER SubjectPublicKeyInfo holding a P-256 key.
pub fn parse_public_key(spki: &[u8]) -> R<VerifyingKey> {
    VerifyingKey::from_public_key_der(spki).map_err(|_| "not a P-256 public key".to_string())
}

/// Verifies a WebAuthn assertion: the authenticator signed `challenge` for this site, with the user present
/// and verified. Returns the authenticator's signature counter.
pub fn check_assertion(
    spki: &[u8],
    challenge: &[u8],
    rp_id: &str,
    origin: &str,
    auth_data: &[u8],
    client_data: &[u8],
    signature_der: &[u8],
) -> R<u32> {
    check_client_data(client_data, "webauthn.get", challenge, origin)?;
    if auth_data.len() < 37 {
        return Err("authenticator data is too short".into());
    }
    if auth_data[..32] != Sha256::digest(rp_id.as_bytes())[..] {
        return Err("authenticator data is for a different site".into());
    }
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err("the user was not present".into());
    }
    if flags & 0x04 == 0 {
        return Err("the user was not verified (PIN or biometric)".into());
    }
    let key = parse_public_key(spki)?;
    let sig = Signature::from_der(signature_der).map_err(|_| "malformed signature".to_string())?;
    let mut signed = auth_data.to_vec();
    signed.extend_from_slice(&Sha256::digest(client_data));
    key.verify(&signed, &sig)
        .map_err(|_| "signature does not verify".to_string())?;
    Ok(u32::from_be_bytes([
        auth_data[33],
        auth_data[34],
        auth_data[35],
        auth_data[36],
    ]))
}

/// What a client sends to prove it holds a registered key.
#[derive(Deserialize)]
pub struct AssertionIn {
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

/// Verifies that `a` is a fresh signature over `challenge` made with one of `user`'s active keys, and advances
/// that key's counter. Returns the key's id and the authenticator's raw output.
async fn assert_with_key(
    st: &AppState,
    tx: &mut PgConnection,
    user: &AuthUser,
    challenge: &[u8],
    a: &AssertionIn,
) -> Res<(Uuid, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let bad = |m: String| AppError::BadRequest(format!("personal signature rejected: {m}"));
    let cred_id = b64(&a.credential_id).map_err(bad)?;
    let key: Option<(Uuid, Vec<u8>, String, i64)> = sqlx::query_as(
        "SELECT id, public_key, status, sign_count FROM user_keys WHERE credential_id = $1 AND user_id = $2 FOR UPDATE",
    )
    .bind(&cred_id)
    .bind(user.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((key_id, spki, status, stored_count)) = key else {
        return Err(AppError::BadRequest(
            "that security key is not registered to you".into(),
        ));
    };
    if status != "active" {
        return Err(AppError::Conflict(format!("that security key is {status}")));
    }
    let auth_data = b64(&a.authenticator_data).map_err(bad)?;
    let client_data = b64(&a.client_data_json).map_err(bad)?;
    let signature = b64(&a.signature).map_err(bad)?;
    let wa = &st.cfg.webauthn;
    let counter = check_assertion(
        &spki,
        challenge,
        &wa.rp_id,
        &wa.origin,
        &auth_data,
        &client_data,
        &signature,
    )
    .map_err(bad)?;
    // A counter that does not advance means the key may have been cloned. Authenticators that always
    // report 0 (synced passkeys) are exempt.
    if (counter != 0 || stored_count != 0) && i64::from(counter) <= stored_count {
        return Err(AppError::Conflict(
            "the key's signature counter did not advance; it may have been cloned".into(),
        ));
    }
    sqlx::query("UPDATE user_keys SET sign_count = $2 WHERE id = $1")
        .bind(key_id)
        .bind(i64::from(counter))
        .execute(&mut *tx)
        .await?;
    Ok((key_id, auth_data, client_data, signature))
}

/// Verifies an assertion made by `user` over `challenge` and stores it as the countersignature of
/// `approval_id`, in the caller's transaction.
pub async fn countersign(
    st: &AppState,
    tx: &mut PgConnection,
    user: &AuthUser,
    approval_id: Uuid,
    challenge: &[u8; 32],
    a: &AssertionIn,
) -> Res<()> {
    let (key_id, auth_data, client_data, signature) =
        assert_with_key(st, tx, user, challenge, a).await?;
    let wa = &st.cfg.webauthn;
    sqlx::query(
        "INSERT INTO approval_countersigs (approval_id, user_key_id, rp_id, origin, authenticator_data, client_data_json, signature)
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(approval_id)
    .bind(key_id)
    .bind(&wa.rp_id)
    .bind(&wa.origin)
    .bind(auth_data)
    .bind(client_data)
    .bind(signature)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

/// The ids of a user's active keys, as the browser needs them to ask for a signature.
pub async fn allowed_credentials(st: &AppState, user_id: Uuid) -> Res<Vec<String>> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT credential_id FROM user_keys WHERE user_id = $1 AND status = 'active' ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(&st.db)
    .await?;
    Ok(rows.iter().map(|(c,)| enc(c)).collect())
}

/// How a new key may be added to this account right now. `true`: an existing active key must approve it.
/// `false`: no key is needed (first enrolment, or an administrator opened the window). Anything else is refused.
/// Without this, anyone who learned a password could register a key of their own and approve as that person.
async fn enrollment_needs_key(st: &AppState, conn: &mut PgConnection, user_id: Uuid) -> Res<bool> {
    let (active, ever): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status = 'active'), count(*) FROM user_keys WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?;
    if active > 0 {
        return Ok(true);
    }
    let window: (Option<DateTime<Utc>>,) =
        sqlx::query_as("SELECT key_enroll_until FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *conn)
            .await?;
    let open = window.0.is_some_and(|t| t > Utc::now());
    if open || (ever == 0 && !st.cfg.require_admin_enrollment) {
        return Ok(false);
    }
    Err(AppError::Conflict(
        "an administrator must allow you to enrol a security key (you have none active)".into(),
    ))
}

/// Step 1 of registering a key: a one-time challenge and the parameters for `navigator.credentials.create`.
/// When the account already has a key, the same challenge must also be signed with that key (`authorize_allow`).
pub async fn key_options(State(st): State<AppState>, user: AuthUser) -> Res<Json<Value>> {
    let mut conn = st.db.acquire().await?;
    let needs_key = enrollment_needs_key(&st, &mut conn, user.id).await?;
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    let id = Uuid::new_v4();
    sqlx::query("DELETE FROM webauthn_challenges WHERE expires_at < now()")
        .execute(&st.db)
        .await?;
    sqlx::query(
        "INSERT INTO webauthn_challenges (id, user_id, challenge, expires_at) VALUES ($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(user.id)
    .bind(challenge.as_slice())
    .bind(Utc::now() + Duration::minutes(CHALLENGE_MINUTES))
    .execute(&st.db)
    .await?;
    let existing = allowed_credentials(&st, user.id).await?;
    Ok(Json(json!({
        "challenge_id": id,
        "challenge": enc(&challenge),
        "rp": { "id": st.cfg.webauthn.rp_id, "name": "ACVS" },
        "user": { "id": enc(user.id.as_bytes()), "name": user.email, "display_name": user.email },
        "exclude": existing,
        "authorize_allow": if needs_key { existing } else { vec![] },
        "timeout_ms": 60_000,
    })))
}

#[derive(Deserialize)]
pub struct RegisterBody {
    challenge_id: Uuid,
    credential_id: String,
    /// base64url DER SubjectPublicKeyInfo (`AuthenticatorAttestationResponse.getPublicKey()`).
    public_key: String,
    client_data_json: String,
    label: String,
    /// An existing key's signature over the registration challenge, required when the account has one.
    authorization: Option<AssertionIn>,
}

/// Step 2: store the new key after checking the browser signed the challenge into the ceremony.
pub async fn key_register(
    State(st): State<AppState>,
    user: AuthUser,
    Json(b): Json<RegisterBody>,
) -> Res<(StatusCode, Json<Value>)> {
    let bad = |m: String| AppError::BadRequest(format!("registration rejected: {m}"));
    let label = b.label.trim();
    if label.is_empty() || label.chars().count() > 80 || label.chars().any(char::is_control) {
        return Err(AppError::BadRequest(
            "label is required (max 80 characters)".into(),
        ));
    }
    // Consumed up front and for good: a failed attempt must not leave the challenge usable again.
    let challenge: Option<(Vec<u8>,)> = sqlx::query_as(
        "DELETE FROM webauthn_challenges WHERE id = $1 AND user_id = $2 AND expires_at > now() RETURNING challenge",
    )
    .bind(b.challenge_id)
    .bind(user.id)
    .fetch_optional(&st.db)
    .await?;
    let Some((challenge,)) = challenge else {
        return Err(AppError::BadRequest(
            "that registration challenge is unknown or expired; start again".into(),
        ));
    };
    let client_data = b64(&b.client_data_json).map_err(bad)?;
    check_client_data(
        &client_data,
        "webauthn.create",
        &challenge,
        &st.cfg.webauthn.origin,
    )
    .map_err(bad)?;
    let spki = b64(&b.public_key).map_err(bad)?;
    parse_public_key(&spki).map_err(bad)?;
    let cred_id = b64(&b.credential_id).map_err(bad)?;
    if cred_id.is_empty() || cred_id.len() > 1023 {
        return Err(bad("credential id has an invalid length".into()));
    }
    let mut tx = st.db.begin().await?;
    if enrollment_needs_key(&st, &mut tx, user.id).await? {
        let Some(auth) = &b.authorization else {
            return Err(AppError::Conflict(
                "adding another key needs your existing key's approval".into(),
            ));
        };
        assert_with_key(&st, &mut tx, &user, &challenge, auth).await?;
    }
    let (active,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM user_keys WHERE user_id = $1 AND status = 'active'")
            .bind(user.id)
            .fetch_one(&mut *tx)
            .await?;
    if active >= MAX_ACTIVE_KEYS {
        return Err(AppError::Conflict(format!(
            "at most {MAX_ACTIVE_KEYS} active keys; retire one first"
        )));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO user_keys (id, user_id, credential_id, public_key, label) VALUES ($1,$2,$3,$4,$5)")
        .bind(id)
        .bind(user.id)
        .bind(&cred_id)
        .bind(&spki)
        .bind(label)
        .execute(&mut *tx)
        .await
        .map_err(|e| match AppError::from(e) {
            AppError::Conflict(_) => AppError::Conflict("that security key is already registered".into()),
            other => other,
        })?;
    sqlx::query("UPDATE users SET key_enroll_until = NULL WHERE id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit::actor_log(
        &st.db,
        &user,
        "USER_KEY_REGISTERED",
        "user_key",
        &id.to_string(),
        json!({ "label": label, "approved_by_existing_key": b.authorization.is_some() }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "label": label, "status": "active" })),
    ))
}

/// Admin: let a user enrol a key without an existing one for the next 24 hours (single use). Used for people
/// who have never enrolled when `REQUIRE_ADMIN_ENROLLMENT` is on, and for people who lost every key.
pub async fn allow_enrollment(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin])?;
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE users SET key_enroll_until = now() + interval '24 hours' WHERE id = $1 AND active RETURNING email",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    let (email,) = row.ok_or_else(|| AppError::NotFound("no active user with that id".into()))?;
    audit::actor_log(
        &st.db,
        &user,
        "USER_KEY_ENROLLMENT_ALLOWED",
        "user",
        &id.to_string(),
        json!({ "email": email }),
    )
    .await;
    Ok(Json(
        json!({ "id": id, "email": email, "allowed_for_hours": 24 }),
    ))
}

#[derive(Serialize, FromRow)]
struct KeyView {
    id: Uuid,
    label: String,
    status: String,
    created_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    end_reason: Option<String>,
    sign_count: i64,
    fingerprint: String,
}

async fn keys_of(st: &AppState, user_id: Uuid) -> Res<Vec<KeyView>> {
    Ok(sqlx::query_as(
        "SELECT id, label, status, created_at, ended_at, end_reason, sign_count,
                substr(encode(sha256(public_key), 'hex'), 1, 16) AS fingerprint
         FROM user_keys WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(&st.db)
    .await?)
}

pub async fn my_keys(State(st): State<AppState>, user: AuthUser) -> Res<Json<Value>> {
    Ok(Json(json!({ "keys": keys_of(&st, user.id).await? })))
}

pub async fn user_keys(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin, Role::Auditor])?;
    Ok(Json(json!({ "keys": keys_of(&st, id).await? })))
}

async fn owner_of(st: &AppState, key_id: Uuid) -> Res<Uuid> {
    let row: Option<(Uuid,)> = sqlx::query_as("SELECT user_id FROM user_keys WHERE id = $1")
        .bind(key_id)
        .fetch_optional(&st.db)
        .await?;
    row.map(|(u,)| u)
        .ok_or_else(|| AppError::NotFound("key not found".into()))
}

/// The owner retires a key they no longer use (replaced or lost). Signatures made with it stay valid.
pub async fn retire(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Res<Json<Value>> {
    if owner_of(&st, id).await? != user.id {
        return Err(AppError::NotFound("key not found".into()));
    }
    let n = sqlx::query(
        "UPDATE user_keys SET status = 'retired', ended_at = now(), end_reason = 'retired by owner' WHERE id = $1 AND status = 'active'",
    )
    .bind(id)
    .execute(&st.db)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(AppError::Conflict(
            "only an active key can be retired".into(),
        ));
    }
    audit::actor_log(
        &st.db,
        &user,
        "USER_KEY_RETIRED",
        "user_key",
        &id.to_string(),
        json!({}),
    )
    .await;
    Ok(Json(json!({ "id": id, "status": "retired" })))
}

#[derive(Deserialize)]
pub struct RevokeBody {
    reason: String,
}

/// Reports a key as compromised (by its owner, or by an admin): whatever it signed no longer verifies.
pub async fn revoke(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(b): Json<RevokeBody>,
) -> Res<Json<Value>> {
    let owner = owner_of(&st, id).await?;
    if owner != user.id && user.role != Role::UniversityAdmin {
        return Err(AppError::NotFound("key not found".into()));
    }
    let reason = b.reason.trim();
    if !(3..=500).contains(&reason.chars().count()) {
        return Err(AppError::BadRequest(
            "reason must be 3-500 characters".into(),
        ));
    }
    let n = sqlx::query(
        "UPDATE user_keys SET status = 'revoked', ended_at = now(), end_reason = $2 WHERE id = $1 AND status <> 'revoked'",
    )
    .bind(id)
    .bind(reason)
    .execute(&st.db)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(AppError::Conflict("key is already revoked".into()));
    }
    audit::actor_log(
        &st.db,
        &user,
        "USER_KEY_REVOKED",
        "user_key",
        &id.to_string(),
        json!({ "owner": owner, "reason": reason }),
    )
    .await;
    Ok(Json(json!({ "id": id, "status": "revoked" })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    const RP: &str = "acvs.example.edu";
    const ORIGIN: &str = "https://acvs.example.edu";

    /// A software authenticator.
    struct Authenticator {
        key: SigningKey,
    }

    struct Output {
        auth_data: Vec<u8>,
        client_data: Vec<u8>,
        signature: Vec<u8>,
    }

    impl Authenticator {
        fn new() -> Self {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            seed[0] |= 1;
            Self {
                key: SigningKey::from_slice(&seed).unwrap(),
            }
        }

        /// DER SubjectPublicKeyInfo as browsers produce it: a fixed P-256 header plus the uncompressed point.
        fn spki(&self) -> Vec<u8> {
            let mut der = vec![
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
            ];
            der.extend_from_slice(self.key.verifying_key().to_encoded_point(false).as_bytes());
            der
        }

        fn sign(
            &self,
            challenge: &[u8],
            rp: &str,
            origin: &str,
            flags: u8,
            counter: u32,
        ) -> Output {
            let mut auth_data = Sha256::digest(rp.as_bytes()).to_vec();
            auth_data.push(flags);
            auth_data.extend_from_slice(&counter.to_be_bytes());
            let client_data = format!(
                r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
                enc(challenge)
            )
            .into_bytes();
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&Sha256::digest(&client_data));
            let sig: Signature = self.key.sign(&signed);
            Output {
                auth_data,
                client_data,
                signature: sig.to_der().as_bytes().to_vec(),
            }
        }
    }

    fn check(a: &Authenticator, o: &Output, challenge: &[u8]) -> R<u32> {
        check_assertion(
            &a.spki(),
            challenge,
            RP,
            ORIGIN,
            &o.auth_data,
            &o.client_data,
            &o.signature,
        )
    }

    #[test]
    fn a_genuine_assertion_verifies_and_reports_its_counter() {
        let a = Authenticator::new();
        let c = [7u8; 32];
        assert_eq!(check(&a, &a.sign(&c, RP, ORIGIN, 0x05, 41), &c), Ok(41));
        assert_eq!(check(&a, &a.sign(&c, RP, ORIGIN, 0x05, 0), &c), Ok(0));
    }

    #[test]
    fn every_part_of_the_ceremony_is_enforced() {
        let a = Authenticator::new();
        let c = [7u8; 32];
        let good = a.sign(&c, RP, ORIGIN, 0x05, 1);

        // signed something else
        assert!(check(&a, &good, &[8u8; 32])
            .unwrap_err()
            .contains("challenge"));
        // another site (relying party)
        let other_rp = a.sign(&c, "evil.example", ORIGIN, 0x05, 1);
        assert!(check(&a, &other_rp, &c)
            .unwrap_err()
            .contains("different site"));
        // another origin
        let other_origin = a.sign(&c, RP, "https://evil.example", 0x05, 1);
        assert!(check(&a, &other_origin, &c).unwrap_err().contains("origin"));
        // no user presence / no user verification
        assert!(check(&a, &a.sign(&c, RP, ORIGIN, 0x04, 1), &c)
            .unwrap_err()
            .contains("present"));
        assert!(check(&a, &a.sign(&c, RP, ORIGIN, 0x01, 1), &c)
            .unwrap_err()
            .contains("verified"));
        // a different key
        let mut forged = a.sign(&c, RP, ORIGIN, 0x05, 1);
        let b = Authenticator::new();
        assert!(check_assertion(
            &b.spki(),
            &c,
            RP,
            ORIGIN,
            &forged.auth_data,
            &forged.client_data,
            &forged.signature
        )
        .unwrap_err()
        .contains("does not verify"));
        // altered authenticator data, client data and signature
        forged.auth_data[34] ^= 1;
        assert!(check(&a, &forged, &c).is_err());
        let mut tampered = a.sign(&c, RP, ORIGIN, 0x05, 1);
        tampered.signature[10] ^= 1;
        assert!(check(&a, &tampered, &c).is_err());
        // garbage
        assert!(check_assertion(&a.spki(), &c, RP, ORIGIN, &[0; 5], b"{}", b"x").is_err());
        assert!(check_assertion(
            b"not a key",
            &c,
            RP,
            ORIGIN,
            &good.auth_data,
            &good.client_data,
            &good.signature
        )
        .is_err());
    }

    #[test]
    fn a_registration_must_carry_the_challenge_and_origin() {
        let c = [3u8; 32];
        let cd = |kind: &str, ch: &[u8], origin: &str| {
            format!(
                r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}"}}"#,
                enc(ch)
            )
            .into_bytes()
        };
        assert!(check_client_data(
            &cd("webauthn.create", &c, ORIGIN),
            "webauthn.create",
            &c,
            ORIGIN
        )
        .is_ok());
        assert!(check_client_data(
            &cd("webauthn.get", &c, ORIGIN),
            "webauthn.create",
            &c,
            ORIGIN
        )
        .is_err());
        assert!(check_client_data(
            &cd("webauthn.create", &[4u8; 32], ORIGIN),
            "webauthn.create",
            &c,
            ORIGIN
        )
        .is_err());
        assert!(check_client_data(
            &cd("webauthn.create", &c, "https://evil"),
            "webauthn.create",
            &c,
            ORIGIN
        )
        .is_err());
        let cross = format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"{ORIGIN}","crossOrigin":true}}"#,
            enc(&c)
        );
        assert!(check_client_data(cross.as_bytes(), "webauthn.create", &c, ORIGIN).is_err());
    }

    #[test]
    fn only_p256_public_keys_are_accepted() {
        let a = Authenticator::new();
        assert!(parse_public_key(&a.spki()).is_ok());
        assert!(parse_public_key(&[1, 2, 3]).is_err());
        assert!(parse_public_key(&[]).is_err());
    }
}
