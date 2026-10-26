//! Two-factor sign-in with time-based one-time passwords (RFC 6238: HMAC-SHA1, 6 digits, 30 seconds), which
//! every authenticator app understands.
//!
//! Sign-in becomes two steps for people who have it: the password yields a short-lived token that is good for
//! nothing but the second step; the code (or a recovery code) turns it into a session. Codes are single-use,
//! guessing is limited per account, and the secret is sealed with the same key ring as the signing keys.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    audit,
    auth::{self, client_ip, finish_login, AuthUser, Role},
    error::{AppError, Res},
    security, AppState,
};

const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;
const SECRET_BYTES: usize = 20;
const RECOVERY_CODES: usize = 10;
const MFA_TOKEN_MINUTES: i64 = 5;
const ISSUER: &str = "ACVS";

/// RFC 4226 HOTP.
fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = (h[19] & 0x0f) as usize;
    let n = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    n % 10u32.pow(DIGITS)
}

pub fn step_at(unix: u64) -> u64 {
    unix / STEP_SECS
}

/// The step whose code `code` is, if it is one of the current, previous or next step (clock drift) and newer
/// than `after` (a code is accepted once).
fn matching_step(secret: &[u8], code: &str, now_step: u64, after: u64) -> Option<u64> {
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut found = None;
    // Every candidate is compared, so the time taken does not say which step (if any) matched.
    for step in now_step.saturating_sub(1)..=now_step + 1 {
        let expected = format!("{:0width$}", hotp(secret, step), width = DIGITS as usize);
        let same = expected
            .bytes()
            .zip(code.bytes())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            == 0;
        if same && step > after {
            found = Some(step);
        }
    }
    found
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32(data: &[u8]) -> String {
    let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn new_recovery_code() -> String {
    let mut raw = [0u8; 10];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let s = base32(&raw); // 16 characters, 80 bits
    format!("{}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12], &s[12..16])
}

fn recovery_digest(code: &str) -> Vec<u8> {
    let canonical: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    Sha256::digest(canonical.as_bytes()).to_vec()
}

#[derive(Serialize, Deserialize)]
struct MfaClaims {
    sub: String,
    purpose: String,
    exp: i64,
}

fn mfa_token(st: &AppState, user: Uuid) -> Res<String> {
    encode(
        &Header::default(),
        &MfaClaims {
            sub: user.to_string(),
            purpose: "mfa".into(),
            exp: (Utc::now() + Duration::minutes(MFA_TOKEN_MINUTES)).timestamp(),
        },
        &EncodingKey::from_secret(st.cfg.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(e.to_string()))
}

/// The token handed out after a correct password, for users who have a second factor.
pub fn begin(st: &AppState, user: Uuid) -> Res<Value> {
    Ok(
        json!({ "mfa_required": true, "mfa_token": mfa_token(st, user)?, "expires_in": MFA_TOKEN_MINUTES * 60 }),
    )
}

async fn secret_of(st: &AppState, user: Uuid, confirmed: bool) -> Res<Option<(Vec<u8>, u64)>> {
    let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT secret_enc, last_step FROM user_totp WHERE user_id = $1 AND (confirmed_at IS NOT NULL) = $2",
    )
    .bind(user)
    .bind(confirmed)
    .fetch_optional(&st.db)
    .await?;
    row.map(|(blob, last)| {
        st.cfg
            .enc_key
            .open(&blob)
            .map(|s| (s, last.max(0) as u64))
            .ok_or_else(|| {
                AppError::Internal(
                    "cannot decrypt a two-factor secret (wrong ENCRYPTION_KEY?)".into(),
                )
            })
    })
    .transpose()
}

/// Accepts a current code (once) or an unused recovery code. Returns which kind was used.
async fn check_code(st: &AppState, user: Uuid, code: &str) -> Res<Option<&'static str>> {
    let code = code.trim();
    if let Some((secret, last)) = secret_of(st, user, true).await? {
        let now = step_at(Utc::now().timestamp().max(0) as u64);
        if let Some(step) = matching_step(&secret, code, now, last) {
            // Atomic: if two requests present the same code, only one moves last_step forward.
            let won = sqlx::query(
                "UPDATE user_totp SET last_step = $2 WHERE user_id = $1 AND last_step < $2",
            )
            .bind(user)
            .bind(step as i64)
            .execute(&st.db)
            .await?;
            if won.rows_affected() == 1 {
                return Ok(Some("code"));
            }
            return Ok(None);
        }
    }
    if code.len() >= 16 {
        let used = sqlx::query(
            "UPDATE totp_recovery SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
        )
        .bind(user)
        .bind(recovery_digest(code))
        .execute(&st.db)
        .await?;
        if used.rows_affected() == 1 {
            return Ok(Some("recovery"));
        }
    }
    Ok(None)
}

#[derive(Deserialize)]
pub struct MfaLogin {
    mfa_token: String,
    code: String,
}

/// Second step of sign-in.
pub async fn login(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(b): Json<MfaLogin>,
) -> Res<Json<Value>> {
    let ip = client_ip(&headers, peer, &st.cfg.trusted_proxies);
    let hit = security::hit(
        &st,
        &format!("login:{ip}"),
        st.cfg.rate.login_ip_per_min,
        60,
    )
    .await;
    if !hit.allowed {
        return Err(AppError::TooMany(hit.retry_after));
    }
    let claims = decode::<MfaClaims>(
        &b.mfa_token,
        &DecodingKey::from_secret(st.cfg.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .ok()
    .map(|d| d.claims)
    .filter(|c| c.purpose == "mfa");
    let expired =
        || AppError::Unauthorized("the sign-in expired; enter your password again".into());
    let user: Uuid = claims
        .and_then(|c| c.sub.parse().ok())
        .ok_or_else(expired)?;
    let (email, role, active): (String, String, bool) =
        sqlx::query_as("SELECT email, role, active FROM users WHERE id = $1")
            .bind(user)
            .fetch_optional(&st.db)
            .await?
            .ok_or_else(expired)?;
    if !active {
        return Err(expired());
    }
    // A six-digit code can be guessed, so: a handful of tries per sign-in window, and the same per-account
    // failure budget that protects passwords.
    if let Some(wait) = security::account_blocked(&st, &email).await {
        return Err(AppError::TooMany(wait));
    }
    if let Some(wait) = security::mfa_blocked(&st, user).await {
        return Err(AppError::TooMany(wait));
    }
    match check_code(&st, user, &b.code).await? {
        Some(kind) => {
            if kind == "recovery" {
                audit::log(
                    &st.db,
                    Some(user),
                    Some(&email),
                    "TOTP_RECOVERY_CODE_USED",
                    Some("user"),
                    Some(&user.to_string()),
                    json!({ "ip": ip }),
                )
                .await;
            }
            finish_login(&st, user, &email, &role, &ip, &headers, false).await
        }
        None => {
            security::mfa_failure(&st, user).await;
            security::account_failure(&st, &email).await;
            audit::log(
                &st.db,
                Some(user),
                Some(&email),
                "LOGIN_MFA_FAILED",
                None,
                None,
                json!({ "ip": ip }),
            )
            .await;
            Err(AppError::Unauthorized("that code is not valid".into()))
        }
    }
}

fn required_for(st: &AppState, role: Role) -> bool {
    st.cfg.require_mfa_roles.contains(&role)
}

pub async fn status(State(st): State<AppState>, user: AuthUser) -> Res<Json<Value>> {
    let (enabled,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM user_totp WHERE user_id = $1 AND confirmed_at IS NOT NULL)",
    )
    .bind(user.id)
    .fetch_one(&st.db)
    .await?;
    let (left,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM totp_recovery WHERE user_id = $1 AND used_at IS NULL")
            .bind(user.id)
            .fetch_one(&st.db)
            .await?;
    Ok(Json(json!({
        "enabled": enabled,
        "recovery_codes_left": left,
        "required": required_for(&st, user.role),
        "setup_required": user.mfa_pending,
    })))
}

async fn check_password(st: &AppState, user: &AuthUser, password: &str) -> Res<()> {
    let hit = security::hit(st, &format!("mfa-pw:{}", user.id), 10, 300).await;
    if !hit.allowed {
        return Err(AppError::TooMany(hit.retry_after));
    }
    let (hash,): (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&st.db)
        .await?;
    // 400, not 401: the front end treats any 401 as an expired session.
    if auth::verify_password(password, &hash) {
        Ok(())
    } else {
        Err(AppError::BadRequest("password is incorrect".into()))
    }
}

#[derive(Deserialize)]
pub struct PasswordBody {
    password: String,
}

/// Step one of turning it on: make a secret and show it (as text and as an otpauth:// link for QR codes).
/// Needs the password, so a stolen session cannot enrol an attacker's phone.
pub async fn setup(
    State(st): State<AppState>,
    user: AuthUser,
    Json(b): Json<PasswordBody>,
) -> Res<Json<Value>> {
    check_password(&st, &user, &b.password).await?;
    let mut raw = [0u8; SECRET_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    // Replaces an earlier unconfirmed secret; never touches a confirmed one.
    let done = sqlx::query(
        "INSERT INTO user_totp (user_id, secret_enc) VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET secret_enc = $2, created_at = now(), last_step = 0
         WHERE user_totp.confirmed_at IS NULL",
    )
    .bind(user.id)
    .bind(st.cfg.enc_key.seal(&raw))
    .execute(&st.db)
    .await?;
    if done.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "two-factor sign-in is already on; turn it off first to change the device".into(),
        ));
    }
    let secret = base32(&raw);
    let uri = format!(
        "otpauth://totp/{ISSUER}:{}?secret={secret}&issuer={ISSUER}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        user.email.replace('@', "%40")
    );
    // Drawn here rather than by a script in the page: the secret never goes to a third party, and the page's
    // content policy forbids loading one anyway.
    let code =
        qrcode::QrCode::new(uri.as_bytes()).map_err(|e| AppError::Internal(e.to_string()))?;
    let img = code
        .render::<image::Luma<u8>>()
        .min_dimensions(240, 240)
        .build();
    let mut png = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let qr = format!("data:image/png;base64,{}", STANDARD.encode(png));
    Ok(Json(json!({ "secret": secret, "uri": uri, "qr": qr })))
}

async fn new_recovery_codes(db: &PgPool, user: Uuid) -> Res<Vec<String>> {
    let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect();
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM totp_recovery WHERE user_id = $1")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    for c in &codes {
        sqlx::query("INSERT INTO totp_recovery (id, user_id, code_hash) VALUES ($1,$2,$3)")
            .bind(Uuid::new_v4())
            .bind(user)
            .bind(recovery_digest(c))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(codes)
}

#[derive(Deserialize)]
pub struct CodeBody {
    code: String,
}

/// Step two: prove the app produces valid codes. Turns the factor on, issues recovery codes (shown once),
/// ends every other session (they were opened with a password alone) and lifts a "set this up first" session.
pub async fn enable(
    State(st): State<AppState>,
    user: AuthUser,
    Json(b): Json<CodeBody>,
) -> Res<Json<Value>> {
    let tries = security::hit(&st, &format!("mfa-enable:{}", user.id), 10, 300).await;
    if !tries.allowed {
        return Err(AppError::TooMany(tries.retry_after));
    }
    let Some((secret, _)) = secret_of(&st, user.id, false).await? else {
        return Err(AppError::BadRequest(
            "start the setup first (or it is already on)".into(),
        ));
    };
    let now = step_at(Utc::now().timestamp().max(0) as u64);
    let Some(step) = matching_step(&secret, b.code.trim(), now, 0) else {
        return Err(AppError::BadRequest(
            "that code is not valid; check the time on your phone and try the next code".into(),
        ));
    };
    sqlx::query("UPDATE user_totp SET confirmed_at = now(), last_step = $2 WHERE user_id = $1 AND confirmed_at IS NULL")
        .bind(user.id)
        .bind(step as i64)
        .execute(&st.db)
        .await?;
    let codes = new_recovery_codes(&st.db, user.id).await?;
    sqlx::query("UPDATE sessions SET mfa_pending = false WHERE id = $1")
        .bind(user.session)
        .execute(&st.db)
        .await?;
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL")
        .bind(user.id)
        .bind(user.session)
        .execute(&st.db)
        .await?;
    audit::actor_log(
        &st.db,
        &user,
        "TOTP_ENABLED",
        "user",
        &user.id.to_string(),
        json!({}),
    )
    .await;
    Ok(Json(json!({ "recovery_codes": codes })))
}

#[derive(Deserialize)]
pub struct PasswordCodeBody {
    password: String,
    code: String,
}

/// Needs the password and a current code (or a recovery code). Not allowed for roles that must have it.
pub async fn disable(
    State(st): State<AppState>,
    user: AuthUser,
    Json(b): Json<PasswordCodeBody>,
) -> Res<Json<Value>> {
    if required_for(&st, user.role) {
        return Err(AppError::Forbidden(
            "your role must use two-factor sign-in; an administrator can reset it if you lost the device".into(),
        ));
    }
    check_password(&st, &user, &b.password).await?;
    if let Some(wait) = security::mfa_blocked(&st, user.id).await {
        return Err(AppError::TooMany(wait));
    }
    if check_code(&st, user.id, &b.code).await?.is_none() {
        security::mfa_failure(&st, user.id).await;
        return Err(AppError::BadRequest("that code is not valid".into()));
    }
    remove(&st.db, user.id).await?;
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL")
        .bind(user.id)
        .bind(user.session)
        .execute(&st.db)
        .await?;
    audit::actor_log(
        &st.db,
        &user,
        "TOTP_DISABLED",
        "user",
        &user.id.to_string(),
        json!({}),
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

/// Replaces the recovery codes (the old ones stop working). Needs the password and a current code.
pub async fn regenerate_codes(
    State(st): State<AppState>,
    user: AuthUser,
    Json(b): Json<PasswordCodeBody>,
) -> Res<Json<Value>> {
    check_password(&st, &user, &b.password).await?;
    if secret_of(&st, user.id, true).await?.is_none() {
        return Err(AppError::BadRequest("two-factor sign-in is not on".into()));
    }
    if let Some(wait) = security::mfa_blocked(&st, user.id).await {
        return Err(AppError::TooMany(wait));
    }
    if check_code(&st, user.id, &b.code).await?.is_none() {
        security::mfa_failure(&st, user.id).await;
        return Err(AppError::BadRequest("that code is not valid".into()));
    }
    let codes = new_recovery_codes(&st.db, user.id).await?;
    audit::actor_log(
        &st.db,
        &user,
        "TOTP_RECOVERY_CODES_REPLACED",
        "user",
        &user.id.to_string(),
        json!({}),
    )
    .await;
    Ok(Json(json!({ "recovery_codes": codes })))
}

pub async fn remove(db: &PgPool, user: Uuid) -> Result<bool, sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM totp_recovery WHERE user_id = $1")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    let gone = sqlx::query("DELETE FROM user_totp WHERE user_id = $1")
        .bind(user)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(gone > 0)
}

/// An administrator removes another user's second factor (lost phone) and signs them out everywhere. If the
/// role requires the factor, the person must set it up again at their next sign-in.
pub async fn admin_reset(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin])?;
    if id == user.id {
        return Err(AppError::BadRequest(
            "another administrator must reset your two-factor sign-in (or run `server totp-reset` on the host)".into(),
        ));
    }
    let (email,): (String,) = sqlx::query_as("SELECT email FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| AppError::NotFound("no such user".into()))?;
    let had = remove(&st.db, id).await?;
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(&st.db)
        .await?;
    audit::actor_log(
        &st.db,
        &user,
        "TOTP_RESET_BY_ADMIN",
        "user",
        &id.to_string(),
        json!({ "email": email, "had_two_factor": had }),
    )
    .await;
    Ok(Json(json!({ "email": email, "had_two_factor": had })))
}

/// `server totp-reset EMAIL`: for the case where no administrator can sign in.
pub async fn cli_reset(db: &PgPool, email: &str) -> Result<(), String> {
    let email = email.trim().to_lowercase();
    let row: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(db)
        .await
        .map_err(|e| e.to_string())?;
    let (id,) = row.ok_or_else(|| format!("no user {email}"))?;
    let had = remove(db, id).await.map_err(|e| e.to_string())?;
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(db)
        .await
        .map_err(|e| e.to_string())?;
    audit::log(
        db,
        None,
        None,
        "TOTP_RESET_BY_OPERATOR",
        Some("user"),
        Some(&id.to_string()),
        json!({ "email": email, "had_two_factor": had }),
    )
    .await;
    eprintln!(
        "{}two-factor sign-in removed for {email}; their sessions were ended",
        if had { "" } else { "(it was not on) " }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 appendix D: secret "12345678901234567890".
    #[test]
    fn hotp_matches_rfc_4226() {
        let s = b"12345678901234567890";
        let want = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(hotp(s, i as u64), *w);
        }
    }

    // RFC 6238 appendix B (SHA-1), last six digits of the 8-digit vectors.
    #[test]
    fn totp_matches_rfc_6238() {
        let s = b"12345678901234567890";
        for (t, code) in [
            (59u64, "287082"),
            (1111111109, "081804"),
            (1234567890, "005924"),
            (2000000000, "279037"),
        ] {
            assert_eq!(format!("{:06}", hotp(s, step_at(t))), code, "t={t}");
        }
    }

    #[test]
    fn a_code_works_in_its_window_once_and_only_nearby() {
        let s = b"12345678901234567890";
        let now = step_at(1111111109);
        let code = format!("{:06}", hotp(s, now));
        assert_eq!(matching_step(s, &code, now, 0), Some(now));
        // clock drift of one step either way
        assert_eq!(matching_step(s, &code, now + 1, 0), Some(now));
        assert_eq!(matching_step(s, &code, now - 1, 0), Some(now));
        assert_eq!(matching_step(s, &code, now + 2, 0), None);
        // already used
        assert_eq!(matching_step(s, &code, now, now), None);
        // not a six-digit number
        for bad in ["", "12345", "1234567", "12345a", " 12345"] {
            assert_eq!(matching_step(s, bad, now, 0), None);
        }
    }

    #[test]
    fn base32_and_recovery_codes() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"fo"), "MZXQ");
        let c = new_recovery_code();
        assert_eq!(c.len(), 19);
        assert_eq!(
            recovery_digest(&c),
            recovery_digest(&c.to_lowercase().replace('-', " "))
        );
        assert_ne!(new_recovery_code(), c);
    }
}
