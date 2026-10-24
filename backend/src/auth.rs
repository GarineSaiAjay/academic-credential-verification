use std::sync::OnceLock;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use async_trait::async_trait;
use axum::{
    extract::{ConnectInfo, FromRequestParts, State},
    http::{header, request::Parts, HeaderMap},
    Json,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::FromRow;
use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

use crate::{
    audit,
    config::Cidr,
    error::{AppError, Res},
    security, totp, AppState,
};

pub const TOKEN_HOURS: i64 = 8;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    Faculty,
    ExamCell,
    Registrar,
    UniversityAdmin,
    Auditor,
}

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "faculty" => Self::Faculty,
            "exam_cell" => Self::ExamCell,
            "registrar" => Self::Registrar,
            "university_admin" => Self::UniversityAdmin,
            "auditor" => Self::Auditor,
            _ => return None,
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Faculty => "faculty",
            Self::ExamCell => "exam_cell",
            Self::Registrar => "registrar",
            Self::UniversityAdmin => "university_admin",
            Self::Auditor => "auditor",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub role: Role,
    pub session: Uuid,
    /// Signed in with a password but still has to set up the second factor its role requires.
    pub mfa_pending: bool,
}

impl AuthUser {
    pub fn require(&self, allowed: &[Role]) -> Res<()> {
        if allowed.contains(&self.role) {
            Ok(())
        } else {
            Err(AppError::Forbidden(
                "your role may not perform this action".into(),
            ))
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    email: String,
    role: String,
    jti: String,
    iat: i64,
    exp: i64,
}

/// The user id in a bearer token, if the token's signature and expiry are valid. Used only to choose a
/// rate-limit bucket, with no database access: a forged or garbage token yields `None` and gets no bucket of
/// its own (it is counted against the client address instead).
pub fn verified_subject(headers: &HeaderMap, jwt_secret: &str) -> Option<Uuid> {
    let token = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .ok()?
    .claims;
    claims.sub.parse().ok()
}

pub fn hash_password(password: &str) -> Res<String> {
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(e.to_string()))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false)
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Res<Self> {
        let unauth = || AppError::Unauthorized("missing or invalid credentials".into());
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(unauth)?;
        let claims = decode::<Claims>(
            token,
            &DecodingKey::from_secret(state.cfg.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| unauth())?
        .claims;

        let session: Uuid = claims.jti.parse().map_err(|_| unauth())?;
        let user: Uuid = claims.sub.parse().map_err(|_| unauth())?;
        // Role comes from the database, not the token, so demotions/deactivation apply immediately.
        let row: Option<(String, String, bool)> = sqlx::query_as(
            "SELECT u.email, u.role, s.mfa_pending FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL AND s.expires_at > now() AND u.active",
        )
        .bind(session)
        .bind(user)
        .fetch_optional(&state.db)
        .await?;
        let (email, role, mfa_pending) = row.ok_or_else(unauth)?;
        // Until the second factor exists, the only things such a session may do are about signing in and setting it up.
        if mfa_pending && !parts.uri.path().starts_with("/api/v1/auth/") {
            return Err(AppError::Forbidden(
                "two-factor sign-in must be set up first".into(),
            ));
        }
        let role = Role::parse(&role).ok_or_else(unauth)?;
        Ok(AuthUser {
            id: user,
            email,
            role,
            session,
            mfa_pending,
        })
    }
}

/// The address of the client that made the request.
///
/// `X-Forwarded-For` is believed only when the connecting peer is one of `trusted`. Even then each proxy appends
/// the address it saw, so the list is read from the right: the first address that is not itself a trusted proxy
/// is the client, and anything further left was written by the client and is ignored. A header that is missing,
/// malformed, or made up only of trusted addresses leaves the peer address.
pub fn client_ip(headers: &HeaderMap, peer: SocketAddr, trusted: &[Cidr]) -> String {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|c| c.contains(ip));
    if is_trusted(peer.ip()) {
        let chain = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim);
        for hop in chain.rev() {
            match hop.parse::<IpAddr>() {
                Ok(ip) if is_trusted(ip) => continue,
                Ok(ip) => return ip.to_string(),
                Err(_) => break,
            }
        }
    }
    peer.ip().to_string()
}

#[derive(Deserialize)]
pub struct LoginBody {
    email: String,
    password: String,
}

#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    password_hash: String,
    role: String,
    active: bool,
}

fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| hash_password("dummy-password-for-timing").expect("hash"))
}

pub async fn login(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
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
    let email = body.email.trim().to_lowercase();
    // Many addresses guessing one account would never trip the per-address limit. This applies equally to
    // accounts that do not exist, so the response does not reveal which emails are registered.
    if let Some(wait) = security::account_blocked(&st, &email).await {
        audit::log(
            &st.db,
            None,
            Some(&email),
            "LOGIN_THROTTLED",
            None,
            None,
            json!({ "ip": ip }),
        )
        .await;
        return Err(AppError::TooMany(wait));
    }
    let user: Option<UserRow> =
        sqlx::query_as("SELECT id, password_hash, role, active FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&st.db)
            .await?;

    // Verify against a dummy hash for unknown users so timing does not reveal account existence.
    let ok = match &user {
        Some(u) => verify_password(&body.password, &u.password_hash) && u.active,
        None => {
            verify_password(&body.password, dummy_hash());
            false
        }
    };
    let Some(user) = user.filter(|_| ok) else {
        security::account_failure(&st, &email).await;
        audit::log(
            &st.db,
            None,
            Some(&email),
            "LOGIN_FAILED",
            None,
            None,
            json!({ "ip": ip }),
        )
        .await;
        return Err(AppError::Unauthorized("invalid email or password".into()));
    };

    // People with a second factor get a token that is good for nothing but the second step.
    let (has_totp,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM user_totp WHERE user_id = $1 AND confirmed_at IS NOT NULL)",
    )
    .bind(user.id)
    .fetch_one(&st.db)
    .await?;
    if has_totp {
        return Ok(Json(totp::begin(&st, user.id)?));
    }
    // A role that must have one, without one yet, may sign in only to set it up.
    let pending = Role::parse(&user.role).is_some_and(|r| st.cfg.require_mfa_roles.contains(&r));
    finish_login(&st, user.id, &email, &user.role, &ip, &headers, pending).await
}

/// Opens the session and returns the token. Shared by the password step and the second factor step.
pub async fn finish_login(
    st: &AppState,
    user_id: Uuid,
    email: &str,
    role: &str,
    ip: &str,
    headers: &HeaderMap,
    mfa_pending: bool,
) -> Res<Json<Value>> {
    let now = Utc::now();
    let exp = now + Duration::hours(TOKEN_HOURS);
    let session = Uuid::new_v4();
    let agent: String = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, expires_at, ip, user_agent, mfa_pending) VALUES ($1, $2, $3, $4, $5, $6)",
    )
        .bind(session)
        .bind(user_id)
        .bind(exp)
        .bind(ip)
        .bind(agent)
        .bind(mfa_pending)
        .execute(&st.db)
        .await?;

    let token = encode(
        &Header::default(),
        &Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            jti: session.to_string(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
        },
        &EncodingKey::from_secret(st.cfg.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    audit::log(
        &st.db,
        Some(user_id),
        Some(email),
        "LOGIN",
        Some("user"),
        Some(&user_id.to_string()),
        json!({ "ip": ip }),
    )
    .await;
    Ok(Json(
        json!({ "token": token, "expires_in": TOKEN_HOURS * 3600, "email": email, "role": role, "mfa_setup_required": mfa_pending }),
    ))
}

pub async fn me(user: AuthUser) -> Json<Value> {
    Json(
        json!({ "id": user.id, "email": user.email, "role": user.role.as_str(), "mfa_setup_required": user.mfa_pending }),
    )
}

pub async fn logout(State(st): State<AppState>, user: AuthUser) -> Res<Json<Value>> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1")
        .bind(user.session)
        .execute(&st.db)
        .await?;
    audit::log(
        &st.db,
        Some(user.id),
        Some(&user.email),
        "LOGOUT",
        None,
        None,
        json!({}),
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod client_ip_tests {
    use super::*;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("x-forwarded-for", v.parse().unwrap());
        }
        h
    }
    fn peer(ip: &str) -> SocketAddr {
        format!("{ip}:4000").parse().unwrap()
    }
    fn trust(list: &[&str]) -> Vec<Cidr> {
        list.iter().map(|c| Cidr::parse(c).unwrap()).collect()
    }

    #[test]
    fn header_is_ignored_unless_the_peer_is_a_trusted_proxy() {
        let h = headers(&["198.51.100.7"]);
        assert_eq!(client_ip(&h, peer("203.0.113.5"), &[]), "203.0.113.5");
        assert_eq!(
            client_ip(&h, peer("203.0.113.5"), &trust(&["172.29.250.12"])),
            "203.0.113.5"
        );
        assert_eq!(
            client_ip(&h, peer("172.29.250.12"), &trust(&["172.29.250.12"])),
            "198.51.100.7"
        );
    }

    #[test]
    fn a_client_cannot_choose_its_address_by_prepending() {
        // The proxy appended the real client (198.51.100.7); the client had sent "1.2.3.4" itself.
        let h = headers(&["1.2.3.4, 198.51.100.7"]);
        assert_eq!(
            client_ip(&h, peer("10.0.0.2"), &trust(&["10.0.0.0/8"])),
            "198.51.100.7"
        );
        // Several header lines are one list, read from the end.
        let h = headers(&["1.2.3.4", "198.51.100.7"]);
        assert_eq!(
            client_ip(&h, peer("10.0.0.2"), &trust(&["10.0.0.0/8"])),
            "198.51.100.7"
        );
    }

    #[test]
    fn trusted_hops_are_skipped_from_the_right() {
        let h = headers(&["1.2.3.4, 198.51.100.7, 10.0.0.9"]);
        assert_eq!(
            client_ip(&h, peer("10.0.0.2"), &trust(&["10.0.0.0/8"])),
            "198.51.100.7"
        );
    }

    #[test]
    fn bad_or_all_trusted_headers_fall_back_to_the_peer() {
        let t = trust(&["10.0.0.0/8"]);
        assert_eq!(
            client_ip(&headers(&["10.0.0.9"]), peer("10.0.0.2"), &t),
            "10.0.0.2"
        );
        assert_eq!(
            client_ip(&headers(&["198.51.100.7, garbage"]), peer("10.0.0.2"), &t),
            "10.0.0.2"
        );
        assert_eq!(client_ip(&headers(&[]), peer("10.0.0.2"), &t), "10.0.0.2");
        assert_eq!(client_ip(&headers(&[""]), peer("10.0.0.2"), &t), "10.0.0.2");
    }

    #[test]
    fn ranges_and_ipv6() {
        let c = Cidr::parse("172.29.250.0/24").unwrap();
        assert!(c.contains("172.29.250.12".parse().unwrap()));
        assert!(!c.contains("172.29.251.12".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
        assert!(Cidr::parse("127.0.0.1")
            .unwrap()
            .contains("::ffff:127.0.0.1".parse().unwrap()));
        assert!(Cidr::parse("fd00::/8")
            .unwrap()
            .contains("fd12::1".parse().unwrap()));
        assert!(!Cidr::parse("fd00::/8")
            .unwrap()
            .contains("fe80::1".parse().unwrap()));
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("nonsense").is_err());
    }
}
