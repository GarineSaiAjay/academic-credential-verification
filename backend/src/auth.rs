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
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    audit,
    error::{AppError, Res},
    AppState,
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

pub fn hash_password(password: &str) -> Res<String> {
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(e.to_string()))
}

fn verify_password(password: &str, hash: &str) -> bool {
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
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT u.email, u.role FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL AND s.expires_at > now() AND u.active",
        )
        .bind(session)
        .bind(user)
        .fetch_optional(&state.db)
        .await?;
        let (email, role) = row.ok_or_else(unauth)?;
        let role = Role::parse(&role).ok_or_else(unauth)?;
        Ok(AuthUser {
            id: user,
            email,
            role,
            session,
        })
    }
}

pub fn client_ip(headers: &HeaderMap, peer: SocketAddr, trust_proxy: bool) -> String {
    if trust_proxy {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
        {
            return ip.trim().to_string();
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
    let ip = client_ip(&headers, peer, st.cfg.trust_proxy);
    if !st.limiter.check(&format!("login:{ip}"), 10, 60) {
        return Err(AppError::TooMany);
    }
    let email = body.email.trim().to_lowercase();
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

    let now = Utc::now();
    let exp = now + Duration::hours(TOKEN_HOURS);
    let session = Uuid::new_v4();
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(session)
        .bind(user.id)
        .bind(exp)
        .execute(&st.db)
        .await?;

    let token = encode(
        &Header::default(),
        &Claims {
            sub: user.id.to_string(),
            email: email.clone(),
            role: user.role.clone(),
            jti: session.to_string(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
        },
        &EncodingKey::from_secret(st.cfg.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    audit::log(
        &st.db,
        Some(user.id),
        Some(&email),
        "LOGIN",
        Some("user"),
        Some(&user.id.to_string()),
        json!({ "ip": ip }),
    )
    .await;
    Ok(Json(
        json!({ "token": token, "expires_in": TOKEN_HOURS * 3600, "email": email, "role": user.role }),
    ))
}

pub async fn me(user: AuthUser) -> Json<Value> {
    Json(json!({ "id": user.id, "email": user.email, "role": user.role.as_str() }))
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
