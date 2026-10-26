use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    audit,
    auth::{self, AuthUser, Role},
    error::{AppError, Res},
    security, AppState,
};

pub const MIN_PASSWORD: usize = 12;
pub const MAX_PASSWORD: usize = 128;

/// Lowercases and validates an email. Login lowercases too, so stored emails must be lowercase.
pub fn normalize_email(raw: &str) -> Res<String> {
    let email = raw.trim().to_lowercase();
    let valid = email.len() <= 254
        && email.chars().all(|c| c.is_ascii_graphic())
        && matches!(
            email.split_once('@'),
            Some((local, domain)) if !local.is_empty()
                && !domain.contains('@')
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        );
    if valid {
        Ok(email)
    } else {
        Err(AppError::BadRequest("email is not valid".into()))
    }
}

/// Passwords people actually choose at twelve characters or more. Not a breach database: a short list that
/// stops the worst, checked case-insensitively.
const COMMON: &[&str] = &[
    "password1234",
    "password12345",
    "password123456",
    "passw0rd1234",
    "p@ssw0rd1234",
    "123456789012",
    "1234567890123",
    "12345678901234",
    "111111111111",
    "000000000000",
    "123123123123",
    "abcdefghijkl",
    "qwertyuiop12",
    "qwertyuiop123",
    "qwertyuiopas",
    "qwertyuiop[]",
    "asdfghjkl123",
    "1q2w3e4r5t6y",
    "1qaz2wsx3edc",
    "zaq12wsxcde3",
    "iloveyou1234",
    "iloveyou12345",
    "welcome12345",
    "welcome12345!",
    "changeme1234",
    "changeme12345",
    "letmein12345",
    "letmein123456",
    "administrator",
    "administrator1",
    "administrator123",
    "universityuniversity",
    "university123",
    "university1234",
    "university12345",
    "university2024",
    "university2025",
    "university2026",
    "trustno1trustno1",
    "monkey123456",
    "dragon123456",
    "football1234",
    "baseball1234",
    "superman1234",
    "sunshine1234",
    "princess1234",
    "mypassword123",
    "mypassword1234",
    "thisisapassword",
    "correcthorsebatterystaple",
    "passwordpassword",
    "adminadminadmin",
    "admin1234567",
    "admin12345678",
    "root12345678",
    "test12345678",
    "testtesttest",
    "default12345",
];

/// Length, the common-password list, and (when the account is known) not built from the e-mail address or
/// from one repeated character.
pub fn check_password_for(password: &str, email: Option<&str>) -> Res<()> {
    let n = password.chars().count();
    if !(MIN_PASSWORD..=MAX_PASSWORD).contains(&n) {
        return Err(AppError::BadRequest(format!(
            "password must be {MIN_PASSWORD}-{MAX_PASSWORD} characters"
        )));
    }
    let lower = password.to_lowercase();
    let first = password.chars().next();
    let weak = COMMON.contains(&lower.as_str())
        || password.chars().all(|c| Some(c) == first)
        || email.is_some_and(|e| {
            let local = e.split('@').next().unwrap_or(e);
            lower == e || (local.chars().count() >= 6 && lower.contains(local))
        });
    if weak {
        return Err(AppError::BadRequest(
            "that password is too easy to guess: avoid common passwords, repeated characters and your e-mail address".into(),
        ));
    }
    Ok(())
}

fn parse_role(s: &str) -> Res<Role> {
    Role::parse(s).ok_or_else(|| AppError::BadRequest("unknown role".into()))
}

async fn insert_user(db: &PgPool, email: &str, role: Role, password: &str) -> Res<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, role) VALUES ($1,$2,$3,$4)")
        .bind(id)
        .bind(email)
        .bind(auth::hash_password(password)?)
        .bind(role.as_str())
        .execute(db)
        .await?;
    Ok(id)
}

/// Creates the first university admin from BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_PASSWORD,
/// but only while the users table is empty, so it never overrides existing accounts.
pub async fn bootstrap_admin(st: &AppState) -> Res<()> {
    let Some((email, password)) = &st.cfg.bootstrap_admin else {
        return Ok(());
    };
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&st.db)
        .await?;
    if count > 0 {
        return Ok(());
    }
    let email = normalize_email(email)?;
    check_password_for(password, Some(&email))?;
    let id = match insert_user(&st.db, &email, Role::UniversityAdmin, password).await {
        Ok(id) => id,
        // Another instance won the race to create it.
        Err(AppError::Conflict(_)) => return Ok(()),
        Err(e) => return Err(e),
    };
    audit::log(
        &st.db,
        None,
        Some(&email),
        "BOOTSTRAP_ADMIN_CREATED",
        Some("user"),
        Some(&id.to_string()),
        json!({}),
    )
    .await;
    tracing::warn!(%email, "created bootstrap university admin; remove BOOTSTRAP_ADMIN_PASSWORD from the environment");
    Ok(())
}

#[derive(Serialize, sqlx::FromRow)]
struct UserInfo {
    id: Uuid,
    email: String,
    role: String,
    active: bool,
    created_at: DateTime<Utc>,
    two_factor: bool,
}

pub async fn list(State(st): State<AppState>, user: AuthUser) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin])?;
    let rows: Vec<UserInfo> = sqlx::query_as(
        "SELECT id, email, role, active, created_at,
                EXISTS (SELECT 1 FROM user_totp t WHERE t.user_id = users.id AND t.confirmed_at IS NOT NULL) AS two_factor
         FROM users ORDER BY email LIMIT 1000",
    )
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!({ "users": rows })))
}

#[derive(Deserialize)]
pub struct CreateBody {
    email: String,
    role: String,
    password: String,
}

pub async fn create(
    State(st): State<AppState>,
    user: AuthUser,
    Json(b): Json<CreateBody>,
) -> Res<(StatusCode, Json<Value>)> {
    user.require(&[Role::UniversityAdmin])?;
    let email = normalize_email(&b.email)?;
    let role = parse_role(&b.role)?;
    check_password_for(&b.password, Some(&email))?;
    let id = insert_user(&st.db, &email, role, &b.password)
        .await
        .map_err(|e| match e {
            AppError::Conflict(_) => {
                AppError::Conflict("a user with that email already exists".into())
            }
            other => other,
        })?;
    audit::actor_log(
        &st.db,
        &user,
        "USER_CREATED",
        "user",
        &id.to_string(),
        json!({ "email": email, "role": role.as_str() }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "email": email, "role": role.as_str(), "active": true })),
    ))
}

/// Locks every active admin row so concurrent demotions/deactivations are serialised.
async fn lock_admins(tx: &mut Transaction<'_, Postgres>) -> Res<()> {
    sqlx::query("SELECT id FROM users WHERE role = 'university_admin' AND active FOR UPDATE")
        .fetch_all(&mut **tx)
        .await?;
    Ok(())
}

/// Refuses the change (the caller's transaction rolls back) if no active admin would remain.
async fn ensure_admin_remains(tx: &mut Transaction<'_, Postgres>) -> Res<()> {
    let (n,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM users WHERE role = 'university_admin' AND active")
            .fetch_one(&mut **tx)
            .await?;
    if n == 0 {
        return Err(AppError::Conflict(
            "at least one active university admin must remain".into(),
        ));
    }
    Ok(())
}

fn not_self(user: &AuthUser, id: Uuid) -> Res<()> {
    if user.id == id {
        return Err(AppError::Conflict(
            "you cannot change your own role or active state".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct RoleBody {
    role: String,
}

pub async fn set_role(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(b): Json<RoleBody>,
) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin])?;
    let role = parse_role(&b.role)?;
    not_self(&user, id)?;

    let mut tx = st.db.begin().await?;
    lock_admins(&mut tx).await?;
    let (email, old): (String, String) =
        sqlx::query_as("SELECT email, role FROM users WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("UPDATE users SET role = $2 WHERE id = $1")
        .bind(id)
        .bind(role.as_str())
        .execute(&mut *tx)
        .await?;
    ensure_admin_remains(&mut tx).await?;
    tx.commit().await?;

    audit::actor_log(
        &st.db,
        &user,
        "USER_ROLE_CHANGED",
        "user",
        &id.to_string(),
        json!({ "email": email, "from": old, "to": role.as_str() }),
    )
    .await;
    Ok(Json(
        json!({ "id": id, "email": email, "role": role.as_str() }),
    ))
}

#[derive(Deserialize)]
pub struct ActiveBody {
    active: bool,
}

pub async fn set_active(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(b): Json<ActiveBody>,
) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin])?;
    not_self(&user, id)?;

    let mut tx = st.db.begin().await?;
    lock_admins(&mut tx).await?;
    let (email,): (String,) = sqlx::query_as("SELECT email FROM users WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("UPDATE users SET active = $2 WHERE id = $1")
        .bind(id)
        .bind(b.active)
        .execute(&mut *tx)
        .await?;
    if !b.active {
        sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
    }
    ensure_admin_remains(&mut tx).await?;
    tx.commit().await?;

    audit::actor_log(
        &st.db,
        &user,
        if b.active {
            "USER_ACTIVATED"
        } else {
            "USER_DEACTIVATED"
        },
        "user",
        &id.to_string(),
        json!({ "email": email }),
    )
    .await;
    Ok(Json(
        json!({ "id": id, "email": email, "active": b.active }),
    ))
}

#[derive(Deserialize)]
pub struct ResetBody {
    password: String,
}

/// Admin sets a new password for another user and signs that user out everywhere.
pub async fn reset_password(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(b): Json<ResetBody>,
) -> Res<Json<Value>> {
    user.require(&[Role::UniversityAdmin])?;
    if user.id == id {
        return Err(AppError::BadRequest(
            "use change password for your own account".into(),
        ));
    }
    let (target,): (String,) = sqlx::query_as("SELECT email FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| AppError::NotFound("no such user".into()))?;
    check_password_for(&b.password, Some(&target))?;
    let hash = auth::hash_password(&b.password)?;

    let mut tx = st.db.begin().await?;
    let (email,): (String,) =
        sqlx::query_as("UPDATE users SET password_hash = $2 WHERE id = $1 RETURNING email")
            .bind(id)
            .bind(hash)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    audit::actor_log(
        &st.db,
        &user,
        "USER_PASSWORD_RESET",
        "user",
        &id.to_string(),
        json!({ "email": email }),
    )
    .await;
    Ok(Json(json!({ "id": id, "email": email })))
}

#[derive(Deserialize)]
pub struct ChangeBody {
    current_password: String,
    new_password: String,
}

/// Any signed-in user changes their own password; their other sessions are revoked.
pub async fn change_password(
    State(st): State<AppState>,
    user: AuthUser,
    Json(b): Json<ChangeBody>,
) -> Res<Json<Value>> {
    let hit = security::hit(&st, &format!("pwchange:{}", user.id), 10, 60).await;
    if !hit.allowed {
        return Err(AppError::TooMany(hit.retry_after));
    }
    check_password_for(&b.new_password, Some(&user.email))?;
    if b.new_password == b.current_password {
        return Err(AppError::BadRequest(
            "new password must differ from the current one".into(),
        ));
    }
    let (hash,): (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&st.db)
        .await?;
    // 400, not 401: the front end treats any 401 as an expired session.
    if !auth::verify_password(&b.current_password, &hash) {
        return Err(AppError::BadRequest("current password is incorrect".into()));
    }
    let new_hash = auth::hash_password(&b.new_password)?;

    let mut tx = st.db.begin().await?;
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(user.id)
        .bind(new_hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL",
    )
    .bind(user.id)
    .bind(user.session)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    audit::actor_log(
        &st.db,
        &user,
        "PASSWORD_CHANGED",
        "user",
        &user.id.to_string(),
        json!({}),
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_is_trimmed_lowercased_and_validated() {
        assert_eq!(
            normalize_email("  Ada@Example.EDU ").unwrap(),
            "ada@example.edu"
        );
        for bad in [
            "",
            "ada",
            "ada@",
            "@x.com",
            "a@b",
            "a@@b.com",
            "a b@x.com",
            "a@.com",
            "a@x.",
            "é@x.com",
        ] {
            assert!(normalize_email(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(normalize_email(&format!("{}@x.com", "a".repeat(250))).is_err());
    }

    #[test]
    fn weak_passwords_are_refused() {
        for weak in [
            "Password1234",
            "aaaaaaaaaaaa",
            "QWERTYUIOP12",
            "ada.lovelace@example.edu",
            "my-ada.lovelace-1",
        ] {
            assert!(
                check_password_for(weak, Some("ada.lovelace@example.edu")).is_err(),
                "{weak:?} should be refused"
            );
        }
        assert!(check_password_for("a long, unusual passphrase", Some("ada@x.edu")).is_ok());
        // a short local part is not a reason to refuse everything that contains it
        assert!(check_password_for("quite-different-1x", Some("ada@x.edu")).is_ok());
    }

    #[test]
    fn password_length_is_bounded() {
        let pw = |n: usize| "xk7Q-".repeat(n).chars().take(n).collect::<String>();
        assert!(check_password_for(&pw(MIN_PASSWORD - 1), None).is_err());
        assert!(check_password_for(&pw(MIN_PASSWORD), None).is_ok());
        assert!(check_password_for(&pw(MAX_PASSWORD), None).is_ok());
        assert!(check_password_for(&pw(MAX_PASSWORD + 1), None).is_err());
    }
}
