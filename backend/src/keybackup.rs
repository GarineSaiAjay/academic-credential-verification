//! Offline backup and restore of the active signing keys.
//!
//! The database stores private keys encrypted under `ENCRYPTION_KEY`. If that key is lost, they can no
//! longer be opened. A backup written here is encrypted under a separate passphrase (Argon2id +
//! AES-256-GCM), so it still opens after `ENCRYPTION_KEY` is gone. Restoring re-encrypts the keys under
//! whatever `ENCRYPTION_KEY` the server is configured with now.
//!
//! Only active keys are included: retired and revoked keys never sign again, and their public halves
//! are already in the database, which is all that verification needs.

use std::{
    env,
    io::{Read, Write},
};

use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    crypto::{self, KeyRing},
    keys::{self, KEY_ROLES},
};

type R<T> = Result<T, String>;

const FORMAT: &str = "acvs-key-backup";
const VERSION: u32 = 1;
const MIN_PASSPHRASE: usize = 16;
const PASSPHRASE_ENV: &str = "KEY_BACKUP_PASSPHRASE";
/// Argon2id cost for new backups: 64 MiB, 3 passes, 1 lane.
const KDF_COST: (u32, u32, u32) = (64 * 1024, 3, 1);

#[derive(Serialize, Deserialize)]
struct Envelope {
    format: String,
    version: u32,
    created_at: DateTime<Utc>,
    kdf: Kdf,
    /// hex of nonce(12) || AES-256-GCM ciphertext of the JSON `Payload`.
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct Kdf {
    alg: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
}

#[derive(Serialize, Deserialize)]
struct Payload {
    keys: Vec<BackupKey>,
}

#[derive(Serialize, Deserialize, Clone)]
struct BackupKey {
    id: Uuid,
    role: String,
    public_key: String,
    seed: String,
    created_at: DateTime<Utc>,
}

impl Kdf {
    fn new((m_kib, t, p): (u32, u32, u32)) -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            alg: "argon2id".into(),
            m_kib,
            t,
            p,
            salt: hex::encode(salt),
        }
    }

    /// The bounds stop a crafted file from forcing a huge memory or CPU cost on restore.
    fn derive(&self, passphrase: &str) -> R<[u8; 32]> {
        if self.alg != "argon2id"
            || !(8..=1 << 20).contains(&self.m_kib)
            || !(1..=10).contains(&self.t)
            || !(1..=8).contains(&self.p)
        {
            return Err("unsupported key derivation settings in backup file".into());
        }
        let salt = hex::decode(&self.salt)
            .ok()
            .filter(|s| (8..=64).contains(&s.len()))
            .ok_or("backup file has a malformed salt")?;
        let params =
            Params::new(self.m_kib, self.t, self.p, Some(32)).map_err(|e| e.to_string())?;
        let mut out = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), &salt, &mut out)
            .map_err(|e| e.to_string())?;
        Ok(out)
    }
}

impl BackupKey {
    /// Checks the entry is well formed and that the seed really belongs to the recorded public key.
    fn seed(&self) -> R<[u8; 32]> {
        let seed = hex::decode(&self.seed)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| format!("key {} has a malformed seed", self.id))?;
        if !KEY_ROLES.contains(&self.role.as_str()) {
            return Err(format!("key {} has unknown role '{}'", self.id, self.role));
        }
        if crypto::public_from_seed(&seed) != self.public_key {
            return Err(format!(
                "key {} ({}): seed does not match its public key",
                self.id, self.role
            ));
        }
        Ok(seed)
    }
}

fn check_passphrase(p: &str) -> R<()> {
    if p.chars().count() < MIN_PASSPHRASE {
        return Err(format!(
            "{PASSPHRASE_ENV} must be at least {MIN_PASSPHRASE} characters"
        ));
    }
    Ok(())
}

fn encrypt(keys: Vec<BackupKey>, passphrase: &str, cost: (u32, u32, u32)) -> R<String> {
    let kdf = Kdf::new(cost);
    let key = kdf.derive(passphrase)?;
    let plain = serde_json::to_vec(&Payload { keys }).map_err(|e| e.to_string())?;
    let env = Envelope {
        format: FORMAT.into(),
        version: VERSION,
        created_at: Utc::now(),
        kdf,
        ciphertext: hex::encode(crypto::seal(&key, &plain)),
    };
    serde_json::to_string_pretty(&env).map_err(|e| e.to_string())
}

fn decrypt(text: &str, passphrase: &str) -> R<Vec<BackupKey>> {
    let env: Envelope =
        serde_json::from_str(text).map_err(|_| "not a valid ACVS key backup file".to_string())?;
    if env.format != FORMAT {
        return Err("not an ACVS key backup file".into());
    }
    if env.version != VERSION {
        return Err(format!("unsupported backup version {}", env.version));
    }
    let blob = hex::decode(&env.ciphertext).map_err(|_| "backup file is corrupted".to_string())?;
    let key = env.kdf.derive(passphrase)?;
    let plain = crypto::open(&key, &blob)
        .ok_or("wrong passphrase, or the backup file is corrupted or was modified")?;
    let payload: Payload =
        serde_json::from_slice(&plain).map_err(|_| "backup contents are malformed".to_string())?;
    if payload.keys.is_empty() {
        return Err("backup contains no keys".into());
    }
    for k in &payload.keys {
        k.seed()?;
    }
    Ok(payload.keys)
}

type KeyRow = (Uuid, String, String, Vec<u8>, DateTime<Utc>);

/// Returns the encrypted backup file and how many keys it holds. Needs the *current* `ENCRYPTION_KEY`.
pub async fn backup(db: &PgPool, ring: &KeyRing, passphrase: &str) -> R<(String, usize)> {
    check_passphrase(passphrase)?;
    let rows: Vec<KeyRow> = sqlx::query_as(
        "SELECT id, role, public_key, private_key_enc, created_at FROM signing_keys WHERE status = 'active' ORDER BY role",
    )
    .fetch_all(db)
    .await
    .map_err(|e| e.to_string())?;
    if rows.is_empty() {
        return Err("there are no active signing keys to back up".into());
    }
    let mut keys = vec![];
    for (id, role, public_key, blob, created_at) in rows {
        let key = BackupKey {
            id,
            role: role.clone(),
            public_key,
            seed: hex::encode(
                ring.open(&blob)
                    .ok_or_else(|| format!("ENCRYPTION_KEY cannot decrypt the '{role}' key; back up while the correct key is configured"))?,
            ),
            created_at,
        };
        key.seed()?;
        keys.push(key);
    }
    let n = keys.len();
    Ok((encrypt(keys, passphrase, KDF_COST)?, n))
}

#[derive(Default, Debug)]
pub struct Report {
    /// Existing keys whose private half was re-encrypted under the current `ENCRYPTION_KEY`.
    pub restored: Vec<String>,
    /// Keys missing from the database that were inserted as active.
    pub inserted: Vec<String>,
    /// Keys in the backup that are no longer active in the database, so they were left alone.
    pub skipped: Vec<String>,
}

/// Re-encrypts the backed-up keys under the ring's current key in one transaction; with `dry_run` nothing is saved.
pub async fn restore(
    db: &PgPool,
    ring: &KeyRing,
    passphrase: &str,
    text: &str,
    dry_run: bool,
) -> R<Report> {
    let keys = decrypt(text, passphrase)?;
    let mut tx = db.begin().await.map_err(|e| e.to_string())?;
    let mut report = Report::default();
    for k in keys {
        let seed = k.seed()?;
        let label = format!("{} {}", k.role, k.id);
        let existing: Option<(String, String, String)> = sqlx::query_as(
            "SELECT public_key, role, status FROM signing_keys WHERE id = $1 FOR UPDATE",
        )
        .bind(k.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        match existing {
            Some((public_key, role, status)) => {
                if public_key != k.public_key || role != k.role {
                    return Err(format!(
                        "key {} exists in the database with a different public key or role; refusing to overwrite",
                        k.id
                    ));
                }
                if status != "active" {
                    report.skipped.push(format!("{label} (now {status})"));
                    continue;
                }
                sqlx::query("UPDATE signing_keys SET private_key_enc = $2 WHERE id = $1")
                    .bind(k.id)
                    .bind(ring.seal(&seed))
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                report.restored.push(label);
            }
            None => {
                let other: Option<(Uuid,)> = sqlx::query_as(
                    "SELECT id FROM signing_keys WHERE role = $1 AND status = 'active'",
                )
                .bind(&k.role)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
                if let Some((other,)) = other {
                    return Err(format!(
                        "the database already has a different active '{}' key ({other}); refusing to add {}",
                        k.role, k.id
                    ));
                }
                sqlx::query(
                    "INSERT INTO signing_keys (id, role, public_key, private_key_enc, status, created_at) VALUES ($1,$2,$3,$4,'active',$5)",
                )
                .bind(k.id)
                .bind(&k.role)
                .bind(&k.public_key)
                .bind(ring.seal(&seed))
                .bind(k.created_at)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
                report.inserted.push(label);
            }
        }
    }
    if dry_run {
        tx.rollback().await.map_err(|e| e.to_string())?;
    } else {
        tx.commit().await.map_err(|e| e.to_string())?;
    }
    Ok(report)
}

pub const USAGE: &str = "usage:
  server                         run the API server
  server key-backup              write an encrypted backup of the active signing keys to stdout
  server key-restore [--in FILE] [--dry-run]
                                 re-encrypt the backed-up keys under the current ENCRYPTION_KEY
                                 (reads the backup from FILE, or stdin)
  server key-rewrap [--dry-run]  re-encrypt every stored signing key under the current ENCRYPTION_KEY
                                 (rotation: set the new key as ENCRYPTION_KEY and the old one in
                                 ENCRYPTION_KEY_PREVIOUS, run this, then remove ENCRYPTION_KEY_PREVIOUS)
  server totp-reset EMAIL        remove a user's two-factor sign-in and end their sessions (when no administrator can sign in)
key-backup and key-restore take the passphrase from the KEY_BACKUP_PASSPHRASE environment variable";

pub fn is_command(arg: &str) -> bool {
    matches!(
        arg,
        "key-backup" | "key-restore" | "key-rewrap" | "totp-reset"
    )
}

pub async fn cli(db: &PgPool, ring: &KeyRing, args: &[String]) -> R<()> {
    let dry_run = args.iter().any(|a| a == "--dry-run");
    if args[0] == "totp-reset" {
        let email = args.get(1).ok_or("usage: server totp-reset EMAIL")?;
        return crate::totp::cli_reset(db, email).await;
    }
    if args[0] == "key-rewrap" {
        let r = keys::rewrap(db, ring, dry_run).await?;
        let verb = if dry_run { "would be " } else { "" };
        eprintln!(
            "{}{} key(s) {verb}re-encrypted under key {}, {} already under it",
            if dry_run {
                "dry run, nothing saved; "
            } else {
                ""
            },
            r.rewrapped,
            ring.current_id(),
            r.already_current
        );
        return Ok(());
    }
    let passphrase = env::var(PASSPHRASE_ENV).map_err(|_| format!("set {PASSPHRASE_ENV}"))?;
    match args[0].as_str() {
        "key-backup" => {
            let (text, n) = backup(db, ring, &passphrase).await?;
            println!("{text}");
            eprintln!(
                "backed up {n} active signing key(s). Store this file and its passphrase apart from .env and from database backups."
            );
        }
        _ => {
            let mut text = String::new();
            match args.iter().position(|a| a == "--in") {
                Some(i) => {
                    let path = args.get(i + 1).ok_or("--in needs a file path")?;
                    text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
                }
                None => {
                    std::io::stdin()
                        .read_to_string(&mut text)
                        .map_err(|e| e.to_string())?;
                }
            }
            let r = restore(db, ring, &passphrase, &text, dry_run).await?;
            let mut err = std::io::stderr();
            let verb = if dry_run { "would be " } else { "" };
            for (name, list) in [
                ("restored", &r.restored),
                ("inserted", &r.inserted),
                ("skipped", &r.skipped),
            ] {
                for item in list {
                    let _ = writeln!(err, "{name}: {item}");
                }
            }
            let _ = writeln!(
                err,
                "{}done: {} {verb}restored, {} {verb}inserted, {} skipped",
                if dry_run {
                    "dry run, nothing saved; "
                } else {
                    ""
                },
                r.restored.len(),
                r.inserted.len(),
                r.skipped.len()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_COST: (u32, u32, u32) = (8, 1, 1);
    const PASS: &str = "a long test passphrase";

    fn key(role: &str) -> BackupKey {
        let (seed, public_key) = crypto::new_keypair();
        BackupKey {
            id: Uuid::new_v4(),
            role: role.into(),
            public_key,
            seed: hex::encode(seed),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn roundtrip_restores_the_same_keys() {
        let keys = vec![key("faculty"), key("university")];
        let file = encrypt(keys.clone(), PASS, TEST_COST).unwrap();
        let back = decrypt(&file, PASS).unwrap();
        assert_eq!(back.len(), 2);
        for (a, b) in keys.iter().zip(&back) {
            assert_eq!(
                (a.id, &a.public_key, &a.seed),
                (b.id, &b.public_key, &b.seed)
            );
        }
    }

    #[test]
    fn file_holds_no_plaintext_secrets() {
        let k = key("registrar");
        let file = encrypt(vec![k.clone()], PASS, TEST_COST).unwrap();
        assert!(!file.contains(&k.seed) && !file.contains(&k.public_key) && !file.contains("seed"));
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let file = encrypt(vec![key("faculty")], PASS, TEST_COST).unwrap();
        assert!(decrypt(&file, "another long passphrase").is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let file = encrypt(vec![key("faculty")], PASS, TEST_COST).unwrap();
        let mut env: Envelope = serde_json::from_str(&file).unwrap();
        let mut ct = hex::decode(&env.ciphertext).unwrap();
        *ct.last_mut().unwrap() ^= 1;
        env.ciphertext = hex::encode(ct);
        assert!(decrypt(&serde_json::to_string(&env).unwrap(), PASS).is_err());
    }

    #[test]
    fn rejects_foreign_files_and_unsafe_kdf_settings() {
        assert!(decrypt("not json", PASS).is_err());
        assert!(decrypt(r#"{"hello":"world"}"#, PASS).is_err());
        let file = encrypt(vec![key("faculty")], PASS, TEST_COST).unwrap();
        for (field, bad) in [("m_kib", 1 << 21), ("t", 11), ("p", 9)] {
            let mut v: serde_json::Value = serde_json::from_str(&file).unwrap();
            v["kdf"][field] = bad.into();
            let err = decrypt(&v.to_string(), PASS).err().unwrap();
            assert!(err.contains("unsupported key derivation"), "{field}: {err}");
        }
        let mut v: serde_json::Value = serde_json::from_str(&file).unwrap();
        v["version"] = 99.into();
        let err = decrypt(&v.to_string(), PASS).err().unwrap();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn mismatched_or_invalid_entries_are_rejected() {
        let mut wrong_public = key("faculty");
        wrong_public.public_key = key("faculty").public_key;
        assert!(wrong_public.seed().is_err());
        let mut bad_role = key("faculty");
        bad_role.role = "janitor".into();
        assert!(bad_role.seed().is_err());
        let mut bad_seed = key("faculty");
        bad_seed.seed = "zz".into();
        assert!(bad_seed.seed().is_err());
        let file = encrypt(vec![wrong_public], PASS, TEST_COST).unwrap();
        assert!(decrypt(&file, PASS).is_err());
    }

    #[test]
    fn passphrase_must_be_long_enough() {
        assert!(check_passphrase("short").is_err());
        assert!(check_passphrase(&"x".repeat(MIN_PASSPHRASE)).is_ok());
    }
}
