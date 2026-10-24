//! External anchoring of the ledger with RFC 3161 time-stamping.
//!
//! Every sealed block's hash is sent to a time-stamping authority (TSA). It answers with a token, signed
//! with its own key, saying "this digest existed at this time". Because each block hash covers the previous
//! one, a token for block N pins the whole chain up to N. Rewriting history, even with full control of the
//! database and the university key, would contradict a signature the university does not control.
//!
//! A token is stored only after `openssl ts -verify` accepts it against the operator-supplied CA file, so
//! all the ASN.1 and certificate-chain work is done by OpenSSL. Tokens are re-checked at the time stamped in
//! them, so they stay valid after the TSA's certificate expires.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use axum::{
    extract::{Path as UrlPath, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, NaiveDateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{FromRow, PgPool};
use tokio::process::Command;
use uuid::Uuid;

use crate::{
    audit,
    auth::{AuthUser, Role},
    config::TsaConfig,
    error::{AppError, Res},
    AppState,
};

type R<T> = Result<T, String>;

const MAX_RESPONSE: usize = 64 * 1024;
/// How far a TSA clock may differ from ours before its token is refused.
const MAX_SKEW_SECS: i64 = 300;
const OPENSSL_TIMEOUT: Duration = Duration::from_secs(20);

// DER of a TimeStampReq: version 1, SHA-256 message imprint, 8-byte nonce, certReq TRUE.
const REQ_PREFIX: [u8; 24] = [
    0x30, 0x43, 0x02, 0x01, 0x01, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
];
const REQ_NONCE_HEAD: [u8; 2] = [0x02, 0x08];
const REQ_TAIL: [u8; 3] = [0x01, 0x01, 0xff];
const REQ_LEN: usize = 69;

pub fn build_request(digest: &[u8; 32], nonce: &[u8; 8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(REQ_LEN);
    v.extend(REQ_PREFIX);
    v.extend(digest);
    v.extend(REQ_NONCE_HEAD);
    v.extend(nonce);
    v.extend(REQ_TAIL);
    v
}

/// The digest a stored request asks to have timestamped; `None` unless it is exactly our request shape.
fn request_imprint(req: &[u8]) -> Option<[u8; 32]> {
    if req.len() != REQ_LEN
        || req[..24] != REQ_PREFIX
        || req[56..58] != REQ_NONCE_HEAD
        || req[66..] != REQ_TAIL
    {
        return None;
    }
    req[24..56].try_into().ok()
}

fn new_nonce() -> [u8; 8] {
    let mut n = [0u8; 8];
    OsRng.fill_bytes(&mut n);
    // A positive DER INTEGER without a redundant leading zero byte.
    n[0] = (n[0] & 0x7f).max(1);
    n
}

#[derive(Debug, PartialEq)]
pub struct Stamp {
    pub gen_time: DateTime<Utc>,
    pub serial: String,
}

/// Reads the time and serial out of `openssl ts -reply -text`. Only trusted after `-verify` passes.
fn parse_reply_text(text: &str) -> R<Stamp> {
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .map(|v| v.trim().to_string())
    };
    let serial = field("Serial number:").ok_or("timestamp reply has no serial number")?;
    let time = field("Time stamp:").ok_or("timestamp reply has no time")?;
    let time = time.trim_end_matches("GMT").trim();
    let gen_time = ["%b %e %H:%M:%S %Y", "%b %e %H:%M:%S%.f %Y"]
        .iter()
        .find_map(|f| NaiveDateTime::parse_from_str(time, f).ok())
        .ok_or_else(|| format!("cannot read timestamp time '{time}'"))?
        .and_utc();
    Ok(Stamp { gen_time, serial })
}

/// Temporary files that are removed when dropped (the container's /tmp is a tmpfs).
struct Tmp(Vec<PathBuf>);

impl Tmp {
    fn file(&mut self, ext: &str, data: &[u8]) -> R<PathBuf> {
        let path = std::env::temp_dir().join(format!("acvs-ts-{}.{ext}", Uuid::new_v4()));
        std::fs::write(&path, data).map_err(|e| format!("temp file: {e}"))?;
        self.0.push(path.clone());
        Ok(path)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Builds the owned argument list for `openssl` from strings and paths.
macro_rules! os {
    ($($a:expr),* $(,)?) => {
        vec![$(AsRef::<std::ffi::OsStr>::as_ref(&$a).to_os_string()),*] as Vec<OsString>
    };
}

/// Runs openssl; returns (success, stdout, stderr).
async fn openssl(arguments: Vec<OsString>) -> R<(bool, String, String)> {
    let run = Command::new("openssl")
        .args(arguments)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(OPENSSL_TIMEOUT, run)
        .await
        .map_err(|_| "openssl timed out".to_string())?
        .map_err(|e| format!("cannot run openssl: {e}"))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// A short, useful summary of OpenSSL's output: its banner is skipped, and only the first lines are kept.
fn first_line(s: &str) -> String {
    let lines: Vec<&str> = s
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("Using configuration from"))
        .take(2)
        .collect();
    lines.join("; ").chars().take(300).collect()
}

/// Fails at startup (rather than at the first block) if OpenSSL or the CA file is unusable.
pub async fn preflight(cfg: &TsaConfig) -> R<()> {
    let (ok, _, err) = openssl(os!["version"]).await?;
    if !ok {
        return Err(format!("openssl is not usable: {}", first_line(&err)));
    }
    let (ok, _, err) = openssl(os!["x509", "-noout", "-in", cfg.ca_file]).await?;
    if !ok {
        return Err(format!(
            "TSA_CA_FILE {} is not a readable PEM certificate: {}",
            cfg.ca_file.display(),
            first_line(&err)
        ));
    }
    Ok(())
}

/// Checks that `resp` is a valid, trusted answer to `req`, that `req` asked about `block_hash`, and that
/// the stamped time is plausible. Returns the stamped time and serial.
pub async fn verify(
    ca_file: &Path,
    block_hash: &str,
    block_ts: i64,
    req: &[u8],
    resp: &[u8],
) -> R<Stamp> {
    let want = hex::decode(block_hash)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or("block hash is malformed")?;
    if request_imprint(req) != Some(want) {
        return Err("the timestamp request does not cover this block's hash".into());
    }
    let mut tmp = Tmp(vec![]);
    let q = tmp.file("tsq", req)?;
    let r = tmp.file("tsr", resp)?;

    let (ok, text, err) = openssl(os!["ts", "-reply", "-in", r, "-text"]).await?;
    if !ok {
        return Err(format!("not a valid timestamp reply: {}", first_line(&err)));
    }
    let stamp = parse_reply_text(&text)?;

    // Validate at the stamped time, so a token stays valid after the TSA's certificate expires.
    let attime = stamp.gen_time.timestamp().to_string();
    let (ok, out, err) = openssl(os![
        "ts",
        "-verify",
        "-queryfile",
        q,
        "-in",
        r,
        "-CAfile",
        ca_file,
        "-attime",
        attime
    ])
    .await?;
    if !ok || !(out.contains("Verification: OK") || err.contains("Verification: OK")) {
        return Err(format!(
            "timestamp rejected by OpenSSL: {}",
            first_line(&format!("{err}{out}"))
        ));
    }

    let now = Utc::now().timestamp();
    let t = stamp.gen_time.timestamp();
    if t > now + MAX_SKEW_SECS || t < block_ts - MAX_SKEW_SECS {
        return Err(format!(
            "timestamp time {} is implausible for a block sealed at {} (now {})",
            stamp.gen_time, block_ts, now
        ));
    }
    Ok(stamp)
}

async fn fetch(cfg: &TsaConfig, req: &[u8]) -> R<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .user_agent("acvs-timestamper")
        .build()
        .map_err(|e| e.to_string())?;
    let mut resp = client
        .post(&cfg.url)
        .header(header::CONTENT_TYPE, "application/timestamp-query")
        .body(req.to_vec())
        .send()
        .await
        .map_err(|e| format!("TSA request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("TSA answered HTTP {}", resp.status()));
    }
    let mut body = vec![];
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("TSA response: {e}"))?
    {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_RESPONSE {
            return Err("TSA response is too large".into());
        }
    }
    Ok(body)
}

#[derive(Serialize, Default)]
pub struct Failure {
    pub height: i64,
    pub error: String,
}

#[derive(Serialize, Default)]
pub struct Report {
    pub attempted: usize,
    pub stamped: usize,
    pub failed: Vec<Failure>,
}

/// Timestamps every block that has no token yet, oldest first. Stops at the first failure so an
/// unreachable TSA is retried on the next tick instead of being hammered once per block.
pub async fn timestamp_pending(st: &AppState) -> Report {
    let mut report = Report::default();
    let Some(cfg) = &st.cfg.tsa else {
        return report;
    };
    let Ok(_guard) = st.ts_lock.try_lock() else {
        return report;
    };
    let pending: Result<Vec<(i64, String, i64)>, _> = sqlx::query_as(
        "SELECT b.height, b.block_hash, b.ts FROM blocks b
         LEFT JOIN block_timestamps t ON t.block_height = b.height
         WHERE t.block_height IS NULL ORDER BY b.height",
    )
    .fetch_all(&st.db)
    .await;
    let pending = match pending {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "cannot list blocks awaiting a timestamp");
            return report;
        }
    };
    for (height, block_hash, block_ts) in pending {
        report.attempted += 1;
        match stamp_block(st, cfg, height, &block_hash, block_ts).await {
            Ok(()) => report.stamped += 1,
            Err(error) => {
                tracing::warn!(height, %error, "could not timestamp block; will retry");
                report.failed.push(Failure { height, error });
                break;
            }
        }
    }
    report
}

async fn stamp_block(
    st: &AppState,
    cfg: &TsaConfig,
    height: i64,
    block_hash: &str,
    block_ts: i64,
) -> R<()> {
    let digest: [u8; 32] = hex::decode(block_hash)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("block hash is malformed")?;
    let req = build_request(&digest, &new_nonce());
    let resp = fetch(cfg, &req).await?;
    let stamp = verify(&cfg.ca_file, block_hash, block_ts, &req, &resp).await?;
    let inserted = sqlx::query(
        "INSERT INTO block_timestamps (block_height, imprint, tsa_url, request, response, gen_time, serial)
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
    )
    .bind(height)
    .bind(block_hash)
    .bind(&cfg.url)
    .bind(&req)
    .bind(&resp)
    .bind(stamp.gen_time)
    .bind(&stamp.serial)
    .execute(&st.db)
    .await
    .map_err(|e| e.to_string())?
    .rows_affected();
    if inserted == 1 {
        audit::log(
            &st.db,
            None,
            None,
            "BLOCK_TIMESTAMPED",
            Some("block"),
            Some(&height.to_string()),
            json!({ "tsa": cfg.url, "time": stamp.gen_time, "serial": stamp.serial }),
        )
        .await;
        tracing::info!(height, time = %stamp.gen_time, "block timestamped");
    }
    Ok(())
}

/// Background retry loop; also picks up blocks sealed while the TSA was unreachable.
pub async fn run_forever(st: AppState) {
    let Some(interval) = st.cfg.tsa.as_ref().map(|c| c.interval) else {
        return;
    };
    loop {
        timestamp_pending(&st).await;
        tokio::time::sleep(interval).await;
    }
}

#[derive(FromRow)]
struct StampRow {
    imprint: String,
    tsa_url: String,
    request: Vec<u8>,
    response: Vec<u8>,
    gen_time: DateTime<Utc>,
    serial: String,
}

async fn load(db: &PgPool, height: i64) -> Res<Option<StampRow>> {
    Ok(sqlx::query_as(
        "SELECT imprint, tsa_url, request, response, gen_time, serial FROM block_timestamps WHERE block_height = $1",
    )
    .bind(height)
    .fetch_optional(db)
    .await?)
}

/// Cheap summary for listings: the stamped time, and whether the stored imprint still matches the block.
pub async fn summary(db: &PgPool, height: i64, block_hash: &str) -> Res<Option<Value>> {
    Ok(load(db, height).await?.map(
        |s| json!({ "time": s.gen_time, "tsa": s.tsa_url, "imprint_ok": s.imprint == block_hash }),
    ))
}

/// Public: the stored token for a block, re-verified now.
pub async fn show(State(st): State<AppState>, UrlPath(height): UrlPath<i64>) -> Res<Json<Value>> {
    let Some(s) = load(&st.db, height).await? else {
        return Err(AppError::NotFound(if st.cfg.tsa.is_some() {
            "this block has not been timestamped yet".into()
        } else {
            "timestamping is not configured".into()
        }));
    };
    let (block_hash, block_ts): (String, i64) =
        sqlx::query_as("SELECT block_hash, ts FROM blocks WHERE height = $1")
            .bind(height)
            .fetch_one(&st.db)
            .await?;
    let check = match &st.cfg.tsa {
        Some(cfg) => {
            Some(verify(&cfg.ca_file, &block_hash, block_ts, &s.request, &s.response).await)
        }
        None => None,
    };
    let (verified, error) = match check {
        Some(Ok(_)) => (Some(true), None),
        Some(Err(e)) => (Some(false), Some(e)),
        None => (None, None),
    };
    Ok(Json(json!({
        "height": height, "block_hash": block_hash, "imprint": s.imprint,
        "tsa": s.tsa_url, "time": s.gen_time, "serial": s.serial,
        "verified": verified, "error": error,
        "request": STANDARD.encode(&s.request), "response": STANDARD.encode(&s.response),
    })))
}

async fn raw(st: &AppState, height: i64, query: bool) -> Res<Response> {
    let s = load(&st.db, height)
        .await?
        .ok_or_else(|| AppError::NotFound("this block has no timestamp".into()))?;
    let (kind, bytes) = if query {
        ("application/timestamp-query", s.request)
    } else {
        ("application/timestamp-reply", s.response)
    };
    Ok(([(header::CONTENT_TYPE, kind)], bytes).into_response())
}

pub async fn raw_request(State(st): State<AppState>, UrlPath(h): UrlPath<i64>) -> Res<Response> {
    raw(&st, h, true).await
}

pub async fn raw_response(State(st): State<AppState>, UrlPath(h): UrlPath<i64>) -> Res<Response> {
    raw(&st, h, false).await
}

/// Admin: timestamp every pending block now instead of waiting for the next tick.
pub async fn run_now(
    State(st): State<AppState>,
    user: AuthUser,
) -> Res<(StatusCode, Json<Report>)> {
    user.require(&[Role::UniversityAdmin])?;
    if st.cfg.tsa.is_none() {
        return Err(AppError::Conflict("timestamping is not configured".into()));
    }
    Ok((StatusCode::OK, Json(timestamp_pending(&st).await)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_well_formed_der() {
        let digest = [0xab; 32];
        let req = build_request(&digest, &[0x11; 8]);
        assert_eq!(req.len(), REQ_LEN);
        // The outer SEQUENCE length must match the content that follows it.
        assert_eq!(req[1] as usize, req.len() - 2);
        assert_eq!(request_imprint(&req), Some(digest));
    }

    #[test]
    fn imprint_parser_rejects_other_shapes() {
        let req = build_request(&[1; 32], &[2; 8]);
        assert!(request_imprint(&req[..68]).is_none());
        let mut longer = req.clone();
        longer.push(0);
        assert!(request_imprint(&longer).is_none());
        for i in [0usize, 5, 20, 57, 68] {
            let mut bad = req.clone();
            bad[i] ^= 0xff;
            assert!(request_imprint(&bad).is_none(), "byte {i}");
        }
    }

    #[test]
    fn nonce_is_a_minimal_positive_integer() {
        for _ in 0..1000 {
            let n = new_nonce();
            assert!(n[0] >= 1 && n[0] < 0x80);
        }
    }

    #[test]
    fn openssl_noise_is_skipped_in_error_summaries() {
        let out = "Using configuration from /etc/ssl/openssl.cnf\nVerification: FAILED\nerror:certificate verify failed\nmore\n";
        assert_eq!(
            first_line(out),
            "Verification: FAILED; error:certificate verify failed"
        );
        assert_eq!(first_line("Using configuration from x\n"), "");
    }

    #[test]
    fn reply_text_is_parsed() {
        let text = "Status info:\nStatus: Granted.\n\nTST info:\nVersion: 1\nSerial number: 0x0A1B\nTime stamp: Oct  5 12:00:09 2026 GMT\nAccuracy: unspecified\n";
        let s = parse_reply_text(text).unwrap();
        assert_eq!(s.serial, "0x0A1B");
        assert_eq!(s.gen_time.to_rfc3339(), "2026-10-05T12:00:09+00:00");
        let frac = text.replace("12:00:09", "12:00:09.250");
        assert_eq!(
            parse_reply_text(&frac).unwrap().gen_time.timestamp(),
            s.gen_time.timestamp()
        );
        assert!(parse_reply_text("Status: Granted.").is_err());
        assert!(parse_reply_text("Serial number: 1\nTime stamp: yesterday").is_err());
    }
}
