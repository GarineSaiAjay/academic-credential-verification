use std::{env, path::PathBuf, time::Duration};

use crate::crypto::KeyRing;

/// External RFC 3161 time-stamping authority that every sealed block is anchored to.
#[derive(Clone)]
pub struct TsaConfig {
    pub url: String,
    /// PEM file with the root certificate(s) the TSA's signing certificate must chain to.
    pub ca_file: PathBuf,
    pub interval: Duration,
    pub timeout: Duration,
}

/// How browsers identify this site to authenticators (WebAuthn relying party).
#[derive(Clone)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub origin: String,
}

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    /// ENCRYPTION_KEY (current) plus ENCRYPTION_KEY_PREVIOUS (still readable during a rotation).
    pub enc_key: KeyRing,
    pub bind: String,
    pub public_base_url: String,
    pub trust_proxy: bool,
    pub seed_password: Option<String>,
    pub bootstrap_admin: Option<(String, String)>,
    pub tsa: Option<TsaConfig>,
    pub webauthn: WebAuthnConfig,
    /// Every approval must carry the approver's personal (WebAuthn) countersignature.
    pub require_personal: bool,
    /// Even a person's first key needs an administrator to open the enrolment window.
    pub require_admin_enrollment: bool,
}

fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

fn seconds(name: &str, default: u64, min: u64, max: u64) -> Result<u64, String> {
    match optional(name) {
        None => Ok(default),
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|n| (min..=max).contains(n))
            .ok_or_else(|| format!("{name} must be a number of seconds between {min} and {max}")),
    }
}

/// Origin and relying-party id from the public URL; WEBAUTHN_RP_ID may widen the id to a parent domain.
fn webauthn_config(
    public_base_url: &str,
    rp_override: Option<String>,
) -> Result<WebAuthnConfig, String> {
    let (scheme, rest) = public_base_url
        .split_once("://")
        .filter(|(s, _)| matches!(*s, "http" | "https"))
        .ok_or("PUBLIC_BASE_URL must start with http:// or https://")?;
    let host_port = rest.split('/').next().unwrap_or("");
    let host = host_port.rsplit_once(':').map_or(host_port, |(h, _)| h);
    if host.is_empty() {
        return Err("PUBLIC_BASE_URL has no host".into());
    }
    let rp_id = rp_override.unwrap_or_else(|| host.to_string());
    if !(host == rp_id || host.ends_with(&format!(".{rp_id}"))) {
        return Err(
            "WEBAUTHN_RP_ID must be the host of PUBLIC_BASE_URL or a parent domain of it".into(),
        );
    }
    Ok(WebAuthnConfig {
        rp_id,
        origin: format!("{scheme}://{host_port}"),
    })
}

fn parse_key(name: &str, hex_key: &str) -> Result<[u8; 32], String> {
    hex::decode(hex_key)
        .map_err(|_| format!("{name} must be hex"))?
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes (64 hex chars)"))
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} must be set"))
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let jwt_secret = required("JWT_SECRET")?;
        if jwt_secret.len() < 32 {
            return Err("JWT_SECRET must be at least 32 characters".into());
        }
        let current = parse_key("ENCRYPTION_KEY", &required("ENCRYPTION_KEY")?)?;
        let mut previous = vec![];
        for (i, part) in optional("ENCRYPTION_KEY_PREVIOUS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .enumerate()
        {
            let key = parse_key("ENCRYPTION_KEY_PREVIOUS", part)?;
            if key == current || previous.contains(&key) {
                return Err(format!(
                    "ENCRYPTION_KEY_PREVIOUS entry {} repeats another key",
                    i + 1
                ));
            }
            previous.push(key);
        }
        if previous.len() > 4 {
            return Err("ENCRYPTION_KEY_PREVIOUS may list at most 4 keys".into());
        }
        let enc_key = KeyRing::new(current, previous);
        let bootstrap_admin = match (
            optional("BOOTSTRAP_ADMIN_EMAIL"),
            optional("BOOTSTRAP_ADMIN_PASSWORD"),
        ) {
            (Some(email), Some(password)) => Some((email, password)),
            (None, None) => None,
            _ => {
                return Err(
                    "BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD must be set together"
                        .into(),
                )
            }
        };
        let tsa = match (optional("TSA_URL"), optional("TSA_CA_FILE")) {
            (Some(url), Some(ca_file)) => {
                if !(url.starts_with("https://") || url.starts_with("http://")) {
                    return Err("TSA_URL must start with https:// or http://".into());
                }
                Some(TsaConfig {
                    url,
                    ca_file: PathBuf::from(ca_file),
                    interval: Duration::from_secs(seconds("TSA_INTERVAL_SECS", 300, 10, 86_400)?),
                    timeout: Duration::from_secs(seconds("TSA_TIMEOUT_SECS", 15, 1, 120)?),
                })
            }
            (None, None) => None,
            _ => return Err("TSA_URL and TSA_CA_FILE must be set together".into()),
        };
        let public_base_url = env::var("PUBLIC_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:3000".into())
            .trim_end_matches('/')
            .to_string();
        let webauthn = webauthn_config(&public_base_url, optional("WEBAUTHN_RP_ID"))?;
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            jwt_secret,
            enc_key,
            bind: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8000".into()),
            public_base_url,
            trust_proxy: env::var("TRUST_PROXY")
                .map(|v| v == "true")
                .unwrap_or(false),
            seed_password: optional("SEED_DEMO_PASSWORD"),
            bootstrap_admin,
            tsa,
            webauthn,
            require_personal: optional("REQUIRE_PERSONAL_SIGNATURES").is_some_and(|v| v == "true"),
            require_admin_enrollment: optional("REQUIRE_ADMIN_ENROLLMENT")
                .is_some_and(|v| v == "true"),
        })
    }
}
