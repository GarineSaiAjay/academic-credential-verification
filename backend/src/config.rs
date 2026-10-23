use std::{env, path::PathBuf, time::Duration};

/// External RFC 3161 time-stamping authority that every sealed block is anchored to.
#[derive(Clone)]
pub struct TsaConfig {
    pub url: String,
    /// PEM file with the root certificate(s) the TSA's signing certificate must chain to.
    pub ca_file: PathBuf,
    pub interval: Duration,
    pub timeout: Duration,
}

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub enc_key: [u8; 32],
    pub bind: String,
    pub public_base_url: String,
    pub trust_proxy: bool,
    pub seed_password: Option<String>,
    pub bootstrap_admin: Option<(String, String)>,
    pub tsa: Option<TsaConfig>,
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

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} must be set"))
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let jwt_secret = required("JWT_SECRET")?;
        if jwt_secret.len() < 32 {
            return Err("JWT_SECRET must be at least 32 characters".into());
        }
        let enc_key: [u8; 32] = hex::decode(required("ENCRYPTION_KEY")?)
            .map_err(|_| "ENCRYPTION_KEY must be hex".to_string())?
            .try_into()
            .map_err(|_| "ENCRYPTION_KEY must be 32 bytes (64 hex chars)".to_string())?;
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
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            jwt_secret,
            enc_key,
            bind: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8000".into()),
            public_base_url: env::var("PUBLIC_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:3000".into())
                .trim_end_matches('/')
                .to_string(),
            trust_proxy: env::var("TRUST_PROXY")
                .map(|v| v == "true")
                .unwrap_or(false),
            seed_password: optional("SEED_DEMO_PASSWORD"),
            bootstrap_admin,
            tsa,
        })
    }
}
