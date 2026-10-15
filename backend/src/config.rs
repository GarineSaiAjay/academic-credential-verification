use std::env;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub enc_key: [u8; 32],
    pub bind: String,
    pub public_base_url: String,
    pub trust_proxy: bool,
    pub seed_password: Option<String>,
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
            seed_password: env::var("SEED_DEMO_PASSWORD")
                .ok()
                .filter(|v| !v.is_empty()),
        })
    }
}
