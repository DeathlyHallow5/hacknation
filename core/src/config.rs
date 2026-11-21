//! Runtime configuration from environment variables (see `.env.example`).

use anyhow::{Context, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    /// Symmetric key for pgp_sym_encrypt (Encryption at Rest). Never stored in the DB.
    pub data_key: String,
    /// Directory with nmap / ProjectDiscovery binaries.
    pub tools_dir: String,
    /// Upper bound of concurrent host probes across all scans.
    pub max_concurrency: usize,
    pub defectdojo_url: Option<String>,
    pub defectdojo_token: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL is not set")?,
            bind_addr: std::env::var("ASI_BIND").unwrap_or_else(|_| "0.0.0.0:8000".into()),
            data_key: std::env::var("ASI_DATA_KEY").context("ASI_DATA_KEY is not set")?,
            tools_dir: std::env::var("ASI_TOOLS_DIR").unwrap_or_else(|_| "/opt/asi-tools".into()),
            max_concurrency: std::env::var("ASI_MAX_CONCURRENCY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(256),
            defectdojo_url: std::env::var("DEFECTDOJO_URL").ok().filter(|v| !v.is_empty()),
            defectdojo_token: std::env::var("DEFECTDOJO_TOKEN").ok().filter(|v| !v.is_empty()),
        })
    }
}
