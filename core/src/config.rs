//! Runtime configuration from environment variables (see `.env.example`).

use anyhow::{Context, Result};

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    /// Symmetric key for pgp_sym_encrypt (Encryption at Rest). Never stored in the DB.
    pub data_key: String,
    /// Directory with nmap / ProjectDiscovery binaries.
    pub tools_dir: String,
    /// Worker threads handed to naabu/httpx (capped at 100).
    pub max_concurrency: usize,
    /// Scan runs executing at the same time. Total rate ≈ max_runs × rate_limit_pps.
    /// 0 = this instance starts no runs (API only).
    pub max_runs: usize,
    pub defectdojo_url: Option<String>,
    pub defectdojo_token: Option<String>,
    /// Session lifetime (PROJECT.md §10).
    pub session_ttl_hours: i64,
    /// Mark the session cookie `Secure` (set when served over HTTPS).
    pub cookie_secure: bool,
    /// First admin, created at startup only while no active admin exists.
    pub admin_user: String,
    pub admin_password: Option<String>,
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
            max_runs: std::env::var("ASI_MAX_RUNS").ok().and_then(|v| v.parse().ok()).unwrap_or(2),
            defectdojo_url: std::env::var("DEFECTDOJO_URL").ok().filter(|v| !v.is_empty()),
            defectdojo_token: std::env::var("DEFECTDOJO_TOKEN").ok().filter(|v| !v.is_empty()),
            session_ttl_hours: std::env::var("ASI_SESSION_TTL_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|h| (1..=720).contains(h))
                .unwrap_or(12),
            cookie_secure: std::env::var("ASI_COOKIE_SECURE").is_ok_and(|v| matches!(v.as_str(), "true" | "1")),
            admin_user: std::env::var("ASI_ADMIN_USER")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "admin".into()),
            admin_password: std::env::var("ASI_ADMIN_PASSWORD").ok().filter(|v| !v.is_empty()),
        })
    }

    /// Settings for unit tests: no environment, nothing reachable.
    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self {
            database_url: String::new(),
            bind_addr: String::new(),
            data_key: "test-only".into(),
            tools_dir: "/nonexistent".into(),
            max_concurrency: 1,
            max_runs: 0,
            defectdojo_url: None,
            defectdojo_token: None,
            session_ttl_hours: 12,
            cookie_secure: false,
            admin_user: "admin".into(),
            admin_password: None,
        }
    }
}

/// Secrets never reach logs, even through `{:?}`.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hidden = |set: bool| if set { "<redacted>" } else { "<unset>" };
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("bind_addr", &self.bind_addr)
            .field("data_key", &hidden(!self.data_key.is_empty()))
            .field("tools_dir", &self.tools_dir)
            .field("max_concurrency", &self.max_concurrency)
            .field("max_runs", &self.max_runs)
            .field("defectdojo_url", &self.defectdojo_url)
            .field("defectdojo_token", &hidden(self.defectdojo_token.is_some()))
            .field("session_ttl_hours", &self.session_ttl_hours)
            .field("cookie_secure", &self.cookie_secure)
            .field("admin_user", &self.admin_user)
            .field("admin_password", &hidden(self.admin_password.is_some()))
            .finish()
    }
}
