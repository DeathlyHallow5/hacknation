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
    pub global_rate: u32,
    pub allowed_ports: std::collections::BTreeSet<u16>,
    pub excluded_cidrs: Vec<ipnet::Ipv4Net>,
    pub allowed_origins: Vec<String>,
    pub allowed_cidrs: Vec<ipnet::Ipv4Net>,
    pub defectdojo_url: Option<String>,
    pub defectdojo_token: Option<String>,
    /// Session lifetime (PROJECT.md §10).
    pub session_ttl_hours: i64,
    /// Mark the session cookie `Secure` (set when served over HTTPS).
    pub cookie_secure: bool,
    /// First admin, created at startup only while no active admin exists.
    pub admin_user: String,
    pub admin_password: Option<String>,
    /// `ASI_SYN_SCAN=1`: SYN (half-open) port discovery with `naabu-raw`. Needs the
    /// `compose.syn.yaml` overrides; checked at startup and switched off if they are missing.
    pub syn_scan: Option<std::path::PathBuf>,
}

fn secret(name: &str) -> Result<Option<String>> {
    let file_key = format!("{name}_FILE");
    if let Some(path) = std::env::var_os(&file_key) {
        let value = std::fs::read_to_string(path).with_context(|| format!("cannot read {file_key}"))?;
        let value = value.trim_end_matches(['\r', '\n']);
        anyhow::ensure!(!value.is_empty(), "{file_key} is empty");
        return Ok(Some(value.to_owned()));
    }
    Ok(std::env::var(name).ok().filter(|s| !s.is_empty()))
}

impl Config {
    pub fn permits_ports(&self, spec: &str) -> bool {
        !matches!(spec, "full" | "100" | "1000") && spec.split(',').all(|part| {
            let (a,b) = part.split_once('-').unwrap_or((part,part));
            match (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                (Ok(a),Ok(b)) => a > 0 && a <= b && (a..=b).all(|port| self.allowed_ports.contains(&port)),
                _ => false,
            }
        })
    }

    pub fn permits_target(&self, target: &str) -> bool {
        use ipnet::Ipv4Net;
        use std::net::Ipv4Addr;
        let Some(net) = target.parse::<Ipv4Net>().ok().or_else(|| target.parse::<Ipv4Addr>().ok().map(Ipv4Net::from)) else { return false };
        let prohibited = ["0.0.0.0/8","127.0.0.0/8","169.254.0.0/16","224.0.0.0/4","240.0.0.0/4"];
        self.allowed_cidrs.iter().any(|allow| allow.contains(&net))
            && !self.excluded_cidrs.iter().any(|deny| deny.contains(&net) || net.contains(deny))
            && !prohibited.iter().map(|s| s.parse::<Ipv4Net>().expect("static network")).any(|deny| deny.contains(&net) || net.contains(&deny))
    }

    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: secret("DATABASE_URL")?.context("DATABASE_URL is not set")?,
            bind_addr: std::env::var("ASI_BIND").unwrap_or_else(|_| "0.0.0.0:8000".into()),
            data_key: secret("ASI_DATA_KEY")?.context("ASI_DATA_KEY is not set")?,
            tools_dir: std::env::var("ASI_TOOLS_DIR").unwrap_or_else(|_| "/opt/asi-tools".into()),
            max_concurrency: std::env::var("ASI_MAX_CONCURRENCY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(256),
            global_rate: std::env::var("ASI_GLOBAL_PPS").unwrap_or_else(|_| "1000".into()).parse::<std::num::NonZeroU32>().context("invalid ASI_GLOBAL_PPS")?.get(),
            max_runs: std::env::var("ASI_MAX_RUNS").ok().and_then(|v| v.parse().ok()).unwrap_or(1),
            allowed_ports: std::env::var("ASI_ALLOWED_PORTS").unwrap_or_default().split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::parse).collect::<Result<_,_>>().context("invalid ASI_ALLOWED_PORTS")?,
            allowed_origins: std::env::var("ASI_ALLOWED_ORIGINS").unwrap_or_else(|_| "http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3001".into()).split(',').map(|s| s.trim().to_owned()).collect(),
            excluded_cidrs: std::env::var("ASI_EXCLUDED_CIDRS").unwrap_or_default().split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::parse).collect::<Result<_,_>>().context("invalid ASI_EXCLUDED_CIDRS")?,
            allowed_cidrs: std::env::var("ASI_ALLOWED_CIDRS").unwrap_or_default().split(',').map(str::trim).filter(|v| !v.is_empty()).map(str::parse).collect::<Result<_, _>>().context("invalid ASI_ALLOWED_CIDRS")?,
            defectdojo_url: std::env::var("DEFECTDOJO_URL").ok().filter(|v| !v.is_empty()),
            defectdojo_token: secret("DEFECTDOJO_TOKEN")?,
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
            admin_password: secret("ASI_ADMIN_PASSWORD")?,
            syn_scan: None,
        }
        .with_syn_scan())
    }

    fn with_syn_scan(mut self) -> Self {
        if std::env::var("ASI_SYN_SCAN").is_ok_and(|v| matches!(v.as_str(), "true" | "1")) {
            match crate::engine::raw_naabu(&self.tools_dir) {
                Ok(bin) => {
                    tracing::info!("port discovery: SYN scan ({})", bin.display());
                    self.syn_scan = Some(bin);
                }
                Err(why) => tracing::warn!("ASI_SYN_SCAN is set but SYN scan is unavailable ({why}); using CONNECT scan"),
            }
        }
        self
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
            global_rate: 1000,
            excluded_cidrs: Vec::new(),
            allowed_origins: Vec::new(),
            allowed_ports: [80,443].into_iter().collect(),
            allowed_cidrs: Vec::new(),
            defectdojo_url: None,
            defectdojo_token: None,
            session_ttl_hours: 12,
            cookie_secure: false,
            admin_user: "admin".into(),
            admin_password: None,
            syn_scan: None,
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

#[cfg(test)]
mod scope_tests {
    use super::*;
    #[test]
    fn network_boundaries() {
        let mut cfg = Config::for_tests();
        assert!(!cfg.permits_target("172.30.0.10"));
        cfg.allowed_cidrs.push("172.30.0.0/24".parse().unwrap());
        assert!(cfg.permits_target("172.30.0.10"));
        assert!(cfg.permits_target("172.30.0.0/25"));
        assert!(!cfg.permits_target("172.30.0.0/23"));
        assert!(!cfg.permits_target("example.com"));
        cfg.allowed_cidrs.push("0.0.0.0/0".parse().unwrap());
        for forbidden in ["127.0.0.1","169.254.169.254","224.0.0.1","127.0.0.0/7","::1"] {
            assert!(!cfg.permits_target(forbidden));
        }
    }
}
