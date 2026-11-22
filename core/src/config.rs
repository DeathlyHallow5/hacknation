//! Runtime configuration from environment variables (see `.env.example`).

use anyhow::{Context, Result};

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    /// Symmetric key for pgp_sym_encrypt (Encryption at Rest). Never stored in the DB.
    pub data_key: String,
    /// `ASI_DATA_KEY_PREVIOUS`: the key being rotated out. Reads fall back to it (`asi_decrypt`)
    /// until `POST /api/v1/security/encryption/rotate` has re-encrypted every row (keyring.rs).
    pub data_key_previous: Option<String>,
    /// `ASI_TRUSTED_PROXIES` (IPs/CIDRs): peers whose `X-Forwarded-For` names the client — the
    /// dashboard container. Every other peer is the client itself (`auth::client_ip`).
    pub trusted_proxies: Vec<ipnet::IpNet>,
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
    /// `ASI_ALLOWED_DOMAINS`: DNS names (and their subdomains) that may be scan targets; each
    /// must still resolve only into `allowed_cidrs` when scanned (`resolve_in_scope`).
    pub allowed_domains: Vec<String>,
    /// DNS servers for naabu, which otherwise asks public resolvers the core cannot reach:
    /// `ASI_DNS_RESOLVERS`, else the container's own (`/etc/resolv.conf`, Docker's 127.0.0.11).
    pub dns_resolvers: Option<String>,
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

    /// An approved DNS name: an `ASI_ALLOWED_DOMAINS` entry or a subdomain of one.
    pub fn permits_domain(&self, name: &str) -> bool {
        let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let valid = !n.is_empty()
            && n.len() <= 253
            && n.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') && !l.starts_with('-') && !l.ends_with('-'));
        valid && self.allowed_domains.iter().any(|d| n == *d || n.ends_with(&format!(".{d}")))
    }

    /// Resolve an approved name and check every IPv4 address it points to is itself approved
    /// (a name cannot lead the scanner outside the allowlist). Checked again before each batch.
    pub async fn resolve_in_scope(&self, name: &str) -> std::result::Result<Vec<std::net::Ipv4Addr>, String> {
        if !self.permits_domain(name) {
            return Err(format!("domena {name} nie jest na liście ASI_ALLOWED_DOMAINS"));
        }
        let lookup = tokio::time::timeout(std::time::Duration::from_secs(5), tokio::net::lookup_host((name, 0)))
            .await
            .map_err(|_| format!("{name}: DNS nie odpowiedział w 5 s"))?
            .map_err(|e| format!("{name}: nie można rozwiązać nazwy ({e})"))?;
        let mut ips: Vec<std::net::Ipv4Addr> = lookup
            .filter_map(|a| match a.ip() {
                std::net::IpAddr::V4(v) => Some(v),
                std::net::IpAddr::V6(_) => None,
            })
            .collect();
        ips.sort();
        ips.dedup();
        if ips.is_empty() {
            return Err(format!("{name}: brak adresu IPv4"));
        }
        if let Some(bad) = ips.iter().find(|ip| !self.permits_target(&ip.to_string())) {
            return Err(format!("{name} wskazuje na {bad} — poza zakresem zatwierdzonym przez administratora (ASI_ALLOWED_CIDRS)"));
        }
        Ok(ips)
    }

    pub fn permits_target(&self, target: &str) -> bool {
        use ipnet::Ipv4Net;
        use std::net::Ipv4Addr;
        let Some(net) = target.parse::<Ipv4Net>().ok().or_else(|| target.parse::<Ipv4Addr>().ok().map(Ipv4Net::from)) else {
            return self.permits_domain(target);
        };
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
            data_key_previous: secret("ASI_DATA_KEY_PREVIOUS")?,
            trusted_proxies: parse_nets(&std::env::var("ASI_TRUSTED_PROXIES").unwrap_or_default()).context("invalid ASI_TRUSTED_PROXIES")?,
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
            dns_resolvers: dns_resolvers(),
            allowed_domains: std::env::var("ASI_ALLOWED_DOMAINS")
                .unwrap_or_default()
                .split(',')
                .map(|d| d.trim().trim_start_matches("*.").trim_matches('.').to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
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
        .with_syn_scan()
        .with_previous_key())
    }

    /// A previous key equal to the current one is no previous key.
    fn with_previous_key(mut self) -> Self {
        if self.data_key_previous.as_deref() == Some(self.data_key.as_str()) {
            tracing::warn!("ASI_DATA_KEY_PREVIOUS equals ASI_DATA_KEY: ignored");
            self.data_key_previous = None;
        }
        self
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
            data_key_previous: None,
            trusted_proxies: Vec::new(),
            tools_dir: "/nonexistent".into(),
            max_concurrency: 1,
            max_runs: 0,
            global_rate: 1000,
            excluded_cidrs: Vec::new(),
            allowed_origins: Vec::new(),
            allowed_ports: [80,443].into_iter().collect(),
            allowed_cidrs: Vec::new(),
            allowed_domains: Vec::new(),
            dns_resolvers: None,
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
            .field("data_key_previous", &hidden(self.data_key_previous.is_some()))
            .field("trusted_proxies", &self.trusted_proxies)
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

/// Comma-separated IPv4/IPv6 addresses or CIDRs (a bare address is a /32 or /128).
pub(crate) fn parse_nets(spec: &str) -> Result<Vec<ipnet::IpNet>> {
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<ipnet::IpNet>()
                .or_else(|_| s.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                .map(|n| n.trunc())
                .with_context(|| format!("not an IP address or CIDR: {s}"))
        })
        .collect()
}

/// `ASI_DNS_RESOLVERS` (comma-separated ip[:port]), else the nameservers of /etc/resolv.conf.
fn dns_resolvers() -> Option<String> {
    let list: Vec<String> = match std::env::var("ASI_DNS_RESOLVERS").ok().filter(|v| !v.trim().is_empty()) {
        Some(v) => v.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect(),
        None => std::fs::read_to_string("/etc/resolv.conf")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().strip_prefix("nameserver"))
            .map(str::trim)
            .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
            .map(|ip| if ip.contains(':') { format!("[{ip}]:53") } else { format!("{ip}:53") })
            .collect(),
    };
    (!list.is_empty()).then(|| list.join(","))
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    #[test]
    fn trusted_proxy_lists() {
        let n = parse_nets(" 10.231.70.250, 172.18.0.0/16 ,fd00::1,").unwrap();
        assert_eq!(n.iter().map(ToString::to_string).collect::<Vec<_>>(), ["10.231.70.250/32", "172.18.0.0/16", "fd00::1/128"]);
        assert_eq!(parse_nets("10.0.0.7/8").unwrap()[0].to_string(), "10.0.0.0/8", "host bits dropped");
        assert!(parse_nets("").unwrap().is_empty());
        for bad in ["web", "10.0.0.0/33", "1.2.3.4:80", "*"] {
            assert!(parse_nets(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn network_boundaries() {
        let mut cfg = Config::for_tests();
        assert!(!cfg.permits_target("172.30.0.10"));
        cfg.allowed_cidrs.push("172.30.0.0/24".parse().unwrap());
        assert!(cfg.permits_target("172.30.0.10"));
        assert!(cfg.permits_target("172.30.0.0/25"));
        assert!(!cfg.permits_target("172.30.0.0/23"));
        assert!(!cfg.permits_target("example.com"));
        cfg.allowed_domains.push("asi.test".into());
        assert!(cfg.permits_target("www.asi.test") && cfg.permits_target("ASI.test") && cfg.permits_target("a.b.asi.test"));
        assert!(!cfg.permits_target("evilasi.test") && !cfg.permits_target("asi.test.evil.com") && !cfg.permits_target("-x.asi.test"));
        cfg.allowed_cidrs.push("0.0.0.0/0".parse().unwrap());
        for forbidden in ["127.0.0.1","169.254.169.254","224.0.0.1","127.0.0.0/7","::1"] {
            assert!(!cfg.permits_target(forbidden));
        }
    }
}
