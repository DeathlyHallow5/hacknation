//! Module 1 — input normalization (PROJECT.md §3.1).
//! Manual entries and CSV/JSON imports all go through `normalize` so they are handled identically.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "target_kind", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Ip,
    Cidr,
    Domain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Target {
    pub kind: TargetKind,
    /// Canonical value: `10.0.0.5`, `10.0.0.0/24`, `example.com`.
    pub value: String,
}

impl Target {
    /// Number of addresses this target expands to (domains count as one).
    pub fn address_count(&self) -> u128 {
        match self.kind {
            TargetKind::Cidr => {
                let net: IpNet = self.value.parse().expect("canonical CIDR");
                1u128 << (net.max_prefix_len() - net.prefix_len())
            }
            _ => 1,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InputError {
    #[error("empty value")]
    Empty,
    #[error("invalid IP, CIDR or domain: {0}")]
    Invalid(String),
    #[error("prefix /{0} is too broad (minimum allowed is /{1})")]
    TooBroad(u8, u8),
}

/// Smallest IPv4 prefix we accept in one entry (/8 = 16.7M addresses). Keeps typos like
/// `0.0.0.0/0` from turning into an internet-wide scan.
const MIN_V4_PREFIX: u8 = 8;
const MIN_V6_PREFIX: u8 = 64;

pub fn normalize(raw: &str) -> Result<Target, InputError> {
    let s = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() {
        return Err(InputError::Empty);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(Target { kind: TargetKind::Ip, value: ip.to_string() });
    }
    if let Ok(net) = s.parse::<IpNet>() {
        let min = if net.addr().is_ipv4() { MIN_V4_PREFIX } else { MIN_V6_PREFIX };
        if net.prefix_len() < min {
            return Err(InputError::TooBroad(net.prefix_len(), min));
        }
        let net = net.trunc(); // 10.0.0.7/24 -> 10.0.0.0/24
        if net.prefix_len() == net.max_prefix_len() {
            return Ok(Target { kind: TargetKind::Ip, value: net.addr().to_string() });
        }
        return Ok(Target { kind: TargetKind::Cidr, value: net.to_string() });
    }
    if is_domain(&s) {
        return Ok(Target { kind: TargetKind::Domain, value: s });
    }
    Err(InputError::Invalid(raw.trim().to_string()))
}

fn is_domain(s: &str) -> bool {
    if s.len() > 253 || !s.contains('.') {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }) && !s.rsplit('.').next().unwrap().chars().all(|c| c.is_ascii_digit())
}

/// Parse a CSV/plain-text list (one target per line, first column, `#` comments allowed).
pub fn parse_list(text: &str) -> (Vec<Target>, Vec<(usize, InputError)>) {
    let mut ok = Vec::new();
    let mut errors = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let first = line.split([',', ';', '\t']).next().unwrap_or("").trim();
        if first.is_empty() || first.starts_with('#') {
            continue;
        }
        match normalize(first) {
            Ok(t) if !ok.contains(&t) => ok.push(t),
            Ok(_) => {}
            Err(e) => errors.push((i + 1, e)),
        }
    }
    (ok, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_and_cidr_are_canonical() {
        assert_eq!(normalize(" 10.0.0.5 ").unwrap().kind, TargetKind::Ip);
        let t = normalize("10.0.0.7/24").unwrap();
        assert_eq!((&t.kind, t.value.as_str()), (&TargetKind::Cidr, "10.0.0.0/24"));
        assert_eq!(t.address_count(), 256);
        assert_eq!(normalize("10.0.0.5/32").unwrap().kind, TargetKind::Ip);
    }

    #[test]
    fn domains() {
        assert_eq!(normalize("Example.COM.").unwrap().value, "example.com");
        assert!(normalize("-bad.example.com").is_err());
        assert!(normalize("localhost").is_err());
        assert!(normalize("1.2.3.999").is_err());
    }

    #[test]
    fn rejects_internet_wide_ranges() {
        assert_eq!(normalize("0.0.0.0/0"), Err(InputError::TooBroad(0, 8)));
    }

    #[test]
    fn list_dedups_and_reports_lines() {
        let (ok, err) = parse_list("# header\n10.0.0.1,web\n10.0.0.1\nfoo..bar\nexample.org");
        assert_eq!(ok.len(), 2);
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].0, 4);
    }
}
