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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Number of scannable hosts (IPv4 network/broadcast excluded, like `IpNet::hosts`).
    pub fn host_count(&self) -> u128 {
        match self.kind {
            TargetKind::Cidr => {
                let net: IpNet = self.value.parse().expect("canonical CIDR");
                let n = self.address_count();
                if net.addr().is_ipv4() && net.prefix_len() < 31 { n - 2 } else { n }
            }
            _ => 1,
        }
    }

    /// Lazily expand to scan inputs: IPs for ip/cidr, the name itself for domains.
    pub fn hosts(&self) -> Box<dyn Iterator<Item = String> + Send + '_> {
        match self.kind {
            TargetKind::Cidr => {
                let net: IpNet = self.value.parse().expect("canonical CIDR");
                Box::new(net.hosts().map(|ip| ip.to_string()))
            }
            _ => Box::new(std::iter::once(self.value.clone())),
        }
    }
}

/// Test helper: fixed-size batch number `index` (0-based).
#[cfg(test)]
pub fn batch(targets: &[Target], index: usize, size: usize) -> Vec<String> {
    slice(targets, (index * size) as u128, size)
}

/// Up to `size` scan inputs starting at `offset` across all targets, in order.
/// Deterministic for a given target list, so an offset checkpoint can resume a run.
pub fn slice(targets: &[Target], offset: u128, size: usize) -> Vec<String> {
    let mut skip = offset;
    let mut out = Vec::with_capacity(size);
    for t in targets {
        let count = t.host_count();
        if skip >= count {
            skip -= count; // jump over whole targets without iterating them
            continue;
        }
        out.extend(t.hosts().skip(skip as usize).take(size - out.len()));
        skip = 0;
        if out.len() == size {
            break;
        }
    }
    out
}

pub fn total_hosts(targets: &[Target]) -> u128 {
    targets.iter().map(Target::host_count).sum()
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
    fn batches_cover_all_hosts_once() {
        let targets = vec![
            normalize("10.0.0.0/30").unwrap(), // 2 hosts
            normalize("example.com").unwrap(), // 1
            normalize("10.1.0.0/29").unwrap(), // 6 hosts
        ];
        assert_eq!(total_hosts(&targets), 9);
        let all: Vec<String> = (0..4).flat_map(|i| batch(&targets, i, 4)).collect();
        assert_eq!(all.len(), 9);
        assert_eq!(&all[..3], ["10.0.0.1", "10.0.0.2", "example.com"]);
        assert_eq!(batch(&targets, 1, 4), ["10.1.0.2", "10.1.0.3", "10.1.0.4", "10.1.0.5"]);
        assert!(batch(&targets, 3, 4).is_empty());
    }

    #[test]
    fn large_range_batch_is_cheap() {
        // /12 = ~1M hosts: fetching a late batch must not materialize the range.
        let t = vec![normalize("10.16.0.0/12").unwrap()];
        assert_eq!(batch(&t, 4000, 256).len(), 256);
    }

    #[test]
    fn list_dedups_and_reports_lines() {
        let (ok, err) = parse_list("# header\n10.0.0.1,web\n10.0.0.1\nfoo..bar\nexample.org");
        assert_eq!(ok.len(), 2);
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].0, 4);
    }
}
