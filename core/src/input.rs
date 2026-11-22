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

    /// Scan inputs `from..from+n` of this target, computed arithmetically (O(n), not
    /// O(from)): same order as `IpNet::hosts`, i.e. IPv4 network/broadcast skipped.
    fn hosts_range(&self, from: u128, n: usize) -> Vec<String> {
        match self.kind {
            TargetKind::Cidr => {
                let net: IpNet = self.value.parse().expect("canonical CIDR");
                let first = match net {
                    IpNet::V4(v4) if v4.prefix_len() < 31 => u32::from(v4.network()) as u128 + 1,
                    IpNet::V4(v4) => u32::from(v4.network()) as u128,
                    IpNet::V6(v6) => u128::from(v6.network()),
                };
                let end = (from + n as u128).min(self.host_count());
                (from..end)
                    .map(|i| match net {
                        IpNet::V4(_) => std::net::Ipv4Addr::from((first + i) as u32).to_string(),
                        IpNet::V6(_) => std::net::Ipv6Addr::from(first + i).to_string(),
                    })
                    .collect()
            }
            _ if from == 0 && n > 0 => vec![self.value.clone()],
            _ => Vec::new(),
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
        out.extend(t.hosts_range(skip, size - out.len()));
        skip = 0;
        if out.len() == size {
            break;
        }
    }
    out
}

/// Is this observed host covered by the target list? (Used so hosts of targets removed
/// from a scan are not reported as "gone".)
pub fn contains(targets: &[Target], ip: &str, hostname: Option<&str>) -> bool {
    let addr: Option<std::net::IpAddr> = ip.parse().ok();
    targets.iter().any(|t| match t.kind {
        TargetKind::Ip => t.value == ip,
        TargetKind::Cidr => match (t.value.parse::<IpNet>(), addr) {
            (Ok(net), Some(a)) => net.contains(&a),
            _ => false,
        },
        TargetKind::Domain => hostname == Some(t.value.as_str()),
    })
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

/// Smallest prefix we accept in one entry (/8 and IPv6 /104 = 16.7M addresses). Keeps typos
/// like `0.0.0.0/0` from turning into an internet-wide scan.
const MIN_V4_PREFIX: u8 = 8;
const MIN_V6_PREFIX: u8 = 104;
/// Upper bound on scan inputs in one scan (sum over its targets).
pub const MAX_SCAN_HOSTS: u128 = 1 << 24;

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
        // /8 = 16.7M hosts: the last batch is computed, not reached by iterating.
        let t = vec![normalize("10.0.0.0/8").unwrap()];
        let started = std::time::Instant::now();
        let last = slice(&t, total_hosts(&t) - 2, 256);
        assert_eq!(last, ["10.255.255.253", "10.255.255.254"]);
        assert!(started.elapsed() < std::time::Duration::from_millis(50));
    }

    #[test]
    fn arithmetic_slice_matches_ipnet_hosts() {
        for cidr in ["10.0.0.0/29", "10.0.0.0/31", "192.168.1.0/24", "fd00::/124", "fd00::/127"] {
            let t = normalize(cidr).unwrap();
            let net: IpNet = t.value.parse().unwrap();
            let expected: Vec<String> = net.hosts().map(|ip| ip.to_string()).collect();
            assert_eq!(expected.len() as u128, t.host_count(), "{cidr}");
            let got: Vec<String> = (0..expected.len()).step_by(3).flat_map(|i| slice(std::slice::from_ref(&t), i as u128, 3)).collect();
            assert_eq!(got, expected, "{cidr}");
        }
    }

    #[test]
    fn rejects_huge_ipv6() {
        assert_eq!(normalize("fd00::/64"), Err(InputError::TooBroad(64, 104)));
    }
}
