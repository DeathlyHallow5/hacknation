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
    /// Addresses inside this target that are never scanned (canonical IP or CIDR): excluded
    /// targets and `ASI_EXCLUDED_CIDRS`, frozen into the run's target list (`with_exclusions`)
    /// so batch offsets, resume and coverage all see the same address set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub except: Vec<String>,
}

fn ip_number(a: IpAddr) -> u128 {
    match a {
        IpAddr::V4(v4) => u32::from(v4) as u128,
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn number_ip(n: u128, v4: bool) -> String {
    if v4 { std::net::Ipv4Addr::from(n as u32).to_string() } else { std::net::Ipv6Addr::from(n).to_string() }
}

/// An IP or CIDR as a network (an address is its /32 or /128).
pub fn as_net(value: &str) -> Option<IpNet> {
    value.parse::<IpNet>().ok().or_else(|| value.parse::<IpAddr>().ok().map(IpNet::from))
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

    /// First and last scannable host number (IPv4 network/broadcast skipped, like
    /// `IpNet::hosts`) and whether it is IPv4; `None` for domains.
    fn host_bounds(&self) -> Option<(u128, u128, bool)> {
        match self.kind {
            TargetKind::Ip => {
                let a: IpAddr = self.value.parse().ok()?;
                Some((ip_number(a), ip_number(a), a.is_ipv4()))
            }
            TargetKind::Cidr => {
                let net: IpNet = self.value.parse().ok()?;
                let n = self.address_count();
                let (first, count) = match net {
                    IpNet::V4(v4) if v4.prefix_len() < 31 => (u32::from(v4.network()) as u128 + 1, n - 2),
                    IpNet::V4(v4) => (u32::from(v4.network()) as u128, n),
                    IpNet::V6(v6) => (u128::from(v6.network()), n),
                };
                Some((first, first + (count - 1), net.addr().is_ipv4()))
            }
            TargetKind::Domain => None,
        }
    }

    /// Scannable host numbers left after removing `except`: ascending, disjoint, inclusive.
    fn segments(&self) -> Vec<(u128, u128)> {
        let Some((lo, hi, v4)) = self.host_bounds() else {
            return Vec::new();
        };
        let mut cuts: Vec<(u128, u128)> = self
            .except
            .iter()
            .filter_map(|e| as_net(e))
            .filter(|n| n.addr().is_ipv4() == v4)
            .map(|n| (ip_number(n.network()), ip_number(n.broadcast())))
            .collect();
        cuts.sort_unstable();
        let mut out = Vec::new();
        // First host not yet emitted or cut; None once past the end of the address space.
        let mut next = Some(lo);
        for (a, b) in cuts {
            let Some(cur) = next.filter(|c| *c <= hi) else { break };
            if b < cur || a > hi {
                continue;
            }
            if a > cur {
                out.push((cur, a - 1));
            }
            next = b.checked_add(1);
        }
        if let Some(cur) = next.filter(|c| *c <= hi) {
            out.push((cur, hi));
        }
        out
    }

    /// Is this address one of the target's exceptions?
    fn excepts(&self, addr: &IpAddr) -> bool {
        self.except.iter().filter_map(|e| as_net(e)).any(|n| n.contains(addr))
    }

    /// Number of scannable hosts (IPv4 network/broadcast and `except` left out).
    pub fn host_count(&self) -> u128 {
        match self.kind {
            TargetKind::Domain => 1,
            _ => self.segments().iter().map(|(a, b)| b - a + 1).sum(),
        }
    }

    /// Scan inputs `from..from+n` of this target, computed arithmetically (O(n + exceptions),
    /// not O(from)): same order as `IpNet::hosts`, minus the exceptions.
    fn hosts_range(&self, from: u128, n: usize) -> Vec<String> {
        match self.kind {
            TargetKind::Domain if from == 0 && n > 0 => vec![self.value.clone()],
            TargetKind::Domain => Vec::new(),
            _ => {
                let v4 = self.host_bounds().is_some_and(|b| b.2);
                let mut skip = from;
                let mut out = Vec::with_capacity(n.min(1 << 16));
                for (a, b) in self.segments() {
                    if out.len() == n {
                        break;
                    }
                    let len = b - a + 1;
                    if skip >= len {
                        skip -= len;
                        continue;
                    }
                    let take = (len - skip).min((n - out.len()) as u128);
                    out.extend((0..take).map(|i| number_ip(a + skip + i, v4)));
                    skip = 0;
                }
                out
            }
        }
    }
}

/// Attach every excluded network that overlaps an IP/CIDR target to its `except` list
/// (two networks overlap only when one contains the other). Domains are left as they are:
/// their addresses are known only when resolved, and `resolve_in_scope` refuses names that
/// point into `ASI_EXCLUDED_CIDRS`.
pub fn with_exclusions(targets: Vec<Target>, excluded: &[IpNet]) -> Vec<Target> {
    targets
        .into_iter()
        .map(|mut t| {
            let net = if t.kind == TargetKind::Domain { None } else { as_net(&t.value) };
            if let Some(net) = net {
                let mut except: Vec<String> = excluded
                    .iter()
                    .map(IpNet::trunc)
                    .filter(|ex| ex.contains(&net) || net.contains(ex))
                    .map(|ex| if ex.prefix_len() == ex.max_prefix_len() { ex.addr().to_string() } else { ex.to_string() })
                    .collect();
                except.append(&mut t.except);
                except.sort();
                except.dedup();
                t.except = except;
            }
            t
        })
        .collect()
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
/// from a scan are not reported as "gone".) Excluded addresses (`except`) are not covered.
pub fn contains(targets: &[Target], ip: &str, hostname: Option<&str>) -> bool {
    let addr: Option<std::net::IpAddr> = ip.parse().ok();
    targets.iter().any(|t| match t.kind {
        TargetKind::Ip => t.value == ip && addr.is_none_or(|a| !t.excepts(&a)),
        TargetKind::Cidr => match (t.value.parse::<IpNet>(), addr) {
            (Ok(net), Some(a)) => net.contains(&a) && !t.excepts(&a),
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
        return Ok(Target { kind: TargetKind::Ip, value: ip.to_string(), except: Vec::new() });
    }
    if let Ok(net) = s.parse::<IpNet>() {
        let min = if net.addr().is_ipv4() { MIN_V4_PREFIX } else { MIN_V6_PREFIX };
        if net.prefix_len() < min {
            return Err(InputError::TooBroad(net.prefix_len(), min));
        }
        let net = net.trunc(); // 10.0.0.7/24 -> 10.0.0.0/24
        if net.prefix_len() == net.max_prefix_len() {
            return Ok(Target { kind: TargetKind::Ip, value: net.addr().to_string(), except: Vec::new() });
        }
        return Ok(Target { kind: TargetKind::Cidr, value: net.to_string(), except: Vec::new() });
    }
    if is_domain(&s) {
        return Ok(Target { kind: TargetKind::Domain, value: s, except: Vec::new() });
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

    fn nets(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|v| as_net(v).unwrap()).collect()
    }

    #[test]
    fn excluded_ip_inside_scanned_cidr_is_never_batched() {
        let t = with_exclusions(vec![normalize("172.30.0.0/28").unwrap()], &nets(&["172.30.0.11"]));
        assert_eq!(t[0].except, ["172.30.0.11"]);
        assert_eq!(total_hosts(&t), 13);
        for size in 1..=14 {
            let all: Vec<String> = (0..14).flat_map(|i| batch(&t, i, size)).collect();
            assert_eq!(all.len(), 13, "batch size {size}");
            assert!(!all.iter().any(|a| a == "172.30.0.11"), "batch size {size}");
            assert_eq!(all.first().map(String::as_str), Some("172.30.0.1"));
            assert_eq!(all.last().map(String::as_str), Some("172.30.0.14"));
        }
        assert!(contains(&t, "172.30.0.10", None));
        assert!(!contains(&t, "172.30.0.11", None), "excluded address is not covered");
    }

    #[test]
    fn excluded_ranges_and_whole_targets() {
        let targets = vec![
            normalize("10.0.0.0/24").unwrap(),
            normalize("10.0.1.5").unwrap(),
            normalize("example.com").unwrap(),
            normalize("10.0.2.0/30").unwrap(),
        ];
        // A /26 inside the /24, a range that swallows the single IP, one unrelated network,
        // and the first and last host of the /30.
        let t = with_exclusions(targets, &nets(&["10.0.0.64/26", "10.0.1.0/24", "192.168.0.0/16", "10.0.2.1", "10.0.2.2"]));
        assert_eq!(t[0].except, ["10.0.0.64/26"]);
        assert_eq!(t[1].except, ["10.0.1.0/24"]);
        assert!(t[2].except.is_empty(), "domains are left as they are");
        assert_eq!(t[0].host_count(), 254 - 64);
        assert_eq!(t[1].host_count(), 0);
        assert_eq!(t[3].host_count(), 0);
        assert_eq!(total_hosts(&t), 254 - 64 + 1);
        let all: Vec<String> = (0..10).flat_map(|i| batch(&t, i, 50)).collect();
        assert_eq!(all.len(), 254 - 64 + 1);
        assert!(all.contains(&"10.0.0.63".to_string()) && all.contains(&"10.0.0.128".to_string()));
        assert!(!all.iter().any(|a| a.starts_with("10.0.1.") || a.starts_with("10.0.2.")));
        let inside: Vec<&String> = all.iter().filter(|a| (64..128).any(|n| **a == format!("10.0.0.{n}"))).collect();
        assert!(inside.is_empty(), "nothing of the excluded /26: {inside:?}");
        assert_eq!(all.last().map(String::as_str), Some("example.com"));
    }

    #[test]
    fn exceptions_survive_the_run_snapshot() {
        let t = with_exclusions(vec![normalize("10.0.0.0/29").unwrap()], &nets(&["10.0.0.3"]));
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, r#"[{"kind":"cidr","value":"10.0.0.0/29","except":["10.0.0.3"]}]"#);
        let back: Vec<Target> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
        // Snapshots written before exclusions existed have no `except` field.
        let old: Vec<Target> = serde_json::from_str(r#"[{"kind":"ip","value":"10.0.0.1"}]"#).unwrap();
        assert!(old[0].except.is_empty());
        assert_eq!(serde_json::to_string(&old).unwrap(), r#"[{"kind":"ip","value":"10.0.0.1"}]"#);
    }

    #[test]
    fn large_range_with_exceptions_is_cheap() {
        let t = with_exclusions(vec![normalize("10.0.0.0/8").unwrap()], &nets(&["10.128.0.0/9", "10.0.0.1"]));
        let started = std::time::Instant::now();
        assert_eq!(total_hosts(&t), (1 << 23) - 2);
        let last = slice(&t, total_hosts(&t) - 2, 256);
        assert_eq!(last, ["10.127.255.254", "10.127.255.255"]);
        assert_eq!(slice(&t, 0, 2), ["10.0.0.2", "10.0.0.3"]);
        assert!(started.elapsed() < std::time::Duration::from_millis(50));
    }

    #[test]
    fn rejects_huge_ipv6() {
        assert_eq!(normalize("fd00::/64"), Err(InputError::TooBroad(64, 104)));
    }
}
