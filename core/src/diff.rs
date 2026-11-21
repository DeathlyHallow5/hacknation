//! Module 4 — Diff Engine (PROJECT.md §7). Pure comparison of two run snapshots.
//!
//! Rules (they answer the task's questions "how to report a change?" and "how sure are we?"):
//! - Hosts are compared by state. Missing hosts are carried into later runs as `unstable`
//!   and become `inactive` after `inactive_after_misses` consecutive misses, so a host that
//!   is only reachable at some times of day is reported "gone (unconfirmed)" first.
//! - Services/HTTP of a host that is not active in B are not reported as gone one by one:
//!   the host-level entry already says it.
//! - confidence = identification confidence × stability, stability = 1 / (1 + flaps).
//!   For a gone host: misses / threshold.
//! - interest 1..3 ranks entries for the "most important changes" view.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Host,
    Service,
    Http,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Host => "host",
            Kind::Service => "service",
            Kind::Http => "http",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Change {
    New,
    Gone,
    Changed,
}

impl Change {
    pub fn as_str(self) -> &'static str {
        match self {
            Change::New => "new",
            Change::Gone => "gone",
            Change::Changed => "changed",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostState {
    pub state: String, // active | unstable | inactive
    pub miss_count: i32,
    pub flaps: i32,
}

/// One service or HTTP observation.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub kind: Kind,
    /// Service: `ip:port/proto`; HTTP: the URL.
    pub key: String,
    pub ip: String,
    pub port: u16,
    pub fields: BTreeMap<String, String>,
    /// Identification confidence 0..=1 (nmap conf for services, 1.0 for HTTP).
    pub confidence: f32,
}

#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    pub hosts: BTreeMap<String, HostState>,
    pub observations: Vec<Observation>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiffEntry {
    pub kind: Kind,
    pub entity: String,
    pub change: Change,
    pub field: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub confidence: f32,
    pub interest: u8,
}

/// Ports whose sudden appearance deserves attention (remote admin, databases, caches...).
const RISKY_PORTS: &[u16] = &[
    21, 23, 445, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017,
];

fn stability(b: &Snapshot, ip: &str) -> f32 {
    let flaps = b.hosts.get(ip).map(|h| h.flaps).unwrap_or(0).max(0);
    1.0 / (1.0 + flaps as f32)
}

fn round2(x: f32) -> f32 {
    (x.clamp(0.0, 1.0) * 100.0).round() / 100.0
}

pub fn diff(a: &Snapshot, b: &Snapshot, inactive_after: i32) -> Vec<DiffEntry> {
    let mut out = Vec::new();
    let threshold = inactive_after.max(1) as f32;

    // 1) Hosts.
    let ips: BTreeSet<&String> = a.hosts.keys().chain(b.hosts.keys()).collect();
    for ip in ips {
        let (ha, hb) = (a.hosts.get(ip), b.hosts.get(ip));
        let entry = |change, field: Option<&str>, old: Option<&str>, new: Option<&str>, confidence, interest| DiffEntry {
            kind: Kind::Host,
            entity: ip.to_string(),
            change,
            field: field.map(str::to_string),
            old_value: old.map(str::to_string),
            new_value: new.map(str::to_string),
            confidence: round2(confidence),
            interest,
        };
        match (ha, hb) {
            (None, Some(hb)) if hb.state == "active" => {
                out.push(entry(Change::New, None, None, None, stability(b, ip), 2))
            }
            (Some(ha), None) if ha.state == "active" => {
                // Not in B's roster at all (e.g. target removed): plain gone.
                out.push(entry(Change::Gone, None, None, None, 1.0, 1))
            }
            (Some(ha), Some(hb)) if ha.state != hb.state => match hb.state.as_str() {
                "unstable" => out.push(entry(
                    Change::Gone,
                    Some("state"),
                    Some(&ha.state),
                    Some("unstable"),
                    hb.miss_count as f32 / threshold,
                    1,
                )),
                "inactive" => out.push(entry(Change::Gone, Some("state"), Some(&ha.state), Some("inactive"), 1.0, 2)),
                // Came back after a miss: reappeared (and counted as a flap).
                _ => out.push(entry(Change::Changed, Some("state"), Some(&ha.state), Some(&hb.state), stability(b, ip), 1)),
            },
            _ => {}
        }
    }

    // 2) Services and HTTP.
    let not_active_in_b = |ip: &str| b.hosts.get(ip).is_none_or(|h| h.state != "active");
    let index = |s: &Snapshot| -> BTreeMap<(Kind, String), Observation> {
        s.observations.iter().map(|o| ((o.kind, o.key.clone()), o.clone())).collect()
    };
    let (ia, ib) = (index(a), index(b));

    for (k, ob) in &ib {
        let stab = stability(b, &ob.ip);
        match ia.get(k) {
            None => out.push(DiffEntry {
                kind: ob.kind,
                entity: ob.key.clone(),
                change: Change::New,
                field: None,
                old_value: None,
                new_value: summary(ob),
                confidence: round2(ob.confidence * stab),
                interest: interest_new(ob),
            }),
            Some(oa) => {
                let fields: BTreeSet<&String> = oa.fields.keys().chain(ob.fields.keys()).collect();
                for f in fields {
                    let (va, vb) = (oa.fields.get(f), ob.fields.get(f));
                    if va == vb {
                        continue;
                    }
                    let base = if ob.kind == Kind::Service { oa.confidence.min(ob.confidence) } else { 1.0 };
                    out.push(DiffEntry {
                        kind: ob.kind,
                        entity: ob.key.clone(),
                        change: Change::Changed,
                        field: Some(f.clone()),
                        old_value: va.cloned(),
                        new_value: vb.cloned(),
                        confidence: round2(base * stab),
                        interest: interest_changed(ob.kind, f, vb),
                    });
                }
            }
        }
    }
    for (k, oa) in &ia {
        if ib.contains_key(k) || not_active_in_b(&oa.ip) {
            continue;
        }
        out.push(DiffEntry {
            kind: oa.kind,
            entity: oa.key.clone(),
            change: Change::Gone,
            field: None,
            old_value: summary(oa),
            new_value: None,
            confidence: round2(stability(b, &oa.ip)),
            interest: if oa.kind == Kind::Service && RISKY_PORTS.contains(&oa.port) { 2 } else { 1 },
        });
    }

    out.sort_by(|x, y| y.interest.cmp(&x.interest).then(x.kind.cmp(&y.kind)).then(x.entity.cmp(&y.entity)));
    out
}

/// Short human-readable description of an observation for new/gone entries.
fn summary(o: &Observation) -> Option<String> {
    let f = |k: &str| o.fields.get(k).map(String::as_str).unwrap_or("");
    let s = match o.kind {
        Kind::Service => format!("{} {} {}", f("service"), f("product"), f("version")),
        Kind::Http => format!("{} {}", f("status"), f("title")),
        Kind::Host => String::new(),
    };
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    (!s.is_empty()).then_some(s)
}

fn flag(o: &Observation, k: &str) -> bool {
    o.fields.get(k).map(String::as_str) == Some("true")
}

fn interest_new(o: &Observation) -> u8 {
    match o.kind {
        Kind::Http if flag(o, "admin") || flag(o, "staging") => 3,
        Kind::Http => 1,
        Kind::Service if RISKY_PORTS.contains(&o.port) => 3,
        _ => 2,
    }
}

fn interest_changed(kind: Kind, field: &str, new: Option<&String>) -> u8 {
    let became_true = new.map(String::as_str) == Some("true");
    match (kind, field) {
        (Kind::Http, "admin" | "staging") if became_true => 3,
        (Kind::Service, "product" | "version" | "service") => 2,
        (Kind::Http, "cms" | "tech" | "header.server" | "header.x_powered_by" | "header.x_generator") => 2,
        (Kind::Http, f) if f.starts_with("tls.") => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(state: &str, miss: i32, flaps: i32) -> HostState {
        HostState { state: state.into(), miss_count: miss, flaps }
    }

    fn svc(ip: &str, port: u16, version: &str, conf: f32) -> Observation {
        Observation {
            kind: Kind::Service,
            key: format!("{ip}:{port}/tcp"),
            ip: ip.into(),
            port,
            fields: [("service", "http"), ("product", "nginx"), ("version", version)]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            confidence: conf,
        }
    }

    fn http(ip: &str, title: &str, admin: bool) -> Observation {
        Observation {
            kind: Kind::Http,
            key: format!("http://{ip}:80"),
            ip: ip.into(),
            port: 80,
            fields: [("status", "200"), ("title", title), ("admin", if admin { "true" } else { "false" })]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            confidence: 1.0,
        }
    }

    fn snap(hosts: &[(&str, HostState)], obs: Vec<Observation>) -> Snapshot {
        Snapshot { hosts: hosts.iter().map(|(ip, h)| (ip.to_string(), h.clone())).collect(), observations: obs }
    }

    #[test]
    fn lab_scenario() {
        // Run A: .10 nginx 1.24, .11 apache. Run B: .10 upgraded, .11 missed once, .12 new admin.
        let a = snap(
            &[("10.0.0.10", host("active", 0, 0)), ("10.0.0.11", host("active", 0, 0))],
            vec![svc("10.0.0.10", 80, "1.24", 1.0), svc("10.0.0.11", 80, "2.4", 1.0), http("10.0.0.11", "It works", false)],
        );
        let b = snap(
            &[
                ("10.0.0.10", host("active", 0, 0)),
                ("10.0.0.11", host("unstable", 1, 0)),
                ("10.0.0.12", host("active", 0, 0)),
            ],
            vec![svc("10.0.0.10", 80, "1.27", 0.8), svc("10.0.0.12", 80, "1.27", 1.0), http("10.0.0.12", "Admin login", true)],
        );
        let d = diff(&a, &b, 3);

        let gone = d.iter().find(|e| e.entity == "10.0.0.11").unwrap();
        assert_eq!((gone.change, gone.confidence), (Change::Gone, 0.33), "unconfirmed gone = 1/3");
        // Services/HTTP of the missing host are not listed separately.
        assert!(!d.iter().any(|e| e.entity.contains("10.0.0.11") && e.kind != Kind::Host));

        let ver = d.iter().find(|e| e.field.as_deref() == Some("version")).unwrap();
        assert_eq!((ver.old_value.as_deref(), ver.new_value.as_deref()), (Some("1.24"), Some("1.27")));
        assert_eq!(ver.confidence, 0.8, "min of both identification confidences");

        assert!(d.iter().any(|e| e.kind == Kind::Host && e.change == Change::New && e.entity == "10.0.0.12"));
        // The new admin panel is the most interesting entry and comes first.
        assert_eq!((d[0].kind, d[0].change, d[0].interest), (Kind::Http, Change::New, 3));
    }

    #[test]
    fn inactive_and_reappeared() {
        let a = snap(&[("h", host("unstable", 2, 0))], vec![]);
        let b = snap(&[("h", host("inactive", 3, 0))], vec![]);
        let d = diff(&a, &b, 3);
        assert_eq!((d[0].change, d[0].confidence, d[0].new_value.as_deref()), (Change::Gone, 1.0, Some("inactive")));

        let c = snap(&[("h", host("active", 0, 1))], vec![]);
        let d = diff(&b, &c, 3);
        assert_eq!((d[0].change, d[0].new_value.as_deref()), (Change::Changed, Some("active")));
        assert_eq!(d[0].confidence, 0.5, "flapping host: changes are less certain");
    }

    #[test]
    fn port_closed_on_live_host_is_reported() {
        let a = snap(&[("h", host("active", 0, 0))], vec![svc("h", 22, "9", 1.0), svc("h", 3306, "8", 1.0)]);
        let b = snap(&[("h", host("active", 0, 0))], vec![svc("h", 22, "9", 1.0)]);
        let d = diff(&a, &b, 3);
        assert_eq!(d.len(), 1);
        assert_eq!((d[0].change, d[0].entity.as_str(), d[0].interest), (Change::Gone, "h:3306/tcp", 2));
    }

    #[test]
    fn identical_runs_have_no_diff() {
        let a = snap(&[("h", host("active", 0, 0))], vec![svc("h", 80, "1", 1.0), http("h", "x", false)]);
        assert!(diff(&a, &a.clone(), 3).is_empty());
    }
}
