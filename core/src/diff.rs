//! Module 4 — Diff Engine (PROJECT.md §7): compare two scan runs.
//! Skeleton: compares service observations by key; confidence and unstable-host
//! re-checks are TODO.

use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Change {
    New,
    Gone,
    Changed,
}

/// One observed service, keyed as `address:port/proto`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub key: String,
    /// Comparable fields: service, version, title, status ...
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffEntry {
    pub entity: String,
    pub change: Change,
    pub field: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

pub fn diff(before: &[Observation], after: &[Observation]) -> Vec<DiffEntry> {
    let a: BTreeMap<_, _> = before.iter().map(|o| (&o.key, &o.fields)).collect();
    let b: BTreeMap<_, _> = after.iter().map(|o| (&o.key, &o.fields)).collect();
    let mut out = Vec::new();

    for (key, fields_b) in &b {
        match a.get(key) {
            None => out.push(entry(key, Change::New, None, None, None)),
            Some(fields_a) => {
                for (field, new) in fields_b.iter() {
                    let old = fields_a.get(field);
                    if old != Some(new) {
                        out.push(entry(key, Change::Changed, Some(field), old, Some(new)));
                    }
                }
                for (field, old) in fields_a.iter().filter(|(f, _)| !fields_b.contains_key(*f)) {
                    out.push(entry(key, Change::Changed, Some(field), Some(old), None));
                }
            }
        }
    }
    for key in a.keys().filter(|k| !b.contains_key(*k)) {
        // TODO: a Gone host may just be offline at this time of day — consult miss_count
        // before marking it Inactive (§7).
        out.push(entry(key, Change::Gone, None, None, None));
    }
    out
}

fn entry(
    key: &str,
    change: Change,
    field: Option<&String>,
    old: Option<&String>,
    new: Option<&String>,
) -> DiffEntry {
    DiffEntry {
        entity: key.to_string(),
        change,
        field: field.cloned(),
        old_value: old.cloned(),
        new_value: new.cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(key: &str, fields: &[(&str, &str)]) -> Observation {
        Observation {
            key: key.into(),
            fields: fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    #[test]
    fn new_gone_changed() {
        let before = vec![
            obs("10.0.0.1:80/tcp", &[("service", "http"), ("version", "nginx 1.24")]),
            obs("10.0.0.2:22/tcp", &[("service", "ssh")]),
        ];
        let after = vec![
            obs("10.0.0.1:80/tcp", &[("service", "http"), ("version", "nginx 1.27")]),
            obs("10.0.0.3:443/tcp", &[("service", "https")]),
        ];
        let d = diff(&before, &after);
        assert_eq!(d.len(), 3);
        assert!(d.iter().any(|e| e.change == Change::New && e.entity == "10.0.0.3:443/tcp"));
        assert!(d.iter().any(|e| e.change == Change::Gone && e.entity == "10.0.0.2:22/tcp"));
        let changed = d.iter().find(|e| e.change == Change::Changed).unwrap();
        assert_eq!(changed.field.as_deref(), Some("version"));
        assert_eq!(changed.new_value.as_deref(), Some("nginx 1.27"));
    }
}
