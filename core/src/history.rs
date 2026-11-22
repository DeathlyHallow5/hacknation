//! Run history around the Diff Engine (PROJECT.md §7), executed when a run finishes:
//!
//! 1. Re-check: hosts/ports seen in the previous run but missing now are scanned once
//!    more ("powtarzanie pomiarów dla hostów niestabilnych"), so a single dropped probe
//!    is not reported as a change.
//! 2. Carry-forward: hosts still missing are copied into this run's roster with
//!    miss_count+1 → `unstable`, or `inactive` once miss_count reaches the scan's
//!    `inactive_after_misses`. Hosts that came back get `flaps+1`.
//! 3. Diff against the previous finished run of the same scan, stored encrypted.
//!
//! Coverage (F-04, F-05): only addresses covered by BOTH runs are compared — inside both
//! target lists and not in a failed batch. Removed/added targets and failed batches are
//! counted as `not_comparable`, never reported as gone/new. `partial` runs are diffed but
//! never used as a baseline.

use crate::{
    diff::{self, DiffEntry, HostState, Kind, Observation, Snapshot},
    input::{self, Target},
    pipeline::{self, RunStats, ScanConfig},
    AppState,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use uuid::Uuid;

/// Pause before re-measuring, so a short outage has a chance to end.
const RECHECK_DELAY: Duration = Duration::from_secs(10);

/// Response headers whose values matter for the security picture.
const INTERESTING_HEADERS: &[&str] = &[
    "server", "x_powered_by", "x_generator", "x_aspnet_version", "x_aspnetmvc_version", "via",
    "x_backend_server", "x_runtime", "x_version", "strict_transport_security",
    "content_security_policy", "x_frame_options", "access_control_allow_origin", "www_authenticate",
];
/// Headers that change on every request: ignored when comparing the header set.
const VOLATILE_HEADERS: &[&str] = &[
    "date", "etag", "last_modified", "content_length", "age", "expires", "set_cookie",
    "x_request_id", "x_correlation_id", "cf_ray", "report_to", "nel", "x_amz_request_id",
];
const VOLATILE_TLS: &[&str] = &["timestamp", "probe_status", "host", "ip", "port"];

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub against: Option<Uuid>,
    pub new: u64,
    pub gone: u64,
    pub changed: u64,
    /// Entries with interest 3 (new admin panel, staging, risky port...).
    pub important: u64,
    /// Addresses seen in either run but not covered by both (skipped, not "gone").
    pub not_comparable: u64,
}

impl DiffSummary {
    pub fn of(against: Option<Uuid>, entries: &[DiffEntry]) -> Self {
        let count = |c: diff::Change| entries.iter().filter(|e| e.change == c).count() as u64;
        Self {
            against,
            new: count(diff::Change::New),
            gone: count(diff::Change::Gone),
            changed: count(diff::Change::Changed),
            important: entries.iter().filter(|e| e.interest >= 3).count() as u64,
            not_comparable: 0,
        }
    }
}

/// What a run actually measured: its frozen target list minus inputs of failed batches.
pub struct Coverage {
    targets: Vec<Target>,
    failed: BTreeSet<String>,
}

impl Coverage {
    pub fn new(targets: &[Target], failed_ranges: &[(u64, u64)]) -> Self {
        let failed = failed_ranges
            .iter()
            .flat_map(|&(offset, n)| input::slice(targets, offset as u128, n as usize))
            .collect();
        Self { targets: targets.to_vec(), failed }
    }

    pub async fn load(db: &PgPool, run_id: Uuid) -> sqlx::Result<Self> {
        let (targets, stats): (Option<sqlx::types::Json<Vec<Target>>>, sqlx::types::Json<RunStats>) =
            sqlx::query_as("SELECT target_snapshot, stats FROM scan_runs WHERE id = $1")
                .bind(run_id)
                .fetch_one(db)
                .await?;
        Ok(Self::new(&targets.map(|t| t.0).unwrap_or_default(), &stats.0.failed_ranges))
    }

    pub fn covers(&self, ip: &str, hostname: Option<&str>) -> bool {
        input::contains(&self.targets, ip, hostname)
            && !self.failed.contains(ip)
            && hostname.is_none_or(|h| !self.failed.contains(h))
    }

    /// Was this DNS name itself a target (so its virtual host was probed by name)?
    pub fn has_domain(&self, name: &str) -> bool {
        self.targets.iter().any(|t| t.kind == input::TargetKind::Domain && t.value.eq_ignore_ascii_case(name))
            && !self.failed.contains(name)
    }
}

/// Addresses of either run that are not covered by both.
fn not_comparable(a: &Loaded, b: &Loaded, cov_a: &Coverage, cov_b: &Coverage) -> BTreeSet<String> {
    let hostname = |ip: &String| {
        b.hostnames.get(ip).cloned().flatten().or_else(|| a.hostnames.get(ip).cloned().flatten())
    };
    a.snapshot
        .hosts
        .keys()
        .chain(b.snapshot.hosts.keys())
        .filter(|ip| {
            let h = hostname(ip);
            !(cov_a.covers(ip, h.as_deref()) && cov_b.covers(ip, h.as_deref()))
        })
        .cloned()
        .collect()
}

/// Previous finished run to compare with: of the same scan, or of another scan that covered
/// exactly the same targets with the same ports (the dashboard starts every scan as a new
/// one, and "what changed since we last looked at these addresses" is the question). Runs
/// with other targets or ports are never mixed in: their differences would be coverage,
/// not changes.
pub async fn previous_run(db: &PgPool, run_id: Uuid) -> sqlx::Result<Option<Uuid>> {
    sqlx::query_scalar(
        "SELECT p.id FROM scan_runs p JOIN scan_runs c ON c.id = $1
         WHERE p.id <> c.id AND p.status = 'done' AND p.started_at < c.started_at
           AND (p.scan_id = c.scan_id
                OR (p.target_snapshot = c.target_snapshot
                    AND p.config_snapshot->>'ports' = c.config_snapshot->>'ports'))
         ORDER BY p.started_at DESC LIMIT 1",
    )
    .bind(run_id)
    .fetch_optional(db)
    .await
}

#[derive(sqlx::FromRow)]
struct HostRow {
    address: String,
    hostname: Option<String>,
    state: String,
    miss_count: i32,
    flaps: i32,
}

#[derive(sqlx::FromRow)]
struct ServiceRow {
    address: String,
    port: i32,
    protocol: String,
    service: Option<String>,
    product: Option<String>,
    version: Option<String>,
    confidence: f32,
}

#[derive(sqlx::FromRow)]
struct HttpRow {
    address: String,
    port: i32,
    url: String,
    status_code: Option<i32>,
    title: Option<String>,
    technologies: Option<Vec<String>>,
    cms: Option<String>,
    favicon_hash: Option<String>,
    is_admin: bool,
    is_staging: bool,
    redirects: Option<Vec<String>>,
    headers: Option<Value>,
    cookies: Option<Value>,
    tls: Option<Value>,
}

/// Snapshot of one run plus hostnames (needed to match domain targets).
pub struct Loaded {
    pub snapshot: Snapshot,
    pub hostnames: BTreeMap<String, Option<String>>,
}

pub async fn load(db: &PgPool, run_id: Uuid, key: &str) -> sqlx::Result<Loaded> {
    let hosts: Vec<HostRow> = sqlx::query_as(
        "SELECT host(address) AS address, hostname, state::text AS state, miss_count, flaps
         FROM hosts WHERE run_id = $1",
    )
    .bind(run_id)
    .fetch_all(db)
    .await?;
    let services: Vec<ServiceRow> = sqlx::query_as(
        "SELECT host(h.address) AS address, s.port, s.protocol, s.service, s.product, s.version, s.confidence
         FROM services s JOIN hosts h ON h.id = s.host_id WHERE h.run_id = $1",
    )
    .bind(run_id)
    .fetch_all(db)
    .await?;
    let http: Vec<HttpRow> = sqlx::query_as(
        "SELECT host(h.address) AS address, s.port, f.url, f.status_code, f.title, f.technologies, f.cms,
                f.favicon_hash, f.is_admin, f.is_staging, f.redirects,
                asi_decrypt(f.headers_enc, $2)::jsonb AS headers,
                asi_decrypt(f.cookies_enc, $2)::jsonb AS cookies,
                asi_decrypt(f.tls_enc, $2)::jsonb AS tls
         FROM http_findings f JOIN services s ON s.id = f.service_id JOIN hosts h ON h.id = s.host_id
         WHERE h.run_id = $1",
    )
    .bind(run_id)
    .bind(key)
    .fetch_all(db)
    .await?;

    let mut snapshot = Snapshot::default();
    let mut hostnames = BTreeMap::new();
    for h in hosts {
        hostnames.insert(h.address.clone(), h.hostname);
        snapshot.hosts.insert(h.address, HostState { state: h.state, miss_count: h.miss_count, flaps: h.flaps });
    }
    for s in services {
        let fields = [("service", s.service), ("product", s.product), ("version", s.version)]
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k.to_string(), v)))
            .collect();
        snapshot.observations.push(Observation {
            kind: Kind::Service,
            key: format!("{}:{}/{}", s.address, s.port, s.protocol),
            ip: s.address,
            port: s.port as u16,
            fields,
            confidence: s.confidence,
        });
    }
    for f in http {
        snapshot.observations.push(Observation {
            kind: Kind::Http,
            key: f.url.clone(),
            ip: f.address.clone(),
            port: f.port as u16,
            fields: http_fields(&f),
            confidence: 1.0,
        });
    }
    Ok(Loaded { snapshot, hostnames })
}

/// Comparable fields of an HTTP finding. Volatile values (dates, ETags, cookie values,
/// body length) are left out so they do not show up as changes.
fn http_fields(f: &HttpRow) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut put = |k: &str, v: Option<String>| {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            m.insert(k.to_string(), v);
        }
    };
    put("status", f.status_code.map(|s| s.to_string()));
    put("title", f.title.clone());
    put("cms", f.cms.clone());
    put("favicon", f.favicon_hash.clone());
    put("admin", Some(f.is_admin.to_string()));
    put("staging", Some(f.is_staging.to_string()));
    let mut tech = f.technologies.clone().unwrap_or_default();
    tech.sort();
    put("tech", Some(tech.join(", ")));
    put("redirects", f.redirects.as_ref().map(|r| r.join(" -> ")));

    if let Some(Value::Object(headers)) = &f.headers {
        for name in INTERESTING_HEADERS {
            put(&format!("header.{name}"), headers.get(*name).map(value_text));
        }
        let mut names: Vec<&str> = headers.keys().map(String::as_str).filter(|k| !VOLATILE_HEADERS.contains(k)).collect();
        names.sort();
        put("headers", Some(names.join(", ")));
    }
    if let Some(Value::Array(cookies)) = &f.cookies {
        // Compare cookie NAMES only; values are session tokens.
        let mut names: Vec<String> = cookies
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|c| c.split('=').next())
            .map(|n| n.trim().to_string())
            .collect();
        names.sort();
        names.dedup();
        put("cookies", Some(names.join(", ")));
    }
    if let Some(tls) = &f.tls {
        let mut flat = BTreeMap::new();
        flatten("tls", tls, &mut flat);
        for (k, v) in flat {
            m.insert(k, v);
        }
    }
    m
}

fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn flatten(prefix: &str, v: &Value, out: &mut BTreeMap<String, String>) {
    match v {
        Value::Object(map) => {
            for (k, v) in map {
                if !VOLATILE_TLS.contains(&k.as_str()) {
                    flatten(&format!("{prefix}.{k}"), v, out);
                }
            }
        }
        Value::Array(items) if items.iter().all(|i| !i.is_object()) => {
            let mut parts: Vec<String> = items.iter().map(value_text).collect();
            parts.sort();
            out.insert(prefix.to_string(), parts.join(", "));
        }
        Value::Null => {}
        other => {
            out.insert(prefix.to_string(), value_text(other));
        }
    }
}

/// Hosts/ports of the previous run that are missing now (within what this run covers).
fn recheck_inputs(prev: &Loaded, cur: &Loaded, coverage: &Coverage) -> Vec<String> {
    let ports = |s: &Snapshot| -> BTreeMap<String, BTreeSet<u16>> {
        let mut m: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
        for o in s.observations.iter().filter(|o| o.kind == Kind::Service) {
            m.entry(o.ip.clone()).or_default().insert(o.port);
        }
        m
    };
    let (pp, cp) = (ports(&prev.snapshot), ports(&cur.snapshot));
    let mut out = Vec::new();
    for (ip, h) in &prev.snapshot.hosts {
        if h.state == "inactive" {
            continue; // already scanned in the main batches; no extra probing
        }
        let hostname = prev.hostnames.get(ip).cloned().flatten();
        if !coverage.covers(ip, hostname.as_deref()) {
            continue;
        }
        let now_active = cur.snapshot.hosts.get(ip).is_some_and(|c| c.state == "active");
        let ports_missing = pp.get(ip).is_some_and(|p| !p.is_subset(cp.get(ip).unwrap_or(&BTreeSet::new())));
        if !now_active || ports_missing {
            out.push(hostname.unwrap_or_else(|| ip.clone()));
        }
    }
    out
}

/// Steps 1–3 for a run that just finished all its batches. Never fails the run: problems
/// are recorded in `stats.errors`.
pub async fn finalize(
    state: &AppState,
    scan: &ScanConfig,
    run_id: Uuid,
    targets: &[Target],
    stats: &mut RunStats,
    deadline: Option<DateTime<Utc>>,
) {
    // The analysis outcome is visible on its own (F-21); it never changes the scan status.
    match finalize_inner(state, scan, run_id, targets, stats, deadline).await {
        Ok(()) => {}
        Err(e) => {
            stats.analysis = Some("failed".into());
            stats.error(format!("diff: {e:#}"));
        }
    }
}

async fn finalize_inner(
    state: &AppState,
    scan: &ScanConfig,
    run_id: Uuid,
    targets: &[Target],
    stats: &mut RunStats,
    deadline: Option<DateTime<Utc>>,
) -> Result<()> {
    let db = &state.db;
    let key = state.config.data_key.as_str();
    let Some(prev_id) = previous_run(db, run_id).await? else {
        stats.diff = Some(DiffSummary::default()); // first run: nothing to compare
        stats.analysis = Some("baseline".into());
        return Ok(());
    };
    let prev = load(db, prev_id, key).await?;
    let cur = load(db, run_id, key).await?;
    let cov_prev = Coverage::load(db, prev_id).await?;
    let cov_cur = Coverage::new(targets, &stats.failed_ranges);

    // 1) Re-check what disappeared, if the window leaves time for it.
    let inputs = recheck_inputs(&prev, &cur, &cov_cur);
    let missing_before: BTreeSet<String> = prev
        .snapshot
        .hosts
        .iter()
        .filter(|(ip, h)| h.state != "inactive" && cur.snapshot.hosts.get(*ip).is_none_or(|c| c.state != "active"))
        .map(|(ip, _)| ip.clone())
        .collect();
    let time_left = deadline.map(|d| (d - Utc::now()).to_std().unwrap_or_default());
    if !inputs.is_empty() && time_left.is_none_or(|t| t > RECHECK_DELAY * 3) {
        tracing::info!(%run_id, n = inputs.len(), "re-checking missing hosts/ports");
        tokio::time::sleep(RECHECK_DELAY).await;
        if pipeline::is_cancelled(db, run_id).await? {
            return Ok(());
        }
        let budget = time_left.map(|t| t.saturating_sub(RECHECK_DELAY)).unwrap_or(pipeline::MAX_TOOL_TIME);
        stats.rechecked += inputs.len() as u64;
        if let Err(e) = pipeline::run_batch(state, scan, run_id, stats.batches_done as usize, &inputs, budget).await {
            stats.error(format!("re-check: {e:#}"));
        }
    }

    // 2) Carry missing hosts forward; count flaps of hosts that came back.
    if pipeline::is_cancelled(db, run_id).await? {
        return Ok(());
    }
    let cur = load(db, run_id, key).await?;
    let missing: Vec<String> = prev
        .snapshot
        .hosts
        .keys()
        .filter(|ip| !cur.snapshot.hosts.contains_key(*ip))
        .filter(|ip| cov_cur.covers(ip, prev.hostnames.get(*ip).cloned().flatten().as_deref()))
        .cloned()
        .collect();
    // Hosts that were missing after the main batches but answered the re-check.
    stats.recovered += missing_before
        .iter()
        .filter(|ip| cur.snapshot.hosts.get(*ip).is_some_and(|h| h.state == "active"))
        .count() as u64;
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO hosts (run_id, address, hostname, state, miss_count, flaps, seen_at, first_seen_at)
         SELECT $1, p.address, p.hostname,
                (CASE WHEN p.miss_count + 1 >= $4 THEN 'inactive' ELSE 'unstable' END)::host_state,
                p.miss_count + 1, p.flaps, p.seen_at, p.first_seen_at
         FROM hosts p WHERE p.run_id = $2 AND host(p.address) = ANY($3)
         ON CONFLICT (run_id, address) DO NOTHING",
    )
    .bind(run_id)
    .bind(prev_id)
    .bind(&missing)
    .bind(scan.inactive_after_misses)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE hosts c SET flaps = p.flaps + (p.state <> 'active')::int, first_seen_at = p.first_seen_at
         FROM hosts p
         WHERE c.run_id = $1 AND p.run_id = $2 AND p.address = c.address AND c.state = 'active'",
    )
    .bind(run_id)
    .bind(prev_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    // 3) Diff and store.
    let cur = load(db, run_id, key).await?;
    let skip = not_comparable(&prev, &cur, &cov_prev, &cov_cur);
    let entries = diff::diff(&prev.snapshot, &cur.snapshot, scan.inactive_after_misses, &skip);
    store(db, prev_id, run_id, &entries, key).await?;
    stats.diff = Some(DiffSummary { not_comparable: skip.len() as u64, ..DiffSummary::of(Some(prev_id), &entries) });
    stats.analysis = Some("complete".into());
    tracing::info!(%run_id, against = %prev_id, entries = entries.len(), "diff stored");
    Ok(())
}

async fn store(db: &PgPool, run_a: Uuid, run_b: Uuid, entries: &[DiffEntry], key: &str) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM diffs WHERE run_a = $1 AND run_b = $2")
        .bind(run_a)
        .bind(run_b)
        .execute(&mut *tx)
        .await?;
    let col = |f: fn(&DiffEntry) -> Option<String>| entries.iter().map(f).collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO diffs (run_a, run_b, kind, entity, change, field, old_enc, new_enc, confidence, interest)
         SELECT $1, $2, k, e, c::change_type, f, pgp_sym_encrypt(o, $11), pgp_sym_encrypt(n, $11), conf, i
         FROM UNNEST($3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::real[], $10::smallint[])
              AS t(k, e, c, f, o, n, conf, i)",
    )
    .bind(run_a)
    .bind(run_b)
    .bind(entries.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>())
    .bind(entries.iter().map(|e| e.entity.as_str()).collect::<Vec<_>>())
    .bind(entries.iter().map(|e| e.change.as_str()).collect::<Vec<_>>())
    .bind(col(|e| e.field.clone()))
    .bind(col(|e| e.old_value.clone()))
    .bind(col(|e| e.new_value.clone()))
    .bind(entries.iter().map(|e| e.confidence).collect::<Vec<_>>())
    .bind(entries.iter().map(|e| e.interest as i16).collect::<Vec<_>>())
    .bind(key)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Compare any two runs on demand (not stored). Returns entries and the number of
/// addresses skipped as not comparable. `RowNotFound` if a run does not exist.
pub async fn compare(db: &PgPool, run_a: Uuid, run_b: Uuid, key: &str) -> sqlx::Result<(Vec<DiffEntry>, usize)> {
    // Threshold of run B as frozen at its start (falls back to the scan for old runs).
    let threshold: i32 = sqlx::query_scalar(
        "SELECT COALESCE((r.config_snapshot->>'inactive_after_misses')::int, s.inactive_after_misses)
         FROM scan_runs r JOIN scans s ON s.id = r.scan_id WHERE r.id = $1",
    )
    .bind(run_b)
    .fetch_one(db)
    .await?;
    let (cov_a, cov_b) = (Coverage::load(db, run_a).await?, Coverage::load(db, run_b).await?);
    let (a, b) = (load(db, run_a, key).await?, load(db, run_b, key).await?);
    let skip = not_comparable(&a, &b, &cov_a, &cov_b);
    Ok((diff::diff(&a.snapshot, &b.snapshot, threshold, &skip), skip.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(headers: Value, cookies: Value) -> HttpRow {
        HttpRow {
            address: "10.0.0.1".into(),
            port: 443,
            url: "https://10.0.0.1".into(),
            status_code: Some(200),
            title: Some("Panel".into()),
            technologies: Some(vec!["Nginx:1.27".into(), "PHP:8.3".into()]),
            cms: None,
            favicon_hash: None,
            is_admin: true,
            is_staging: false,
            redirects: None,
            headers: Some(headers),
            cookies: Some(cookies),
            tls: Some(json!({"subject_cn": "a.example", "not_after": "2027-01-01", "timestamp": "x", "san": ["b", "a"]})),
        }
    }

    #[test]
    fn coverage_excludes_failed_batches_and_other_targets() {
        let targets = vec![input::normalize("10.0.0.0/29").unwrap(), input::normalize("example.com").unwrap()];
        // Inputs 2..4 (10.0.0.3, 10.0.0.4) failed.
        let cov = Coverage::new(&targets, &[(2, 2)]);
        assert!(cov.covers("10.0.0.1", None));
        assert!(!cov.covers("10.0.0.3", None), "failed batch is not covered");
        assert!(!cov.covers("10.0.0.9", None), "outside the targets");
        assert!(cov.covers("93.184.215.14", Some("example.com")), "domain target by hostname");
    }

    #[test]
    fn volatile_values_are_ignored() {
        let a = http_fields(&row(
            json!({"server": "nginx", "date": "Mon", "etag": "1", "x_frame_options": "DENY"}),
            json!(["PHPSESSID=abc; Path=/", "lang=pl"]),
        ));
        let b = http_fields(&row(
            json!({"server": "nginx", "date": "Tue", "etag": "2", "x_frame_options": "DENY"}),
            json!(["PHPSESSID=zzz; Path=/", "lang=pl"]),
        ));
        assert_eq!(a, b, "dates, etags and cookie values must not count as changes");
        assert_eq!(a["cookies"], "PHPSESSID, lang");
        assert_eq!(a["headers"], "server, x_frame_options");
        assert_eq!(a["tls.subject_cn"], "a.example");
        assert_eq!(a["tls.san"], "a, b");
        assert!(!a.contains_key("tls.timestamp"));
    }

    #[test]
    fn interesting_header_change_is_visible() {
        let a = http_fields(&row(json!({"server": "nginx/1.24"}), json!([])));
        let b = http_fields(&row(json!({"server": "nginx/1.27", "x_debug_token": "1"}), json!([])));
        assert_ne!(a["header.server"], b["header.server"]);
        assert_ne!(a["headers"], b["headers"], "a new header name is a change");
    }
}
