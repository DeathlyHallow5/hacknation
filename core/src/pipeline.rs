//! Pipeline A — executes one scan run batch by batch (PROJECT.md §3.2, §6).
//!
//! Per batch: pre-flight (`nmap -sn`) → ports (`naabu`, CONNECT scan) → services
//! (`nmap -sV` on open ports only) → HTTP/HTTPS fingerprint (`httpx`) → Postgres.
//!
//! Safety: every tool gets the scan's `rate_limit_pps`; batches run sequentially so a run
//! never exceeds that rate; tool timeouts are capped by the scan window, so a run stops at
//! the window end and resumes from its checkpoint in the next window.
//!
//! Integrity: targets and scan settings are frozen per run; a batch whose tools fail is
//! retried once at half size, then recorded as not covered and the run ends `partial`
//! (diffed only on what it covered, never a baseline).

use crate::{
    engine::{self, Tool},
    fingerprint,
    input::{self, Target},
    parse, AppState,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

/// Ports probed by pre-flight. Pre-flight only ADDS hosts that are up but have none of the
/// scanned ports open; it never removes inputs from port discovery, since a host that
/// ignores these probes may still have open ports (F-06).
const PREFLIGHT_PORTS: &str = "-PS21,22,23,25,53,80,110,135,139,143,443,445,3389,8080,8443";
/// Hard cap per tool invocation when the scan has no window.
pub(crate) const MAX_TOOL_TIME: Duration = Duration::from_secs(30 * 60);
/// Default period between windows if the scan has a window but no repeat interval.
const DEFAULT_WINDOW_PERIOD_MIN: i64 = 24 * 60;

/// Scan settings as frozen into `scan_runs.config_snapshot` at run start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub inactive_after_misses: i32,
    pub rate_limit_pps: i32,
    pub window_minutes: Option<i32>,
    pub repeat_every_minutes: Option<i32>,
    pub ports: String,
    pub batch_size: i32,
    pub preflight: bool,
}

/// Aim for batches of this duration (or half the remaining window, if shorter).
const TARGET_BATCH_SECS: f64 = 120.0;

/// Size the next batch from the measured speed of the last one ("podział adresów na
/// optymalne podgrupy w zależności od szybkości skanowania"). Capped by the scan's batch_size.
fn next_batch_size(done: usize, secs: f64, deadline: Option<DateTime<Utc>>, max_size: usize) -> usize {
    let per_sec = done as f64 / secs.max(0.5);
    let target = match deadline {
        Some(d) => ((d - Utc::now()).num_seconds() as f64 / 2.0).clamp(10.0, TARGET_BATCH_SECS),
        None => TARGET_BATCH_SECS,
    };
    ((per_sec * target).round() as usize).clamp(1, max_size)
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RunStats {
    pub hosts_total: u64,
    pub hosts_done: u64,
    /// Active scanning time across all windows (excludes pauses).
    pub elapsed_secs: f64,
    /// Estimated active scanning time left at the measured speed.
    pub eta_secs: Option<u64>,
    pub batch_size_current: Option<usize>,
    pub batches_done: u64,
    pub alive: u64,
    pub open_ports: u64,
    pub services_identified: u64,
    pub http: u64,
    pub admin_panels: u64,
    pub staging: u64,
    pub pauses: u64,
    /// Hosts re-scanned at the end because they (or some ports) went missing.
    pub rechecked: u64,
    /// Missing hosts that answered the re-check (transient misses, not changes).
    pub recovered: u64,
    pub diff: Option<crate::history::DiffSummary>,
    /// Diff/analysis outcome, separate from the scan status: baseline | complete | failed.
    pub analysis: Option<String>,
    /// Inputs whose batch failed even after a retry: (offset, count). Not covered by
    /// this run, so they are excluded from its diff instead of reported as gone.
    pub failed_ranges: Vec<(u64, u64)>,
    pub hosts_failed: u64,
    pub errors: Vec<String>,
}

impl RunStats {
    fn add(&mut self, b: &BatchStats) {
        self.batches_done += 1;
        self.alive += b.alive;
        self.open_ports += b.open_ports;
        self.services_identified += b.services_identified;
        self.http += b.http;
        self.admin_panels += b.admin_panels;
        self.staging += b.staging;
    }

    pub(crate) fn error(&mut self, msg: String) {
        tracing::warn!("{msg}");
        self.errors.push(msg);
        if self.errors.len() > 20 {
            self.errors.remove(0);
        }
    }
}

#[derive(Debug, Default)]
pub struct BatchStats {
    alive: u64,
    open_ports: u64,
    services_identified: u64,
    http: u64,
    admin_panels: u64,
    staging: u64,
}

#[derive(sqlx::FromRow)]
struct RunRow {
    checkpoint: i64,
    window_started_at: Option<DateTime<Utc>>,
    stats: sqlx::types::Json<RunStats>,
    target_snapshot: sqlx::types::Json<Vec<Target>>,
    config_snapshot: sqlx::types::Json<ScanConfig>,
}

/// `ports` validation shared with the API.
pub fn valid_ports(spec: &str) -> bool {
    matches!(spec, "100" | "1000" | "full")
        || (!spec.is_empty()
            && spec.split(',').all(|part| {
                let mut ends = part.splitn(2, '-').map(|p| p.trim().parse::<u16>());
                match (ends.next(), ends.next()) {
                    (Some(Ok(a)), None) => a > 0,
                    (Some(Ok(a)), Some(Ok(b))) => a > 0 && a <= b,
                    _ => false,
                }
            }))
}

enum Outcome {
    Done,
    Paused,
    Cancelled,
}

/// Execute (or resume) a run. Errors here fail the run; per-batch tool errors are
/// retried once, then recorded in stats as uncovered and the run continues.
pub async fn execute_run(state: AppState, run_id: Uuid) -> Result<()> {
    let db = &state.db;
    // Freeze targets and scan settings once per run (F-07): edits apply to the next run.
    sqlx::query(
        "UPDATE scan_runs r SET
             target_snapshot = COALESCE(r.target_snapshot, (
                 SELECT COALESCE(jsonb_agg(jsonb_build_object('kind', t.kind, 'value', t.value) ORDER BY t.value), '[]'::jsonb)
                 FROM scan_targets st JOIN targets t ON t.id = st.target_id WHERE st.scan_id = r.scan_id)),
             config_snapshot = COALESCE(r.config_snapshot, (
                 SELECT to_jsonb(c) FROM (SELECT inactive_after_misses, rate_limit_pps, window_minutes,
                     repeat_every_minutes, ports, batch_size, preflight FROM scans WHERE id = r.scan_id) c))
         WHERE r.id = $1",
    )
    .bind(run_id)
    .execute(db)
    .await?;

    let run: RunRow = sqlx::query_as(
        "SELECT checkpoint, window_started_at, stats, target_snapshot, config_snapshot FROM scan_runs WHERE id = $1",
    )
    .bind(run_id)
    .fetch_one(db)
    .await?;
    let scan = run.config_snapshot.0;

    let targets = run.target_snapshot.0;
    let total = input::total_hosts(&targets);
    let max_size = scan.batch_size.max(1) as usize;
    let mut stats = run.stats.0;
    stats.hosts_total = total as u64;
    // checkpoint = number of scan inputs already done (an offset, not a batch index), so the
    // batch size can adapt between batches without breaking resume.
    let mut offset = run.checkpoint.max(0) as u128;
    let mut size = stats.batch_size_current.unwrap_or(max_size).clamp(1, max_size);
    // Offset of a batch that already failed once; a second failure there is recorded.
    let mut retrying: Option<u128> = None;

    let window_start = run.window_started_at.unwrap_or_else(Utc::now);
    let deadline = scan.window_minutes.map(|m| window_start + ChronoDuration::minutes(m as i64));
    tracing::info!(%run_id, total, from = %offset, size, "run started");

    let mut outcome = Outcome::Done;
    while offset < total {
        if is_cancelled(db, run_id).await? {
            outcome = Outcome::Cancelled;
            break;
        }
        let budget = match deadline {
            Some(d) if Utc::now() >= d => {
                outcome = Outcome::Paused;
                break;
            }
            Some(d) => (d - Utc::now()).to_std().unwrap_or_default().min(MAX_TOOL_TIME),
            None => MAX_TOOL_TIME,
        };

        let hosts = input::slice(&targets, offset, size);
        let batch_no = stats.batches_done as usize;
        let started = std::time::Instant::now();
        match run_batch(&state, &scan, run_id, batch_no, &hosts, budget).await {
            Ok(b) => {
                let secs = started.elapsed().as_secs_f64().max(0.5);
                stats.add(&b);
                stats.elapsed_secs += secs;
                offset += hosts.len() as u128;
                stats.hosts_done = offset as u64;
                size = next_batch_size(hosts.len(), secs, deadline, max_size);
                retrying = None;
            }
            Err(e) if deadline.is_some_and(|d| Utc::now() >= d) => {
                // Window closed mid-batch: nothing of it was stored. Redo it in the next
                // window with half the size, so an oversized batch cannot loop forever.
                size = (size / 2).max(1);
                tracing::info!(%run_id, batch_no, next_size = size, "window closed mid-batch: {e:#}");
                outcome = Outcome::Paused;
            }
            Err(e) if retrying != Some(offset) => {
                // First failure: retry the same offset at half size (isolates a bad input,
                // rides out a transient tool error).
                tracing::warn!(%run_id, batch_no, "batch failed, retrying at half size: {e:#}");
                retrying = Some(offset);
                size = (size / 2).max(1);
            }
            Err(e) => {
                // Failed twice: record the slice as NOT covered (F-04) and move on.
                stats.error(format!("batch {batch_no} ({} inputs from offset {offset}) not covered: {e:#}", hosts.len()));
                stats.failed_ranges.push((offset as u64, hosts.len() as u64));
                stats.hosts_failed += hosts.len() as u64;
                stats.batches_done += 1;
                offset += hosts.len() as u128;
                stats.hosts_done = offset as u64;
                retrying = None;
            }
        }
        stats.batch_size_current = Some(size);
        stats.eta_secs = (stats.hosts_done > 0 && stats.elapsed_secs > 0.0).then(|| {
            let per_sec = stats.hosts_done as f64 / stats.elapsed_secs;
            ((total - offset) as f64 / per_sec).round() as u64
        });
        let batches_left = (total - offset).div_ceil(size as u128) as i32;
        sqlx::query("UPDATE scan_runs SET checkpoint = $2, total_batches = $3, stats = $4 WHERE id = $1")
            .bind(run_id)
            .bind(offset as i64)
            .bind(stats.batches_done as i32 + batches_left)
            .bind(sqlx::types::Json(&stats))
            .execute(db)
            .await?;
        if matches!(outcome, Outcome::Paused) {
            break;
        }
    }
    if matches!(outcome, Outcome::Done) && is_cancelled(db, run_id).await? {
        outcome = Outcome::Cancelled;
    }

    let finished = match outcome {
        Outcome::Done => {
            crate::history::finalize(&state, &scan, run_id, &targets, &mut stats, deadline).await;
            // Some inputs were not covered: the run is usable, but only as 'partial'.
            let status = if stats.hosts_failed > 0 { "partial" } else { "done" };
            let n = sqlx::query(
                "UPDATE scan_runs SET status = $3::scan_status, finished_at = now(), stats = $2
                 WHERE id = $1 AND status = 'running'",
            )
            .bind(run_id)
            .bind(sqlx::types::Json(&stats))
            .bind(status)
            .execute(db)
            .await?
            .rows_affected();
            tracing::info!(%run_id, status, "run finished");
            n > 0
        }
        Outcome::Paused => {
            stats.pauses += 1;
            let period = scan.repeat_every_minutes.map(i64::from).unwrap_or(DEFAULT_WINDOW_PERIOD_MIN);
            let resume_at = window_start + ChronoDuration::minutes(period);
            let n = sqlx::query("UPDATE scan_runs SET status = 'paused', resume_at = $2, stats = $3 WHERE id = $1 AND status = 'running'")
                .bind(run_id)
                .bind(resume_at)
                .bind(sqlx::types::Json(&stats))
                .execute(db)
                .await?
                .rows_affected();
            tracing::info!(%run_id, %resume_at, "window closed, run paused");
            n > 0
        }
        Outcome::Cancelled => false,
    };
    if !finished {
        // Cancelled (possibly while finalizing): keep 'cancelled', record the end and stats.
        sqlx::query(
            "UPDATE scan_runs SET finished_at = COALESCE(finished_at, now()), stats = $2
             WHERE id = $1 AND status = 'cancelled'",
        )
        .bind(run_id)
        .bind(sqlx::types::Json(&stats))
        .execute(db)
        .await?;
        tracing::info!(%run_id, "run cancelled");
    }
    Ok(())
}

async fn is_cancelled(db: &sqlx::PgPool, run_id: Uuid) -> sqlx::Result<bool> {
    sqlx::query_scalar("SELECT status = 'cancelled' FROM scan_runs WHERE id = $1")
        .bind(run_id)
        .fetch_one(db)
        .await
}

/// Temporary input list for `-iL` / `-l`, removed on drop.
struct ListFile(PathBuf);

impl ListFile {
    async fn new(run_id: Uuid, index: usize, stage: &str, lines: Vec<String>) -> Result<Self> {
        let dir = std::env::temp_dir().join("asi");
        tokio::fs::create_dir_all(&dir).await?;
        let path = dir.join(format!("{run_id}-{index}-{stage}.txt"));
        tokio::fs::write(&path, lines.join("\n") + "\n").await?;
        Ok(Self(path))
    }

    fn arg(&self) -> &str {
        self.0.to_str().expect("utf-8 temp path")
    }
}

impl Drop for ListFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub(crate) async fn run_batch(
    state: &AppState,
    scan: &ScanConfig,
    run_id: Uuid,
    index: usize,
    inputs: &[String],
    budget: Duration,
) -> Result<BatchStats> {
    let tools = state.config.tools_dir.as_str();
    let rate = scan.rate_limit_pps.to_string();
    let threads = state.config.max_concurrency.clamp(1, 100).to_string();
    let deadline = tokio::time::Instant::now() + budget;
    let left = || deadline.saturating_duration_since(tokio::time::Instant::now());
    let mut stats = BatchStats::default();

    // 1) Pre-flight: hosts that are up even with no scanned port open. It does not filter
    //    the inputs of step 2 (F-06): "no answer to probes" is not "no services".
    let mut alive: BTreeMap<String, Option<String>> = BTreeMap::new();
    if scan.preflight {
        let list = ListFile::new(run_id, index, "pre", inputs.to_vec()).await?;
        let xml = engine::run(
            tools,
            Tool::Nmap,
            &["-sn", "-n", PREFLIGHT_PORTS, "--max-rate", &rate, "-oX", "-", "-iL", list.arg()],
            left(),
        )
        .await
        .context("pre-flight")?;
        alive = parse::nmap_alive(&xml)?;
    }

    // 2) Open ports on every input (CONNECT scan: works without raw-socket capabilities).
    let list = ListFile::new(run_id, index, "ports", inputs.to_vec()).await?;
    let mut naabu_args = vec!["-l", list.arg(), "-s", "c", "-Pn", "-rate", &rate, "-c", &threads, "-retries", "1", "-json", "-silent"];
    match scan.ports.as_str() {
        preset @ ("100" | "1000" | "full") => naabu_args.extend(["-top-ports", preset]),
        list => naabu_args.extend(["-p", list]),
    }
    // Raw outputs are kept (encrypted) for DefectDojo, whose parsers take these native
    // formats: "Naabu Scan", "Nmap Scan", "httpx Scan" (PROJECT.md §11.2).
    let mut artifacts: Vec<(&str, String)> = Vec::new();
    let naabu_out = engine::run(tools, Tool::Naabu, &naabu_args, left()).await.context("naabu")?;
    let open = parse::naabu(&naabu_out);
    artifacts.push(("naabu", naabu_out));
    for (ip, hp) in &open {
        alive.entry(ip.clone()).or_insert_with(|| hp.hostname.clone());
    }
    stats.alive = alive.len() as u64;
    stats.open_ports = open.values().map(|h| h.ports.len() as u64).sum();

    // 3) Service/version detection only where something is open.
    let mut services: BTreeMap<(String, u16), parse::NmapService> = BTreeMap::new();
    if !open.is_empty() {
        let union: BTreeSet<u16> = open.values().flat_map(|h| h.ports.iter().copied()).collect();
        let ports = union.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
        let list = ListFile::new(run_id, index, "sv", open.keys().cloned().collect()).await?;
        match engine::run(
            tools,
            Tool::Nmap,
            &["-sT", "-sV", "-Pn", "-n", "--max-rate", &rate, "--host-timeout", "90s", "-p", &ports, "-oX", "-", "-iL", list.arg()],
            left(),
        )
        .await
        {
            Ok(xml) => {
                for s in parse::nmap_services(&xml)? {
                    services.insert((s.ip.clone(), s.port), s);
                }
                artifacts.push(("nmap", xml));
            }
            // Out of time: abort the batch so it is redone whole, not stored half-scanned.
            Err(e) if left().is_zero() => return Err(e.context("window closed during nmap -sV")),
            // Keep the ports even if version detection fails; confidence stays low.
            Err(e) => tracing::warn!(%run_id, index, "nmap -sV failed: {e:#}"),
        }
    }

    // 4) HTTP/HTTPS fingerprint on every open port (non-HTTP ports simply fail).
    let mut http = Vec::new();
    if !open.is_empty() {
        let endpoints = open.iter().flat_map(|(ip, hp)| {
            let name = hp.hostname.clone().or_else(|| alive.get(ip).cloned().flatten()).unwrap_or_else(|| ip.clone());
            hp.ports.iter().map(move |p| format!("{name}:{p}"))
        }).collect();
        let list = ListFile::new(run_id, index, "http", endpoints).await?;
        match engine::run(
            tools,
            Tool::Httpx,
            &[
                "-l", list.arg(), "-json", "-silent", "-nc", "-sc", "-title", "-server", "-td", "-favicon",
                // No -fr: redirects are recorded (-location), never followed, so a 30x cannot
                // lead the scanner outside the approved targets (F-03).
                "-irh", "-tls-grab", "-location", "-ip",
                "-rl", &rate, "-t", &threads, "-timeout", "5", "-retries", "1",
            ],
            left(),
        )
        .await
        {
            Ok(out) => {
                http = parse::httpx(&out);
                artifacts.push(("httpx", out));
            }
            Err(e) if left().is_zero() => return Err(e.context("window closed during httpx")),
            Err(e) => tracing::warn!(%run_id, index, "httpx failed: {e:#}"),
        }
    }

    // 5) Persist in one transaction; sensitive fields encrypted with pgp_sym_encrypt.
    let key = state.config.data_key.as_str();
    let mut tx = state.db.begin().await?;
    for (tool, content) in &artifacts {
        sqlx::query(
            "INSERT INTO run_artifacts (run_id, batch, tool, content_enc) VALUES ($1, $2, $3, pgp_sym_encrypt($4, $5))
             ON CONFLICT (run_id, batch, tool) DO UPDATE SET content_enc = EXCLUDED.content_enc, created_at = now()",
        )
        .bind(run_id)
        .bind(index as i32)
        .bind(tool)
        .bind(content)
        .bind(key)
        .execute(&mut *tx)
        .await?;
    }
    let mut service_ids: BTreeMap<(String, u16), Uuid> = BTreeMap::new();
    for (ip, hostname) in &alive {
        let host_id: Uuid = sqlx::query_scalar(
            "INSERT INTO hosts (run_id, address, hostname, state) VALUES ($1, $2::inet, $3, 'active')
             ON CONFLICT (run_id, address) DO UPDATE SET hostname = COALESCE(EXCLUDED.hostname, hosts.hostname), seen_at = now()
             RETURNING id",
        )
        .bind(run_id)
        .bind(ip)
        .bind(hostname)
        .fetch_one(&mut *tx)
        .await?;

        for port in open.get(ip).map(|h| h.ports.clone()).unwrap_or_default() {
            let svc = services.get(&(ip.clone(), port));
            if svc.is_some_and(|s| s.confidence >= 0.5) {
                stats.services_identified += 1;
            }
            let banner = svc.map(|s| serde_json::json!({ "extrainfo": s.extrainfo, "cpe": s.cpe }).to_string());
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO services (host_id, port, protocol, service, product, version, confidence, banner_enc)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, pgp_sym_encrypt($8, $9))
                 ON CONFLICT (host_id, port, protocol) DO UPDATE SET service = EXCLUDED.service,
                   product = EXCLUDED.product, version = EXCLUDED.version,
                   confidence = EXCLUDED.confidence, banner_enc = EXCLUDED.banner_enc
                 RETURNING id",
            )
            .bind(host_id)
            .bind(port as i32)
            .bind(svc.map(|s| s.protocol.as_str()).unwrap_or("tcp"))
            .bind(svc.and_then(|s| s.name.clone()))
            .bind(svc.and_then(|s| s.product.clone()))
            .bind(svc.and_then(|s| s.version.clone()))
            // Port open but service unknown: low but non-zero confidence.
            .bind(svc.map(|s| s.confidence).unwrap_or(0.3))
            .bind(banner)
            .bind(key)
            .fetch_one(&mut *tx)
            .await?;
            service_ids.insert((ip.clone(), port), id);
        }
    }

    for (rec, raw) in &http {
        let Some(port) = rec.port_num() else { continue };
        let Some(&service_id) = service_ids.get(&(rec.ip().to_string(), port)) else { continue };
        let is_admin = fingerprint::is_admin(&rec.url, rec.title.as_deref());
        let is_staging = fingerprint::is_staging(&rec.host, rec.title.as_deref());
        stats.http += 1;
        stats.admin_panels += is_admin as u64;
        stats.staging += is_staging as u64;
        let cookies = rec.cookies();
        sqlx::query(
            "INSERT INTO http_findings (service_id, url, status_code, title, redirects, technologies, cms,
                favicon_hash, is_admin, is_staging, headers_enc, cookies_enc, tls_enc, raw_enc)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                pgp_sym_encrypt($11, $15), pgp_sym_encrypt($12, $15), pgp_sym_encrypt($13, $15), pgp_sym_encrypt($14, $15))
             ON CONFLICT (service_id, url) DO UPDATE SET status_code = EXCLUDED.status_code, title = EXCLUDED.title,
                redirects = EXCLUDED.redirects, technologies = EXCLUDED.technologies, cms = EXCLUDED.cms,
                favicon_hash = EXCLUDED.favicon_hash, is_admin = EXCLUDED.is_admin, is_staging = EXCLUDED.is_staging,
                headers_enc = EXCLUDED.headers_enc, cookies_enc = EXCLUDED.cookies_enc,
                tls_enc = EXCLUDED.tls_enc, raw_enc = EXCLUDED.raw_enc",
        )
        .bind(service_id)
        .bind(&rec.url)
        .bind(rec.status_code)
        .bind(&rec.title)
        .bind(rec.redirects())
        .bind(&rec.tech)
        .bind(fingerprint::cms(&rec.tech))
        .bind(&rec.favicon)
        .bind(is_admin)
        .bind(is_staging)
        .bind(serde_json::to_string(&rec.header)?)
        .bind((!cookies.is_empty()).then(|| serde_json::to_string(&cookies)).transpose()?)
        .bind(rec.tls.as_ref().map(|t| t.to_string()))
        .bind(raw)
        .bind(key)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    tracing::info!(%run_id, index, alive = stats.alive, open = stats.open_ports, http = stats.http, "batch done");
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::{next_batch_size, valid_ports};
    use chrono::{Duration, Utc};

    #[test]
    fn batch_size_follows_speed_and_window() {
        // 10 hosts in 10 s = 1 host/s → ~120 hosts per 120 s target batch.
        assert_eq!(next_batch_size(10, 10.0, None, 1000), 120);
        // Capped by the scan's configured batch_size.
        assert_eq!(next_batch_size(10, 10.0, None, 64), 64);
        // 60 s of window left → aim for ~30 s batches.
        let d = Some(Utc::now() + Duration::seconds(60));
        assert!((28..=30).contains(&next_batch_size(10, 10.0, d, 1000)));
        // Very slow scan never drops below one input.
        assert_eq!(next_batch_size(1, 600.0, None, 64), 1);
    }

    #[test]
    fn port_specs() {
        for ok in ["100", "1000", "full", "22", "22,80,443", "8000-8100,443"] {
            assert!(valid_ports(ok), "{ok}");
        }
        for bad in ["", "0", "80-22", "abc", "22;rm -rf", "70000", "-p 1"] {
            assert!(!valid_ports(bad), "{bad}");
        }
    }
}
