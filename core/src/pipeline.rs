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

/// Page body read by httpx (`-rstr`) and kept for signatures: bounded so one batch of web
/// servers stays far below the tool output cap (`engine::MAX_STDOUT`).
const BODY_READ: &str = "32768";
const BODY_KEEP: usize = 32 * 1024;
/// Same for path probes (a probe only needs to show what is there).
const PROBE_READ: &str = "16384";
const PROBE_KEEP: usize = 16 * 1024;
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
    /// Clock window (local `HH:MM[:SS]` in `timezone`); absent in snapshots taken before 0009.
    #[serde(default)]
    pub window_start: Option<String>,
    #[serde(default)]
    pub window_end: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    /// ISO weekdays the clock window opens on; empty = every day.
    #[serde(default)]
    pub schedule_days: Vec<i32>,
    /// Demo: the window closes after N seconds and reopens N seconds later.
    #[serde(default)]
    pub test_window_seconds: Option<i32>,
    /// `pause_resume` (default) or `stop` when the window closes.
    #[serde(default)]
    pub on_window_exceeded: Option<String>,
}

impl ScanConfig {
    fn clock_window(&self) -> Option<(&str, &str, &str)> {
        match (&self.window_start, &self.window_end) {
            (Some(s), Some(e)) => Some((s, e, self.timezone.as_deref().unwrap_or("Europe/Warsaw"))),
            _ => None,
        }
    }
}

/// End of the current window: test window, clock window (containing `start`) or duration.
/// A run started outside its clock window ("start now") has no deadline.
async fn window_deadline(db: &sqlx::PgPool, scan: &ScanConfig, start: DateTime<Utc>) -> sqlx::Result<Option<DateTime<Utc>>> {
    if let Some(secs) = scan.test_window_seconds {
        return Ok(Some(start + ChronoDuration::seconds(secs as i64)));
    }
    if let Some((ws, we, tz)) = scan.clock_window() {
        let close: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT asi_window_close($1::time, $2::time, $3, $4::int[], $5)")
                .bind(ws)
                .bind(we)
                .bind(tz)
                .bind(&scan.schedule_days)
                .bind(start)
                .fetch_one(db)
                .await?;
        return Ok(close);
    }
    Ok(scan.window_minutes.map(|m| start + ChronoDuration::minutes(m as i64)))
}

/// When a paused run continues: the next window opening.
async fn next_window(db: &sqlx::PgPool, scan: &ScanConfig, window_start: DateTime<Utc>) -> sqlx::Result<DateTime<Utc>> {
    if let Some(secs) = scan.test_window_seconds {
        return Ok(Utc::now() + ChronoDuration::seconds(secs as i64));
    }
    if let Some((ws, _, tz)) = scan.clock_window() {
        let next: Option<DateTime<Utc>> = sqlx::query_scalar("SELECT asi_next_window_open($1::time, $2, $3::int[], now())")
            .bind(ws)
            .bind(tz)
            .bind(&scan.schedule_days)
            .fetch_one(db)
            .await?;
        if let Some(n) = next {
            return Ok(n);
        }
    }
    let period = scan.repeat_every_minutes.map(i64::from).unwrap_or(DEFAULT_WINDOW_PERIOD_MIN);
    Ok(window_start + ChronoDuration::minutes(period))
}

/// User-Agent of HTTP requests when settings have none.
pub(crate) const DEFAULT_USER_AGENT: &str = "ASI/0.1 (Attack Surface Intelligence; authorised scan)";

/// nmap service names that can carry HTTP (or that nmap could not identify).
fn may_speak_http(name: Option<&str>) -> bool {
    match name {
        None => true,
        Some(n) => {
            let n = n.to_ascii_lowercase();
            n.contains("http") || n.contains("www") || matches!(n.as_str(), "ssl" | "tls" | "unknown" | "tcpwrapped" | "")
        }
    }
}

/// Hosts grouped by their set of open ports → (nmap port list, hosts). At most 32 groups:
/// the rest share one group with the union of their ports (bounded extra probing).
fn port_groups(open: &BTreeMap<String, parse::HostPorts>) -> Vec<(String, Vec<String>)> {
    let mut by_set: BTreeMap<BTreeSet<u16>, Vec<String>> = BTreeMap::new();
    for (ip, hp) in open {
        let set: BTreeSet<u16> = hp.ports.iter().copied().collect();
        if !set.is_empty() {
            by_set.entry(set).or_default().push(ip.clone());
        }
    }
    let mut groups: Vec<(BTreeSet<u16>, Vec<String>)> = by_set.into_iter().collect();
    groups.sort_by_key(|g| std::cmp::Reverse(g.1.len()));
    if groups.len() > 32 {
        let rest = groups.split_off(31);
        let ports = rest.iter().flat_map(|g| g.0.iter().copied()).collect();
        let hosts = rest.into_iter().flat_map(|g| g.1).collect();
        groups.push((ports, hosts));
    }
    groups
        .into_iter()
        .map(|(ports, hosts)| (ports.iter().map(u16::to_string).collect::<Vec<_>>().join(","), hosts))
        .collect()
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
    /// Started with "now" while its clock window was closed: runs without the window.
    ignore_window: bool,
    stats: sqlx::types::Json<RunStats>,
    target_snapshot: sqlx::types::Json<Vec<Target>>,
    config_snapshot: sqlx::types::Json<ScanConfig>,
}

/// Networks no run may scan: every target marked `excluded` (the "no-scan list") plus the
/// administrator's `ASI_EXCLUDED_CIDRS`.
pub(crate) async fn excluded_networks(state: &AppState) -> sqlx::Result<Vec<ipnet::IpNet>> {
    let values: Vec<String> = sqlx::query_scalar("SELECT value FROM targets WHERE excluded AND kind <> 'domain'")
        .fetch_all(&state.db)
        .await?;
    Ok(values
        .iter()
        .filter_map(|v| input::as_net(v))
        .chain(state.config.excluded_cidrs.iter().copied().map(ipnet::IpNet::V4))
        .collect())
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
    /// Paused by a user (`POST /api/v1/scans/{id}/pause`); resumes only on request.
    ManualPause,
    Cancelled,
}

/// Execute (or resume) a run. Errors here fail the run; per-batch tool errors are
/// retried once, then recorded in stats as uncovered and the run continues.
pub async fn execute_run(state: AppState, run_id: Uuid) -> Result<()> {
    let db = &state.db;
    // Freeze targets and scan settings once per run (F-07): edits apply to the next run.
    // Excluded targets and ASI_EXCLUDED_CIDRS are subtracted from the address set here, so
    // an excluded address inside a scanned range never reaches a batch (nor its coverage).
    let frozen: bool = sqlx::query_scalar("SELECT target_snapshot IS NOT NULL FROM scan_runs WHERE id = $1")
        .bind(run_id)
        .fetch_one(db)
        .await?;
    if !frozen {
        let selected: Vec<(input::TargetKind, String)> = sqlx::query_as(
            "SELECT t.kind, t.value FROM scan_runs r JOIN scan_targets st ON st.scan_id = r.scan_id
             JOIN targets t ON t.id = st.target_id
             WHERE r.id = $1 AND NOT t.excluded ORDER BY t.value",
        )
        .bind(run_id)
        .fetch_all(db)
        .await?;
        let targets: Vec<Target> = selected.into_iter().map(|(kind, value)| Target { kind, value, except: Vec::new() }).collect();
        let targets = input::with_exclusions(targets, &excluded_networks(&state).await?);
        sqlx::query("UPDATE scan_runs SET target_snapshot = $2 WHERE id = $1 AND target_snapshot IS NULL")
            .bind(run_id)
            .bind(sqlx::types::Json(&targets))
            .execute(db)
            .await?;
    }
    sqlx::query(
        "UPDATE scan_runs r SET
             config_snapshot = COALESCE(r.config_snapshot, (
                 SELECT to_jsonb(c) FROM (SELECT inactive_after_misses, rate_limit_pps, window_minutes,
                     repeat_every_minutes, ports, batch_size, preflight, window_start::text AS window_start,
                     window_end::text AS window_end, timezone, schedule_days, test_window_seconds,
                     on_window_exceeded FROM scans WHERE id = r.scan_id) c))
         WHERE r.id = $1",
    )
    .bind(run_id)
    .execute(db)
    .await?;

    let run: RunRow = sqlx::query_as(
        "SELECT checkpoint, window_started_at, ignore_window, stats, target_snapshot, config_snapshot FROM scan_runs WHERE id = $1",
    )
    .bind(run_id)
    .fetch_one(db)
    .await?;
    let scan = run.config_snapshot.0;

    let targets = run.target_snapshot.0;
    anyhow::ensure!(targets.iter().all(|t| state.config.permits_target(&t.value)), "run outside administrator-approved network");
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
    let deadline = if run.ignore_window && scan.test_window_seconds.is_none() {
        None
    } else {
        window_deadline(db, &scan, window_start).await?
    };
    tracing::info!(%run_id, total, from = %offset, size, "run started");

    let mut outcome = Outcome::Done;
    while offset < total {
        match run_status(db, run_id).await?.as_str() {
            "cancelled" => {
                outcome = Outcome::Cancelled;
                break;
            }
            // Paused from the dashboard: stop after the last finished batch.
            "paused" => {
                outcome = Outcome::ManualPause;
                break;
            }
            _ => {}
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
            // Detection signatures on what this run collected (no extra network traffic).
            if let Err(e) = crate::signatures::evaluate_run(db, &state.config.data_key, run_id).await {
                stats.error(format!("signature evaluation failed: {e}"));
            }
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
            if n > 0 {
                // DefectDojo "automatic export" (dashboard setting); never blocks or fails the run.
                tokio::spawn(crate::v1_admin::auto_export(state.clone(), run_id));
            }
            n > 0
        }
        Outcome::Paused if scan.on_window_exceeded.as_deref() == Some("stop") => {
            // The scan is configured to stop at the window's end: what is not scanned stays
            // uncovered, so the run is closed as cancelled (no diff on partial coverage).
            stats.error("window closed: stopped (on_window_exceeded = stop)".into());
            sqlx::query("UPDATE scan_runs SET status = 'cancelled', error = $2 WHERE id = $1 AND status = 'running'")
                .bind(run_id)
                .bind("Okno skanowania zamknięte — przebieg zatrzymany (tryb „stop”).")
                .execute(db)
                .await?;
            false
        }
        Outcome::ManualPause => {
            sqlx::query("UPDATE scan_runs SET stats = $2 WHERE id = $1 AND status = 'paused'")
                .bind(run_id)
                .bind(sqlx::types::Json(&stats))
                .execute(db)
                .await?;
            tracing::info!(%run_id, "run paused by a user");
            true
        }
        Outcome::Paused => {
            stats.pauses += 1;
            let resume_at = next_window(db, &scan, window_start).await?;
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

pub(crate) async fn run_status(db: &sqlx::PgPool, run_id: Uuid) -> sqlx::Result<String> {
    sqlx::query_scalar("SELECT status::text FROM scan_runs WHERE id = $1").bind(run_id).fetch_one(db).await
}

pub(crate) async fn is_cancelled(db: &sqlx::PgPool, run_id: Uuid) -> sqlx::Result<bool> {
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
    // Addresses the tools may report back: the inputs, plus what approved names resolve to now
    // (a name may have changed since the scan was planned, so it is resolved again here).
    let mut resolved: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for target in inputs {
        let approved = state.config.permits_target(target);
        anyhow::ensure!(approved, "target outside administrator-approved network");
        if state.config.permits_domain(target) {
            for ip in state.config.resolve_in_scope(target).await.map_err(|e| anyhow::anyhow!(e))? {
                resolved.insert(ip.to_string());
            }
        }
    }
    let tools = state.config.tools_dir.as_str();
    let allowed = &state.config.allowed_ports;
    anyhow::ensure!(state.config.permits_ports(&scan.ports), "use explicit approved ports");
    let preflight_ports = format!("-PS{}", scan.ports);
    let slots = state.config.max_runs.max(1);
    let share = state.config.global_rate as usize / slots;
    anyhow::ensure!(share > 0, "worker slots exceed global rate budget");
    let rate = (scan.rate_limit_pps.max(1) as usize).min(share).to_string();
    let thread_share = state.config.max_concurrency / slots;
    anyhow::ensure!(thread_share > 0, "worker slots exceed connection budget");
    let threads = thread_share.min(100).to_string();
    let deadline = tokio::time::Instant::now() + budget;
    let left = || deadline.saturating_duration_since(tokio::time::Instant::now());
    let mut stats = BatchStats::default();
    // Identify ourselves honestly to the web servers we fingerprint (settings → user_agent).
    let user_agent: String = sqlx::query_scalar("SELECT value #>> '{scan_safety,user_agent}' FROM settings WHERE key = 'system'")
        .fetch_optional(&state.db)
        .await?
        .flatten()
        .filter(|ua: &String| !ua.trim().is_empty() && !ua.contains(['\r', '\n']))
        .unwrap_or_else(|| DEFAULT_USER_AGENT.to_string());
    let ua_header = format!("User-Agent: {user_agent}");

    // 1) Pre-flight: hosts that are up even with no scanned port open. It does not filter
    //    the inputs of step 2 (F-06): "no answer to probes" is not "no services".
    let mut alive: BTreeMap<String, Option<String>> = BTreeMap::new();
    if scan.preflight {
        let list = ListFile::new(run_id, index, "pre", inputs.to_vec()).await?;
        let xml = engine::run(
            tools,
            Tool::Nmap,
            // -T4 --max-retries 0: unprivileged nmap pings with connect(); with retries, the
            // connects to dead addresses pile up and a /22 took ~160 s at 100% CPU — 6 s
            // without (same hosts found). A lost probe only loses a host with no open port in
            // the list: step 2 still scans every input, with a retry.
            &["-sn", "-n", "-T4", "--max-retries", "0", &preflight_ports, "--max-rate", &rate, "-oX", "-", "-iL", list.arg()],
            left(),
        )
        .await
        .context("pre-flight")?;
        alive = parse::nmap_alive(&xml)?;
    }

    // 2) Open ports on every input. CONNECT scan by default (no raw-socket capabilities);
    //    SYN (half-open, nothing reaches the applications) when enabled — compose.syn.yaml.
    let list = ListFile::new(run_id, index, "ports", inputs.to_vec()).await?;
    let syn = state.config.syn_scan.as_deref();
    // -duc: no update check — the scanner never talks to anything but the targets.
    let mut naabu_args = vec![
        "-l", list.arg(), "-s", if syn.is_some() { "s" } else { "c" }, "-Pn", "-rate", &rate, "-c", &threads,
        "-retries", "1", "-json", "-silent", "-duc",
    ];
    if let Some(r) = state.config.dns_resolvers.as_deref() {
        naabu_args.extend(["-r", r]);
    }
    match scan.ports.as_str() {
        preset @ ("100" | "1000" | "full") => naabu_args.extend(["-top-ports", preset]),
        list => naabu_args.extend(["-p", list]),
    }
    let naabu_out = match syn {
        Some(bin) => engine::run_bin(bin, "naabu", &naabu_args, left()).await,
        None => engine::run(tools, Tool::Naabu, &naabu_args, left()).await,
    }
    .context("naabu")?;
    let open = parse::naabu(&naabu_out);
    anyhow::ensure!(open.iter().all(|(ip,h)| (inputs.contains(ip) || resolved.contains(ip)) && state.config.permits_target(ip) && h.ports.iter().all(|port| allowed.contains(port))), "tool returned address outside approved batch");
    for (ip, hp) in &open {
        alive.entry(ip.clone()).or_insert_with(|| hp.hostname.clone());
    }
    stats.alive = alive.len() as u64;
    stats.open_ports = open.values().map(|h| h.ports.len() as u64).sum();

    // 3) Service/version detection only on the ports found open on each host: hosts are
    //    grouped by their open-port set, so no host is probed on its neighbours' ports.
    //    --version-light: the common probes only (no RTSP/SIP/... on every unknown port).
    let mut services: BTreeMap<(String, u16), parse::NmapService> = BTreeMap::new();
    let mut sv_failed = false;
    for (group, (ports, hosts)) in port_groups(&open).into_iter().enumerate() {
        let list = ListFile::new(run_id, index, &format!("sv{group}"), hosts).await?;
        match engine::run(
            tools,
            Tool::Nmap,
            &[
                "-sT", "-sV", "--version-light", "-Pn", "-n", "--max-rate", &rate, "--host-timeout", "90s", "-p", &ports,
                "-oX", "-", "-iL", list.arg(),
            ],
            left(),
        )
        .await
        {
            Ok(xml) => {
                for s in parse::nmap_services(&xml)? {
                    services.insert((s.ip.clone(), s.port), s);
                }
            }
            // Out of time: abort the batch so it is redone whole, not stored half-scanned.
            Err(e) if left().is_zero() => return Err(e.context("window closed during nmap -sV")),
            // Keep the ports even if version detection fails; confidence stays low.
            Err(e) => {
                sv_failed = true;
                tracing::warn!(%run_id, index, "nmap -sV failed: {e:#}");
            }
        }
    }
    // 4) HTTP/HTTPS fingerprint only where a web server can be: ports nmap identified as
    //    HTTP/TLS or could not identify. No HTTP requests to SSH, AMQP, databases... (they
    //    log them as protocol errors). If version detection failed, every open port.
    let mut http = Vec::new();
    if !open.is_empty() {
        let endpoints: Vec<String> = open.iter().flat_map(|(ip, hp)| {
            // Never reconnect using a name learned from a remote service; a domain the
            // operator gave as a target is used as is (virtual hosts answer by name).
            let name = hp.hostname.as_ref().filter(|h| inputs.contains(h)).unwrap_or(ip);
            let services = &services;
            hp.ports
                .iter()
                .filter(move |p| {
                    // A name guessed from the port table only (nmap conf 3 → 0.3) is not an
                    // identification: such ports still get the HTTP probe.
                    let svc = services.get(&(ip.clone(), **p)).filter(|s| s.confidence >= 0.5);
                    sv_failed || may_speak_http(svc.and_then(|s| s.name.as_deref()))
                })
                .map(move |p| format!("{name}:{p}"))
        }).collect();
        let list = ListFile::new(run_id, index, "http", endpoints).await?;
        match engine::run(
            tools,
            Tool::Httpx,
            &[
                "-l", list.arg(), "-json", "-silent", "-nc", "-sc", "-title", "-server", "-td", "-duc",
                "-random-agent=false", "-H", &ua_header,
                // No -fr: redirects are recorded (-location), never followed, so a 30x cannot
                // lead the scanner outside the approved targets (F-03).
                "-irh", "-tls-grab", "-location", "-ip",
                // Page body for html/footer signatures, read up to 32 KiB per page.
                "-irr", "-rstr", BODY_READ,
                "-rl", &rate, "-t", &threads, "-timeout", "5", "-retries", "1",
            ],
            left(),
        )
        .await
        {
            Ok(out) => {
                http = parse::httpx(&out);
                // Never persist raw HTTP output containing credentials.
            }
            Err(e) if left().is_zero() => return Err(e.context("window closed during httpx")),
            Err(e) => tracing::warn!(%run_id, index, "httpx failed: {e:#}"),
        }
    }

    // 4b) Safe GET probes for "path" signature conditions (/admin, /login, /version...): only
    //     the paths of enabled signatures, only on web services found above, GET without
    //     credentials, redirects recorded but not followed, same rate limit and User-Agent.
    let mut probes = Vec::new();
    let paths = crate::signatures::probe_paths(&state.db).await?;
    if !http.is_empty() && !paths.is_empty() {
        let bases: std::collections::BTreeSet<String> = http
            .iter()
            .filter_map(|(r, _)| Some(format!("{}://{}:{}", r.url.split("://").next()?, r.input.rsplit_once(':')?.0, r.port)))
            .collect();
        let list = ListFile::new(run_id, index, "probe", bases.into_iter().collect()).await?;
        let joined = paths.join(",");
        match engine::run(
            tools,
            Tool::Httpx,
            &[
                "-l", list.arg(), "-path", &joined, "-json", "-silent", "-nc", "-sc", "-title", "-duc", "-ip",
                "-random-agent=false", "-H", &ua_header, "-irr", "-rstr", PROBE_READ,
                "-rl", &rate, "-t", &threads, "-timeout", "5", "-retries", "0",
            ],
            left(),
        )
        .await
        {
            Ok(out) => probes = parse::httpx(&out),
            Err(e) if left().is_zero() => return Err(e.context("window closed during path probes")),
            Err(e) => tracing::warn!(%run_id, index, "path probes failed: {e:#}"),
        }
    }

    // 5) Persist in one transaction; sensitive fields encrypted with pgp_sym_encrypt.
    let key = state.config.data_key.as_str();
    let mut tx = state.db.begin().await?;
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

    for (rec, _) in &http {
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
                favicon_hash, is_admin, is_staging, headers_enc, cookies_enc, tls_enc, raw_enc, body_enc)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                pgp_sym_encrypt($11, $15), pgp_sym_encrypt($12, $15), pgp_sym_encrypt($13, $15), pgp_sym_encrypt($14, $15),
                pgp_sym_encrypt($16, $15))
             ON CONFLICT (service_id, url) DO UPDATE SET status_code = EXCLUDED.status_code, title = EXCLUDED.title,
                redirects = EXCLUDED.redirects, technologies = EXCLUDED.technologies, cms = EXCLUDED.cms,
                favicon_hash = EXCLUDED.favicon_hash, is_admin = EXCLUDED.is_admin, is_staging = EXCLUDED.is_staging,
                headers_enc = EXCLUDED.headers_enc, cookies_enc = EXCLUDED.cookies_enc,
                tls_enc = EXCLUDED.tls_enc, raw_enc = EXCLUDED.raw_enc, body_enc = EXCLUDED.body_enc",
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
        .bind(serde_json::to_string(&fingerprint::stored_headers(&rec.header))?)
        .bind((!cookies.is_empty()).then(|| serde_json::to_string(&cookies)).transpose()?)
        .bind(rec.tls.as_ref().map(|t| t.to_string()))
        .bind(None::<String>)
        .bind(key)
        .bind(rec.body.as_deref().map(|b| fingerprint::clip_body(b, BODY_KEEP)))
        .execute(&mut *tx)
        .await?;
    }
    for (rec, _) in &probes {
        let Some(port) = rec.port_num() else { continue };
        let Some(&service_id) = service_ids.get(&(rec.ip().to_string(), port)) else { continue };
        let Some(path) = rec.path.as_deref().filter(|p| paths.iter().any(|x| x == p)) else { continue };
        sqlx::query(
            "INSERT INTO http_probes (run_id, service_id, path, url, status_code, title, content_length, body_enc)
             VALUES ($1, $2, $3, $4, $5, $6, $7, pgp_sym_encrypt($8, $9))
             ON CONFLICT (service_id, path) DO UPDATE SET status_code = EXCLUDED.status_code, title = EXCLUDED.title,
                 content_length = EXCLUDED.content_length, body_enc = EXCLUDED.body_enc, url = EXCLUDED.url, probed_at = now()",
        )
        .bind(run_id)
        .bind(service_id)
        .bind(path)
        .bind(&rec.url)
        .bind(rec.status_code)
        .bind(&rec.title)
        .bind(rec.content_length)
        .bind(rec.body.as_deref().map(|b| fingerprint::clip_body(b, PROBE_KEEP)).unwrap_or_default())
        .bind(key)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    tracing::info!(%run_id, index, alive = stats.alive, open = stats.open_ports, http = stats.http, probes = probes.len(), "batch done");
    Ok(stats)
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_web_capable_ports_go_to_httpx() {
        for yes in [None, Some("http"), Some("https"), Some("http-proxy"), Some("ssl/http"), Some("ssl"), Some("unknown"), Some("tcpwrapped")] {
            assert!(may_speak_http(yes), "{yes:?}");
        }
        for no in [Some("ssh"), Some("amqp"), Some("postgresql"), Some("mysql"), Some("ftp"), Some("smtp"), Some("redis")] {
            assert!(!may_speak_http(no), "{no:?}");
        }
    }

    #[test]
    fn hosts_are_probed_only_on_their_own_ports() {
        let hp = |ports: &[u16]| parse::HostPorts { hostname: None, ports: ports.iter().copied().collect() };
        let open: BTreeMap<String, parse::HostPorts> = [
            ("10.0.0.1".to_string(), hp(&[22, 80])),
            ("10.0.0.2".to_string(), hp(&[80, 22])),
            ("10.0.0.3".to_string(), hp(&[443])),
        ]
        .into_iter()
        .collect();
        let g = port_groups(&open);
        assert_eq!(g.len(), 2);
        assert!(g.contains(&("22,80".to_string(), vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()])));
        assert!(g.contains(&("443".to_string(), vec!["10.0.0.3".to_string()])));
        let many: BTreeMap<String, parse::HostPorts> = (1..=40u16).map(|i| (format!("10.0.1.{i}"), hp(&[1000 + i]))).collect();
        let g = port_groups(&many);
        assert_eq!(g.len(), 32, "bounded number of nmap runs");
        assert_eq!(g.iter().map(|x| x.1.len()).sum::<usize>(), 40, "every host still covered");
    }

    use super::{may_speak_http, next_batch_size, parse, port_groups, valid_ports};
    use std::collections::BTreeMap;
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
