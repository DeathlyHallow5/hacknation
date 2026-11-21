//! Module 6 — HTTP API consumed by the Next.js frontend through its `/api` proxy.
//! TODO(C): auth + RBAC extractor (rbac::Role::can) on every route; decrypted evidence in
//! `/runs/{id}/findings` must then require at least `Read` on the scan.

use crate::{diff::DiffEntry, engine::Tool, history, input, pipeline, AppState};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/tools", get(tools))
        .route("/api/targets", get(list_targets).post(import_targets))
        .route("/api/scans", get(list_scans).post(create_scan))
        .route("/api/scans/{id}/run", post(run_now))
        .route("/api/scans/{id}/runs", get(list_runs))
        .route("/api/runs/{id}", get(get_run))
        .route("/api/runs/{id}/findings", get(run_findings))
        .route("/api/runs/{id}/diff", get(run_diff))
        .route("/api/runs/{id}/cancel", post(cancel_run))
        .with_state(state)
}

type ApiError = (StatusCode, Json<Value>);
type ApiResult<T> = Result<Json<T>, ApiError>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("{e}");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "detail": "internal error" })))
}

fn bad(msg: impl Into<String>) -> ApiError {
    (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "detail": msg.into() })))
}

fn not_found() -> ApiError {
    (StatusCode::NOT_FOUND, Json(json!({ "detail": "not found" })))
}

async fn health(State(s): State<AppState>) -> ApiResult<Value> {
    sqlx::query("SELECT 1").execute(&s.db).await.map_err(internal)?;
    Ok(Json(json!({ "status": "ok" })))
}

async fn tools(State(s): State<AppState>) -> Json<Vec<Value>> {
    Json(
        Tool::ALL
            .iter()
            .map(|t| json!({ "name": t.binary(), "available": t.resolve(&s.config.tools_dir).is_some() }))
            .collect(),
    )
}

// ---------- targets ----------

#[derive(Serialize, sqlx::FromRow)]
struct TargetRow {
    id: Uuid,
    kind: input::TargetKind,
    value: String,
    label: Option<String>,
    manual_edit: bool,
}

async fn list_targets(State(s): State<AppState>) -> ApiResult<Vec<TargetRow>> {
    let rows = sqlx::query_as::<_, TargetRow>(
        "SELECT id, kind, value, label, manual_edit FROM targets ORDER BY created_at DESC LIMIT 1000",
    )
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct ImportBody {
    /// One target per line; CSV first column; `#` comments. Same path as manual input.
    text: String,
}

/// Upsert targets, returning their ids (existing rows are reused).
async fn upsert_targets(
    tx: &mut sqlx::PgConnection,
    targets: &[input::Target],
) -> Result<(Vec<Uuid>, u64), ApiError> {
    let mut ids = Vec::with_capacity(targets.len());
    let mut inserted = 0;
    for t in targets {
        let (id, new): (Uuid, bool) = sqlx::query_as(
            "INSERT INTO targets (kind, value) VALUES ($1, $2)
             ON CONFLICT (value) DO UPDATE SET value = EXCLUDED.value
             RETURNING id, (xmax = 0) AS inserted",
        )
        .bind(&t.kind)
        .bind(&t.value)
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?;
        ids.push(id);
        inserted += new as u64;
    }
    Ok((ids, inserted))
}

fn parse_errors(errors: &[(usize, input::InputError)]) -> Vec<Value> {
    errors.iter().map(|(line, e)| json!({ "line": line, "error": e.to_string() })).collect()
}

async fn import_targets(State(s): State<AppState>, Json(body): Json<ImportBody>) -> ApiResult<Value> {
    let (targets, errors) = input::parse_list(&body.text);
    let mut tx = s.db.begin().await.map_err(internal)?;
    let (_, inserted) = upsert_targets(&mut tx, &targets).await?;
    tx.commit().await.map_err(internal)?;
    Ok(Json(json!({
        "parsed": targets.len(),
        "inserted": inserted,
        "hosts": input::total_hosts(&targets).to_string(),
        "errors": parse_errors(&errors),
    })))
}

// ---------- scans ----------

#[derive(Serialize, sqlx::FromRow)]
struct ScanRow {
    id: Uuid,
    name: String,
    enabled: bool,
    rate_limit_pps: i32,
    window_minutes: Option<i32>,
    repeat_every_minutes: Option<i32>,
    ports: String,
    batch_size: i32,
    preflight: bool,
    inactive_after_misses: i32,
    next_run_at: Option<chrono::DateTime<chrono::Utc>>,
    target_count: i64,
    last_run_id: Option<Uuid>,
    last_run_status: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn list_scans(State(s): State<AppState>) -> ApiResult<Vec<ScanRow>> {
    let rows = sqlx::query_as::<_, ScanRow>(
        "SELECT s.id, s.name, s.enabled, s.rate_limit_pps, s.window_minutes, s.repeat_every_minutes,
                s.ports, s.batch_size, s.preflight, s.inactive_after_misses, s.next_run_at, s.created_at,
                (SELECT count(*) FROM scan_targets st WHERE st.scan_id = s.id) AS target_count,
                r.id AS last_run_id, r.status::text AS last_run_status
         FROM scans s
         LEFT JOIN LATERAL (SELECT id, status FROM scan_runs WHERE scan_id = s.id
                            ORDER BY started_at DESC LIMIT 1) r ON true
         ORDER BY s.created_at DESC LIMIT 100",
    )
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct CreateScan {
    name: String,
    /// Targets as text (same format as /targets import). Optional if `target_ids` given.
    #[serde(default)]
    targets: String,
    #[serde(default)]
    target_ids: Vec<Uuid>,
    #[serde(default = "default_rate")]
    rate_limit_pps: i32,
    window_minutes: Option<i32>,
    repeat_every_minutes: Option<i32>,
    #[serde(default = "default_ports")]
    ports: String,
    #[serde(default = "default_batch")]
    batch_size: i32,
    #[serde(default = "yes")]
    preflight: bool,
    /// Consecutive missed runs before a host is reported Inactive.
    #[serde(default = "default_misses")]
    inactive_after_misses: i32,
    /// Start immediately (default). `false` = saved, start later via /scans/{id}/run.
    #[serde(default = "yes")]
    start: bool,
}
fn default_rate() -> i32 {
    100
}
fn default_ports() -> String {
    "100".into()
}
fn default_batch() -> i32 {
    256
}
fn default_misses() -> i32 {
    3
}
fn yes() -> bool {
    true
}

async fn create_scan(State(s): State<AppState>, Json(b): Json<CreateScan>) -> ApiResult<Value> {
    if b.name.trim().is_empty() {
        return Err(bad("name is required"));
    }
    if !(1..=10_000).contains(&b.rate_limit_pps) {
        return Err(bad("rate_limit_pps must be 1..=10000"));
    }
    if !(1..=65_536).contains(&b.batch_size) {
        return Err(bad("batch_size must be 1..=65536"));
    }
    if !pipeline::valid_ports(&b.ports) {
        return Err(bad("ports must be 100, 1000, full or a list like 22,80,8000-8100"));
    }
    if b.window_minutes.is_some_and(|w| w <= 0) || b.repeat_every_minutes.is_some_and(|r| r <= 0) {
        return Err(bad("window_minutes and repeat_every_minutes must be positive"));
    }
    if let (Some(w), Some(r)) = (b.window_minutes, b.repeat_every_minutes) {
        if r < w {
            return Err(bad("repeat_every_minutes must be >= window_minutes"));
        }
    }
    if !(1..=100).contains(&b.inactive_after_misses) {
        return Err(bad("inactive_after_misses must be 1..=100"));
    }
    let (targets, errors) = input::parse_list(&b.targets);
    if targets.is_empty() && b.target_ids.is_empty() {
        return Err(bad("no valid targets"));
    }

    let mut tx = s.db.begin().await.map_err(internal)?;
    let (mut ids, _) = upsert_targets(&mut tx, &targets).await?;
    ids.extend(&b.target_ids);
    let scan_id: Uuid = sqlx::query_scalar(
        "INSERT INTO scans (name, rate_limit_pps, window_minutes, repeat_every_minutes, ports, batch_size, preflight,
                            inactive_after_misses, next_run_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $9, CASE WHEN $8 THEN now() ELSE NULL END) RETURNING id",
    )
    .bind(b.name.trim())
    .bind(b.rate_limit_pps)
    .bind(b.window_minutes)
    .bind(b.repeat_every_minutes)
    .bind(&b.ports)
    .bind(b.batch_size)
    .bind(b.preflight)
    .bind(b.start)
    .bind(b.inactive_after_misses)
    .fetch_one(&mut *tx)
    .await
    .map_err(internal)?;
    let linked = sqlx::query(
        "INSERT INTO scan_targets (scan_id, target_id) SELECT $1, t.id FROM targets t WHERE t.id = ANY($2)
         ON CONFLICT DO NOTHING",
    )
    .bind(scan_id)
    .bind(&ids)
    .execute(&mut *tx)
    .await
    .map_err(internal)?
    .rows_affected();
    // Size cap on the whole scan (F-12), incl. targets linked by id.
    let linked_targets: Vec<(input::TargetKind, String)> = sqlx::query_as(
        "SELECT t.kind, t.value FROM targets t JOIN scan_targets st ON st.target_id = t.id WHERE st.scan_id = $1",
    )
    .bind(scan_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(internal)?;
    let linked_targets: Vec<input::Target> =
        linked_targets.into_iter().map(|(kind, value)| input::Target { kind, value }).collect();
    let total = input::total_hosts(&linked_targets);
    if total > input::MAX_SCAN_HOSTS {
        return Err(bad(format!("scan covers {total} addresses, maximum is {}", input::MAX_SCAN_HOSTS)));
    }
    tx.commit().await.map_err(internal)?;

    Ok(Json(json!({
        "id": scan_id,
        "targets": linked,
        "hosts": total.to_string(),
        "errors": parse_errors(&errors),
        "scheduled": b.start,
    })))
}

async fn run_now(State(s): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    let active: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT (SELECT r.id FROM scan_runs r WHERE r.scan_id = s.id AND r.status IN ('queued', 'running', 'paused'))
         FROM scans s WHERE s.id = $1",
    )
    .bind(id)
    .fetch_optional(&s.db)
    .await
    .map_err(internal)?;
    match active {
        None => return Err(not_found()),
        // One active run per scan: starting another would be silently ignored.
        Some(Some(run)) => {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({ "detail": "scan already has an active run", "run_id": run })),
            ))
        }
        Some(None) => {}
    }
    sqlx::query("UPDATE scans SET next_run_at = now(), enabled = true WHERE id = $1")
        .bind(id)
        .execute(&s.db)
        .await
        .map_err(internal)?;
    Ok(Json(json!({ "id": id, "scheduled": true })))
}

// ---------- runs ----------

#[derive(Serialize, sqlx::FromRow)]
struct RunRow {
    id: Uuid,
    scan_id: Uuid,
    status: String,
    checkpoint: i64,
    total_batches: Option<i32>,
    started_at: chrono::DateTime<chrono::Utc>,
    window_started_at: Option<chrono::DateTime<chrono::Utc>>,
    resume_at: Option<chrono::DateTime<chrono::Utc>>,
    finished_at: Option<chrono::DateTime<chrono::Utc>>,
    error: Option<String>,
    stats: Value,
}

const RUN_COLUMNS: &str = "id, scan_id, status::text AS status, checkpoint, total_batches, started_at,
    window_started_at, resume_at, finished_at, error, stats";

async fn list_runs(State(s): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Vec<RunRow>> {
    let rows = sqlx::query_as::<_, RunRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {RUN_COLUMNS} FROM scan_runs WHERE scan_id = $1 ORDER BY started_at DESC LIMIT 100"
    )))
    .bind(id)
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    Ok(Json(rows))
}

async fn get_run(State(s): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<RunRow> {
    sqlx::query_as::<_, RunRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {RUN_COLUMNS} FROM scan_runs WHERE id = $1"
    )))
    .bind(id)
    .fetch_optional(&s.db)
    .await
    .map_err(internal)?
    .map(Json)
    .ok_or_else(not_found)
}

async fn cancel_run(State(s): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    let n = sqlx::query(
        "UPDATE scan_runs SET status = 'cancelled', resume_at = NULL,
             finished_at = CASE WHEN status = 'running' THEN finished_at ELSE now() END
         WHERE id = $1 AND status IN ('queued', 'running', 'paused')",
    )
    .bind(id)
    .execute(&s.db)
    .await
    .map_err(internal)?
    .rows_affected();
    if n == 0 {
        return Err(bad("run is not active"));
    }
    // A running run stops after its current batch.
    Ok(Json(json!({ "id": id, "status": "cancelled" })))
}

#[derive(Serialize, sqlx::FromRow)]
struct HostOut {
    id: Uuid,
    address: String,
    hostname: Option<String>,
    state: String,
    miss_count: i32,
    flaps: i32,
    first_seen_at: chrono::DateTime<chrono::Utc>,
    seen_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
struct ServiceOut {
    id: Uuid,
    host_id: Uuid,
    port: i32,
    protocol: String,
    service: Option<String>,
    product: Option<String>,
    version: Option<String>,
    confidence: f32,
    banner: Option<Value>,
}

#[derive(Serialize, sqlx::FromRow)]
struct HttpOut {
    service_id: Uuid,
    url: String,
    status_code: Option<i32>,
    title: Option<String>,
    redirects: Option<Vec<String>>,
    technologies: Option<Vec<String>>,
    cms: Option<String>,
    favicon_hash: Option<String>,
    is_admin: bool,
    is_staging: bool,
    headers: Option<Value>,
    cookies: Option<Value>,
    tls: Option<Value>,
}

/// Hosts → services → HTTP findings of one run, with encrypted fields decrypted.
async fn run_findings(State(s): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    let key = s.config.data_key.as_str();
    let hosts = sqlx::query_as::<_, HostOut>(
        "SELECT id, host(address) AS address, hostname, state::text AS state, miss_count, flaps, first_seen_at, seen_at
         FROM hosts WHERE run_id = $1 ORDER BY address",
    )
    .bind(id)
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    let services = sqlx::query_as::<_, ServiceOut>(
        "SELECT s.id, s.host_id, s.port, s.protocol, s.service, s.product, s.version, s.confidence,
                pgp_sym_decrypt(s.banner_enc, $2)::jsonb AS banner
         FROM services s JOIN hosts h ON h.id = s.host_id WHERE h.run_id = $1 ORDER BY s.port",
    )
    .bind(id)
    .bind(key)
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    let http = sqlx::query_as::<_, HttpOut>(
        "SELECT f.service_id, f.url, f.status_code, f.title, f.redirects, f.technologies, f.cms,
                f.favicon_hash, f.is_admin, f.is_staging,
                pgp_sym_decrypt(f.headers_enc, $2)::jsonb AS headers,
                pgp_sym_decrypt(f.cookies_enc, $2)::jsonb AS cookies,
                pgp_sym_decrypt(f.tls_enc, $2)::jsonb AS tls
         FROM http_findings f JOIN services s ON s.id = f.service_id JOIN hosts h ON h.id = s.host_id
         WHERE h.run_id = $1",
    )
    .bind(id)
    .bind(key)
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;

    let mut http_by_service: BTreeMap<Uuid, Vec<HttpOut>> = BTreeMap::new();
    for f in http {
        http_by_service.entry(f.service_id).or_default().push(f);
    }
    let mut services_by_host: BTreeMap<Uuid, Vec<Value>> = BTreeMap::new();
    for svc in services {
        let http = http_by_service.remove(&svc.id).unwrap_or_default();
        let mut v = serde_json::to_value(&svc).map_err(internal)?;
        v["http"] = serde_json::to_value(http).map_err(internal)?;
        services_by_host.entry(svc.host_id).or_default().push(v);
    }
    let hosts: Vec<Value> = hosts
        .into_iter()
        .map(|h| {
            let services = services_by_host.remove(&h.id).unwrap_or_default();
            json!({
                "address": h.address, "hostname": h.hostname, "state": h.state,
                "miss_count": h.miss_count, "flaps": h.flaps, "unstable": h.flaps > 0 || h.state != "active",
                "first_seen_at": h.first_seen_at, "last_seen_at": h.seen_at, "services": services,
            })
        })
        .collect();
    Ok(Json(json!({ "run_id": id, "hosts": hosts })))
}

// ---------- diff ----------

#[derive(Deserialize)]
struct DiffQuery {
    /// Compare with any other run instead of the stored diff vs the previous run.
    against: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct DiffRow {
    run_a: Uuid,
    kind: String,
    entity: String,
    change: String,
    field: Option<String>,
    old_value: Option<String>,
    new_value: Option<String>,
    confidence: f32,
    interest: i16,
}

/// Changes of a run: stored diff vs the previous finished run of the same scan, or a live
/// comparison with `?against=<run_id>`. Sorted by interest (3 = most important) first.
async fn run_diff(State(s): State<AppState>, Path(id): Path<Uuid>, Query(q): Query<DiffQuery>) -> ApiResult<Value> {
    let key = s.config.data_key.as_str();
    let not_comparable: Option<u64>;
    let (against, entries): (Option<Uuid>, Vec<Value>) = match q.against {
        Some(a) => {
            let (entries, skipped): (Vec<DiffEntry>, usize) =
                history::compare(&s.db, a, id, key).await.map_err(|e| match e {
                    sqlx::Error::RowNotFound => not_found(),
                    e => internal(e),
                })?;
            not_comparable = Some(skipped as u64);
            (Some(a), entries.iter().map(|e| serde_json::to_value(e).unwrap_or_default()).collect())
        }
        None => {
            let rows = sqlx::query_as::<_, DiffRow>(
                "SELECT run_a, kind, entity, change::text AS change, field,
                        pgp_sym_decrypt(old_enc, $2) AS old_value, pgp_sym_decrypt(new_enc, $2) AS new_value,
                        confidence, interest
                 FROM diffs WHERE run_b = $1 ORDER BY interest DESC, kind, entity",
            )
            .bind(id)
            .bind(key)
            .fetch_all(&s.db)
            .await
            .map_err(internal)?;
            let against = match rows.first() {
                Some(r) => Some(r.run_a),
                None => history::previous_run(&s.db, id).await.map_err(internal)?,
            };
            not_comparable = sqlx::query_scalar::<_, Option<i64>>(
                "SELECT (stats->'diff'->>'not_comparable')::bigint FROM scan_runs WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&s.db)
            .await
            .map_err(internal)?
            .flatten()
            .map(|n| n as u64);
            let entries = rows
                .into_iter()
                .map(|r| json!({
                    "kind": r.kind, "entity": r.entity, "change": r.change, "field": r.field,
                    "old_value": r.old_value, "new_value": r.new_value,
                    "confidence": r.confidence, "interest": r.interest,
                }))
                .collect();
            (against, entries)
        }
    };
    let count = |c: &str| entries.iter().filter(|e| e["change"] == c).count();
    Ok(Json(json!({
        "run_b": id,
        "run_a": against,
        "summary": {
            "new": count("new"), "gone": count("gone"), "changed": count("changed"),
            "important": entries.iter().filter(|e| e["interest"].as_i64() >= Some(3)).count(),
            // Addresses not covered by both runs: skipped, not reported as new/gone.
            "not_comparable": not_comparable,
        },
        "entries": entries,
    })))
}
