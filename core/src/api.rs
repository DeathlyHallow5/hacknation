//! Module 6 — HTTP API consumed by the Next.js frontend through its `/api` proxy.
//! Every route goes through `auth::gate` (deny by default, rights from `rbac::ROUTES`).

use crate::{
    audit::{self, Note},
    auth::{self, CurrentUser},
    diff::DiffEntry,
    engine::Tool,
    history, input, overlay,
    overlay::Overlay,
    pipeline,
    rbac::Action,
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    middleware,
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/auth/me", get(auth::me))
        .route("/api/users", get(auth::list_users).post(auth::create_user))
        .route("/api/users/{id}", patch(auth::update_user).delete(auth::disable_user))
        .route("/api/audit", get(audit::list))
        .route("/api/tools", get(tools))
        .route("/api/targets", get(list_targets).post(import_targets))
        .route("/api/targets/{id}", patch(patch_target).delete(delete_target))
        .route("/api/scans", get(list_scans).post(create_scan))
        .route("/api/scans/{id}", get(get_scan).patch(patch_scan).delete(delete_scan))
        .route("/api/scans/{id}/run", post(run_now))
        .route("/api/scans/{id}/runs", get(list_runs))
        .route("/api/scans/{id}/annotations", get(overlay::list).put(overlay::put))
        .route("/api/scans/{id}/annotations/{annotation_id}", delete(overlay::delete))
        .route("/api/scans/{id}/annotations/{annotation_id}/history", get(overlay::history))
        .route("/api/runs/{id}", get(get_run))
        .route("/api/runs/{id}/findings", get(run_findings))
        .route("/api/runs/{id}/diff", get(run_diff))
        .route("/api/runs/{id}/cancel", post(cancel_run))
        .merge(v1_routes());
    // Add routes and `.merge(...)`s ABOVE this line: the gate covers only what exists when
    // it is installed. New routes also need a row in `rbac::ROUTES` (else admin-only).
    api.route_layer(middleware::from_fn_with_state(state.clone(), auth::gate)).with_state(state)
}

/// The dashboard contract (`/api/v1`, see `v1.rs`), behind the same gate.
fn v1_routes() -> Router<AppState> {
    use crate::v1;
    Router::new()
        .route("/api/v1/auth/login", post(v1::login))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/me", get(v1::me))
        .route("/api/v1/dashboard/summary", get(v1::summary))
        .route("/api/v1/dashboard/top-findings", get(v1::top_findings))
        .route("/api/v1/dashboard/changes-timeline", get(v1::changes_timeline))
        .route("/api/v1/dashboard/availability", get(v1::availability))
        .route("/api/v1/dashboard/technologies", get(v1::technologies))
        .route("/api/v1/dashboard/address-map", get(v1::address_map))
        .route("/api/v1/search", get(v1::search))
        .route("/api/v1/targets", get(v1::list_targets).post(v1::create_targets))
        .route("/api/v1/targets/export", get(v1::export_targets))
        .route(
            "/api/v1/targets/import",
            post(v1::import_targets).layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024)),
        )
        .route("/api/v1/targets/bulk", post(v1::bulk_targets))
        .route("/api/v1/targets/{id}", get(v1::get_target).patch(v1::update_target).delete(v1::delete_target))
        .route("/api/v1/scans", get(v1::list_scans))
        .route("/api/v1/findings", get(v1::list_findings))
        .route("/api/v1/findings/export", get(v1::export_findings))
        .route("/api/v1/findings/defectdojo", post(v1::defectdojo_export))
        .route("/api/v1/findings/{id}", get(v1::get_finding).patch(v1::update_finding))
        .route("/api/v1/audit", get(v1::audit_list))
}

pub(crate) type ApiError = (StatusCode, Json<Value>);
#[cfg(test)]
mod run_integrity_tests;
pub(crate) type ApiResult<T> = Result<Json<T>, ApiError>;

pub(crate) fn internal(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("{e}");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "detail": "internal error" })))
}

pub(crate) fn bad(msg: impl Into<String>) -> ApiError {
    (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "detail": msg.into() })))
}

pub(crate) fn not_found() -> ApiError {
    (StatusCode::NOT_FOUND, Json(json!({ "detail": "not found" })))
}

fn forbidden() -> ApiError {
    (StatusCode::FORBIDDEN, Json(json!({ "detail": "forbidden" })))
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
    notes: Option<String>,
    manual_edit: bool,
}

/// `$1` = data key. Notes written before encryption (or by older importers) stay readable.
const TARGET_SELECT: &str = "SELECT id, kind, value, label,
        COALESCE(pgp_sym_decrypt(notes_enc, $1), notes) AS notes, manual_edit FROM targets";

async fn list_targets(State(s): State<AppState>) -> ApiResult<Vec<TargetRow>> {
    let rows = sqlx::query_as::<_, TargetRow>(sqlx::AssertSqlSafe(format!(
        "{TARGET_SELECT} ORDER BY created_at DESC LIMIT 1000"
    )))
    .bind(&s.config.data_key)
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchTarget {
    /// Absent = unchanged, empty string = cleared.
    label: Option<String>,
    notes: Option<String>,
}

/// `PATCH /api/targets/{id}` — analyst label and notes (notes stored encrypted).
async fn patch_target(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    Json(b): Json<PatchTarget>,
) -> Result<(Extension<Note>, Json<TargetRow>), ApiError> {
    let label = overlay::text(b.label.as_deref(), "label", 200, false)?;
    let notes = overlay::text(b.notes.as_deref(), "notes", 10_000, true)?;
    let key = s.config.data_key.as_str();
    let mut tx = s.db.begin().await.map_err(internal)?;
    let n = sqlx::query(
        "UPDATE targets SET
             label = CASE WHEN $2 THEN $3 ELSE label END,
             notes_enc = CASE WHEN $4 THEN pgp_sym_encrypt($5, $6) ELSE notes_enc END,
             notes = CASE WHEN $4 THEN NULL ELSE notes END,
             manual_edit = true
         WHERE id = $1",
    )
    .bind(id)
    .bind(b.label.is_some())
    .bind(&label)
    .bind(b.notes.is_some())
    .bind(&notes)
    .bind(key)
    .execute(&mut *tx)
    .await
    .map_err(internal)?
    .rows_affected();
    if n == 0 {
        return Err(not_found());
    }
    let row = sqlx::query_as::<_, TargetRow>(sqlx::AssertSqlSafe(format!("{TARGET_SELECT} WHERE id = $2")))
        .bind(key)
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    let changed: Vec<&str> = [("label", b.label.is_some()), ("notes", b.notes.is_some())]
        .into_iter()
        .filter_map(|(f, set)| set.then_some(f))
        .collect();
    let note = Note::new("target.update", "target", id, json!({ "fields": changed }));
    Ok((Extension(note), Json(row)))
}

/// `DELETE /api/targets/{id}` — also unlinks it from scans; runs keep their own snapshot.
async fn delete_target(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(Extension<Note>, Json<Value>), ApiError> {
    let value: String = sqlx::query_scalar("DELETE FROM targets WHERE id = $1 RETURNING value")
        .bind(id)
        .fetch_optional(&s.db)
        .await
        .map_err(internal)?
        .ok_or_else(not_found)?;
    let note = Note::new("target.delete", "target", id, json!({ "value": value }));
    Ok((Extension(note), Json(json!({ "id": id, "deleted": true }))))
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

const SCAN_SELECT: &str = "SELECT s.id, s.name, s.enabled, s.rate_limit_pps, s.window_minutes,
        s.repeat_every_minutes, s.ports, s.batch_size, s.preflight, s.inactive_after_misses, s.next_run_at,
        s.created_at, (SELECT count(*) FROM scan_targets st WHERE st.scan_id = s.id) AS target_count,
        r.id AS last_run_id, r.status::text AS last_run_status
    FROM scans s
    LEFT JOIN LATERAL (SELECT id, status FROM scan_runs WHERE scan_id = s.id
                       ORDER BY started_at DESC LIMIT 1) r ON true";

async fn list_scans(State(s): State<AppState>) -> ApiResult<Vec<ScanRow>> {
    let rows = sqlx::query_as::<_, ScanRow>(sqlx::AssertSqlSafe(format!(
        "{SCAN_SELECT} ORDER BY s.created_at DESC LIMIT 100"
    )))
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    Ok(Json(rows))
}

async fn scan_by_id(db: &sqlx::PgPool, id: Uuid) -> Result<ScanRow, ApiError> {
    sqlx::query_as::<_, ScanRow>(sqlx::AssertSqlSafe(format!("{SCAN_SELECT} WHERE s.id = $1")))
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(internal)?
        .ok_or_else(not_found)
}

/// `GET /api/scans/{id}` — settings, last run and linked targets.
async fn get_scan(State(s): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    let scan = scan_by_id(&s.db, id).await?;
    let targets = sqlx::query_as::<_, TargetRow>(sqlx::AssertSqlSafe(format!(
        "{TARGET_SELECT} WHERE id IN (SELECT target_id FROM scan_targets WHERE scan_id = $2) ORDER BY value"
    )))
    .bind(&s.config.data_key)
    .bind(id)
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    let mut v = serde_json::to_value(scan).map_err(internal)?;
    v["targets"] = serde_json::to_value(targets).map_err(internal)?;
    Ok(Json(v))
}

/// Checks shared by create and PATCH (on the merged values).
fn validate_settings(
    rate_limit_pps: i32,
    window_minutes: Option<i32>,
    repeat_every_minutes: Option<i32>,
    ports: &str,
    batch_size: i32,
    inactive_after_misses: i32,
) -> Result<(), ApiError> {
    if !(1..=10_000).contains(&rate_limit_pps) {
        return Err(bad("rate_limit_pps must be 1..=10000"));
    }
    if !(1..=65_536).contains(&batch_size) {
        return Err(bad("batch_size must be 1..=65536"));
    }
    if !pipeline::valid_ports(ports) {
        return Err(bad("ports must be 100, 1000, full or a list like 22,80,8000-8100"));
    }
    if window_minutes.is_some_and(|w| w <= 0) || repeat_every_minutes.is_some_and(|r| r <= 0) {
        return Err(bad("window_minutes and repeat_every_minutes must be positive"));
    }
    if let (Some(w), Some(r)) = (window_minutes, repeat_every_minutes)
        && r < w
    {
        return Err(bad("repeat_every_minutes must be >= window_minutes"));
    }
    if !(1..=100).contains(&inactive_after_misses) {
        return Err(bad("inactive_after_misses must be 1..=100"));
    }
    Ok(())
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

async fn create_scan(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(b): Json<CreateScan>,
) -> Result<(Extension<Note>, Json<Value>), ApiError> {
    // Starting a scan is active network impact: Create alone is not enough.
    if b.start && !user.can(Action::ExecuteScan) {
        return Err(forbidden());
    }
    if b.name.trim().is_empty() {
        return Err(bad("name is required"));
    }
    validate_settings(
        b.rate_limit_pps,
        b.window_minutes,
        b.repeat_every_minutes,
        &b.ports,
        b.batch_size,
        b.inactive_after_misses,
    )?;
    let (targets, errors) = input::parse_list(&b.targets);
    if targets.is_empty() && b.target_ids.is_empty() {
        return Err(bad("no valid targets"));
    }

    let mut tx = s.db.begin().await.map_err(internal)?;
    let (mut ids, _) = upsert_targets(&mut tx, &targets).await?;
    ids.extend(&b.target_ids);
    let scan_id: Uuid = sqlx::query_scalar(
        "INSERT INTO scans (name, rate_limit_pps, window_minutes, repeat_every_minutes, ports, batch_size, preflight,
                            inactive_after_misses, next_run_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $9, CASE WHEN $8 THEN now() ELSE NULL END, $10) RETURNING id",
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
    .bind(user.id)
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

    let note = Note::new(
        "scan.create",
        "scan",
        scan_id,
        json!({ "name": b.name.trim(), "targets": linked, "hosts": total.to_string(), "start": b.start }),
    );
    Ok((
        Extension(note),
        Json(json!({
            "id": scan_id,
            "targets": linked,
            "hosts": total.to_string(),
            "errors": parse_errors(&errors),
            "scheduled": b.start,
        })),
    ))
}

/// `Some(value)` for a field that is present, also when it is null (to clear it).
pub(crate) fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchScan {
    name: Option<String>,
    enabled: Option<bool>,
    rate_limit_pps: Option<i32>,
    #[serde(default, deserialize_with = "present")]
    window_minutes: Option<Option<i32>>,
    #[serde(default, deserialize_with = "present")]
    repeat_every_minutes: Option<Option<i32>>,
    ports: Option<String>,
    batch_size: Option<i32>,
    preflight: Option<bool>,
    inactive_after_misses: Option<i32>,
}

#[derive(sqlx::FromRow)]
struct ScanSettings {
    name: String,
    enabled: bool,
    rate_limit_pps: i32,
    window_minutes: Option<i32>,
    repeat_every_minutes: Option<i32>,
    ports: String,
    batch_size: i32,
    preflight: bool,
    inactive_after_misses: i32,
}

/// `PATCH /api/scans/{id}` — settings take effect from the next run (a running run keeps
/// its `config_snapshot`). Enabling a scan, or retuning an enabled one, needs ExecuteScan.
async fn patch_scan(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(b): Json<PatchScan>,
) -> Result<(Extension<Note>, Json<ScanRow>), ApiError> {
    let mut tx = s.db.begin().await.map_err(internal)?;
    let cur = sqlx::query_as::<_, ScanSettings>(
        "SELECT name, enabled, rate_limit_pps, window_minutes, repeat_every_minutes, ports, batch_size, preflight,
                inactive_after_misses
         FROM scans WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?
    .ok_or_else(not_found)?;
    let new = ScanSettings {
        name: match b.name {
            Some(n) if n.trim().is_empty() => return Err(bad("name is required")),
            Some(n) => n.trim().to_string(),
            None => cur.name.clone(),
        },
        enabled: b.enabled.unwrap_or(cur.enabled),
        rate_limit_pps: b.rate_limit_pps.unwrap_or(cur.rate_limit_pps),
        window_minutes: b.window_minutes.unwrap_or(cur.window_minutes),
        repeat_every_minutes: b.repeat_every_minutes.unwrap_or(cur.repeat_every_minutes),
        ports: b.ports.unwrap_or_else(|| cur.ports.clone()),
        batch_size: b.batch_size.unwrap_or(cur.batch_size),
        preflight: b.preflight.unwrap_or(cur.preflight),
        inactive_after_misses: b.inactive_after_misses.unwrap_or(cur.inactive_after_misses),
    };
    validate_settings(
        new.rate_limit_pps,
        new.window_minutes,
        new.repeat_every_minutes,
        &new.ports,
        new.batch_size,
        new.inactive_after_misses,
    )?;
    // (field, changed, affects network load)
    let changes = [
        ("name", new.name != cur.name, false),
        ("enabled", new.enabled != cur.enabled, true),
        ("rate_limit_pps", new.rate_limit_pps != cur.rate_limit_pps, true),
        ("window_minutes", new.window_minutes != cur.window_minutes, true),
        ("repeat_every_minutes", new.repeat_every_minutes != cur.repeat_every_minutes, true),
        ("ports", new.ports != cur.ports, true),
        ("batch_size", new.batch_size != cur.batch_size, true),
        ("preflight", new.preflight != cur.preflight, true),
        ("inactive_after_misses", new.inactive_after_misses != cur.inactive_after_misses, false),
    ];
    let retunes = changes.iter().any(|&(_, changed, network)| changed && network);
    if new.enabled && retunes && !user.can(Action::ExecuteScan) {
        return Err(forbidden());
    }
    sqlx::query(
        "UPDATE scans SET name = $2, enabled = $3, rate_limit_pps = $4, window_minutes = $5,
             repeat_every_minutes = $6, ports = $7, batch_size = $8, preflight = $9, inactive_after_misses = $10
         WHERE id = $1",
    )
    .bind(id)
    .bind(&new.name)
    .bind(new.enabled)
    .bind(new.rate_limit_pps)
    .bind(new.window_minutes)
    .bind(new.repeat_every_minutes)
    .bind(&new.ports)
    .bind(new.batch_size)
    .bind(new.preflight)
    .bind(new.inactive_after_misses)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    let fields: Vec<&str> = changes.iter().filter(|c| c.1).map(|c| c.0).collect();
    let note = Note::new("scan.update", "scan", id, json!({ "fields": fields }));
    Ok((Extension(note), Json(scan_by_id(&s.db, id).await?)))
}

/// `DELETE /api/scans/{id}` — with all its runs, results, diffs and annotations; 409 while
/// a run is active.
async fn delete_scan(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(Extension<Note>, Json<Value>), ApiError> {
    let mut tx = s.db.begin().await.map_err(internal)?;
    // The row lock keeps the scheduler (FOR UPDATE SKIP LOCKED) from starting a run meanwhile.
    let name: String = sqlx::query_scalar("SELECT name FROM scans WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?
        .ok_or_else(not_found)?;
    let active: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM scan_runs WHERE scan_id = $1 AND status IN ('queued', 'running', 'paused') LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    if let Some(run) = active {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({ "detail": "scan has an active run; cancel it first", "run_id": run })),
        ));
    }
    sqlx::query("DELETE FROM scans WHERE id = $1").bind(id).execute(&mut *tx).await.map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    let note = Note::new("scan.delete", "scan", id, json!({ "name": name }));
    Ok((Extension(note), Json(json!({ "id": id, "deleted": true }))))
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
             finished_at = COALESCE(finished_at, now())
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

/// Hosts → services → HTTP findings of one run, each with its annotation (or null).
/// Banners, headers, cookies and TLS are decrypted only for users with ReadEvidence (F-14);
/// for others they are null and the response says `"redacted": true`.
async fn run_findings(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    let key = s.config.data_key.as_str();
    let evidence = user.can(Action::ReadEvidence);
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
                CASE WHEN $3 THEN pgp_sym_decrypt(s.banner_enc, $2)::jsonb END AS banner
         FROM services s JOIN hosts h ON h.id = s.host_id WHERE h.run_id = $1 ORDER BY s.port",
    )
    .bind(id)
    .bind(key)
    .bind(evidence)
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    let http = sqlx::query_as::<_, HttpOut>(
        "SELECT f.service_id, f.url, f.status_code, f.title, f.redirects, f.technologies, f.cms,
                f.favicon_hash, f.is_admin, f.is_staging,
                CASE WHEN $3 THEN pgp_sym_decrypt(f.headers_enc, $2)::jsonb END AS headers,
                CASE WHEN $3 THEN pgp_sym_decrypt(f.cookies_enc, $2)::jsonb END AS cookies,
                CASE WHEN $3 THEN pgp_sym_decrypt(f.tls_enc, $2)::jsonb END AS tls
         FROM http_findings f JOIN services s ON s.id = f.service_id JOIN hosts h ON h.id = s.host_id
         WHERE h.run_id = $1",
    )
    .bind(id)
    .bind(key)
    .bind(evidence)
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    let overlay = Overlay::for_run(&s.db, id, key).await.map_err(internal)?;

    let address: HashMap<Uuid, String> = hosts.iter().map(|h| (h.id, h.address.clone())).collect();
    let mut http_by_service: BTreeMap<Uuid, Vec<Value>> = BTreeMap::new();
    for f in http {
        let mut v = serde_json::to_value(&f).map_err(internal)?;
        v["annotation"] = overlay.json("http", &f.url);
        http_by_service.entry(f.service_id).or_default().push(v);
    }
    let mut services_by_host: BTreeMap<Uuid, Vec<Value>> = BTreeMap::new();
    for svc in services {
        let http = http_by_service.remove(&svc.id).unwrap_or_default();
        let mut v = serde_json::to_value(&svc).map_err(internal)?;
        v["http"] = Value::Array(http);
        if let Some(addr) = address.get(&svc.host_id) {
            v["annotation"] = overlay.json("service", &format!("{addr}:{}/{}", svc.port, svc.protocol));
        }
        services_by_host.entry(svc.host_id).or_default().push(v);
    }
    let hosts: Vec<Value> = hosts
        .into_iter()
        .map(|h| {
            let services = services_by_host.remove(&h.id).unwrap_or_default();
            json!({
                "address": h.address, "hostname": h.hostname, "state": h.state,
                "miss_count": h.miss_count, "flaps": h.flaps, "unstable": h.flaps > 0 || h.state != "active",
                "first_seen_at": h.first_seen_at, "last_seen_at": h.seen_at,
                "annotation": overlay.json("host", &h.address), "services": services,
            })
        })
        .collect();
    Ok(Json(json!({ "run_id": id, "redacted": !evidence, "hosts": hosts })))
}

// ---------- diff ----------

#[derive(Deserialize)]
struct DiffQuery {
    /// Compare with any other run instead of the stored diff vs the previous run.
    against: Option<Uuid>,
    /// Leave out entries whose entity is annotated as suppressed.
    #[serde(default)]
    hide_suppressed: bool,
}

/// Diff fields whose values come from evidence (header/cookie names, TLS details).
fn evidence_field(field: &str) -> bool {
    matches!(field, "headers" | "cookies" | "banner") || field.starts_with("tls.")
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
async fn run_diff(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Query(q): Query<DiffQuery>,
) -> ApiResult<Value> {
    let key = s.config.data_key.as_str();
    let evidence = user.can(Action::ReadEvidence);
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
    let overlay = Overlay::for_run(&s.db, id, key).await.map_err(internal)?;
    let mut suppressed_hidden = 0;
    let mut redacted = false;
    let entries: Vec<Value> = entries
        .into_iter()
        .filter_map(|mut e| {
            let kind = e["kind"].as_str().unwrap_or_default().to_string();
            let entity = e["entity"].as_str().unwrap_or_default().to_string();
            if q.hide_suppressed && overlay.suppressed(&kind, &entity) {
                suppressed_hidden += 1;
                return None;
            }
            if !evidence && e["field"].as_str().is_some_and(evidence_field) {
                e["old_value"] = Value::Null;
                e["new_value"] = Value::Null;
                e["redacted"] = Value::Bool(true);
                redacted = true;
            }
            e["annotation"] = overlay.json(&kind, &entity);
            Some(e)
        })
        .collect();
    let count = |c: &str| entries.iter().filter(|e| e["change"] == c).count();
    Ok(Json(json!({
        "run_b": id,
        "run_a": against,
        "summary": {
            "new": count("new"), "gone": count("gone"), "changed": count("changed"),
            "important": entries.iter().filter(|e| e["interest"].as_i64() >= Some(3)).count(),
            // Addresses not covered by both runs: skipped, not reported as new/gone.
            "not_comparable": not_comparable,
            "suppressed_hidden": suppressed_hidden,
        },
        "redacted": redacted,
        "entries": entries,
    })))
}
