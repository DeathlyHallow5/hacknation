//! `/api/v1` scans: profiles, one-off scans with clock windows, control (pause, resume,
//! cancel), batches, log, live progress (SSE), schedules (F-20), export and import of
//! results. A contract `ScanRun` is a run (`scan_runs`); its settings live on `scans`.

use crate::{
    audit::Note,
    auth::CurrentUser,
    input,
    rbac::Action,
    v1::{self, err, fail, forbidden, invalid, missing, paginated, text, clean_tags, opt, V1},
    v1_admin::load_settings,
    AppState,
};
use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        Response,
    },
    Extension, Json,
};
use chrono::{DateTime, Utc};
use futures_util::stream::{self, Stream};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::time::Duration;
use uuid::Uuid;

// ---------- profiles ----------

#[derive(sqlx::FromRow)]
struct ProfileRow {
    id: Uuid,
    name: String,
    description: String,
    builtin: bool,
    config: Value,
}

fn profile_json(p: &ProfileRow) -> Value {
    let mut v = p.config.clone();
    v["id"] = json!(p.id);
    v["name"] = json!(p.name);
    v["description"] = json!(p.description);
    v["builtin"] = json!(p.builtin);
    v
}

async fn profile(db: &sqlx::PgPool, id: Uuid) -> V1<ProfileRow> {
    sqlx::query_as::<_, ProfileRow>("SELECT id, name, description, builtin, config FROM scan_profiles WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(fail)?
        .ok_or_else(|| invalid("Wybierz profil skanowania."))
}

/// `GET /api/v1/profiles`
pub async fn list_profiles(State(s): State<AppState>) -> V1<Json<Vec<Value>>> {
    let rows = sqlx::query_as::<_, ProfileRow>(
        "SELECT id, name, description, builtin, config FROM scan_profiles ORDER BY builtin DESC, name",
    )
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    Ok(Json(rows.iter().map(profile_json).collect()))
}

const PROFILE_KEYS: [&str; 14] = [
    "ports", "rate_limit_rps", "max_concurrency", "nmap_timing", "host_timeout_s", "http_probe", "tls_probe",
    "follow_redirects", "max_redirects", "signatures", "signature_ids", "unstable_retries", "batch_strategy", "batch_prefix",
];

/// Validate the config part of a profile against the safety settings.
fn check_profile(cfg: &Value, settings: &Value) -> V1<()> {
    let max = settings["scan_safety"]["max_rate_rps"].as_i64().unwrap_or(1000);
    let rate = cfg["rate_limit_rps"].as_i64().unwrap_or(0);
    if !(1..=max).contains(&rate) {
        return Err(invalid(format!("Limit zapytań: 1–{max}/s (limit globalny z ustawień).")));
    }
    match cfg["ports"]["preset"].as_str() {
        Some("top100" | "top1000" | "allowed") => {}
        Some("custom") if crate::pipeline::valid_ports(cfg["ports"]["custom"].as_str().unwrap_or("")) => {}
        Some("custom") => return Err(invalid("Porty: lista w formacie 22,80,8000-8100.")),
        _ => return Err(invalid("Porty: top100, top1000, allowed lub custom.")),
    }
    let prefix = cfg["batch_prefix"].as_i64().unwrap_or(24);
    if !(16..=30).contains(&prefix) {
        return Err(invalid("Podgrupa: od /16 do /30."));
    }
    Ok(())
}

fn profile_config(body: &Value) -> Value {
    let mut cfg = json!({});
    for k in PROFILE_KEYS {
        if let Some(v) = body.get(k) {
            cfg[k] = v.clone();
        }
    }
    cfg
}

/// `POST /api/v1/profiles`
pub async fn create_profile(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(b): Json<Value>,
) -> V1<(StatusCode, Extension<Note>, Json<Value>)> {
    let name = text(b["name"].as_str(), "name", 120, false)?.ok_or_else(|| invalid("Podaj nazwę profilu."))?;
    let description = text(b["description"].as_str(), "description", 1000, true)?.unwrap_or_default();
    let mut cfg = profile(&s.db, builtin_id(&s.db).await?).await?.config;
    for (k, v) in profile_config(&b).as_object().into_iter().flatten() {
        cfg[k] = v.clone();
    }
    check_profile(&cfg, &load_settings(&s.db).await?)?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO scan_profiles (name, description, config, created_by) VALUES ($1, $2, $3, $4)
         ON CONFLICT (name) DO NOTHING RETURNING id",
    )
    .bind(&name)
    .bind(&description)
    .bind(&cfg)
    .bind(user.id)
    .fetch_optional(&s.db)
    .await
    .map_err(fail)?
    .ok_or_else(|| err(StatusCode::CONFLICT, "conflict", "Profil o tej nazwie już istnieje."))?;
    let note = Note::new("profile.create", "profile", id, json!({ "name": name }));
    Ok((StatusCode::CREATED, Extension(note), Json(profile_json(&profile(&s.db, id).await?))))
}

async fn builtin_id(db: &sqlx::PgPool) -> V1<Uuid> {
    sqlx::query_scalar("SELECT id FROM scan_profiles WHERE builtin ORDER BY name LIMIT 1")
        .fetch_one(db)
        .await
        .map_err(fail)
}

/// `PATCH /api/v1/profiles/{id}`
pub async fn update_profile(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    Json(b): Json<Value>,
) -> V1<(Extension<Note>, Json<Value>)> {
    let mut p = profile(&s.db, id).await.map_err(|_| missing())?;
    for (k, v) in profile_config(&b).as_object().into_iter().flatten() {
        p.config[k] = v.clone();
    }
    check_profile(&p.config, &load_settings(&s.db).await?)?;
    if let Some(n) = b["name"].as_str() {
        p.name = text(Some(n), "name", 120, false)?.ok_or_else(|| invalid("Podaj nazwę profilu."))?;
    }
    if let Some(d) = b["description"].as_str() {
        p.description = text(Some(d), "description", 1000, true)?.unwrap_or_default();
    }
    sqlx::query("UPDATE scan_profiles SET name = $2, description = $3, config = $4, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(&p.name)
        .bind(&p.description)
        .bind(&p.config)
        .execute(&s.db)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_unique_violation() => err(StatusCode::CONFLICT, "conflict", "Profil o tej nazwie już istnieje."),
            e => fail(e),
        })?;
    let note = Note::new("profile.update", "profile", id, json!({ "name": p.name }));
    Ok((Extension(note), Json(profile_json(&profile(&s.db, id).await?))))
}

/// `DELETE /api/v1/profiles/{id}`
pub async fn delete_profile(State(s): State<AppState>, Path(id): Path<Uuid>) -> V1<(StatusCode, Extension<Note>)> {
    let p = profile(&s.db, id).await.map_err(|_| missing())?;
    if p.builtin {
        return Err(err(StatusCode::CONFLICT, "conflict", "Profili wbudowanych nie można usuwać."));
    }
    let used: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM scans WHERE profile_id = $1 AND is_schedule)")
        .bind(id)
        .fetch_one(&s.db)
        .await
        .map_err(fail)?;
    if used {
        return Err(err(StatusCode::CONFLICT, "conflict", "Profil jest używany przez harmonogram."));
    }
    sqlx::query("DELETE FROM scan_profiles WHERE id = $1").bind(id).execute(&s.db).await.map_err(fail)?;
    Ok((StatusCode::NO_CONTENT, Extension(Note::new("profile.delete", "profile", id, json!({ "name": p.name })))))
}

// ---------- tuning and estimate ----------

/// Scan settings derived from a profile and the global safety settings.
struct Tuning {
    ports: String,
    rate: i32,
    batch_size: i32,
    inactive_after_misses: i32,
    port_count: u64,
}

/// TCP ports by nmap's measured open frequency (`nmap-services`, shipped in the image), most
/// common first — the same ranking as the scanners' top-N presets.
fn nmap_top_ports() -> Option<&'static [u16]> {
    static TOP: std::sync::OnceLock<Option<Vec<u16>>> = std::sync::OnceLock::new();
    TOP.get_or_init(|| {
        let text = std::fs::read_to_string("/usr/share/nmap/nmap-services").ok()?;
        Some(rank_ports(&text))
    })
    .as_deref()
}

fn rank_ports(nmap_services: &str) -> Vec<u16> {
    let mut ranked: Vec<(f64, u16)> = nmap_services
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut f = l.split_whitespace().skip(1);
            let port = f.next()?.strip_suffix("/tcp")?.parse().ok()?;
            Some((f.next()?.parse().ok()?, port))
        })
        .collect();
    ranked.sort_by(|a, b| b.0.total_cmp(&a.0));
    ranked.into_iter().map(|(_, p)| p).collect()
}

/// A top-N preset under an administrator allowlist: only the approved ports among the N most
/// common (the scope policy refuses the bare preset). No allowlist = the preset as is.
fn top_ports(n: usize, approved: &std::collections::BTreeSet<u16>) -> String {
    match nmap_top_ports() {
        Some(top) if !approved.is_empty() => {
            top.iter().take(n).filter(|p| approved.contains(p)).map(u16::to_string).collect::<Vec<_>>().join(",")
        }
        _ => n.to_string(),
    }
}

/// `approved`: the administrator's port allowlist (`ASI_ALLOWED_PORTS`); the "allowed" preset
/// means exactly those ports, top-N presets keep only the approved ones. Empty (no policy) =
/// presets as is and the dashboard setting `scan_safety.allowed_ports`.
fn tuning(cfg: &Value, settings: &Value, approved: &std::collections::BTreeSet<u16>) -> Tuning {
    let max = settings["scan_safety"]["max_rate_rps"].as_i64().unwrap_or(1000) as i32;
    let rate = (cfg["rate_limit_rps"].as_i64().unwrap_or(100) as i32).clamp(1, max.max(1));
    let ports = match cfg["ports"]["preset"].as_str() {
        Some("top1000") => top_ports(1000, approved),
        Some("allowed") if !approved.is_empty() => approved.iter().map(u16::to_string).collect::<Vec<_>>().join(","),
        Some("allowed") => settings["scan_safety"]["allowed_ports"].as_str().unwrap_or("100").to_string(),
        Some("custom") => cfg["ports"]["custom"].as_str().unwrap_or("100").to_string(),
        _ => top_ports(100, approved),
    };
    let port_count = match ports.as_str() {
        "100" => 100,
        "1000" => 1000,
        "full" => 65535,
        list => list
            .split(',')
            .filter_map(|p| {
                let mut e = p.trim().split('-').map(|x| x.trim().parse::<u64>().ok());
                match (e.next().flatten(), e.next().flatten()) {
                    (Some(a), Some(b)) => Some(b.saturating_sub(a) + 1),
                    (Some(_), None) => Some(1),
                    _ => None,
                }
            })
            .sum::<u64>()
            .max(1),
    };
    let batch_size = if cfg["batch_strategy"] == json!("fixed") {
        1i32 << (32 - cfg["batch_prefix"].as_i64().unwrap_or(24).clamp(16, 30) as i32)
    } else {
        256
    };
    Tuning {
        ports,
        rate,
        batch_size,
        inactive_after_misses: settings["change_detection"]["inactive_after_misses"].as_i64().unwrap_or(3) as i32,
        port_count,
    }
}

#[derive(Deserialize, Clone)]
pub struct WindowIn {
    start: String,
    end: String,
    #[serde(default = "warsaw")]
    timezone: String,
}

fn warsaw() -> String {
    "Europe/Warsaw".into()
}

fn window_minutes(w: &WindowIn) -> i64 {
    let m = |t: &str| t.get(..2).and_then(|h| h.parse::<i64>().ok()).unwrap_or(0) * 60 + t.get(3..5).and_then(|x| x.parse::<i64>().ok()).unwrap_or(0);
    let d = m(&w.end) - m(&w.start);
    if d <= 0 { d + 24 * 60 } else { d }
}

async fn check_window(db: &sqlx::PgPool, w: &WindowIn) -> V1<()> {
    let ok = |t: &str| {
        let b = t.as_bytes();
        b.len() == 5 && b[2] == b':' && t[..2].parse::<u8>().is_ok_and(|h| h < 24) && t[3..].parse::<u8>().is_ok_and(|m| m < 60)
    };
    if !ok(&w.start) || !ok(&w.end) {
        return Err(invalid("Okno musi mieć format GG:MM."));
    }
    let tz_ok: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = $1)")
        .bind(&w.timezone)
        .fetch_one(db)
        .await
        .map_err(fail)?;
    if !tz_ok {
        return Err(invalid("Nieznana strefa czasowa."));
    }
    Ok(())
}

fn default_window(settings: &Value) -> WindowIn {
    serde_json::from_value(settings["default_window"].clone()).unwrap_or(WindowIn {
        start: "22:00".into(),
        end: "06:00".into(),
        timezone: warsaw(),
    })
}

#[derive(Deserialize)]
pub struct EstimateBody {
    target_ids: Vec<Uuid>,
    profile_id: Uuid,
    #[serde(default)]
    window: Option<WindowIn>,
}

async fn estimate_value(s: &AppState, target_ids: &[Uuid], profile_id: Uuid, window: Option<&WindowIn>) -> V1<(Value, u64)> {
    let settings = load_settings(&s.db).await?;
    let p = profile(&s.db, profile_id).await?;
    if target_ids.is_empty() {
        return Err(invalid("Wybierz co najmniej jeden cel."));
    }
    let targets = v1::load_targets(&s.db, &s.config.data_key, Some(target_ids)).await?;
    if let Some(t) = targets.iter().find(|t| !t.excluded && !s.config.permits_target(&t.value)) {
        return Err(invalid(format!(
            "Cel {} jest poza zakresem zatwierdzonym przez administratora (ASI_ALLOWED_CIDRS) — skaner go nie obejmie.",
            t.value
        )));
    }
    if targets.is_empty() {
        return Err(invalid("Wybrane cele nie istnieją."));
    }
    let addresses: u64 = targets.iter().filter(|t| !t.excluded).map(|t| t.address_count).fold(0, u64::saturating_add);
    let excluded: u64 = targets.iter().filter(|t| t.excluded).map(|t| t.address_count).sum();
    let t = tuning(&p.config, &settings, &s.config.allowed_ports);
    let preset = p.config["ports"]["preset"].as_str().unwrap_or("top100");
    let top_n = matches!(preset, "top100" | "top1000") && !s.config.allowed_ports.is_empty();
    if top_n && t.ports.is_empty() {
        return Err(invalid(
            "Żaden z najczęstszych portów tego profilu nie jest zatwierdzony przez administratora (ASI_ALLOWED_PORTS).",
        ));
    }
    if !s.config.permits_ports(&t.ports) {
        return Err(invalid(
            "Profil używa portów spoza listy zatwierdzonej przez administratora (ASI_ALLOWED_PORTS). Wybierz profil z portami „Dozwolone” (np. „Laboratorium”) albo wpisz porty z tej listy.",
        ));
    }
    let rate = t.rate as f64;
    let est_alive = ((addresses as f64) * 0.19).round().max(1.0);
    let batches = addresses.div_ceil(t.batch_size.max(1) as u64).max(1);
    // Every address gets the pre-flight probes and every port probe (naabu -Pn), all under the
    // rate limit; then ~6 s per batch for -sV and httpx, ~20 s per run (start, diff, signatures).
    // Measured: lab /28 top-100 at 100/s: 42 s (model 42 s); lab /24: 280 s (318 s);
    // /18, 8 ports at 1000/s: 476 s (493 s) — docs/BENCHMARK.md.
    // Pre-flight probes the profile's own ports (`-PS<ports>`), then naabu probes them again.
    let probes_per_address = (2 * t.port_count) as f64;
    let seconds = ((addresses as f64) * probes_per_address / rate + batches as f64 * 6.0 + 20.0).round();
    let win = window.cloned().unwrap_or_else(|| default_window(&settings));
    let window_seconds = window_minutes(&win) * 60;
    let mut notes = Vec::new();
    if top_n {
        notes.push(format!(
            "Z {} najczęstszych portów skanowane są tylko zatwierdzone przez administratora: {}.",
            if preset == "top1000" { 1000 } else { 100 },
            t.ports
        ));
    }
    if excluded > 0 {
        notes.push(format!("Pominięto {excluded} adresów z celów wykluczonych."));
    }
    if p.config["rate_limit_rps"].as_i64().unwrap_or(0) > t.rate as i64 {
        notes.push(format!("Limit profilu obniżono do globalnego maksimum {} zapytań/s.", t.rate));
    }
    notes.push(format!(
        "Podział na {batches} podgrup po maks. {} adresów — po zamknięciu okna skan wznowi się od ostatniej ukończonej podgrupy.",
        t.batch_size
    ));
    let prefix = 32 - (t.batch_size.max(1) as f64).log2().round() as i32;
    Ok((
        json!({
            "addresses": addresses, "excluded": excluded, "est_alive": est_alive as u64,
            "batch_prefix": prefix, "batch_size": t.batch_size, "batches": batches, "rate_rps": t.rate,
            "est_duration_s": seconds as u64, "window_seconds": window_seconds,
            "fits_window": seconds as i64 <= window_seconds,
            "windows_needed": ((seconds as i64) / window_seconds.max(1) + 1).max(1),
            "notes": notes,
        }),
        addresses,
    ))
}

/// `POST /api/v1/scans/estimate`
pub async fn estimate(State(s): State<AppState>, Json(b): Json<EstimateBody>) -> V1<Json<Value>> {
    Ok(Json(estimate_value(&s, &b.target_ids, b.profile_id, b.window.as_ref()).await?.0))
}

// ---------- scans ----------

#[derive(Deserialize)]
pub struct CreateScan {
    name: String,
    target_ids: Vec<Uuid>,
    profile_id: Uuid,
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    window: Option<WindowIn>,
    #[serde(default)]
    on_window_exceeded: Option<String>,
    #[serde(default)]
    test_window_seconds: Option<i32>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    notes: Option<String>,
}

async fn run_by_id(db: &sqlx::PgPool, id: Uuid) -> V1<Value> {
    v1::load_runs(db, &format!("WHERE id = '{id}'"), 1).await?.first().map(v1::run_json).ok_or_else(missing)
}

/// Insert a `scans` row with settings from a profile; returns its id.
#[allow(clippy::too_many_arguments)]
async fn insert_scan(
    tx: &mut sqlx::PgConnection,
    name: &str,
    t: &Tuning,
    profile_id: Uuid,
    window: Option<&WindowIn>,
    days: &[i32],
    schedule: bool,
    on_exceeded: &str,
    test_secs: Option<i32>,
    tags: &[String],
    notes: Option<&str>,
    user: Uuid,
) -> sqlx::Result<Uuid> {
    sqlx::query_scalar(
        "INSERT INTO scans (name, enabled, rate_limit_pps, ports, batch_size, preflight, inactive_after_misses, profile_id,
                            window_start, window_end, timezone, schedule_days, is_schedule, on_window_exceeded,
                            test_window_seconds, tags, notes, created_by)
         VALUES ($1, false, $2, $3, $4, true, $5, $6, $7::time, $8::time, COALESCE($9, 'Europe/Warsaw'), $10, $11, $12,
                 $13, $14, $15, $16)
         RETURNING id",
    )
    .bind(name)
    .bind(t.rate)
    .bind(&t.ports)
    .bind(t.batch_size)
    .bind(t.inactive_after_misses)
    .bind(profile_id)
    .bind(window.map(|w| w.start.clone()))
    .bind(window.map(|w| w.end.clone()))
    .bind(window.map(|w| w.timezone.clone()))
    .bind(days)
    .bind(schedule)
    .bind(on_exceeded)
    .bind(test_secs)
    .bind(tags)
    .bind(notes)
    .bind(user)
    .fetch_one(tx)
    .await
}

async fn link_targets(tx: &mut sqlx::PgConnection, scan: Uuid, ids: &[Uuid]) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM scan_targets WHERE scan_id = $1").bind(scan).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO scan_targets (scan_id, target_id) SELECT $1, id FROM targets WHERE id = ANY($2) ON CONFLICT DO NOTHING")
        .bind(scan)
        .bind(ids)
        .execute(tx)
        .await
        .map(drop)
}

fn on_exceeded(v: Option<&str>) -> V1<&'static str> {
    match v.unwrap_or("pause_resume") {
        "pause_resume" => Ok("pause_resume"),
        "stop" => Ok("stop"),
        _ => Err(invalid("on_window_exceeded: pause_resume lub stop.")),
    }
}

/// `POST /api/v1/scans` → ScanRun (201). `start: "window"` waits for the window to open.
pub async fn create_scan(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(b): Json<CreateScan>,
) -> V1<(StatusCode, Extension<Note>, Json<Value>)> {
    let name = text(Some(&b.name), "name", 200, false)?.ok_or_else(|| invalid("Podaj nazwę skanowania."))?;
    if let Some(w) = &b.window {
        check_window(&s.db, w).await?;
    }
    if b.test_window_seconds.is_some_and(|t| !(30..=3600).contains(&t)) {
        // Shorter than one host scan (nmap -sV) the window would never let a batch finish.
        return Err(invalid("Okno testowe: 30–3600 sekund."));
    }
    let exceeded = on_exceeded(b.on_window_exceeded.as_deref())?;
    let (_, addresses) = estimate_value(&s, &b.target_ids, b.profile_id, b.window.as_ref()).await?;
    if addresses == 0 {
        return Err(invalid("Wszystkie wybrane cele są wykluczone ze skanowania."));
    }
    if u128::from(addresses) > input::MAX_SCAN_HOSTS {
        return Err(invalid(format!("Skan obejmuje {addresses} adresów, maksimum to {}.", input::MAX_SCAN_HOSTS)));
    }
    let settings = load_settings(&s.db).await?;
    let p = profile(&s.db, b.profile_id).await?;
    let t = tuning(&p.config, &settings, &s.config.allowed_ports);
    let tags = clean_tags(&b.tags)?;
    let notes = text(b.notes.as_deref(), "notes", 5000, true)?;
    let mut tx = s.db.begin().await.map_err(fail)?;
    let scan = insert_scan(
        &mut tx, &name, &t, p.id, b.window.as_ref(), &[], false, exceeded, b.test_window_seconds, &tags, notes.as_deref(), user.id,
    )
    .await
    .map_err(fail)?;
    link_targets(&mut tx, scan, &b.target_ids).await.map_err(fail)?;
    // The scheduler picks the run up at `resume_at` (now, or when the window opens).
    let wait_for_window = b.start.as_deref() == Some("window") && b.window.is_some();
    let run: Uuid = sqlx::query_scalar(
        "INSERT INTO scan_runs (scan_id, status, resume_at, tags, notes, ignore_window, stats)
         SELECT s.id, 'paused',
                CASE WHEN $2 AND asi_window_close(s.window_start, s.window_end, s.timezone, s.schedule_days, now()) IS NULL
                     THEN asi_next_window_open(s.window_start, s.timezone, s.schedule_days, now()) ELSE now() END,
                $3, $4,
                -- \"Teraz\" with the window closed: run now, without it (migration 0011).
                NOT $2 AND s.window_start IS NOT NULL
                    AND asi_window_close(s.window_start, s.window_end, s.timezone, s.schedule_days, now()) IS NULL,
                -- Address count shown before the pipeline starts (it sets the same value).
                jsonb_build_object('hosts_total', $5::bigint)
         FROM scans s WHERE s.id = $1 RETURNING id",
    )
    .bind(scan)
    .bind(wait_for_window)
    .bind(&tags)
    .bind(&notes)
    .bind(addresses as i64)
    .fetch_one(&mut *tx)
    .await
    .map_err(fail)?;
    tx.commit().await.map_err(fail)?;
    let note = Note::new("scan.start", "scan", run, json!({ "name": name, "addresses": addresses, "start": b.start }));
    Ok((StatusCode::CREATED, Extension(note), Json(run_by_id(&s.db, run).await?)))
}

/// `GET /api/v1/scans/{id}`
pub async fn get_scan(State(s): State<AppState>, Path(id): Path<Uuid>) -> V1<Json<Value>> {
    Ok(Json(run_by_id(&s.db, id).await?))
}

#[derive(Deserialize)]
pub struct PatchScan {
    name: Option<String>,
    tags: Option<Vec<String>>,
    #[serde(default, deserialize_with = "crate::api::present")]
    notes: Option<Option<String>>,
}

/// `PATCH /api/v1/scans/{id}` — name (of the scan), tags and notes (of this run).
pub async fn update_scan(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    Json(b): Json<PatchScan>,
) -> V1<(Extension<Note>, Json<Value>)> {
    let scan_id: Uuid = sqlx::query_scalar("SELECT scan_id FROM scan_runs WHERE id = $1")
        .bind(id)
        .fetch_optional(&s.db)
        .await
        .map_err(fail)?
        .ok_or_else(missing)?;
    if let Some(n) = &b.name {
        let n = text(Some(n), "name", 200, false)?.ok_or_else(|| invalid("Podaj nazwę."))?;
        sqlx::query("UPDATE scans SET name = $2 WHERE id = $1").bind(scan_id).bind(n).execute(&s.db).await.map_err(fail)?;
    }
    if let Some(t) = &b.tags {
        let t = clean_tags(t)?;
        sqlx::query("UPDATE scan_runs SET tags = $2 WHERE id = $1").bind(id).bind(t).execute(&s.db).await.map_err(fail)?;
    }
    if let Some(n) = &b.notes {
        let n = text(n.as_deref(), "notes", 5000, true)?;
        sqlx::query("UPDATE scan_runs SET notes = $2 WHERE id = $1").bind(id).bind(n).execute(&s.db).await.map_err(fail)?;
    }
    Ok((Extension(Note::new("scan.update", "scan", id, json!({}))), Json(run_by_id(&s.db, id).await?)))
}

/// `DELETE /api/v1/scans/{id}` — a finished run with its results (409 while active).
pub async fn delete_scan(State(s): State<AppState>, Path(id): Path<Uuid>) -> V1<(StatusCode, Extension<Note>)> {
    let status: String = sqlx::query_scalar("SELECT status::text FROM scan_runs WHERE id = $1")
        .bind(id)
        .fetch_optional(&s.db)
        .await
        .map_err(fail)?
        .ok_or_else(missing)?;
    if matches!(status.as_str(), "queued" | "running" | "paused") {
        return Err(err(StatusCode::CONFLICT, "conflict", "Skanowanie trwa — najpierw je przerwij."));
    }
    sqlx::query("DELETE FROM scan_runs WHERE id = $1").bind(id).execute(&s.db).await.map_err(fail)?;
    Ok((StatusCode::NO_CONTENT, Extension(Note::new("scan.delete", "scan", id, json!({ "status": status })))))
}

/// `POST /api/v1/scans/{id}/{pause|resume|cancel}`
pub async fn control(
    State(s): State<AppState>,
    Path((id, action)): Path<(Uuid, String)>,
) -> V1<(Extension<Note>, Json<Value>)> {
    let sql = match action.as_str() {
        // A running pipeline stops after its current batch; a waiting run stops waiting.
        "pause" => "UPDATE scan_runs SET status = 'paused', resume_at = NULL WHERE id = $1 AND status IN ('queued', 'running', 'paused')",
        "resume" => "UPDATE scan_runs SET resume_at = now() WHERE id = $1 AND status = 'paused'",
        "cancel" => {
            "UPDATE scan_runs SET status = 'cancelled', resume_at = NULL,
                 finished_at = CASE WHEN status = 'running' THEN finished_at ELSE now() END
             WHERE id = $1 AND status IN ('queued', 'running', 'paused')"
        }
        _ => return Err(missing()),
    };
    let n = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(id).execute(&s.db).await.map_err(fail)?.rows_affected();
    if n == 0 {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM scan_runs WHERE id = $1)")
            .bind(id)
            .fetch_one(&s.db)
            .await
            .map_err(fail)?;
        return Err(if exists { err(StatusCode::CONFLICT, "conflict", "To skanowanie już się zakończyło.") } else { missing() });
    }
    let note = Note {
        action: match action.as_str() {
            "pause" => "scan.pause",
            "resume" => "scan.resume",
            _ => "scan.cancel",
        },
        entity: "scan",
        entity_id: Some(id.to_string()),
        details: json!({}),
    };
    Ok((Extension(note), Json(run_by_id(&s.db, id).await?)))
}

/// `GET /api/v1/scans/{id}/batches` — from progress and the per-batch raw outputs.
pub async fn batches(State(s): State<AppState>, Path(id): Path<Uuid>) -> V1<Json<Vec<Value>>> {
    let run = v1::load_runs(&s.db, &format!("WHERE id = '{id}'"), 1).await?.into_iter().next().ok_or_else(missing)?;
    let times: BTreeMap<i32, (DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as::<_, (i32, DateTime<Utc>, DateTime<Utc>)>(
        "SELECT batch, min(created_at), max(created_at) FROM run_artifacts WHERE run_id = $1 GROUP BY batch",
    )
    .bind(id)
    .fetch_all(&s.db)
    .await
    .map_err(fail)?
    .into_iter()
    .map(|(b, a, z)| (b, (a, z)))
    .collect();
    let st = &run.stats;
    let done = v1::f(st, "batches_done") as i64;
    let total = (run.total_batches.unwrap_or(0) as i64).max(done);
    let size = st["batch_size_current"].as_u64().unwrap_or(256);
    let failed: Vec<(u64, u64)> = serde_json::from_value(st["failed_ranges"].clone()).unwrap_or_default();
    let active = matches!(run.status.as_str(), "running");
    let mut out = Vec::new();
    for i in 0..total {
        let (status, started, finished) = match times.get(&(i as i32)) {
            Some((a, z)) if i < done => ("done", Some(*a), Some(*z)),
            _ if i < done => ("done", None, None),
            _ if i == done && active => ("running", None, None),
            _ if i == done && run.status == "paused" => ("paused", None, None),
            _ => ("pending", None, None),
        };
        let status = if i < done && failed.len() as i64 > 0 && i >= done - failed.len() as i64 && !times.contains_key(&(i as i32)) {
            "failed"
        } else {
            status
        };
        out.push(json!({
            "id": format!("{id}-{i}"), "index": i, "cidr": format!("podgrupa {} (~{size} adresów)", i + 1),
            "addresses": size, "status": status, "started_at": started, "finished_at": finished,
            "duration_s": match (started, finished) { (Some(a), Some(z)) => Some((z - a).num_seconds().max(1)), _ => None },
            "hosts_alive": null, "rate_rps": run.rate_limit_pps, "retries": 0,
        }));
    }
    Ok(Json(out))
}

fn log_line(at: DateTime<Utc>, level: &str, message: impl Into<String>) -> Value {
    json!({ "at": at, "level": level, "message": message.into() })
}

/// Log lines of a run, built from its state and stats.
fn logs_of(run: &v1::RunRow, view: &Value) -> Vec<Value> {
    let st = &run.stats;
    let mut out = vec![log_line(
        run.started_at,
        "info",
        format!("Utworzono skanowanie „{}” ({} adresów, limit {} zapytań/s)", run.name, view["address_count"], run.rate_limit_pps),
    )];
    if let Some(w) = run.window_started_at {
        out.push(log_line(w, "info", "Okno skanowania otwarte — skaner pracuje"));
    }
    let done = v1::f(st, "batches_done") as u64;
    if done > 0 {
        out.push(log_line(
            run.window_started_at.unwrap_or(run.started_at),
            "info",
            format!(
                "Ukończono {done} podgrup: {} aktywnych hostów, {} otwartych portów, {} usług WWW",
                v1::f(st, "alive"), v1::f(st, "open_ports"), v1::f(st, "http")
            ),
        ));
    }
    if run.status == "paused" {
        let at = |t: DateTime<Utc>| t.format("%d.%m.%Y %H:%M UTC").to_string();
        match run.resume_at {
            // Not started yet: waiting for the scheduler (a few seconds) or for its window. A fixed
            // time (the run's creation), so polling clients see one line, not one per poll.
            Some(r) if run.window_started_at.is_none() && r <= Utc::now() => {
                out.push(log_line(run.started_at, "info", "W kolejce — skaner zaraz rozpocznie pracę"))
            }
            Some(r) if run.window_started_at.is_none() => {
                out.push(log_line(run.started_at, "info", format!("Czeka na okno skanowania — start {}", at(r))))
            }
            Some(r) => out.push(log_line(Utc::now(), "warn", format!("Okno zamknięte — wznowienie {}", at(r)))),
            None => out.push(log_line(Utc::now(), "warn", "Wstrzymano na żądanie użytkownika")),
        }
    }
    for e in st["errors"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        out.push(log_line(run.finished_at.unwrap_or_else(Utc::now), "error", e));
    }
    if let Some(d) = st.get("diff").filter(|d| !d.is_null()) {
        out.push(log_line(
            run.finished_at.unwrap_or_else(Utc::now),
            "info",
            format!("Porównanie z poprzednim przebiegiem: {} nowych, {} zmienionych, {} zniknęło", v1::f(d, "new"), v1::f(d, "changed"), v1::f(d, "gone")),
        ));
    }
    if let Some(f) = run.finished_at {
        let (lvl, msg) = match run.status.as_str() {
            "done" => ("info", "Skanowanie zakończone".to_string()),
            "partial" => ("warn", "Skanowanie zakończone częściowo — część zakresu nie została pokryta".to_string()),
            "cancelled" => ("warn", "Skanowanie przerwane".to_string()),
            _ => ("error", format!("Skanowanie zakończone błędem: {}", run.error.clone().unwrap_or_default())),
        };
        out.push(log_line(f, lvl, msg));
    }
    out
}

/// `GET /api/v1/scans/{id}/logs`
pub async fn logs(State(s): State<AppState>, Path(id): Path<Uuid>) -> V1<Json<Vec<Value>>> {
    let run = v1::load_runs(&s.db, &format!("WHERE id = '{id}'"), 1).await?.into_iter().next().ok_or_else(missing)?;
    let view = v1::run_json(&run);
    Ok(Json(logs_of(&run, &view)))
}

/// `GET /api/v1/scans/{id}/events` — Server-Sent Events: progress, log, window, done.
pub async fn events(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
) -> V1<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    run_by_id(&s.db, id).await?;
    struct St {
        db: sqlx::PgPool,
        id: Uuid,
        queue: VecDeque<Event>,
        logs_sent: usize,
        last_status: String,
        done: bool,
        started: std::time::Instant,
    }
    let init = St {
        db: s.db.clone(),
        id,
        queue: VecDeque::new(),
        logs_sent: 0,
        last_status: String::new(),
        done: false,
        started: std::time::Instant::now(),
    };
    let ev = |kind: &str, data: Value| Event::default().event(kind).data(data.to_string());
    let stream = stream::unfold(init, move |mut st| async move {
        loop {
            if let Some(e) = st.queue.pop_front() {
                return Some((Ok(e), st));
            }
            if st.done {
                return None;
            }
            if st.last_status.is_empty() {
                // First tick immediately.
            } else {
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
            let Ok(runs) = v1::load_runs(&st.db, &format!("WHERE id = '{}'", st.id), 1).await else {
                return None;
            };
            let run = runs.into_iter().next()?;
            let view = v1::run_json(&run);
            let status = view["status"].as_str().unwrap_or_default().to_string();
            st.queue.push_back(ev("progress", json!({ "type": "progress", "scan": view })));
            let lines = logs_of(&run, &view);
            for l in lines.iter().skip(st.logs_sent) {
                let mut l = l.clone();
                l["type"] = json!("log");
                st.queue.push_back(ev("log", l));
            }
            st.logs_sent = lines.len();
            if status == "paused_window" && st.last_status != "paused_window" {
                st.queue.push_back(ev("window", json!({ "type": "window", "state": "paused", "resume_at": run.resume_at })));
            }
            if st.last_status == "paused_window" && status == "running" {
                st.queue.push_back(ev("window", json!({ "type": "window", "state": "resumed", "resume_at": null })));
            }
            if matches!(status.as_str(), "completed" | "cancelled" | "failed") || st.started.elapsed() > Duration::from_secs(15 * 60) {
                st.queue.push_back(ev("done", json!({ "type": "done", "scan": view })));
                st.done = true;
            }
            st.last_status = status;
        }
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

// ---------- export / import of results ----------

#[derive(Deserialize)]
pub struct FormatQuery {
    format: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ResultRow {
    ip: String,
    hostname: Option<String>,
    state: String,
    port: Option<i32>,
    protocol: Option<String>,
    service: Option<String>,
    product: Option<String>,
    version: Option<String>,
    url: Option<String>,
    status_code: Option<i32>,
    title: Option<String>,
    technologies: Option<Vec<String>>,
}

/// `GET /api/v1/scans/{id}/export?format=json|csv` — results without secrets
/// (no header/cookie values, no raw outputs). The JSON re-imports with `/scans/import`.
pub async fn export(State(s): State<AppState>, Path(id): Path<Uuid>, Query(q): Query<FormatQuery>) -> V1<Response> {
    let run = v1::load_runs(&s.db, &format!("WHERE id = '{id}'"), 1).await?.into_iter().next().ok_or_else(missing)?;
    let rows = sqlx::query_as::<_, ResultRow>(
        "SELECT host(h.address) AS ip, h.hostname, h.state::text AS state, sv.port, sv.protocol, sv.service, sv.product, sv.version,
                f.url, f.status_code, f.title, f.technologies
         FROM hosts h LEFT JOIN services sv ON sv.host_id = h.id LEFT JOIN http_findings f ON f.service_id = sv.id
         WHERE h.run_id = $1 ORDER BY h.address, sv.port",
    )
    .bind(id)
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    let number = run.number;
    let note = |format: &str| Note::new("scan.export", "scan", id, json!({ "format": format, "rows": rows.len() }));
    if q.format.as_deref() == Some("csv") {
        let mut w = csv::Writer::from_writer(Vec::new());
        w.write_record(["ip", "hostname", "state", "port", "protocol", "service", "product", "version", "url", "status_code", "title", "technologies"])
            .map_err(fail)?;
        for r in &rows {
            w.write_record([
                r.ip.clone(),
                v1::csv_text(r.hostname.as_deref().unwrap_or_default()),
                r.state.clone(),
                r.port.map(|p| p.to_string()).unwrap_or_default(),
                v1::csv_text(r.protocol.as_deref().unwrap_or_default()),
                v1::csv_text(r.service.as_deref().unwrap_or_default()),
                v1::csv_text(r.product.as_deref().unwrap_or_default()),
                v1::csv_text(r.version.as_deref().unwrap_or_default()),
                v1::csv_text(r.url.as_deref().unwrap_or_default()),
                r.status_code.map(|c| c.to_string()).unwrap_or_default(),
                v1::csv_text(r.title.as_deref().unwrap_or_default()),
                v1::csv_text(&r.technologies.clone().unwrap_or_default().join(";")),
            ])
            .map_err(fail)?;
        }
        let body = w.into_inner().map_err(fail)?;
        return Ok(v1::file("text/csv; charset=utf-8", &format!("skan-{number}.csv"), body, note("csv")));
    }
    let mut hosts: BTreeMap<String, Value> = BTreeMap::new();
    for r in &rows {
        let h = hosts.entry(r.ip.clone()).or_insert_with(|| {
            json!({ "ip": r.ip, "hostnames": r.hostname.iter().collect::<Vec<_>>(), "state": r.state, "services": [] })
        });
        if let Some(port) = r.port {
            let services = h["services"].as_array_mut().expect("array");
            let pos = services.iter().position(|x| x["port"] == json!(port));
            let svc = match pos {
                Some(i) => &mut services[i],
                None => {
                    services.push(json!({ "port": port, "protocol": r.protocol, "name": r.service, "product": r.product, "version": r.version, "http": [] }));
                    services.last_mut().expect("pushed")
                }
            };
            if let Some(url) = &r.url {
                svc["http"].as_array_mut().expect("array").push(json!({
                    "url": url, "status_code": r.status_code, "title": r.title, "technologies": r.technologies,
                }));
            }
        }
    }
    let data = json!({
        "format": "asi-results", "version": 1, "exported_at": Utc::now(),
        "scan": { "id": id, "number": number, "name": run.name, "started_at": run.started_at, "finished_at": run.finished_at },
        "hosts": hosts.into_values().collect::<Vec<_>>(),
    });
    let body = serde_json::to_vec_pretty(&data).map_err(fail)?;
    Ok(v1::file("application/json", &format!("skan-{number}.json"), body, note("json")))
}

/// One imported observation.
#[derive(Debug, Clone, PartialEq)]
struct ImportRow {
    ip: std::net::IpAddr,
    hostname: Option<String>,
    port: Option<u16>,
    protocol: String,
    service: Option<String>,
    product: Option<String>,
    version: Option<String>,
}

fn import_rows(bytes: &[u8], filename: &str) -> Result<Vec<ImportRow>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "Plik musi być w UTF-8.".to_string())?.trim_start_matches('\u{feff}');
    let clip = |v: Option<&str>| v.map(str::trim).filter(|v| !v.is_empty()).map(|v| v.chars().take(200).collect::<String>());
    let lower = filename.to_lowercase();
    let mut out = Vec::new();
    if lower.ends_with(".xml") || text.trim_start().starts_with("<?xml") || text.contains("<nmaprun") {
        let services = crate::parse::nmap_services(text).map_err(|e| format!("Niepoprawny XML nmap: {e}"))?;
        for s in services {
            let ip = s.ip.parse().map_err(|_| format!("Niepoprawny adres: {}", s.ip))?;
            out.push(ImportRow {
                ip,
                hostname: None,
                port: Some(s.port),
                protocol: s.protocol,
                service: s.name,
                product: s.product,
                version: s.version,
            });
        }
        return Ok(out);
    }
    if lower.ends_with(".json") || text.trim_start().starts_with(['{', '[']) {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("Niepoprawny JSON: {e}"))?;
        let hosts = match &v {
            Value::Array(a) => a.clone(),
            Value::Object(o) => o.get("hosts").and_then(Value::as_array).cloned().unwrap_or_default(),
            _ => vec![],
        };
        for h in hosts {
            let Some(ip) = h["ip"].as_str().and_then(|i| i.trim().parse().ok()) else { continue };
            let hostname = clip(h["hostnames"].get(0).and_then(Value::as_str).or(h["hostname"].as_str()));
            let services = h["services"].as_array().cloned().unwrap_or_default();
            if services.is_empty() {
                out.push(ImportRow { ip, hostname: hostname.clone(), port: None, protocol: "tcp".into(), service: None, product: None, version: None });
            }
            for s in services {
                out.push(ImportRow {
                    ip,
                    hostname: hostname.clone(),
                    port: s["port"].as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0),
                    protocol: if s["protocol"] == json!("udp") { "udp".into() } else { "tcp".into() },
                    service: clip(s["name"].as_str().or(s["service"].as_str())),
                    product: clip(s["product"].as_str()),
                    version: clip(s["version"].as_str()),
                });
            }
        }
        return Ok(out);
    }
    let mut rdr = csv::ReaderBuilder::new().trim(csv::Trim::All).flexible(true).from_reader(text.as_bytes());
    let headers: Vec<String> = rdr.headers().map_err(|e| e.to_string())?.iter().map(str::to_lowercase).collect();
    let col = |n: &str| headers.iter().position(|h| h == n);
    let ip_col = col("ip").ok_or("CSV: brak kolumny „ip”.")?;
    for (index, record) in rdr.records().enumerate() {
        if index >= 200_000 { return Err("CSV row limit exceeded".into()); }
        let rec = record.map_err(|_| format!("Invalid CSV record {}", index + 2))?;
        let get = |c: Option<usize>| clip(c.and_then(|i| rec.get(i)));
        let Some(ip) = get(Some(ip_col)).and_then(|i| i.parse().ok()) else { continue };
        out.push(ImportRow {
            ip,
            hostname: get(col("hostname")),
            port: get(col("port")).and_then(|p| p.parse().ok()).filter(|p| *p > 0),
            protocol: if get(col("protocol")).as_deref() == Some("udp") { "udp".into() } else { "tcp".into() },
            service: get(col("service")),
            product: get(col("product")),
            version: get(col("version")),
        });
    }
    Ok(out)
}

/// `POST /api/v1/scans/import` (multipart `file`: ASI JSON, CSV `ip,…` or nmap `-oX` XML).
/// Creates a finished run (`source = import`) — nothing is scanned.
pub async fn import(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    mut form: Multipart,
) -> V1<(StatusCode, Extension<Note>, Json<Value>)> {
    let (mut bytes, mut filename) = (None, String::from("wyniki"));
    while let Some(field) = form.next_field().await.map_err(|e| invalid(format!("Niepoprawny formularz: {e}")))? {
        if field.name() == Some("file") {
            filename = field.file_name().unwrap_or("wyniki").chars().take(120).collect();
            bytes = Some(field.bytes().await.map_err(|e| invalid(e.to_string()))?);
        }
    }
    let bytes = bytes.ok_or_else(|| invalid("Dołącz plik w polu „file”."))?;
    let rows = import_rows(&bytes, &filename).map_err(invalid)?;
    if rows.is_empty() {
        return Err(invalid("Plik nie zawiera żadnych hostów (oczekiwano kolumny lub pola „ip”)."));
    }
    if rows.len() > 200_000 {
        return Err(invalid("Najwyżej 200 000 wierszy w jednym imporcie."));
    }
    let key = s.config.data_key.as_str();
    let mut tx = s.db.begin().await.map_err(fail)?;
    let scan: Uuid = sqlx::query_scalar(
        "INSERT INTO scans (name, enabled, tags, created_by) VALUES ($1, false, '{import}', $2) RETURNING id",
    )
    .bind(format!("Import: {filename}"))
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(fail)?;
    let ips: std::collections::BTreeSet<std::net::IpAddr> = rows.iter().map(|r| r.ip).collect();
    let snapshot: Vec<Value> = ips.iter().map(|ip| json!({ "kind": "ip", "value": ip.to_string() })).collect();
    let run: Uuid = sqlx::query_scalar(
        "INSERT INTO scan_runs (scan_id, status, source, finished_at, target_snapshot, tags, notes, stats)
         VALUES ($1, 'done', 'import', now(), $2, '{import}', $3, $4) RETURNING id",
    )
    .bind(scan)
    .bind(Value::Array(snapshot))
    .bind(format!("Zaimportowano {} wierszy z pliku {filename}", rows.len()))
    .bind(json!({
        "hosts_total": ips.len(), "hosts_done": ips.len(), "alive": ips.len(),
        "open_ports": rows.iter().filter(|r| r.port.is_some()).count(), "analysis": "baseline",
    }))
    .fetch_one(&mut *tx)
    .await
    .map_err(fail)?;
    let mut host_ids: BTreeMap<std::net::IpAddr, Uuid> = BTreeMap::new();
    for r in &rows {
        let host = match host_ids.get(&r.ip) {
            Some(h) => *h,
            None => {
                let h: Uuid = sqlx::query_scalar(
                    "INSERT INTO hosts (run_id, address, hostname, state) VALUES ($1, $2::inet, $3, 'active') RETURNING id",
                )
                .bind(run)
                .bind(r.ip.to_string())
                .bind(&r.hostname)
                .fetch_one(&mut *tx)
                .await
                .map_err(fail)?;
                host_ids.insert(r.ip, h);
                h
            }
        };
        if let Some(port) = r.port {
            sqlx::query(
                "INSERT INTO services (host_id, port, protocol, service, product, version, confidence, banner_enc)
                 VALUES ($1, $2, $3, $4, $5, $6, 0.7, pgp_sym_encrypt('null', $7))
                 ON CONFLICT (host_id, port, protocol) DO NOTHING",
            )
            .bind(host)
            .bind(i32::from(port))
            .bind(&r.protocol)
            .bind(&r.service)
            .bind(&r.product)
            .bind(&r.version)
            .bind(key)
            .execute(&mut *tx)
            .await
            .map_err(fail)?;
        }
    }
    tx.commit().await.map_err(fail)?;
    let note = Note::new("scan.import", "scan", run, json!({ "file": filename, "hosts": ips.len(), "rows": rows.len() }));
    Ok((StatusCode::CREATED, Extension(note), Json(run_by_id(&s.db, run).await?)))
}

// ---------- schedules (F-20) ----------

#[derive(sqlx::FromRow)]
struct ScheduleRow {
    id: Uuid,
    name: String,
    enabled: bool,
    profile_id: Option<Uuid>,
    window_start: Option<String>,
    window_end: Option<String>,
    timezone: String,
    schedule_days: Vec<i32>,
    on_window_exceeded: String,
    next_run_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    target_ids: Option<Vec<Uuid>>,
    last_run_id: Option<Uuid>,
}

const SCHEDULE_SELECT: &str = "SELECT s.id, s.name, s.enabled, s.profile_id, to_char(s.window_start, 'HH24:MI') AS window_start,
        to_char(s.window_end, 'HH24:MI') AS window_end, s.timezone, s.schedule_days, s.on_window_exceeded, s.next_run_at,
        s.created_at, (SELECT array_agg(st.target_id) FROM scan_targets st WHERE st.scan_id = s.id) AS target_ids,
        (SELECT r.id FROM scan_runs r WHERE r.scan_id = s.id ORDER BY r.started_at DESC LIMIT 1) AS last_run_id
    FROM scans s WHERE s.is_schedule";

fn schedule_json(r: &ScheduleRow) -> Value {
    let days = if r.schedule_days.is_empty() { (1..=7).collect() } else { r.schedule_days.clone() };
    json!({
        "id": r.id, "name": r.name, "enabled": r.enabled, "target_ids": r.target_ids.clone().unwrap_or_default(),
        "profile_id": r.profile_id,
        "window": { "start": r.window_start, "end": r.window_end, "timezone": r.timezone },
        "days": days, "frequency": if days.len() == 7 { "daily" } else { "weekly" }, "cron": null,
        "on_window_exceeded": r.on_window_exceeded, "next_run_at": r.next_run_at, "last_run_id": r.last_run_id,
        "created_at": r.created_at,
    })
}

async fn schedule(db: &sqlx::PgPool, id: Uuid) -> V1<ScheduleRow> {
    sqlx::query_as::<_, ScheduleRow>(sqlx::AssertSqlSafe(format!("{SCHEDULE_SELECT} AND s.id = $1")))
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(fail)?
        .ok_or_else(missing)
}

/// `GET /api/v1/schedules`
pub async fn list_schedules(State(s): State<AppState>) -> V1<Json<Vec<Value>>> {
    let rows = sqlx::query_as::<_, ScheduleRow>(sqlx::AssertSqlSafe(format!("{SCHEDULE_SELECT} ORDER BY s.name")))
        .fetch_all(&s.db)
        .await
        .map_err(fail)?;
    Ok(Json(rows.iter().map(schedule_json).collect()))
}

#[derive(Deserialize)]
pub struct ScheduleIn {
    name: Option<String>,
    enabled: Option<bool>,
    target_ids: Option<Vec<Uuid>>,
    profile_id: Option<Uuid>,
    window: Option<WindowIn>,
    days: Option<Vec<i32>>,
    frequency: Option<String>,
    on_window_exceeded: Option<String>,
}

fn check_days(days: &[i32], frequency: Option<&str>) -> V1<()> {
    if frequency == Some("cron") {
        return Err(invalid("Harmonogram cron nie jest obsługiwany — wybierz dni tygodnia i okno godzinowe."));
    }
    if days.is_empty() {
        return Err(invalid("Wybierz co najmniej jeden dzień tygodnia."));
    }
    if days.iter().any(|d| !(1..=7).contains(d)) {
        return Err(invalid("Dni tygodnia: 1 (poniedziałek) – 7 (niedziela)."));
    }
    Ok(())
}

/// Recompute when a schedule next opens its window (NULL when disabled).
async fn reschedule(db: &sqlx::PgPool, id: Uuid) -> V1<()> {
    sqlx::query(
        "UPDATE scans SET next_run_at = CASE WHEN enabled
             THEN asi_next_window_open(window_start, timezone, schedule_days, now() - interval '1 second') END
         WHERE id = $1",
    )
    .bind(id)
    .execute(db)
    .await
    .map_err(fail)?;
    Ok(())
}

/// `POST /api/v1/schedules`
pub async fn create_schedule(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(b): Json<ScheduleIn>,
) -> V1<(StatusCode, Extension<Note>, Json<Value>)> {
    if !user.can(Action::ExecuteScan) {
        return Err(forbidden());
    }
    let name = text(b.name.as_deref(), "name", 200, false)?.ok_or_else(|| invalid("Podaj nazwę harmonogramu."))?;
    let window = b.window.clone().ok_or_else(|| invalid("Podaj okno godzinowe."))?;
    check_window(&s.db, &window).await?;
    let days = b.days.clone().unwrap_or_else(|| (1..=7).collect());
    check_days(&days, b.frequency.as_deref())?;
    let target_ids = b.target_ids.clone().unwrap_or_default();
    if target_ids.is_empty() {
        return Err(invalid("Wybierz co najmniej jeden cel."));
    }
    let profile_id = b.profile_id.ok_or_else(|| invalid("Wybierz profil skanowania."))?;
    let settings = load_settings(&s.db).await?;
    let p = profile(&s.db, profile_id).await?;
    let t = tuning(&p.config, &settings, &s.config.allowed_ports);
    let exceeded = on_exceeded(b.on_window_exceeded.as_deref())?;
    let mut tx = s.db.begin().await.map_err(fail)?;
    let days_stored: Vec<i32> = if days.len() == 7 { vec![] } else { days };
    let id = insert_scan(&mut tx, &name, &t, p.id, Some(&window), &days_stored, true, exceeded, None, &[], None, user.id)
        .await
        .map_err(fail)?;
    sqlx::query("UPDATE scans SET enabled = $2 WHERE id = $1").bind(id).bind(b.enabled.unwrap_or(true)).execute(&mut *tx).await.map_err(fail)?;
    link_targets(&mut tx, id, &target_ids).await.map_err(fail)?;
    tx.commit().await.map_err(fail)?;
    reschedule(&s.db, id).await?;
    let note = Note::new("schedule.create", "schedule", id, json!({ "name": name }));
    Ok((StatusCode::CREATED, Extension(note), Json(schedule_json(&schedule(&s.db, id).await?))))
}

/// `PATCH /api/v1/schedules/{id}`
pub async fn update_schedule(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(b): Json<ScheduleIn>,
) -> V1<(Extension<Note>, Json<Value>)> {
    let cur = schedule(&s.db, id).await?;
    // Turning a schedule on or retuning it changes network load: scan.execute.
    if (b.enabled == Some(true) || b.window.is_some() || b.days.is_some() || b.profile_id.is_some() || b.target_ids.is_some())
        && !user.can(Action::ExecuteScan)
    {
        return Err(forbidden());
    }
    let mut tx = s.db.begin().await.map_err(fail)?;
    if let Some(n) = &b.name {
        let n = text(Some(n), "name", 200, false)?.ok_or_else(|| invalid("Podaj nazwę."))?;
        sqlx::query("UPDATE scans SET name = $2 WHERE id = $1").bind(id).bind(n).execute(&mut *tx).await.map_err(fail)?;
    }
    if let Some(w) = &b.window {
        check_window(&s.db, w).await?;
        sqlx::query("UPDATE scans SET window_start = $2::time, window_end = $3::time, timezone = $4 WHERE id = $1")
            .bind(id)
            .bind(&w.start)
            .bind(&w.end)
            .bind(&w.timezone)
            .execute(&mut *tx)
            .await
            .map_err(fail)?;
    }
    if let Some(d) = &b.days {
        check_days(d, b.frequency.as_deref())?;
        let stored: Vec<i32> = if d.len() == 7 { vec![] } else { d.clone() };
        sqlx::query("UPDATE scans SET schedule_days = $2 WHERE id = $1").bind(id).bind(stored).execute(&mut *tx).await.map_err(fail)?;
    } else if b.frequency.as_deref() == Some("cron") {
        check_days(&[], Some("cron"))?;
    }
    if let Some(e) = b.enabled {
        sqlx::query("UPDATE scans SET enabled = $2 WHERE id = $1").bind(id).bind(e).execute(&mut *tx).await.map_err(fail)?;
    }
    if let Some(o) = &b.on_window_exceeded {
        let o = on_exceeded(Some(o))?;
        sqlx::query("UPDATE scans SET on_window_exceeded = $2 WHERE id = $1").bind(id).bind(o).execute(&mut *tx).await.map_err(fail)?;
    }
    if let Some(pid) = b.profile_id {
        let settings = load_settings(&s.db).await?;
        let p = profile(&s.db, pid).await?;
        let t = tuning(&p.config, &settings, &s.config.allowed_ports);
        sqlx::query("UPDATE scans SET profile_id = $2, rate_limit_pps = $3, ports = $4, batch_size = $5 WHERE id = $1")
            .bind(id)
            .bind(pid)
            .bind(t.rate)
            .bind(&t.ports)
            .bind(t.batch_size)
            .execute(&mut *tx)
            .await
            .map_err(fail)?;
    }
    if let Some(ids) = &b.target_ids {
        if ids.is_empty() {
            return Err(invalid("Wybierz co najmniej jeden cel."));
        }
        link_targets(&mut tx, id, ids).await.map_err(fail)?;
    }
    tx.commit().await.map_err(fail)?;
    reschedule(&s.db, id).await?;
    let note = Note::new("schedule.update", "schedule", id, json!({ "name": cur.name }));
    Ok((Extension(note), Json(schedule_json(&schedule(&s.db, id).await?))))
}

/// `DELETE /api/v1/schedules/{id}` — keeps finished runs? No: removes the schedule and its runs
/// (409 while one is active).
pub async fn delete_schedule(State(s): State<AppState>, Path(id): Path<Uuid>) -> V1<(StatusCode, Extension<Note>)> {
    let cur = schedule(&s.db, id).await?;
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM scan_runs WHERE scan_id = $1 AND status IN ('queued', 'running', 'paused'))",
    )
    .bind(id)
    .fetch_one(&s.db)
    .await
    .map_err(fail)?;
    if active {
        return Err(err(StatusCode::CONFLICT, "conflict", "Harmonogram ma trwające skanowanie — najpierw je przerwij."));
    }
    sqlx::query("DELETE FROM scans WHERE id = $1").bind(id).execute(&s.db).await.map_err(fail)?;
    Ok((StatusCode::NO_CONTENT, Extension(Note::new("schedule.delete", "schedule", id, json!({ "name": cur.name })))))
}

// ---------- list (replaces the basic one in v1.rs) ----------

#[derive(Deserialize)]
pub struct ListQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    status: Option<String>,
    source: Option<String>,
    q: Option<String>,
}

/// `GET /api/v1/scans?status=a,b&source=&q=`
pub async fn list(State(s): State<AppState>, Query(q): Query<ListQuery>) -> V1<Json<Value>> {
    let runs = v1::load_runs(&s.db, "", 5000).await?;
    let mut items: Vec<Value> = runs.iter().map(v1::run_json).collect();
    if let Some(st) = opt(&q.status) {
        let wanted: Vec<&str> = st.split(',').map(str::trim).collect();
        items.retain(|r| r["status"].as_str().is_some_and(|s| wanted.contains(&s)));
    }
    if let Some(src) = opt(&q.source) {
        items.retain(|r| r["source"] == json!(src));
    }
    if let Some(needle) = opt(&q.q).map(str::to_lowercase) {
        items.retain(|r| {
            [r["name"].as_str(), r["targets_label"].as_str()].into_iter().flatten().any(|v| v.to_lowercase().contains(&needle))
                || format!("#{}", r["number"]).contains(&needle)
        });
    }
    Ok(Json(paginated(items, q.page, q.page_size.or(Some(20)))))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_lengths() {
        let w = |a: &str, b: &str| WindowIn { start: a.into(), end: b.into(), timezone: warsaw() };
        assert_eq!(window_minutes(&w("22:00", "06:00")), 480, "across midnight");
        assert_eq!(window_minutes(&w("08:30", "16:00")), 450);
        assert_eq!(window_minutes(&w("10:00", "10:00")), 1440);
    }

    #[test]
    fn profile_tuning() {
        let settings = json!({ "scan_safety": { "max_rate_rps": 150, "allowed_ports": "22,80,8000-8009" }, "change_detection": { "inactive_after_misses": 2 } });
        let none = Default::default();
        let t = tuning(&json!({ "ports": { "preset": "allowed", "custom": "" }, "rate_limit_rps": 500, "batch_strategy": "fixed", "batch_prefix": 26 }), &settings, &none);
        assert_eq!((t.rate, t.ports.as_str(), t.port_count, t.batch_size, t.inactive_after_misses), (150, "22,80,8000-8009", 12, 64, 2));
        // With an administrator allowlist, "allowed" means exactly those ports.
        let approved = [443, 22, 80].into_iter().collect();
        let t = tuning(&json!({ "ports": { "preset": "allowed", "custom": "" } }), &settings, &approved);
        assert_eq!((t.ports.as_str(), t.port_count), ("22,80,443", 3));
        let t = tuning(&json!({ "ports": { "preset": "top1000" }, "rate_limit_rps": 20 }), &settings, &none);
        assert_eq!((t.rate, t.ports.as_str(), t.batch_size), (20, "1000", 256));
    }

    #[test]
    fn top_n_presets_keep_only_approved_ports() {
        let services = "# comment\nhttp\t80/tcp\t0.48\nssh\t22/tcp\t0.18\nsnmp\t161/udp\t0.43\nhttps\t443/tcp\t0.20\nredis\t6379/tcp\t0.0001\n";
        assert_eq!(rank_ports(services), vec![80, 443, 22, 6379]);
    }

    #[test]
    fn import_formats() {
        let csv = b"ip,hostname,port,protocol,service,product,version\n10.0.0.5,web,443,tcp,https,nginx,1.25\n10.0.0.6,,,,,,\nbad,,,\n";
        let rows = import_rows(csv, "x.csv").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].port, Some(443));
        let json = br#"{"format":"asi-results","hosts":[{"ip":"10.0.0.7","hostnames":["a"],"services":[{"port":22,"name":"ssh","product":"OpenSSH"}]}]}"#;
        let rows = import_rows(json, "r.json").unwrap();
        assert_eq!((rows[0].ip.to_string().as_str(), rows[0].service.as_deref()), ("10.0.0.7", Some("ssh")));
        assert!(import_rows(b"{", "r.json").is_err());
        assert!(import_rows(b"host,port\n1,2\n", "r.csv").is_err(), "ip column required");
    }
}
