//! `/api/v1` — the contract of the Next.js dashboard (`frontend/src/lib/api/types.ts`).
//!
//! An adapter over the core data model with the same session, gate, RBAC and audit as
//! `/api`. It covers what the dashboard pages use today: sign-in, the summary page,
//! targets, findings, scan runs, search and the audit log. Anything else answers 404 and
//! the frontend shows its own "not available" state.
//!
//! Findings are derived from the latest finished run of every scan (admin panels, staging,
//! risky ports). Their ids are stable (UUIDv5 of scan + category + entity), so the analyst's
//! status, score, assignee and notes (`finding_states`) survive every rescan.

use crate::{
    api::{present, ApiError},
    audit::Note,
    auth::{self, ClientIp, CurrentUser, SignInError},
    diff::RISKY_PORTS,
    input,
    rbac::{Action, Role},
    AppState,
};
use axum::{
    extract::{Multipart, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use uuid::Uuid;

// ---------- errors and helpers ----------

fn err(status: StatusCode, code: &str, message: impl Into<String>) -> ApiError {
    let message = message.into();
    (status, Json(json!({ "error": { "code": code, "message": message }, "detail": message })))
}

fn invalid(message: impl Into<String>) -> ApiError {
    err(StatusCode::UNPROCESSABLE_ENTITY, "validation", message)
}

fn missing() -> ApiError {
    err(StatusCode::NOT_FOUND, "not_found", "Nie znaleziono.")
}

fn fail(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("v1: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "internal", "Błąd serwera. Szczegóły w logach.")
}

fn forbidden() -> ApiError {
    err(StatusCode::FORBIDDEN, "forbidden", "Twoja rola nie ma uprawnienia do tej operacji.")
}

type V1<T> = Result<T, ApiError>;

/// Empty query values (`?q=`) mean "no filter".
fn opt(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn paginated<T: Serialize>(mut items: Vec<T>, page: Option<usize>, page_size: Option<usize>) -> Value {
    let page_size = page_size.unwrap_or(25).clamp(1, 500);
    let page = page.unwrap_or(1).max(1);
    let total = items.len();
    let start = ((page - 1) * page_size).min(total);
    let end = (start + page_size).min(total);
    let items: Vec<T> = items.drain(start..end).collect();
    json!({ "items": items, "page": page, "page_size": page_size, "total": total })
}

/// `-field` = descending.
fn sort_spec(sort: Option<&str>, default: &str) -> (String, bool) {
    let s = sort.unwrap_or(default);
    match s.strip_prefix('-') {
        Some(f) => (f.to_string(), true),
        None => (s.to_string(), false),
    }
}

/// CSV cells that a spreadsheet would run as a formula get a leading apostrophe.
fn csv_text(s: &str) -> String {
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() }
}

fn file(content_type: &str, filename: &str, body: Vec<u8>, note: Note) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
        ],
        Extension(note),
        body,
    )
        .into_response()
}

/// Trimmed text or None; length and control characters checked.
fn text(v: Option<&str>, field: &str, max: usize, multiline: bool) -> V1<Option<String>> {
    crate::overlay::text(v, field, max, multiline).map_err(|(_, Json(b))| invalid(b["detail"].as_str().unwrap_or(field).to_string()))
}

const CRITICALITY: [&str; 4] = ["low", "medium", "high", "critical"];

fn criticality_rank(c: &str) -> usize {
    CRITICALITY.iter().position(|x| *x == c).unwrap_or(1)
}

fn clean_tags(tags: &[String]) -> V1<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        if let Some(t) = text(Some(t), "tag", 64, false)? {
            let t = t.to_lowercase();
            if !out.contains(&t) {
                out.push(t);
            }
        }
    }
    if out.len() > 32 {
        return Err(invalid("Najwyżej 32 tagi."));
    }
    Ok(out)
}

/// Latest finished run of every scan (the "current state").
const LATEST: &str = "SELECT DISTINCT ON (scan_id) id, scan_id, started_at, finished_at FROM scan_runs
    WHERE status IN ('done', 'partial') ORDER BY scan_id, started_at DESC";

// ---------- sessions and roles ----------

fn role_meta(role: Role) -> (&'static str, &'static str, &'static str) {
    match role {
        Role::Admin => ("admin", "Administrator", "Administracja — pełny dostęp, użytkownicy i integracje"),
        Role::Editor => ("operator", "Operator", "Dodawanie, usuwanie i modyfikacja"),
        Role::Modifier => ("analyst", "Analityk", "Modyfikacja i odczyt"),
        Role::Viewer => ("viewer", "Obserwator", "Tylko odczyt"),
    }
}

/// Contract permissions granted by the core RBAC (`rbac::Role::can`).
fn permissions(user: &CurrentUser) -> Vec<&'static str> {
    let mut p = Vec::new();
    let mut grant = |action: Action, keys: &[&'static str]| {
        if user.can(action) {
            p.extend_from_slice(keys);
        }
    };
    grant(
        Action::Read,
        &[
            "dashboard:read", "targets:read", "targets:export", "scans:read", "scans:export", "schedules:read",
            "assets:read", "findings:read", "findings:export", "changes:read", "signatures:read",
        ],
    );
    grant(Action::Create, &["targets:create", "targets:import", "scans:import", "schedules:create", "signatures:create"]);
    grant(
        Action::Update,
        &["targets:update", "scans:update", "schedules:update", "assets:update", "findings:update", "signatures:update", "signatures:test"],
    );
    grant(Action::Delete, &["targets:delete", "scans:delete", "schedules:delete", "signatures:delete"]);
    grant(Action::ReadEvidence, &["sensitive:reveal"]);
    grant(Action::ExecuteScan, &["scans:create", "scans:control", "assets:recheck"]);
    grant(Action::ManageUsers, &["users:read", "users:manage", "roles:read", "roles:manage"]);
    grant(Action::ManageIntegrations, &["integrations:read", "integrations:manage", "findings:defectdojo", "settings:read", "settings:manage"]);
    grant(Action::ReadAudit, &["audit:read"]);
    p
}

async fn session_json(db: &sqlx::PgPool, user: &CurrentUser) -> V1<Value> {
    let (created_at, last_login_at): (DateTime<Utc>, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT created_at, last_login_at FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(db)
            .await
            .map_err(fail)?;
    let (key, name, description) = role_meta(user.role);
    let perms = permissions(user);
    Ok(json!({
        "user": {
            "id": user.id, "login": user.username, "name": user.username, "email": "",
            "role_id": key, "role_name": name, "active": true,
            "last_login_at": last_login_at, "created_at": created_at,
        },
        "role": {
            "id": key, "key": key, "name": name, "description": description, "builtin": true,
            "permissions": perms, "users_count": 0,
        },
        "permissions": perms,
    }))
}

#[derive(Deserialize)]
pub struct LoginBody {
    login: String,
    password: String,
}

/// `POST /api/v1/auth/login` → Session + session cookie.
pub async fn login(State(s): State<AppState>, Extension(ClientIp(ip)): Extension<ClientIp>, Json(b): Json<LoginBody>) -> Response {
    let si = match auth::sign_in(&s, ip, &b.login, b.password, "/api/v1/auth/login").await {
        Ok(si) => si,
        Err(SignInError::Invalid) => {
            return err(StatusCode::UNAUTHORIZED, "invalid_credentials", "Nieprawidłowy login lub hasło.").into_response()
        }
        Err(SignInError::Limited) => {
            return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Zbyt wiele nieudanych prób. Spróbuj za 15 minut.")
                .into_response()
        }
        Err(SignInError::Internal) => return fail("sign-in failed").into_response(),
    };
    let user = CurrentUser {
        id: si.user_id,
        username: si.username.clone(),
        role: si.role,
        can_execute_scans: si.can_execute_scans,
        session_id: Uuid::nil(),
    };
    match session_json(&s.db, &user).await {
        Ok(body) => auth::with_session_cookie(Json(body).into_response(), &s, &si.token),
        Err(e) => e.into_response(),
    }
}

/// `GET /api/v1/auth/me`
pub async fn me(State(s): State<AppState>, Extension(user): Extension<CurrentUser>) -> V1<Json<Value>> {
    Ok(Json(session_json(&s.db, &user).await?))
}

// ---------- targets ----------

#[derive(Serialize, Clone)]
pub struct TargetOut {
    id: Uuid,
    value: String,
    #[serde(rename = "type")]
    kind: String,
    address_count: u64,
    name: Option<String>,
    owner: Option<String>,
    criticality: String,
    tags: Vec<String>,
    notes: Option<String>,
    excluded: bool,
    source: String,
    active_hosts: i64,
    last_scanned_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    updated_by: Option<String>,
}

#[derive(sqlx::FromRow)]
struct TargetRow {
    id: Uuid,
    value: String,
    kind: String,
    name: Option<String>,
    owner: Option<String>,
    criticality: String,
    tags: Vec<String>,
    notes: Option<String>,
    excluded: bool,
    source: String,
    active_hosts: i64,
    last_scanned_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    updated_by: Option<String>,
}

fn address_count(kind: &str, value: &str) -> u64 {
    let kind = match kind {
        "ip" => input::TargetKind::Ip,
        "cidr" => input::TargetKind::Cidr,
        _ => return 1,
    };
    u64::try_from(input::total_hosts(&[input::Target { kind, value: value.to_string() }])).unwrap_or(u64::MAX)
}

/// `$1` data key; optional `$2` = only these ids.
async fn load_targets(db: &sqlx::PgPool, key: &str, ids: Option<&[Uuid]>) -> V1<Vec<TargetOut>> {
    let rows = sqlx::query_as::<_, TargetRow>(sqlx::AssertSqlSafe(format!(
        "WITH latest AS ({LATEST})
         SELECT t.id, t.value, t.kind::text AS kind, t.label AS name, t.owner, t.criticality, t.tags,
                COALESCE(pgp_sym_decrypt(t.notes_enc, $1), t.notes) AS notes, t.excluded, t.source,
                t.created_at, t.updated_at, u.username AS updated_by,
                COALESCE(a.active_hosts, 0) AS active_hosts, a.last_scanned_at
         FROM targets t
         LEFT JOIN users u ON u.id = t.updated_by
         LEFT JOIN LATERAL (
             SELECT count(DISTINCT h.address) FILTER (WHERE h.state = 'active') AS active_hosts,
                    max(l.finished_at) AS last_scanned_at
             FROM latest l JOIN hosts h ON h.run_id = l.id
             WHERE CASE WHEN t.kind = 'domain' THEN h.hostname = t.value ELSE h.address <<= t.value::inet END
         ) a ON true
         WHERE $2::uuid[] IS NULL OR t.id = ANY($2)
         ORDER BY t.created_at DESC"
    )))
    .bind(key)
    .bind(ids)
    .fetch_all(db)
    .await
    .map_err(fail)?;
    Ok(rows
        .into_iter()
        .map(|r| TargetOut {
            address_count: address_count(&r.kind, &r.value),
            id: r.id,
            value: r.value,
            kind: r.kind,
            name: r.name,
            owner: r.owner,
            criticality: r.criticality,
            tags: r.tags,
            notes: r.notes,
            excluded: r.excluded,
            source: r.source,
            active_hosts: r.active_hosts,
            last_scanned_at: r.last_scanned_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
            updated_by: r.updated_by,
        })
        .collect())
}

#[derive(Deserialize)]
pub struct TargetsQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    sort: Option<String>,
    q: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    criticality: Option<String>,
    tag: Option<String>,
    excluded: Option<String>,
}

/// `GET /api/v1/targets`
pub async fn list_targets(State(s): State<AppState>, Query(q): Query<TargetsQuery>) -> V1<Json<Value>> {
    let mut items = load_targets(&s.db, &s.config.data_key, None).await?;
    if let Some(needle) = opt(&q.q).map(str::to_lowercase) {
        items.retain(|t| {
            [Some(&t.value), t.name.as_ref(), t.owner.as_ref()].into_iter().flatten().any(|v| v.to_lowercase().contains(&needle))
                || t.tags.iter().any(|g| g.contains(&needle))
        });
    }
    if let Some(k) = opt(&q.kind) {
        items.retain(|t| t.kind == k);
    }
    if let Some(c) = opt(&q.criticality) {
        items.retain(|t| t.criticality == c);
    }
    if let Some(tag) = opt(&q.tag) {
        items.retain(|t| t.tags.iter().any(|g| g == tag));
    }
    if let Some(ex) = opt(&q.excluded) {
        let ex = ex == "true";
        items.retain(|t| t.excluded == ex);
    }
    let (field, desc) = sort_spec(opt(&q.sort), "-criticality_rank");
    items.sort_by(|a, b| {
        let o = match field.as_str() {
            "type" => a.kind.cmp(&b.kind),
            "address_count" => a.address_count.cmp(&b.address_count),
            "active_hosts" => a.active_hosts.cmp(&b.active_hosts),
            "owner" => a.owner.cmp(&b.owner),
            "name" => a.name.cmp(&b.name),
            "criticality" | "criticality_rank" => criticality_rank(&a.criticality).cmp(&criticality_rank(&b.criticality)),
            "created_at" => a.created_at.cmp(&b.created_at),
            "updated_at" => a.updated_at.cmp(&b.updated_at),
            "last_scanned_at" => a.last_scanned_at.cmp(&b.last_scanned_at),
            _ => a.value.cmp(&b.value),
        };
        let o = if desc { o.reverse() } else { o };
        o.then_with(|| a.value.cmp(&b.value))
    });
    Ok(Json(paginated(items, q.page, q.page_size)))
}

/// `GET /api/v1/targets/{id}`
pub async fn get_target(State(s): State<AppState>, Path(id): Path<Uuid>) -> V1<Json<TargetOut>> {
    load_targets(&s.db, &s.config.data_key, Some(&[id])).await?.pop().map(Json).ok_or_else(missing)
}

#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct TargetInput {
    #[serde(alias = "target")]
    value: String,
    #[serde(default, alias = "label")]
    name: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    criticality: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    excluded: Option<bool>,
}

/// A validated input row.
struct CleanInput {
    target: input::Target,
    name: Option<String>,
    owner: Option<String>,
    criticality: Option<String>,
    tags: Vec<String>,
    notes: Option<String>,
    excluded: Option<bool>,
}

fn clean_input(i: &TargetInput) -> Result<CleanInput, String> {
    let target = input::normalize(&i.value).map_err(|e| e.to_string())?;
    let criticality = match i.criticality.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) if CRITICALITY.contains(&c) => Some(c.to_string()),
        Some(c) => return Err(format!("nieznana krytyczność: {c}")),
        None => None,
    };
    let msg = |(_, Json(b)): ApiError| b["error"]["message"].as_str().unwrap_or("invalid").to_string();
    Ok(CleanInput {
        target,
        name: text(i.name.as_deref(), "name", 200, false).map_err(msg)?,
        owner: text(i.owner.as_deref(), "owner", 200, false).map_err(msg)?,
        criticality,
        tags: clean_tags(&i.tags).map_err(msg)?,
        notes: text(i.notes.as_deref(), "notes", 10_000, true).map_err(msg)?,
        excluded: i.excluded,
    })
}

/// Insert or (with `update`) refresh one target. Returns (id, created) or None when skipped.
async fn upsert_target(
    tx: &mut sqlx::PgConnection,
    c: &CleanInput,
    update: bool,
    source: &str,
    user: Uuid,
    key: &str,
) -> sqlx::Result<Option<(Uuid, bool)>> {
    let existing: Option<Uuid> = sqlx::query_scalar("SELECT id FROM targets WHERE value = $1 FOR UPDATE")
        .bind(&c.target.value)
        .fetch_optional(&mut *tx)
        .await?;
    match existing {
        Some(_) if !update => Ok(None),
        Some(id) => {
            sqlx::query(
                "UPDATE targets SET label = COALESCE($2, label), owner = COALESCE($3, owner),
                     criticality = COALESCE($4, criticality),
                     tags = CASE WHEN cardinality($5::text[]) > 0 THEN $5 ELSE tags END,
                     notes_enc = CASE WHEN $6::text IS NULL THEN notes_enc ELSE pgp_sym_encrypt($6, $7) END,
                     notes = CASE WHEN $6::text IS NULL THEN notes ELSE NULL END,
                     excluded = COALESCE($8, excluded), manual_edit = true, updated_at = now(), updated_by = $9
                 WHERE id = $1",
            )
            .bind(id)
            .bind(&c.name)
            .bind(&c.owner)
            .bind(&c.criticality)
            .bind(&c.tags)
            .bind(&c.notes)
            .bind(key)
            .bind(c.excluded)
            .bind(user)
            .execute(&mut *tx)
            .await?;
            Ok(Some((id, false)))
        }
        None => {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO targets (kind, value, label, owner, criticality, tags, notes_enc, excluded, source,
                                      manual_edit, updated_by)
                 VALUES ($1, $2, $3, $4, COALESCE($5, 'medium'), $6, pgp_sym_encrypt($7, $8), COALESCE($9, false),
                         $10, true, $11)
                 RETURNING id",
            )
            .bind(&c.target.kind)
            .bind(&c.target.value)
            .bind(&c.name)
            .bind(&c.owner)
            .bind(&c.criticality)
            .bind(&c.tags)
            .bind(&c.notes)
            .bind(key)
            .bind(c.excluded)
            .bind(source)
            .bind(user)
            .fetch_one(&mut *tx)
            .await?;
            Ok(Some((id, true)))
        }
    }
}

#[derive(Deserialize)]
pub struct CreateTargets {
    items: Vec<TargetInput>,
    #[serde(default)]
    on_conflict: Option<String>,
}

/// `POST /api/v1/targets` — `{items, on_conflict}` → created / updated / skipped / errors.
pub async fn create_targets(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(b): Json<CreateTargets>,
) -> V1<(StatusCode, Extension<Note>, Json<Value>)> {
    if b.items.is_empty() || b.items.len() > 10_000 {
        return Err(invalid("Podaj od 1 do 10 000 celów."));
    }
    let update = b.on_conflict.as_deref() == Some("update");
    if update && !user.can(Action::Update) {
        return Err(forbidden());
    }
    let key = s.config.data_key.as_str();
    let mut tx = s.db.begin().await.map_err(fail)?;
    let (mut created, mut updated, mut skipped, mut errors) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for i in &b.items {
        match clean_input(i) {
            Err(e) => errors.push(json!({ "value": i.value, "error": e })),
            Ok(c) => match upsert_target(&mut tx, &c, update, "manual", user.id, key).await.map_err(fail)? {
                Some((id, true)) => created.push(id),
                Some((id, false)) => updated.push(id),
                None => skipped.push(json!({ "value": c.target.value, "reason": "Cel już istnieje" })),
            },
        }
    }
    tx.commit().await.map_err(fail)?;
    let created_t = if created.is_empty() { vec![] } else { load_targets(&s.db, key, Some(&created)).await? };
    let updated_t = if updated.is_empty() { vec![] } else { load_targets(&s.db, key, Some(&updated)).await? };
    let note = Note {
        action: "target.create",
        entity: "target",
        entity_id: None,
        details: json!({ "created": created.len(), "updated": updated.len(), "skipped": skipped.len(), "errors": errors.len() }),
    };
    let status = if created.is_empty() { StatusCode::OK } else { StatusCode::CREATED };
    Ok((
        status,
        Extension(note),
        Json(json!({ "created": created_t, "updated": updated_t, "skipped": skipped, "errors": errors })),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchTarget {
    #[serde(default, deserialize_with = "present")]
    name: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    owner: Option<Option<String>>,
    criticality: Option<String>,
    tags: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    notes: Option<Option<String>>,
    excluded: Option<bool>,
}

/// `PATCH /api/v1/targets/{id}` — absent = unchanged, null = cleared.
pub async fn update_target(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(b): Json<PatchTarget>,
) -> V1<(Extension<Note>, Json<TargetOut>)> {
    if b.criticality.as_deref().is_some_and(|c| !CRITICALITY.contains(&c)) {
        return Err(invalid("Krytyczność: low, medium, high lub critical."));
    }
    let name = match &b.name {
        Some(v) => Some(text(v.as_deref(), "name", 200, false)?),
        None => None,
    };
    let owner = match &b.owner {
        Some(v) => Some(text(v.as_deref(), "owner", 200, false)?),
        None => None,
    };
    let notes = match &b.notes {
        Some(v) => Some(text(v.as_deref(), "notes", 10_000, true)?),
        None => None,
    };
    let tags = b.tags.as_deref().map(clean_tags).transpose()?;
    let key = s.config.data_key.as_str();
    let n = sqlx::query(
        "UPDATE targets SET
             label = CASE WHEN $2 THEN $3 ELSE label END,
             owner = CASE WHEN $4 THEN $5 ELSE owner END,
             criticality = COALESCE($6, criticality),
             tags = COALESCE($7, tags),
             notes_enc = CASE WHEN $8 THEN pgp_sym_encrypt($9, $10) ELSE notes_enc END,
             notes = CASE WHEN $8 THEN NULL ELSE notes END,
             excluded = COALESCE($11, excluded),
             manual_edit = true, updated_at = now(), updated_by = $12
         WHERE id = $1",
    )
    .bind(id)
    .bind(name.is_some())
    .bind(name.clone().flatten())
    .bind(owner.is_some())
    .bind(owner.clone().flatten())
    .bind(&b.criticality)
    .bind(&tags)
    .bind(notes.is_some())
    .bind(notes.clone().flatten())
    .bind(key)
    .bind(b.excluded)
    .bind(user.id)
    .execute(&s.db)
    .await
    .map_err(fail)?
    .rows_affected();
    if n == 0 {
        return Err(missing());
    }
    let fields: Vec<&str> = [
        ("name", name.is_some()),
        ("owner", owner.is_some()),
        ("criticality", b.criticality.is_some()),
        ("tags", tags.is_some()),
        ("notes", notes.is_some()),
        ("excluded", b.excluded.is_some()),
    ]
    .into_iter()
    .filter_map(|(f, set)| set.then_some(f))
    .collect();
    let t = load_targets(&s.db, key, Some(&[id])).await?.pop().ok_or_else(missing)?;
    let note = Note::new("target.update", "target", id, json!({ "value": t.value, "fields": fields }));
    Ok((Extension(note), Json(t)))
}

/// `DELETE /api/v1/targets/{id}` → 204.
pub async fn delete_target(State(s): State<AppState>, Path(id): Path<Uuid>) -> V1<(StatusCode, Extension<Note>)> {
    let value: String = sqlx::query_scalar("DELETE FROM targets WHERE id = $1 RETURNING value")
        .bind(id)
        .fetch_optional(&s.db)
        .await
        .map_err(fail)?
        .ok_or_else(missing)?;
    Ok((StatusCode::NO_CONTENT, Extension(Note::new("target.delete", "target", id, json!({ "value": value })))))
}

#[derive(Deserialize)]
pub struct BulkBody {
    ids: Vec<Uuid>,
    action: String,
    #[serde(default)]
    payload: Value,
}

/// `POST /api/v1/targets/bulk` — tag, untag, exclude, include, delete, set_owner, set_criticality.
pub async fn bulk_targets(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(b): Json<BulkBody>,
) -> V1<(Extension<Note>, Json<Value>)> {
    if b.ids.is_empty() || b.ids.len() > 10_000 {
        return Err(invalid("Zaznacz od 1 do 10 000 celów."));
    }
    let p = |k: &str| b.payload.get(k).and_then(Value::as_str).map(str::to_string);
    let q = match b.action.as_str() {
        "delete" => {
            if !user.can(Action::Delete) {
                return Err(forbidden());
            }
            sqlx::query("DELETE FROM targets WHERE id = ANY($1)").bind(&b.ids)
        }
        "exclude" | "include" => sqlx::query(
            "UPDATE targets SET excluded = $2, updated_at = now(), updated_by = $3 WHERE id = ANY($1)",
        )
        .bind(&b.ids)
        .bind(b.action == "exclude")
        .bind(user.id),
        "tag" | "untag" => {
            let tag = clean_tags(&[p("tag").unwrap_or_default()])?.pop().ok_or_else(|| invalid("Podaj tag."))?;
            let sql = if b.action == "tag" {
                "UPDATE targets SET tags = CASE WHEN $2 = ANY(tags) THEN tags ELSE array_append(tags, $2) END,
                     updated_at = now(), updated_by = $3 WHERE id = ANY($1)"
            } else {
                "UPDATE targets SET tags = array_remove(tags, $2), updated_at = now(), updated_by = $3 WHERE id = ANY($1)"
            };
            sqlx::query(sql).bind(&b.ids).bind(tag).bind(user.id)
        }
        "set_owner" => {
            let owner = text(p("owner").as_deref(), "owner", 200, false)?;
            sqlx::query("UPDATE targets SET owner = $2, updated_at = now(), updated_by = $3 WHERE id = ANY($1)")
                .bind(&b.ids)
                .bind(owner)
                .bind(user.id)
        }
        "set_criticality" => {
            let c = p("criticality").filter(|c| CRITICALITY.contains(&c.as_str())).ok_or_else(|| invalid("Nieznana krytyczność."))?;
            sqlx::query("UPDATE targets SET criticality = $2, updated_at = now(), updated_by = $3 WHERE id = ANY($1)")
                .bind(&b.ids)
                .bind(c)
                .bind(user.id)
        }
        _ => return Err(invalid("Nieznana operacja.")),
    };
    let affected = q.execute(&s.db).await.map_err(fail)?.rows_affected();
    let note = Note {
        action: if b.action == "delete" { "target.delete" } else { "target.update" },
        entity: "target",
        entity_id: None,
        details: json!({ "bulk": b.action, "affected": affected }),
    };
    Ok((Extension(note), Json(json!({ "affected": affected }))))
}

/// Parse an uploaded target list: JSON (array of strings/objects, or `{items|targets: [...]}`)
/// or CSV (optional header: value|target, name|label, owner, criticality, tags, notes).
fn parse_import(bytes: &[u8], filename: &str) -> Result<(&'static str, Vec<TargetInput>), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "Plik musi być w UTF-8.".to_string())?;
    let text = text.trim_start_matches('\u{feff}');
    let looks_json = filename.to_lowercase().ends_with(".json") || text.trim_start().starts_with(['[', '{']);
    if looks_json {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("Niepoprawny JSON: {e}"))?;
        let list = match &v {
            Value::Array(a) => a.clone(),
            Value::Object(o) => o
                .get("items")
                .or_else(|| o.get("targets"))
                .and_then(Value::as_array)
                .cloned()
                .ok_or("JSON: oczekiwano tablicy lub pola items/targets.")?,
            _ => return Err("JSON: oczekiwano tablicy.".into()),
        };
        let rows = list
            .into_iter()
            .map(|item| match item {
                Value::String(s) => Ok(TargetInput { value: s, ..Default::default() }),
                other => serde_json::from_value::<TargetInput>(other).map_err(|e| e.to_string()),
            })
            .map(|r| r.unwrap_or_else(|e| TargetInput { value: format!("!{e}"), ..Default::default() }))
            .collect();
        return Ok(("json", rows));
    }
    let mut rdr = csv::ReaderBuilder::new().has_headers(false).flexible(true).trim(csv::Trim::All).from_reader(text.as_bytes());
    let mut records = rdr.records().filter_map(Result::ok).filter(|r| r.iter().any(|c| !c.is_empty())).peekable();
    let header: Option<Vec<String>> = records.peek().and_then(|r| {
        let first = r.get(0).unwrap_or_default().to_lowercase();
        ["value", "target", "cel", "adres", "address"].contains(&first.as_str()).then(|| r.iter().map(str::to_lowercase).collect())
    });
    if header.is_some() {
        records.next();
    }
    let col = |names: &[&str], fallback: usize| -> usize {
        header.as_ref().and_then(|h| h.iter().position(|c| names.contains(&c.as_str()))).unwrap_or(if header.is_some() { usize::MAX } else { fallback })
    };
    let (cv, cn, co, cc, ct, cnotes) = (
        col(&["value", "target", "cel", "adres", "address"], 0),
        col(&["name", "label", "nazwa"], 1),
        col(&["owner", "właściciel"], 2),
        col(&["criticality", "krytyczność"], 3),
        col(&["tags", "tagi"], 4),
        col(&["notes", "notatki"], 5),
    );
    let rows = records
        .filter(|r| !r.get(0).unwrap_or_default().starts_with('#'))
        .map(|r| {
            let get = |i: usize| r.get(i).map(str::to_string).filter(|s| !s.is_empty());
            TargetInput {
                value: get(cv).unwrap_or_default(),
                name: get(cn),
                owner: get(co),
                criticality: get(cc),
                tags: get(ct).map(|t| t.split([';', '|']).map(str::to_string).collect()).unwrap_or_default(),
                notes: get(cnotes),
                excluded: None,
            }
        })
        .collect();
    Ok(("csv", rows))
}

/// `POST /api/v1/targets/import` (multipart: file, dry_run, on_conflict) → ImportReport.
pub async fn import_targets(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    mut form: Multipart,
) -> V1<(Extension<Note>, Json<Value>)> {
    let (mut bytes, mut filename, mut dry_run, mut on_conflict) = (None, String::new(), true, "skip".to_string());
    while let Some(field) = form.next_field().await.map_err(|e| invalid(format!("Niepoprawny formularz: {e}")))? {
        match field.name().unwrap_or_default() {
            "file" => {
                filename = field.file_name().unwrap_or_default().to_string();
                bytes = Some(field.bytes().await.map_err(|e| invalid(format!("Nie udało się odczytać pliku: {e}")))?);
            }
            "dry_run" => dry_run = field.text().await.unwrap_or_default() != "false",
            "on_conflict" => on_conflict = field.text().await.unwrap_or_default(),
            _ => {}
        }
    }
    let bytes = bytes.ok_or_else(|| invalid("Brak pliku."))?;
    let (format, rows) = parse_import(&bytes, &filename).map_err(invalid)?;
    if rows.len() > 50_000 {
        return Err(invalid("Najwyżej 50 000 wierszy w jednym imporcie."));
    }
    let update = on_conflict == "update";
    if update && !user.can(Action::Update) {
        return Err(forbidden());
    }
    let existing: HashSet<String> = sqlx::query_scalar("SELECT value FROM targets")
        .fetch_all(&s.db)
        .await
        .map_err(fail)?
        .into_iter()
        .collect();

    let key = s.config.data_key.as_str();
    let mut tx = s.db.begin().await.map_err(fail)?;
    let (mut seen, mut report) = (HashSet::new(), Vec::new());
    let (mut valid, mut invalid_n, mut dups, mut created, mut updated) = (0, 0, 0, 0, 0);
    for (i, row) in rows.iter().enumerate() {
        let n = i + 1;
        if let Some(e) = row.value.strip_prefix('!') {
            invalid_n += 1;
            report.push(json!({ "row": n, "value": "", "status": "invalid", "error": e }));
            continue;
        }
        match clean_input(row) {
            Err(e) => {
                invalid_n += 1;
                report.push(json!({ "row": n, "value": row.value, "status": "invalid", "error": e }));
            }
            Ok(c) => {
                let kind = serde_json::to_value(&c.target.kind).unwrap_or_default();
                let count = address_count(kind.as_str().unwrap_or_default(), &c.target.value);
                if !seen.insert(c.target.value.clone()) || (existing.contains(&c.target.value) && !update) {
                    dups += 1;
                    report.push(json!({ "row": n, "value": c.target.value, "status": "duplicate", "type": kind, "address_count": count }));
                    continue;
                }
                valid += 1;
                report.push(json!({ "row": n, "value": c.target.value, "status": "ok", "type": kind, "address_count": count }));
                if !dry_run {
                    match upsert_target(&mut tx, &c, update, "import", user.id, key).await.map_err(fail)? {
                        Some((_, true)) => created += 1,
                        Some((_, false)) => updated += 1,
                        None => {}
                    }
                } else if existing.contains(&c.target.value) {
                    updated += 1;
                } else {
                    created += 1;
                }
            }
        }
    }
    if dry_run {
        tx.rollback().await.map_err(fail)?;
    } else {
        tx.commit().await.map_err(fail)?;
    }
    report.truncate(500);
    let note = Note {
        action: if dry_run { "target.import_preview" } else { "target.import" },
        entity: "target",
        entity_id: None,
        details: json!({ "format": format, "rows": rows.len(), "created": created, "updated": updated, "invalid": invalid_n }),
    };
    Ok((
        Extension(note),
        Json(json!({
            "format": format, "dry_run": dry_run, "total_rows": rows.len(), "valid": valid, "invalid": invalid_n,
            "duplicates": dups, "created": created, "updated": updated, "rows": report,
        })),
    ))
}

#[derive(Deserialize)]
pub struct FormatQuery {
    format: Option<String>,
}

/// `GET /api/v1/targets/export?format=csv|json` — re-importable.
pub async fn export_targets(State(s): State<AppState>, Query(q): Query<FormatQuery>) -> V1<Response> {
    let items = load_targets(&s.db, &s.config.data_key, None).await?;
    let stamp = Utc::now().format("%Y%m%d-%H%M");
    let note = |format: &str| Note {
        action: "target.export",
        entity: "target",
        entity_id: None,
        details: json!({ "format": format, "count": items.len() }),
    };
    if q.format.as_deref() == Some("json") {
        let rows: Vec<Value> = items
            .iter()
            .map(|t| json!({
                "value": t.value, "type": t.kind, "name": t.name, "owner": t.owner, "criticality": t.criticality,
                "tags": t.tags, "notes": t.notes, "excluded": t.excluded,
            }))
            .collect();
        let body = serde_json::to_vec_pretty(&json!({
            "format": "asi-targets", "version": 1, "exported_at": Utc::now(), "items": rows,
        }))
        .map_err(fail)?;
        return Ok(file("application/json", &format!("asi-targets-{stamp}.json"), body, note("json")));
    }
    let mut w = csv::Writer::from_writer(Vec::new());
    w.write_record(["value", "type", "name", "owner", "criticality", "tags", "notes", "excluded", "address_count", "active_hosts", "last_scanned_at"])
        .map_err(fail)?;
    for t in &items {
        w.write_record([
            csv_text(&t.value),
            t.kind.clone(),
            csv_text(t.name.as_deref().unwrap_or_default()),
            csv_text(t.owner.as_deref().unwrap_or_default()),
            t.criticality.clone(),
            csv_text(&t.tags.join(";")),
            csv_text(t.notes.as_deref().unwrap_or_default()),
            t.excluded.to_string(),
            t.address_count.to_string(),
            t.active_hosts.to_string(),
            t.last_scanned_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
        ])
        .map_err(fail)?;
    }
    let body = w.into_inner().map_err(fail)?;
    Ok(file("text/csv; charset=utf-8", &format!("asi-targets-{stamp}.csv"), body, note("csv")))
}

// ---------- scan runs ----------

#[derive(sqlx::FromRow)]
struct RunRow {
    id: Uuid,
    number: i64,
    name: String,
    status: String,
    started_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    resume_at: Option<DateTime<Utc>>,
    window_started_at: Option<DateTime<Utc>>,
    total_batches: Option<i32>,
    error: Option<String>,
    stats: Value,
    rate_limit_pps: i32,
    window_minutes: Option<i32>,
    created_by: Option<String>,
    target_ids: Option<Vec<Uuid>>,
    targets_label: Option<String>,
    unstable: i64,
}

const RUNS: &str = "SELECT * FROM (
    SELECT r.id, row_number() OVER (ORDER BY r.started_at) AS number, s.name, r.status::text AS status,
           r.started_at, r.finished_at, r.resume_at, r.window_started_at, r.total_batches, r.error, r.stats,
           COALESCE((r.config_snapshot->>'rate_limit_pps')::int, s.rate_limit_pps) AS rate_limit_pps,
           COALESCE((r.config_snapshot->>'window_minutes')::int, s.window_minutes) AS window_minutes,
           u.username AS created_by,
           (SELECT array_agg(st.target_id) FROM scan_targets st WHERE st.scan_id = r.scan_id) AS target_ids,
           (SELECT string_agg(t.value, ', ' ORDER BY t.value) FROM scan_targets st JOIN targets t ON t.id = st.target_id
             WHERE st.scan_id = r.scan_id) AS targets_label,
           (SELECT count(*) FROM hosts h WHERE h.run_id = r.id AND h.state = 'unstable') AS unstable
    FROM scan_runs r JOIN scans s ON s.id = r.scan_id LEFT JOIN users u ON u.id = s.created_by
) runs";

fn f(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(Value::as_f64).unwrap_or(0.0)
}

fn run_json(r: &RunRow) -> Value {
    let st = &r.stats;
    let total = f(st, "hosts_total");
    let done = f(st, "hosts_done");
    let elapsed = f(st, "elapsed_secs");
    let diff = st.get("diff").cloned().unwrap_or(Value::Null);
    let status = match r.status.as_str() {
        "done" | "partial" => "completed",
        "paused" if r.resume_at.is_some() => "paused_window",
        other => other,
    };
    let error = match (&r.error, r.status.as_str()) {
        (Some(e), _) => Some(e.clone()),
        (None, "partial") => Some("Część zakresu nie została przeskanowana (failed_ranges).".to_string()),
        _ => None,
    };
    let label = r.targets_label.clone().unwrap_or_default();
    let label = if label.chars().count() > 80 { format!("{}…", label.chars().take(80).collect::<String>()) } else { label };
    let window_ends_at = match (r.window_started_at, r.window_minutes, status) {
        (Some(ws), Some(m), "running") => Some(ws + chrono::Duration::minutes(m as i64)),
        _ => None,
    };
    json!({
        "id": r.id, "number": r.number, "name": r.name, "status": status,
        "phase": if status == "running" { Some("discovery") } else { None },
        "source": "scanner", "profile_id": null, "profile_name": null, "schedule_id": null,
        "target_ids": r.target_ids.clone().unwrap_or_default(), "targets_label": label,
        "address_count": total as u64,
        "progress": if total > 0.0 { (done / total).min(1.0) } else if status == "completed" { 1.0 } else { 0.0 },
        "batches_total": r.total_batches.unwrap_or(0), "batches_done": f(st, "batches_done") as u64,
        "rate_rps": if elapsed > 0.0 { (done / elapsed * 10.0).round() / 10.0 } else { 0.0 },
        "rate_limit_rps": r.rate_limit_pps,
        "window": null, "window_ends_at": window_ends_at, "resume_at": r.resume_at,
        "windows_used": f(st, "pauses") as u64 + 1,
        "started_at": r.started_at, "finished_at": r.finished_at, "duration_s": elapsed.round() as u64,
        "eta_s": st.get("eta_secs").cloned().unwrap_or(Value::Null),
        "stats": {
            "hosts_alive": f(st, "alive") as u64, "services": f(st, "open_ports") as u64,
            "http_services": f(st, "http") as u64, "findings": (f(st, "admin_panels") + f(st, "staging")) as u64,
            "new": f(&diff, "new") as u64, "changed": f(&diff, "changed") as u64, "gone": f(&diff, "gone") as u64,
            "unstable": r.unstable,
        },
        "error": error, "tags": [], "notes": null, "created_by": r.created_by.clone().unwrap_or_else(|| "system".into()),
    })
}

async fn load_runs(db: &sqlx::PgPool, filter: &str, limit: i64) -> V1<Vec<RunRow>> {
    sqlx::query_as::<_, RunRow>(sqlx::AssertSqlSafe(format!("{RUNS} {filter} ORDER BY started_at DESC LIMIT $1")))
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(fail)
}

#[derive(Deserialize)]
pub struct PageQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    status: Option<String>,
}

/// `GET /api/v1/scans` — scan runs, newest first.
pub async fn list_scans(State(s): State<AppState>, Query(q): Query<PageQuery>) -> V1<Json<Value>> {
    let runs = load_runs(&s.db, "", 5000).await?;
    let mut items: Vec<Value> = runs.iter().map(run_json).collect();
    if let Some(st) = opt(&q.status) {
        let wanted: Vec<&str> = st.split(',').map(str::trim).collect();
        items.retain(|r| r["status"].as_str().is_some_and(|s| wanted.contains(&s)));
    }
    Ok(Json(paginated(items, q.page, q.page_size)))
}

// ---------- findings ----------

#[derive(Serialize, Clone)]
pub struct Finding {
    id: Uuid,
    title: String,
    category: &'static str,
    host_id: Uuid,
    ip: String,
    hostname: Option<String>,
    port: Option<i32>,
    service_id: Option<Uuid>,
    service_label: Option<String>,
    technologies: Vec<String>,
    change: String,
    status: String,
    score: i32,
    score_override: Option<i16>,
    score_breakdown: Vec<Value>,
    confidence: f32,
    measurements: Value,
    evidence: Vec<Value>,
    signature_id: Option<String>,
    signature_name: Option<String>,
    assignee: Option<String>,
    tags: Vec<String>,
    notes: Option<String>,
    manual_overrides: Value,
    defectdojo: Option<Value>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    #[serde(skip)]
    scan_id: Uuid,
    #[serde(skip)]
    entity_key: String,
}

impl Finding {
    fn effective_score(&self) -> i32 {
        self.score_override.map_or(self.score, i32::from)
    }
    fn is_open(&self) -> bool {
        !matches!(self.status.as_str(), "false_positive" | "accepted")
    }
}

#[derive(sqlx::FromRow)]
struct ObsRow {
    scan_id: Uuid,
    run_id: Uuid,
    host_id: Uuid,
    ip: String,
    hostname: Option<String>,
    state: String,
    first_seen_at: DateTime<Utc>,
    seen_at: DateTime<Utc>,
    service_id: Uuid,
    port: i32,
    protocol: String,
    service: Option<String>,
    product: Option<String>,
    version: Option<String>,
    confidence: f32,
    url: Option<String>,
    title: Option<String>,
    technologies: Option<Vec<String>>,
    is_admin: Option<bool>,
    is_staging: Option<bool>,
}

#[derive(sqlx::FromRow)]
struct StateRow {
    finding_id: Uuid,
    status: String,
    score_override: Option<i16>,
    assignee: Option<String>,
    tags: Vec<String>,
    notes: Option<String>,
}

/// Stable id of a derived finding.
fn finding_id(scan_id: Uuid, category: &str, key: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_URL, format!("asi:{scan_id}:{category}:{key}").as_bytes())
}

/// Highest criticality of the targets covering an address (+ score points).
fn criticality_points(ip: &str, nets: &[(ipnet::IpNet, String)]) -> Option<(String, i32)> {
    let addr: std::net::IpAddr = ip.parse().ok()?;
    let best = nets.iter().filter(|(n, _)| n.contains(&addr)).map(|(_, c)| c).max_by_key(|c| criticality_rank(c))?;
    let points = [0, 5, 10, 20][criticality_rank(best)];
    Some((best.clone(), points))
}

fn tech_name(t: &str) -> String {
    t.split(':').next().unwrap_or(t).trim().to_string()
}

/// Derive findings from the latest finished run of every scan.
async fn load_findings(db: &sqlx::PgPool, key: &str) -> V1<Vec<Finding>> {
    let rows = sqlx::query_as::<_, ObsRow>(sqlx::AssertSqlSafe(format!(
        "WITH latest AS ({LATEST})
         SELECT l.scan_id, l.id AS run_id, h.id AS host_id, host(h.address) AS ip, h.hostname, h.state::text AS state,
                h.first_seen_at, h.seen_at, s.id AS service_id, s.port, s.protocol, s.service, s.product,
                s.version, s.confidence, f.url, f.title, f.technologies, f.is_admin, f.is_staging
         FROM latest l JOIN hosts h ON h.run_id = l.id JOIN services s ON s.host_id = h.id
         LEFT JOIN http_findings f ON f.service_id = s.id
         ORDER BY h.address, s.port"
    )))
    .fetch_all(db)
    .await
    .map_err(fail)?;
    let run_ids: Vec<Uuid> = rows.iter().map(|r| r.run_id).collect::<HashSet<_>>().into_iter().collect();
    let changes: HashMap<(Uuid, String, String), String> = sqlx::query_as::<_, (Uuid, String, String, String)>(
        "SELECT run_b, kind, entity, change::text FROM diffs WHERE run_b = ANY($1)",
    )
    .bind(&run_ids)
    .fetch_all(db)
    .await
    .map_err(fail)?
    .into_iter()
    .map(|(run, kind, entity, change)| ((run, kind, entity), change))
    .collect();
    // Per scan and address: finished runs that observed the host, and how many it answered.
    let measured: HashMap<(Uuid, String), (i64, i64)> = sqlx::query_as::<_, (Uuid, String, i64, i64)>(
        "SELECT r.scan_id, host(h.address), count(*) FILTER (WHERE h.state = 'active'), count(*)
         FROM scan_runs r JOIN hosts h ON h.run_id = r.id
         WHERE r.status IN ('done', 'partial') GROUP BY 1, 2",
    )
    .fetch_all(db)
    .await
    .map_err(fail)?
    .into_iter()
    .map(|(scan, ip, up, total)| ((scan, ip), (up, total)))
    .collect();
    let states: HashMap<Uuid, StateRow> = sqlx::query_as::<_, StateRow>(
        "SELECT finding_id, status, score_override, assignee, tags, pgp_sym_decrypt(notes_enc, $1) AS notes
         FROM finding_states",
    )
    .bind(key)
    .fetch_all(db)
    .await
    .map_err(fail)?
    .into_iter()
    .map(|r| (r.finding_id, r))
    .collect();
    let nets: Vec<(ipnet::IpNet, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT value, criticality FROM targets WHERE kind <> 'domain'",
    )
    .fetch_all(db)
    .await
    .map_err(fail)?
    .into_iter()
    .filter_map(|(v, c)| {
        let net = v.parse::<ipnet::IpNet>().ok().or_else(|| v.parse::<std::net::IpAddr>().ok().map(ipnet::IpNet::from))?;
        Some((net, c))
    })
    .collect();

    // Technologies per service (from all its HTTP findings).
    let mut tech_by_service: HashMap<Uuid, Vec<String>> = HashMap::new();
    for r in &rows {
        let entry = tech_by_service.entry(r.service_id).or_default();
        for t in r.technologies.iter().flatten().map(|t| tech_name(t)) {
            if !entry.contains(&t) {
                entry.push(t);
            }
        }
    }

    let mut out: Vec<Finding> = Vec::new();
    let mut seen: HashSet<Uuid> = HashSet::new();
    for r in &rows {
        let host_change = changes.get(&(r.run_id, "host".into(), r.ip.clone()));
        let base_change = match r.state.as_str() {
            "unstable" => Some("unstable".to_string()),
            "inactive" => Some("gone".to_string()),
            _ => host_change.filter(|c| *c == "new").cloned(),
        };
        let service_key = format!("{}:{}/{}", r.ip, r.port, r.protocol);
        let label = format!(
            "{}/{}",
            r.port,
            r.service.as_deref().map(str::to_uppercase).unwrap_or_else(|| r.protocol.to_uppercase())
        );
        let (responded, total) = measured.get(&(r.scan_id, r.ip.clone())).copied().unwrap_or((1, 1));
        let mut candidates: Vec<(&'static str, String, String, i32, Vec<Value>)> = Vec::new();
        if let Some(url) = &r.url {
            let title = r.title.clone().unwrap_or_else(|| url.clone());
            let ev = vec![
                json!({ "type": "title", "label": "Tytuł strony", "snippet": title, "highlight": null }),
                json!({ "type": "path", "label": "Adres", "snippet": url, "highlight": null }),
            ];
            if r.is_admin == Some(true) {
                candidates.push(("admin_panel", url.clone(), format!("Panel administracyjny: {title}"), 60, ev.clone()));
            }
            if r.is_staging == Some(true) {
                candidates.push(("staging", url.clone(), format!("Środowisko testowe (staging): {url}"), 45, ev));
            }
        }
        if RISKY_PORTS.contains(&(r.port as u16)) {
            let what = [r.service.as_deref(), r.product.as_deref(), r.version.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            candidates.push((
                "exposure",
                service_key.clone(),
                format!("Usługa {} dostępna z sieci ({}/{})", r.service.as_deref().unwrap_or("?"), r.port, r.protocol),
                50,
                vec![json!({ "type": "banner", "label": "Usługa (nmap)", "snippet": what, "highlight": null })],
            ));
        }
        for (category, entity_key, title, base, evidence) in candidates {
            let id = finding_id(r.scan_id, category, &entity_key);
            if !seen.insert(id) {
                continue;
            }
            let entity_kind = if category == "exposure" { "service" } else { "http" };
            let change = base_change
                .clone()
                .or_else(|| changes.get(&(r.run_id, entity_kind.to_string(), entity_key.clone())).cloned())
                .unwrap_or_else(|| "unchanged".into());
            let mut breakdown = vec![json!({ "factor": format!("Kategoria: {category}"), "points": base })];
            let mut score = base;
            if change == "new" {
                breakdown.push(json!({ "factor": "Nowe od poprzedniego skanu", "points": 20 }));
                score += 20;
            }
            if let Some((crit, points)) = criticality_points(&r.ip, &nets).filter(|(_, p)| *p > 0) {
                breakdown.push(json!({ "factor": format!("Krytyczność zakresu: {crit}"), "points": points }));
                score += points;
            }
            if r.confidence < 0.6 {
                breakdown.push(json!({ "factor": "Niska pewność identyfikacji", "points": -10 }));
                score -= 10;
            }
            let st = states.get(&id);
            out.push(Finding {
                id,
                title,
                category,
                host_id: r.host_id,
                ip: r.ip.clone(),
                hostname: r.hostname.clone(),
                port: Some(r.port),
                service_id: Some(r.service_id),
                service_label: Some(label.clone()),
                technologies: tech_by_service.get(&r.service_id).cloned().unwrap_or_default(),
                change,
                status: st.map_or("open".into(), |s| s.status.clone()),
                score: score.clamp(0, 100),
                score_override: st.and_then(|s| s.score_override),
                score_breakdown: breakdown,
                confidence: r.confidence,
                measurements: json!({ "responded": responded, "total": total }),
                evidence,
                signature_id: None,
                signature_name: None,
                assignee: st.and_then(|s| s.assignee.clone()),
                tags: st.map(|s| s.tags.clone()).unwrap_or_default(),
                notes: st.and_then(|s| s.notes.clone()),
                manual_overrides: json!({}),
                defectdojo: None,
                first_seen: r.first_seen_at,
                last_seen: r.seen_at,
                scan_id: r.scan_id,
                entity_key,
            });
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
pub struct FindingsQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    limit: Option<usize>,
    sort: Option<String>,
    q: Option<String>,
    change: Option<String>,
    category: Option<String>,
    status: Option<String>,
    format: Option<String>,
}

fn filter_findings(mut items: Vec<Finding>, q: &FindingsQuery) -> Vec<Finding> {
    if let Some(needle) = opt(&q.q).map(str::to_lowercase) {
        items.retain(|f| {
            f.title.to_lowercase().contains(&needle)
                || f.ip.contains(&needle)
                || f.hostname.as_deref().is_some_and(|h| h.to_lowercase().contains(&needle))
                || f.technologies.iter().any(|t| t.to_lowercase().contains(&needle))
        });
    }
    if let Some(c) = opt(&q.change) {
        items.retain(|f| f.change == c);
    }
    if let Some(c) = opt(&q.category) {
        items.retain(|f| f.category == c);
    }
    if let Some(st) = opt(&q.status) {
        let wanted: Vec<&str> = st.split(',').collect();
        items.retain(|f| wanted.contains(&f.status.as_str()));
    }
    let (field, desc) = sort_spec(opt(&q.sort), "-score");
    items.sort_by(|a, b| {
        let o = match field.as_str() {
            "ip" => a.ip.cmp(&b.ip),
            "title" => a.title.cmp(&b.title),
            "category" => a.category.cmp(b.category),
            "status" => a.status.cmp(&b.status),
            "first_seen" => a.first_seen.cmp(&b.first_seen),
            "last_seen" => a.last_seen.cmp(&b.last_seen),
            "confidence" => a.confidence.total_cmp(&b.confidence),
            _ => a.effective_score().cmp(&b.effective_score()),
        };
        let o = if desc { o.reverse() } else { o };
        o.then_with(|| a.ip.cmp(&b.ip))
    });
    items
}

/// `GET /api/v1/findings`
pub async fn list_findings(State(s): State<AppState>, Query(q): Query<FindingsQuery>) -> V1<Json<Value>> {
    let items = filter_findings(load_findings(&s.db, &s.config.data_key).await?, &q);
    Ok(Json(paginated(items, q.page, q.page_size)))
}

/// `GET /api/v1/dashboard/top-findings?limit=&q=&change=&category=` — open findings by score.
pub async fn top_findings(State(s): State<AppState>, Query(q): Query<FindingsQuery>) -> V1<Json<Vec<Finding>>> {
    let mut items = filter_findings(load_findings(&s.db, &s.config.data_key).await?, &q);
    items.retain(Finding::is_open);
    items.truncate(q.limit.unwrap_or(10).clamp(1, 100));
    Ok(Json(items))
}

/// `GET /api/v1/findings/{id}`
pub async fn get_finding(State(s): State<AppState>, Path(id): Path<Uuid>) -> V1<Json<Finding>> {
    load_findings(&s.db, &s.config.data_key).await?.into_iter().find(|f| f.id == id).map(Json).ok_or_else(missing)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchFinding {
    status: Option<String>,
    #[serde(default, deserialize_with = "present")]
    score_override: Option<Option<i16>>,
    #[serde(default, deserialize_with = "present")]
    assignee: Option<Option<String>>,
    tags: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    notes: Option<Option<String>>,
}

const FINDING_STATUS: [&str; 5] = ["open", "in_review", "confirmed", "false_positive", "accepted"];

/// `PATCH /api/v1/findings/{id}` — analyst state, kept across rescans.
pub async fn update_finding(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(b): Json<PatchFinding>,
) -> V1<(Extension<Note>, Json<Finding>)> {
    let key = s.config.data_key.as_str();
    let current = load_findings(&s.db, key).await?.into_iter().find(|f| f.id == id).ok_or_else(missing)?;
    let status = b.status.clone().unwrap_or_else(|| current.status.clone());
    if !FINDING_STATUS.contains(&status.as_str()) {
        return Err(invalid("Nieznany status."));
    }
    let score_override = b.score_override.unwrap_or(current.score_override);
    if score_override.is_some_and(|v| !(0..=100).contains(&v)) {
        return Err(invalid("Priorytet musi mieścić się w zakresie 0–100."));
    }
    let assignee = match &b.assignee {
        Some(v) => text(v.as_deref(), "assignee", 200, false)?,
        None => current.assignee.clone(),
    };
    let tags = match &b.tags {
        Some(t) => clean_tags(t)?,
        None => current.tags.clone(),
    };
    let notes = match &b.notes {
        Some(v) => text(v.as_deref(), "notes", 10_000, true)?,
        None => current.notes.clone(),
    };
    sqlx::query(
        "INSERT INTO finding_states (finding_id, scan_id, category, entity_key, status, score_override, assignee, tags,
                                     notes_enc, updated_by, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, pgp_sym_encrypt($9, $10), $11, now())
         ON CONFLICT (finding_id) DO UPDATE SET status = EXCLUDED.status, score_override = EXCLUDED.score_override,
             assignee = EXCLUDED.assignee, tags = EXCLUDED.tags, notes_enc = EXCLUDED.notes_enc,
             updated_by = EXCLUDED.updated_by, updated_at = now()",
    )
    .bind(id)
    .bind(current.scan_id)
    .bind(current.category)
    .bind(&current.entity_key)
    .bind(&status)
    .bind(score_override)
    .bind(&assignee)
    .bind(&tags)
    .bind(&notes)
    .bind(key)
    .bind(user.id)
    .execute(&s.db)
    .await
    .map_err(fail)?;
    let updated = load_findings(&s.db, key).await?.into_iter().find(|f| f.id == id).ok_or_else(missing)?;
    let note = Note::new(
        "finding.update",
        "finding",
        id,
        json!({ "title": updated.title, "status": status, "from_status": current.status, "score_override": score_override }),
    );
    Ok((Extension(note), Json(updated)))
}

/// `GET /api/v1/findings/export?format=csv|json` (same filters as the list).
pub async fn export_findings(State(s): State<AppState>, Query(q): Query<FindingsQuery>) -> V1<Response> {
    let items = filter_findings(load_findings(&s.db, &s.config.data_key).await?, &q);
    let stamp = Utc::now().format("%Y%m%d-%H%M");
    let note = |format: &str| Note {
        action: "finding.export",
        entity: "finding",
        entity_id: None,
        details: json!({ "format": format, "count": items.len() }),
    };
    if q.format.as_deref() == Some("json") {
        let body = serde_json::to_vec_pretty(&json!({
            "format": "asi-findings", "version": 1, "exported_at": Utc::now(), "items": items,
        }))
        .map_err(fail)?;
        return Ok(file("application/json", &format!("asi-findings-{stamp}.json"), body, note("json")));
    }
    let mut w = csv::Writer::from_writer(Vec::new());
    w.write_record([
        "id", "title", "category", "ip", "hostname", "service", "status", "score", "change", "confidence", "technologies",
        "assignee", "first_seen", "last_seen",
    ])
    .map_err(fail)?;
    for x in &items {
        w.write_record([
            x.id.to_string(),
            csv_text(&x.title),
            x.category.to_string(),
            x.ip.clone(),
            csv_text(x.hostname.as_deref().unwrap_or_default()),
            x.service_label.clone().unwrap_or_default(),
            x.status.clone(),
            x.effective_score().to_string(),
            x.change.clone(),
            format!("{:.2}", x.confidence),
            csv_text(&x.technologies.join(";")),
            csv_text(x.assignee.as_deref().unwrap_or_default()),
            x.first_seen.to_rfc3339(),
            x.last_seen.to_rfc3339(),
        ])
        .map_err(fail)?;
    }
    let body = w.into_inner().map_err(fail)?;
    Ok(file("text/csv; charset=utf-8", &format!("asi-findings-{stamp}.csv"), body, note("csv")))
}

/// `POST /api/v1/findings/defectdojo` — not implemented yet (raw outputs are kept in
/// `run_artifacts` for it); says so instead of pretending.
pub async fn defectdojo_export() -> ApiError {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "not_implemented",
        "Eksport do DefectDojo nie jest jeszcze dostępny w tej wersji.",
    )
}

// ---------- dashboard ----------

async fn count(db: &sqlx::PgPool, sql: &str) -> V1<i64> {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.to_string())).fetch_one(db).await.map_err(fail)
}

/// `GET /api/v1/dashboard/summary`
pub async fn summary(State(s): State<AppState>) -> V1<Json<Value>> {
    let db = &s.db;
    let active_hosts = count(
        db,
        &format!("WITH latest AS ({LATEST}) SELECT count(DISTINCT h.address) FROM latest l JOIN hosts h ON h.run_id = l.id WHERE h.state = 'active'"),
    )
    .await?;
    let services_count = count(
        db,
        &format!("WITH latest AS ({LATEST}) SELECT count(*) FROM latest l JOIN hosts h ON h.run_id = l.id
                  JOIN services sv ON sv.host_id = h.id WHERE h.state = 'active'"),
    )
    .await?;
    let web_services_count = count(
        db,
        &format!("WITH latest AS ({LATEST}) SELECT count(DISTINCT f.service_id) FROM latest l JOIN hosts h ON h.run_id = l.id
                  JOIN services sv ON sv.host_id = h.id JOIN http_findings f ON f.service_id = sv.id WHERE h.state = 'active'"),
    )
    .await?;
    let targets = load_targets(db, &s.config.data_key, None).await?;
    let monitored: u64 = targets.iter().filter(|t| !t.excluded).map(|t| t.address_count).fold(0, u64::saturating_add);

    let finished = load_runs(db, "WHERE status IN ('done', 'partial')", 12).await?;
    let mut trend: Vec<Value> = Vec::new();
    for r in finished.iter().rev() {
        trend.push(json!({ "scan_number": r.number, "at": r.finished_at.unwrap_or(r.started_at), "value": f(&r.stats, "alive") as u64 }));
    }
    let delta = match trend.as_slice() {
        [.., a, b] => b["value"].as_i64().unwrap_or(0) - a["value"].as_i64().unwrap_or(0),
        _ => 0,
    };
    let last_scan = finished.first().map(run_json);
    // Latest run that was compared with an earlier one.
    let compared = finished.iter().find(|r| r.stats.pointer("/diff/against").is_some_and(|v| !v.is_null()));
    let (changes, base, head) = match compared {
        Some(r) => {
            let d = &r.stats["diff"];
            let against = d["against"].as_str().and_then(|v| v.parse::<Uuid>().ok());
            let base: Option<i64> = match against {
                Some(a) => sqlx::query_scalar(
                    "SELECT n FROM (SELECT id, row_number() OVER (ORDER BY started_at) AS n FROM scan_runs) x WHERE id = $1",
                )
                .bind(a)
                .fetch_optional(db)
                .await
                .map_err(fail)?,
                None => None,
            };
            (
                json!({ "new": f(d, "new") as u64, "changed": f(d, "changed") as u64, "gone": f(d, "gone") as u64, "unstable": r.unstable }),
                base,
                Some(r.number),
            )
        }
        None => (json!({ "new": 0, "changed": 0, "gone": 0, "unstable": 0 }), None, None),
    };
    let running = load_runs(db, "WHERE status IN ('queued', 'running', 'paused')", 1).await?;
    let running_scan = running.first().map(run_json);
    let rate: i32 = match running.first() {
        Some(r) => r.rate_limit_pps,
        None => sqlx::query_scalar("SELECT COALESCE(max(rate_limit_pps), 0) FROM scans WHERE enabled")
            .fetch_one(db)
            .await
            .map_err(fail)?,
    };
    let findings = load_findings(db, &s.config.data_key).await?;
    let open: Vec<&Finding> = findings.iter().filter(|f| f.is_open()).collect();
    let paused_window = running.first().is_some_and(|r| r.status == "paused" && r.resume_at.is_some());
    Ok(Json(json!({
        "active_hosts": active_hosts, "active_hosts_delta": delta, "active_trend": trend,
        "monitored_addresses": monitored, "targets_count": targets.len(),
        "services_count": services_count, "web_services_count": web_services_count,
        "findings_open": open.len(), "findings_high": open.iter().filter(|f| f.effective_score() >= 70).count(),
        "changes": changes, "changes_base_scan": base, "changes_head_scan": head,
        "last_scan": last_scan, "running_scan": running_scan,
        // Clock-based windows (HH:MM, time zone) are not implemented yet (F-20): scans run
        // in duration windows, so the dashboard shows an always-open day window.
        "window": { "start": "00:00", "end": "23:59", "timezone": "Europe/Warsaw" },
        "window_open": !paused_window, "window_progress": 0.0,
        "next_window_at": running.first().and_then(|r| r.resume_at),
        "rate_limit_rps": rate,
    })))
}

#[derive(Deserialize)]
pub struct LimitQuery {
    limit: Option<i64>,
}

/// `GET /api/v1/dashboard/changes-timeline?limit=`
pub async fn changes_timeline(State(s): State<AppState>, Query(q): Query<LimitQuery>) -> V1<Json<Vec<Value>>> {
    let runs = load_runs(&s.db, "WHERE status IN ('done', 'partial')", q.limit.unwrap_or(30).clamp(1, 200)).await?;
    Ok(Json(
        runs.iter()
            .rev()
            .map(|r| {
                let d = r.stats.get("diff").cloned().unwrap_or(Value::Null);
                json!({
                    "scan_id": r.id, "scan_number": r.number, "at": r.finished_at.unwrap_or(r.started_at),
                    "new": f(&d, "new") as u64, "changed": f(&d, "changed") as u64, "gone": f(&d, "gone") as u64,
                    "unstable": r.unstable,
                })
            })
            .collect(),
    ))
}

/// `GET /api/v1/dashboard/availability` — response rate by weekday × hour (Europe/Warsaw).
pub async fn availability(State(s): State<AppState>) -> V1<Json<Value>> {
    let rows: Vec<(i32, i32, i64, i64)> = sqlx::query_as(
        "SELECT extract(isodow FROM r.started_at AT TIME ZONE 'Europe/Warsaw')::int,
                extract(hour FROM r.started_at AT TIME ZONE 'Europe/Warsaw')::int,
                count(*) FILTER (WHERE h.state = 'active'), count(*)
         FROM scan_runs r JOIN hosts h ON h.run_id = r.id
         WHERE r.status IN ('done', 'partial') GROUP BY 1, 2",
    )
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    let mut matrix = vec![vec![Value::Null; 24]; 7];
    let mut samples = 0;
    for (dow, hour, up, total) in rows {
        if (1..=7).contains(&dow) && (0..24).contains(&hour) && total > 0 {
            matrix[(dow - 1) as usize][hour as usize] = json!((up as f64 / total as f64 * 100.0).round() / 100.0);
            samples += total;
        }
    }
    let hosts = count(&s.db, "SELECT count(DISTINCT address) FROM hosts").await?;
    Ok(Json(json!({ "matrix": matrix, "hosts_considered": hosts, "samples": samples })))
}

fn tech_category(name: &str) -> &'static str {
    let n = name.to_lowercase();
    let has = |list: &[&str]| list.iter().any(|x| n.contains(x));
    if has(&["nginx", "apache", "iis", "caddy", "lighttpd", "litespeed", "openresty"]) {
        "web_server"
    } else if has(&["wordpress", "drupal", "joomla", "typo3", "moodle"]) {
        "cms"
    } else if has(&["tomcat", "jboss", "wildfly", "weblogic", "websphere", "jetty"]) {
        "app_server"
    } else if has(&["phpmyadmin", "grafana", "kibana", "webmin", "cpanel", "plesk", "portainer"]) {
        "admin_panel"
    } else if has(&["jenkins", "gitlab", "docker", "kubernetes"]) {
        "devops"
    } else if has(&["php", "python", "java", "node", "ruby", "asp.net", "perl"]) {
        "language"
    } else if has(&["react", "angular", "vue", "django", "laravel", "spring", "rails", "express", "bootstrap", "jquery"]) {
        "framework"
    } else if has(&["mysql", "postgres", "redis", "mongodb", "elasticsearch"]) {
        "database"
    } else {
        "other"
    }
}

/// `GET /api/v1/dashboard/technologies?limit=` — hosts per technology now vs the run before.
pub async fn technologies(State(s): State<AppState>, Query(q): Query<LimitQuery>) -> V1<Json<Vec<Value>>> {
    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "WITH ranked AS (
             SELECT id, row_number() OVER (PARTITION BY scan_id ORDER BY started_at DESC) AS n
             FROM scan_runs WHERE status IN ('done', 'partial'))
         SELECT r.n, host(h.address), t.tech
         FROM ranked r JOIN hosts h ON h.run_id = r.id AND h.state = 'active'
         JOIN services sv ON sv.host_id = h.id
         JOIN LATERAL (
             SELECT unnest(f.technologies) AS tech FROM http_findings f WHERE f.service_id = sv.id
             UNION SELECT sv.product WHERE sv.product IS NOT NULL
         ) t ON true
         WHERE r.n <= 2",
    )
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    let mut now: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    let mut before: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for (n, ip, tech) in rows {
        let name = tech_name(&tech);
        if name.is_empty() {
            continue;
        }
        let map = if n == 1 { &mut now } else { &mut before };
        map.entry(name).or_default().insert(ip);
    }
    let mut out: Vec<Value> = now
        .iter()
        .map(|(name, hosts)| {
            let prev = before.get(name).map_or(0, HashSet::len) as i64;
            json!({ "name": name, "category": tech_category(name), "count": hosts.len(), "delta": hosts.len() as i64 - prev })
        })
        .collect();
    out.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()).then_with(|| a["name"].as_str().cmp(&b["name"].as_str())));
    out.truncate(q.limit.unwrap_or(10).clamp(1, 100) as usize);
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct MapQuery {
    cidr: String,
}

/// `GET /api/v1/dashboard/address-map?cidr=` — 4-bit status per address (IPv4, /16 or smaller).
pub async fn address_map(State(s): State<AppState>, Query(q): Query<MapQuery>) -> V1<Json<Value>> {
    let net: Ipv4Net = q.cidr.trim().parse().map_err(|_| invalid("Podaj zakres IPv4 w notacji CIDR, np. 10.0.0.0/24."))?;
    let net = net.trunc();
    if net.prefix_len() < 16 {
        return Err(invalid("Mapa obsługuje zakresy od /16 wzwyż."));
    }
    let size = 1usize << (32 - net.prefix_len());
    let base = u32::from(net.network());
    let mut status = vec![0u8; size];
    let index = |ip: &str| -> Option<usize> {
        let a: Ipv4Addr = ip.parse().ok()?;
        let off = u32::from(a).checked_sub(base)? as usize;
        (off < size).then_some(off)
    };
    // Excluded targets first; scan results override them.
    let excluded: Vec<String> = sqlx::query_scalar("SELECT value FROM targets WHERE excluded AND kind <> 'domain'")
        .fetch_all(&s.db)
        .await
        .map_err(fail)?;
    for v in excluded {
        let ex: Option<Ipv4Net> = v.parse().ok().or_else(|| v.parse::<Ipv4Addr>().ok().map(Ipv4Net::from));
        if let Some(ex) = ex {
            let (lo, hi) = (u32::from(ex.network()).max(base), u32::from(ex.broadcast()).min(base + (size as u32 - 1)));
            if lo <= hi {
                for a in lo..=hi {
                    status[(a - base) as usize] = 7;
                }
            }
        }
    }
    let hosts: Vec<(String, String, Uuid)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "WITH latest AS ({LATEST}) SELECT host(h.address), h.state::text, l.id FROM latest l JOIN hosts h ON h.run_id = l.id
         WHERE h.address <<= $1::inet"
    )))
    .bind(net.to_string())
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    let runs: Vec<Uuid> = hosts.iter().map(|h| h.2).collect::<HashSet<_>>().into_iter().collect();
    let diffs: Vec<(String, String, String)> = sqlx::query_as("SELECT kind, entity, change::text FROM diffs WHERE run_b = ANY($1)")
        .bind(&runs)
        .fetch_all(&s.db)
        .await
        .map_err(fail)?;
    for (ip, state, _) in &hosts {
        if let Some(i) = index(ip) {
            status[i] = match state.as_str() {
                "active" => 1,
                "unstable" => 5,
                _ => 6,
            };
        }
    }
    for (kind, entity, change) in &diffs {
        let ip = entity.split(['/', ':']).next().unwrap_or_default();
        let ip = if kind == "http" { entity.split("://").nth(1).and_then(|r| r.split([':', '/']).next()).unwrap_or_default() } else { ip };
        if let Some(i) = index(ip) {
            match (kind.as_str(), change.as_str()) {
                ("host", "new") => status[i] = 2,
                ("host", "gone") if status[i] != 5 => status[i] = 4,
                (_, _) if status[i] == 1 => status[i] = 3,
                _ => {}
            }
        }
    }
    let names = ["none", "active", "new", "changed", "gone", "unstable", "inactive", "excluded"];
    let mut counts: BTreeMap<&str, u64> = names.iter().map(|n| (*n, 0)).collect();
    let mut packed = vec![0u8; size.div_ceil(2)];
    for (i, st) in status.iter().enumerate() {
        *counts.entry(names[*st as usize]).or_default() += 1;
        packed[i >> 1] |= if i % 2 == 0 { st << 4 } else { *st };
    }
    use base64::Engine;
    Ok(Json(json!({
        "cidr": net.to_string(), "prefix": net.prefix_len(), "size": size,
        "data": base64::engine::general_purpose::STANDARD.encode(packed),
        "counts": counts, "scan_head": null, "generated_at": Utc::now(),
    })))
}

// ---------- search and audit ----------

#[derive(Deserialize)]
pub struct SearchQuery {
    q: Option<String>,
}

/// `GET /api/v1/search?q=` — hosts, targets, findings.
pub async fn search(State(s): State<AppState>, Query(q): Query<SearchQuery>) -> V1<Json<Value>> {
    let Some(needle) = opt(&q.q).filter(|n| n.chars().count() >= 2) else {
        return Ok(Json(json!({ "hosts": [], "targets": [], "findings": [] })));
    };
    let like = format!("%{}%", needle.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
    let hosts: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "WITH latest AS ({LATEST}) SELECT DISTINCT ON (h.address) h.id, host(h.address), h.hostname
         FROM latest l JOIN hosts h ON h.run_id = l.id
         WHERE host(h.address) ILIKE $1 OR h.hostname ILIKE $1 ORDER BY h.address LIMIT 8"
    )))
    .bind(&like)
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    let targets: Vec<(Uuid, String, Option<String>)> =
        sqlx::query_as("SELECT id, value, label FROM targets WHERE value ILIKE $1 OR label ILIKE $1 ORDER BY value LIMIT 8")
            .bind(&like)
            .fetch_all(&s.db)
            .await
            .map_err(fail)?;
    let lower = needle.to_lowercase();
    let findings: Vec<Value> = load_findings(&s.db, &s.config.data_key)
        .await?
        .into_iter()
        .filter(|f| f.title.to_lowercase().contains(&lower) || f.ip.contains(&lower))
        .take(8)
        .map(|f| json!({ "id": f.id, "title": f.title, "ip": f.ip }))
        .collect();
    Ok(Json(json!({
        "hosts": hosts.into_iter().map(|(id, ip, hostname)| json!({ "id": id, "ip": ip, "hostname": hostname })).collect::<Vec<_>>(),
        "targets": targets.into_iter().map(|(id, value, name)| json!({ "id": id, "value": value, "name": name })).collect::<Vec<_>>(),
        "findings": findings,
    })))
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: i64,
    at: DateTime<Utc>,
    user_id: Option<Uuid>,
    username: Option<String>,
    role: Option<Role>,
    action: String,
    entity: String,
    entity_id: Option<String>,
    details: Option<Value>,
    method: Option<String>,
    path: Option<String>,
    outcome: String,
}

/// Contract action and a Polish one-line summary of an audit row.
fn audit_view(r: &AuditRow) -> (&'static str, String, String) {
    let d = r.details.clone().unwrap_or(Value::Null);
    let label = ["username", "value", "name", "title", "entity_key"]
        .iter()
        .find_map(|k| d.get(*k).and_then(Value::as_str))
        .map(str::to_string)
        .unwrap_or_default();
    let path = r.path.as_deref().unwrap_or_default();
    let action: &'static str = match r.action.as_str() {
        "auth.login" => "login",
        "auth.logout" => "logout",
        a if a.ends_with("import") => "import",
        a if a.ends_with("import_preview") => "import",
        a if a.ends_with("export") => "export",
        a if a.ends_with(".create") || a.ends_with(".bootstrap") => "create",
        a if a.ends_with(".delete") || a.ends_with(".disable") => "delete",
        a if a.ends_with(".update") => "update",
        _ if path.ends_with("/run") => "scan_start",
        _ if path.ends_with("/cancel") => "scan_cancel",
        _ => match r.method.as_deref() {
            Some("DELETE") => "delete",
            Some("POST") => "create",
            _ => "update",
        },
    };
    let resource = if r.entity == "route" {
        path.trim_start_matches("/api/").trim_start_matches("v1/").split('/').next().unwrap_or("api").to_string()
    } else {
        r.entity.clone()
    };
    let verb = match action {
        "login" if r.outcome == "success" => "Zalogowano".to_string(),
        "login" => "Nieudane logowanie".to_string(),
        "logout" => "Wylogowano".to_string(),
        "create" => format!("Utworzono: {resource}"),
        "update" => format!("Zmieniono: {resource}"),
        "delete" => format!("Usunięto: {resource}"),
        "import" => format!("Import: {resource}"),
        "export" => format!("Eksport: {resource}"),
        "scan_start" => "Uruchomiono skanowanie".to_string(),
        "scan_cancel" => "Zatrzymano skanowanie".to_string(),
        _ => r.action.clone(),
    };
    let summary = match (r.outcome.as_str(), label.is_empty()) {
        ("denied", _) => format!("Odmowa dostępu: {} {}", r.method.as_deref().unwrap_or(""), path),
        (_, false) => format!("{verb} — {label}"),
        _ => verb,
    };
    (action, resource, summary)
}

/// `GET /api/v1/audit?page=&page_size=`
pub async fn audit_list(State(s): State<AppState>, Query(q): Query<PageQuery>) -> V1<Json<Value>> {
    let page_size = q.page_size.unwrap_or(25).clamp(1, 200) as i64;
    let page = q.page.unwrap_or(1).max(1) as i64;
    let total = count(&s.db, "SELECT count(*) FROM audit_log").await?;
    let rows = sqlx::query_as::<_, AuditRow>(
        "SELECT a.id, a.at, a.user_id, u.username, u.role, a.action, a.entity, a.entity_id, a.details, a.method, a.path,
                a.outcome
         FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
         ORDER BY a.id DESC LIMIT $1 OFFSET $2",
    )
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            let (action, resource, summary) = audit_view(r);
            let role = r.role.map_or("", |role| role_meta(role).1);
            json!({
                "id": r.id.to_string(), "at": r.at,
                "actor": { "id": r.user_id.map(|u| u.to_string()).unwrap_or_default(),
                           "name": r.username.clone().unwrap_or_else(|| "anonim".into()), "role": role },
                "action": action, "resource": resource, "resource_id": r.entity_id,
                "resource_label": r.details.as_ref().and_then(|d| ["username", "value", "name", "title"].iter()
                    .find_map(|k| d.get(*k).and_then(Value::as_str))),
                "summary": summary, "changes": [],
            })
        })
        .collect();
    Ok(Json(json!({ "items": items, "page": page, "page_size": page_size, "total": total })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_ids_are_stable() {
        let scan = Uuid::nil();
        assert_eq!(finding_id(scan, "admin_panel", "http://10.0.0.1"), finding_id(scan, "admin_panel", "http://10.0.0.1"));
        assert_ne!(finding_id(scan, "admin_panel", "http://10.0.0.1"), finding_id(scan, "staging", "http://10.0.0.1"));
    }

    #[test]
    fn csv_formulas_are_neutralised() {
        assert_eq!(csv_text("=cmd()"), "'=cmd()");
        assert_eq!(csv_text("@x"), "'@x");
        assert_eq!(csv_text("10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn pagination() {
        let v = paginated((1..=30).collect::<Vec<_>>(), Some(2), Some(25));
        assert_eq!(v["items"].as_array().unwrap().len(), 5);
        assert_eq!(v["total"], 30);
        let v = paginated(vec![1, 2], Some(9), Some(25));
        assert!(v["items"].as_array().unwrap().is_empty());
    }

    #[test]
    fn import_parsing() {
        let (f, rows) = parse_import(b"value,name,criticality,tags\n10.0.0.0/24,DMZ,high,dmz;prod\n# c\n10.0.0.5\n", "t.csv").unwrap();
        assert_eq!(f, "csv");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name.as_deref(), Some("DMZ"));
        assert_eq!(rows[0].tags, ["dmz", "prod"]);
        let (_, rows) = parse_import(b"10.0.0.1,web\n10.0.0.2\n", "list.txt").unwrap();
        assert_eq!((rows[0].value.as_str(), rows[0].name.as_deref()), ("10.0.0.1", Some("web")));
        let (f, rows) = parse_import(br#"{"items":[{"value":"example.com","owner":"IT"},"10.0.0.9"]}"#, "x.json").unwrap();
        assert_eq!((f, rows.len(), rows[0].owner.as_deref()), ("json", 2, Some("IT")));
        assert!(parse_import(b"[1,2", "x.json").is_err());
    }

    #[test]
    fn tech_names_and_categories() {
        assert_eq!(tech_name("Nginx:1.27.5"), "Nginx");
        assert_eq!(tech_category("Apache HTTP Server"), "web_server");
        assert_eq!(tech_category("WordPress"), "cms");
    }
}
