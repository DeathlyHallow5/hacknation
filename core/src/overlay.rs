//! Editable overlays (PROJECT.md §2.6, §5.2; F-15; AGH requirement 14; review §19.4).
//!
//! Raw scan evidence is immutable. Analysts annotate a stable entity key at SCAN level —
//! the keys the diff uses (host → IP, service → `ip:port/proto`, http → URL) — so an
//! annotation applies to every past and future run of the scan and can be edited at any
//! time, also while a run is in progress. `version` gives optimistic locking; every
//! replaced or deleted version is kept in the append-only `annotation_history`.

use crate::api::{bad, internal, not_found, ApiError, ApiResult};
use crate::{audit::Note, auth::CurrentUser, AppState};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgConnection;
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

pub const KINDS: [&str; 3] = ["host", "service", "http"];

const SERVICE_FORMAT: &str = "service key must look like 10.0.0.5:443/tcp";

/// Validate an entity key and bring it to the form the diff and findings use.
pub fn canonical_key(kind: &str, key: &str) -> Result<String, &'static str> {
    let key = key.trim();
    match kind {
        "host" => key.parse::<IpAddr>().map(|ip| ip.to_string()).map_err(|_| "host key must be an IP address"),
        "service" => {
            let (addr_port, proto) = key.rsplit_once('/').ok_or(SERVICE_FORMAT)?;
            let (addr, port) = addr_port.rsplit_once(':').ok_or(SERVICE_FORMAT)?;
            let ip: IpAddr = addr.parse().map_err(|_| SERVICE_FORMAT)?;
            let port: u16 = port.parse().map_err(|_| SERVICE_FORMAT)?;
            let proto = proto.to_ascii_lowercase();
            if proto.is_empty() || proto.len() > 8 || !proto.bytes().all(|b| b.is_ascii_lowercase()) {
                return Err(SERVICE_FORMAT);
            }
            Ok(format!("{ip}:{port}/{proto}"))
        }
        "http" => {
            let scheme_ok = ["http://", "https://"]
                .iter()
                .any(|p| key.len() > p.len() && key.get(..p.len()).is_some_and(|s| s.eq_ignore_ascii_case(p)));
            if !scheme_ok || key.len() > 2048 || key.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err("http key must be the finding's URL (http:// or https://)");
            }
            Ok(key.to_string())
        }
        _ => Err("entity_kind must be host, service or http"),
    }
}

/// Trimmed text, `None` when empty; rejects over-long values and control characters
/// (newlines/tabs allowed only in multi-line fields).
pub(crate) fn text(v: Option<&str>, field: &str, max: usize, multiline: bool) -> Result<Option<String>, ApiError> {
    let Some(v) = v.map(str::trim).filter(|v| !v.is_empty()) else { return Ok(None) };
    if v.chars().count() > max {
        return Err(bad(format!("{field} is longer than {max} characters")));
    }
    if v.chars().any(|c| c.is_control() && !(multiline && matches!(c, '\n' | '\r' | '\t'))) {
        return Err(bad(format!("{field} contains control characters")));
    }
    Ok(Some(v.to_string()))
}

/// `PUT /api/scans/{id}/annotations` body: the full overlay of one entity (fields left out
/// are cleared) plus the version it replaces.
#[derive(Deserialize)]
pub struct PutAnnotation {
    entity_kind: String,
    entity_key: String,
    label: Option<String>,
    owner: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    priority: Option<i16>,
    #[serde(default)]
    false_positive: bool,
    #[serde(default)]
    suppressed: bool,
    suppress_reason: Option<String>,
    notes: Option<String>,
    /// Why the change was made; kept with the version in the history.
    reason: Option<String>,
    /// Version being replaced; absent or 0 = create.
    #[serde(default)]
    version: i32,
}

/// Validated overlay fields.
struct Fields {
    label: Option<String>,
    owner: Option<String>,
    tags: Vec<String>,
    priority: Option<i16>,
    false_positive: bool,
    suppressed: bool,
    suppress_reason: Option<String>,
    notes: Option<String>,
    reason: Option<String>,
}

impl Fields {
    fn validate(b: &PutAnnotation) -> Result<Self, ApiError> {
        let mut tags: Vec<String> = Vec::new();
        for t in &b.tags {
            if let Some(t) = text(Some(t.as_str()), "tag", 64, false)?
                && !tags.contains(&t)
            {
                tags.push(t);
            }
        }
        if tags.len() > 32 {
            return Err(bad("at most 32 tags"));
        }
        if b.priority.is_some_and(|p| !(1..=3).contains(&p)) {
            return Err(bad("priority must be 1..=3"));
        }
        let suppress_reason = text(b.suppress_reason.as_deref(), "suppress_reason", 1000, true)?;
        if b.suppressed && suppress_reason.is_none() {
            return Err(bad("suppress_reason is required when suppressed"));
        }
        Ok(Self {
            label: text(b.label.as_deref(), "label", 200, false)?,
            owner: text(b.owner.as_deref(), "owner", 200, false)?,
            tags,
            priority: b.priority,
            false_positive: b.false_positive,
            suppressed: b.suppressed,
            suppress_reason,
            notes: text(b.notes.as_deref(), "notes", 10_000, true)?,
            reason: text(b.reason.as_deref(), "reason", 1000, true)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Annotation {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub entity_kind: String,
    pub entity_key: String,
    pub label: Option<String>,
    pub owner: Option<String>,
    pub tags: Vec<String>,
    pub priority: Option<i16>,
    pub false_positive: bool,
    pub suppressed: bool,
    pub suppress_reason: Option<String>,
    pub notes: Option<String>,
    pub reason: Option<String>,
    pub version: i32,
    pub created_by: Option<Uuid>,
    pub updated_by: Option<Uuid>,
    pub updated_by_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// `$1` = data key; callers append a WHERE clause (constant SQL only).
const SELECT: &str = "SELECT a.id, a.scan_id, a.entity_kind, a.entity_key, a.label, a.owner, a.tags, a.priority,
        a.false_positive, a.suppressed, a.suppress_reason, pgp_sym_decrypt(a.notes_enc, $1) AS notes, a.reason,
        a.version, a.created_by, a.updated_by, u.username AS updated_by_name, a.created_at, a.updated_at
    FROM annotations a LEFT JOIN users u ON u.id = a.updated_by";

async fn by_entity(
    conn: &mut PgConnection,
    key: &str,
    scan_id: Uuid,
    kind: &str,
    entity: &str,
) -> sqlx::Result<Option<Annotation>> {
    sqlx::query_as::<_, Annotation>(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE a.scan_id = $2 AND a.entity_kind = $3 AND a.entity_key = $4"
    )))
    .bind(key)
    .bind(scan_id)
    .bind(kind)
    .bind(entity)
    .fetch_optional(conn)
    .await
}

async fn by_id(conn: &mut PgConnection, key: &str, scan_id: Uuid, id: Uuid) -> sqlx::Result<Option<Annotation>> {
    sqlx::query_as::<_, Annotation>(sqlx::AssertSqlSafe(format!("{SELECT} WHERE a.scan_id = $2 AND a.id = $3")))
        .bind(key)
        .bind(scan_id)
        .bind(id)
        .fetch_optional(conn)
        .await
}

async fn ensure_scan(conn: &mut PgConnection, scan_id: Uuid) -> Result<(), ApiError> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM scans WHERE id = $1)")
        .bind(scan_id)
        .fetch_one(conn)
        .await
        .map_err(internal)?;
    if exists { Ok(()) } else { Err(not_found()) }
}

/// 409 carrying the record as it is now (or null if it no longer exists).
fn conflict(current: Option<Annotation>) -> ApiError {
    (StatusCode::CONFLICT, Json(json!({ "detail": "version conflict", "current": current })))
}

/// Copy the current version into the history before it is replaced or deleted.
async fn archive(conn: &mut PgConnection, id: Uuid, change: &str, user: Uuid) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO annotation_history (annotation_id, scan_id, entity_kind, entity_key, version, label, owner,
             tags, priority, false_positive, suppressed, suppress_reason, notes_enc, reason, author, authored_at,
             change, changed_by)
         SELECT id, scan_id, entity_kind, entity_key, version, label, owner, tags, priority, false_positive,
             suppressed, suppress_reason, notes_enc, reason, updated_by, updated_at, $2, $3
         FROM annotations WHERE id = $1",
    )
    .bind(id)
    .bind(change)
    .bind(user)
    .execute(conn)
    .await
    .map(drop)
}

#[derive(Deserialize)]
pub struct ListQuery {
    kind: Option<String>,
}

/// `GET /api/scans/{id}/annotations?kind=` — all overlays of a scan.
pub async fn list(
    State(s): State<AppState>,
    Path(scan_id): Path<Uuid>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Vec<Annotation>> {
    if q.kind.as_deref().is_some_and(|k| !KINDS.contains(&k)) {
        return Err(bad("kind must be host, service or http"));
    }
    let mut conn = s.db.acquire().await.map_err(internal)?;
    ensure_scan(&mut conn, scan_id).await?;
    let rows = sqlx::query_as::<_, Annotation>(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE a.scan_id = $2 AND ($3::text IS NULL OR a.entity_kind = $3)
         ORDER BY a.entity_kind, a.entity_key"
    )))
    .bind(&s.config.data_key)
    .bind(scan_id)
    .bind(&q.kind)
    .fetch_all(&mut *conn)
    .await
    .map_err(internal)?;
    Ok(Json(rows))
}

/// `PUT /api/scans/{id}/annotations` — create (version 0) or replace (version = current).
/// A stale version gets 409 with the current record. Works whatever the run status.
pub async fn put(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(scan_id): Path<Uuid>,
    Json(b): Json<PutAnnotation>,
) -> Result<(StatusCode, Extension<Note>, Json<Annotation>), ApiError> {
    let kind = b.entity_kind.trim().to_ascii_lowercase();
    if !KINDS.contains(&kind.as_str()) {
        return Err(bad("entity_kind must be host, service or http"));
    }
    let entity = canonical_key(&kind, &b.entity_key).map_err(bad)?;
    let f = Fields::validate(&b)?;
    let key = s.config.data_key.as_str();

    let mut tx = s.db.begin().await.map_err(internal)?;
    ensure_scan(&mut tx, scan_id).await?;
    let (id, status, action) = if b.version <= 0 {
        let id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO annotations (scan_id, entity_kind, entity_key, label, owner, tags, priority, false_positive,
                 suppressed, suppress_reason, notes_enc, reason, created_by, updated_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, pgp_sym_encrypt($11, $12), $13, $14, $14)
             ON CONFLICT (scan_id, entity_kind, entity_key) DO NOTHING RETURNING id",
        )
        .bind(scan_id)
        .bind(&kind)
        .bind(&entity)
        .bind(&f.label)
        .bind(&f.owner)
        .bind(&f.tags)
        .bind(f.priority)
        .bind(f.false_positive)
        .bind(f.suppressed)
        .bind(&f.suppress_reason)
        .bind(&f.notes)
        .bind(key)
        .bind(&f.reason)
        .bind(user.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
        match id {
            Some(id) => (id, StatusCode::CREATED, "annotation.create"),
            // Someone created it first: the client must merge and send that version.
            None => return Err(conflict(by_entity(&mut tx, key, scan_id, &kind, &entity).await.map_err(internal)?)),
        }
    } else {
        let current: Option<(Uuid, i32)> = sqlx::query_as(
            "SELECT id, version FROM annotations WHERE scan_id = $1 AND entity_kind = $2 AND entity_key = $3
             FOR UPDATE",
        )
        .bind(scan_id)
        .bind(&kind)
        .bind(&entity)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
        let id = match current {
            Some((id, v)) if v == b.version => id,
            Some(_) => return Err(conflict(by_entity(&mut tx, key, scan_id, &kind, &entity).await.map_err(internal)?)),
            None => return Err(conflict(None)),
        };
        archive(&mut tx, id, "update", user.id).await.map_err(internal)?;
        sqlx::query(
            "UPDATE annotations SET label = $2, owner = $3, tags = $4, priority = $5, false_positive = $6,
                 suppressed = $7, suppress_reason = $8, notes_enc = pgp_sym_encrypt($9, $10), reason = $11,
                 version = version + 1, updated_by = $12, updated_at = now()
             WHERE id = $1",
        )
        .bind(id)
        .bind(&f.label)
        .bind(&f.owner)
        .bind(&f.tags)
        .bind(f.priority)
        .bind(f.false_positive)
        .bind(f.suppressed)
        .bind(&f.suppress_reason)
        .bind(&f.notes)
        .bind(key)
        .bind(&f.reason)
        .bind(user.id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
        (id, StatusCode::OK, "annotation.update")
    };
    let record = by_id(&mut tx, key, scan_id, id).await.map_err(internal)?.ok_or_else(not_found)?;
    tx.commit().await.map_err(internal)?;
    let note = Note::new(
        action,
        "annotation",
        id,
        json!({ "scan_id": scan_id, "entity_kind": kind, "entity_key": entity, "version": record.version }),
    );
    Ok((status, Extension(note), Json(record)))
}

#[derive(Deserialize)]
pub struct DeleteQuery {
    /// Optional optimistic lock: delete only this version.
    version: Option<i32>,
}

/// `DELETE /api/scans/{id}/annotations/{annotation_id}` — the last version stays in the history.
pub async fn delete(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path((scan_id, id)): Path<(Uuid, Uuid)>,
    Query(q): Query<DeleteQuery>,
) -> Result<(Extension<Note>, Json<Value>), ApiError> {
    let key = s.config.data_key.as_str();
    let mut tx = s.db.begin().await.map_err(internal)?;
    // Scoped to the scan in the path: an id from another scan is "not found".
    let version: i32 = sqlx::query_scalar("SELECT version FROM annotations WHERE id = $1 AND scan_id = $2 FOR UPDATE")
        .bind(id)
        .bind(scan_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?
        .ok_or_else(not_found)?;
    if q.version.is_some_and(|v| v != version) {
        return Err(conflict(by_id(&mut tx, key, scan_id, id).await.map_err(internal)?));
    }
    archive(&mut tx, id, "delete", user.id).await.map_err(internal)?;
    sqlx::query("DELETE FROM annotations WHERE id = $1").bind(id).execute(&mut *tx).await.map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    let note = Note::new("annotation.delete", "annotation", id, json!({ "scan_id": scan_id, "version": version }));
    Ok((Extension(note), Json(json!({ "id": id, "deleted": true }))))
}

#[derive(Serialize, sqlx::FromRow)]
struct HistoryRow {
    version: i32,
    label: Option<String>,
    owner: Option<String>,
    tags: Vec<String>,
    priority: Option<i16>,
    false_positive: bool,
    suppressed: bool,
    suppress_reason: Option<String>,
    notes: Option<String>,
    reason: Option<String>,
    author: Option<Uuid>,
    author_name: Option<String>,
    authored_at: DateTime<Utc>,
    change: String,
    changed_by: Option<Uuid>,
    changed_by_name: Option<String>,
    changed_at: DateTime<Utc>,
}

/// `GET /api/scans/{id}/annotations/{annotation_id}/history` — current record (null once
/// deleted) and all previous versions, newest first.
pub async fn history(State(s): State<AppState>, Path((scan_id, id)): Path<(Uuid, Uuid)>) -> ApiResult<Value> {
    let key = s.config.data_key.as_str();
    let mut conn = s.db.acquire().await.map_err(internal)?;
    let current = by_id(&mut conn, key, scan_id, id).await.map_err(internal)?;
    let rows = sqlx::query_as::<_, HistoryRow>(
        "SELECT h.version, h.label, h.owner, h.tags, h.priority, h.false_positive, h.suppressed, h.suppress_reason,
                pgp_sym_decrypt(h.notes_enc, $1) AS notes, h.reason, h.author, ua.username AS author_name,
                h.authored_at, h.change, h.changed_by, uc.username AS changed_by_name, h.changed_at
         FROM annotation_history h
         LEFT JOIN users ua ON ua.id = h.author LEFT JOIN users uc ON uc.id = h.changed_by
         WHERE h.annotation_id = $2 AND h.scan_id = $3 ORDER BY h.version DESC, h.id DESC",
    )
    .bind(key)
    .bind(id)
    .bind(scan_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(internal)?;
    if current.is_none() && rows.is_empty() {
        return Err(not_found());
    }
    Ok(Json(json!({ "annotation_id": id, "current": current, "history": rows })))
}

/// Annotations of the scan a run belongs to, for attaching to findings and diff entries.
pub struct Overlay(HashMap<(String, String), Annotation>);

impl Overlay {
    pub async fn for_run(db: &sqlx::PgPool, run_id: Uuid, key: &str) -> sqlx::Result<Self> {
        let rows = sqlx::query_as::<_, Annotation>(sqlx::AssertSqlSafe(format!(
            "{SELECT} WHERE a.scan_id = (SELECT scan_id FROM scan_runs WHERE id = $2)"
        )))
        .bind(key)
        .bind(run_id)
        .fetch_all(db)
        .await?;
        Ok(Self(rows.into_iter().map(|a| ((a.entity_kind.clone(), a.entity_key.clone()), a)).collect()))
    }

    pub fn get(&self, kind: &str, key: &str) -> Option<&Annotation> {
        self.0.get(&(kind.to_string(), key.to_string()))
    }

    /// The annotation as JSON, or null.
    pub fn json(&self, kind: &str, key: &str) -> Value {
        self.get(kind, key).map_or(Value::Null, |a| serde_json::to_value(a).unwrap_or_default())
    }

    pub fn suppressed(&self, kind: &str, key: &str) -> bool {
        self.get(kind, key).is_some_and(|a| a.suppressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_match_the_diff_format() {
        assert_eq!(canonical_key("host", " 10.0.0.5 ").unwrap(), "10.0.0.5");
        assert_eq!(canonical_key("host", "2001:DB8:0::1").unwrap(), "2001:db8::1");
        assert!(canonical_key("host", "10.0.0.0/24").is_err());
        assert!(canonical_key("host", "example.com").is_err());

        assert_eq!(canonical_key("service", "10.0.0.5:443/TCP").unwrap(), "10.0.0.5:443/tcp");
        assert_eq!(canonical_key("service", "2001:db8::1:8443/tcp").unwrap(), "2001:db8::1:8443/tcp");
        assert!(canonical_key("service", "10.0.0.5:70000/tcp").is_err());
        assert!(canonical_key("service", "10.0.0.5/tcp").is_err());
        assert!(canonical_key("service", "10.0.0.5:80/t c").is_err());

        assert_eq!(canonical_key("http", "https://10.0.0.5:8443/admin").unwrap(), "https://10.0.0.5:8443/admin");
        assert!(canonical_key("http", "ftp://10.0.0.5").is_err());
        assert!(canonical_key("http", "http://").is_err());
        assert!(canonical_key("http", "http://a b").is_err());
        assert!(canonical_key("vuln", "x").is_err());
    }

    fn body(v: Value) -> PutAnnotation {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn fields_are_validated() {
        let ok = Fields::validate(&body(json!({
            "entity_kind": "host", "entity_key": "10.0.0.5",
            "tags": [" prod ", "prod", "", "dmz"], "label": "  ", "notes": "line 1\nline 2", "priority": 3
        })))
        .ok()
        .unwrap();
        assert_eq!(ok.tags, ["prod", "dmz"], "trimmed, empty dropped, deduplicated");
        assert_eq!(ok.label, None, "blank clears the field");
        assert_eq!(ok.notes.as_deref(), Some("line 1\nline 2"));

        let err = |v: Value| Fields::validate(&body(v)).is_err();
        assert!(err(json!({"entity_kind": "host", "entity_key": "x", "priority": 4})));
        assert!(err(json!({"entity_kind": "host", "entity_key": "x", "suppressed": true})), "reason required");
        assert!(err(json!({"entity_kind": "host", "entity_key": "x", "label": "a\u{0007}b"})));
        assert!(err(json!({"entity_kind": "host", "entity_key": "x", "owner": "x".repeat(201)})));
        assert!(!err(json!({"entity_kind": "host", "entity_key": "x", "suppressed": true, "suppress_reason": "known"})));
    }
}
