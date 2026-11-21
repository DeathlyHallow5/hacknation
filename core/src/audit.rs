//! Audit trail (PROJECT.md §2.7, review §8.5): who did what, from where, with which result.
//! Append-only in the database (migration 0006). Never stores passwords, tokens or bodies.

use crate::api::{internal, ApiResult};
use crate::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
    Denied,
}

impl Outcome {
    pub fn of_status(status: u16) -> Self {
        match status {
            401 | 403 | 429 => Outcome::Denied,
            s if s < 400 => Outcome::Success,
            _ => Outcome::Failure,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Denied => "denied",
        }
    }
}

/// One audit row.
pub struct Event {
    pub user_id: Option<Uuid>,
    pub action: String,
    pub entity: String,
    pub entity_id: Option<String>,
    pub details: Value,
    pub ip: Option<IpAddr>,
    /// Request method and matched route template (never the raw URI or query string).
    pub request: Option<(String, String)>,
    pub status: Option<u16>,
    pub outcome: Outcome,
}

/// What a handler did, attached to its response as `Extension(Note)`. `auth::gate` merges
/// it into the row it writes for the request, so each request yields exactly one row.
#[derive(Debug, Clone)]
pub struct Note {
    pub action: &'static str,
    pub entity: &'static str,
    pub entity_id: Option<String>,
    pub details: Value,
}

impl Note {
    pub fn new(action: &'static str, entity: &'static str, entity_id: impl ToString, details: Value) -> Self {
        Self { action, entity, entity_id: Some(entity_id.to_string()), details }
    }
}

/// Write one row. A failure is logged and never shown to the client.
pub async fn record(db: &PgPool, e: Event) {
    let (method, path) = e.request.unzip();
    let res = sqlx::query(
        "INSERT INTO audit_log (user_id, action, entity, entity_id, details, ip, method, path, status, outcome)
         VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10)",
    )
    .bind(e.user_id)
    .bind(&e.action)
    .bind(&e.entity)
    .bind(&e.entity_id)
    .bind(&e.details)
    .bind(e.ip.map(|ip| ip.to_string()))
    .bind(method)
    .bind(path)
    .bind(e.status.map(|s| s as i16))
    .bind(e.outcome.as_str())
    .execute(db)
    .await;
    if let Err(err) = res {
        tracing::error!(action = %e.action, "audit write failed: {err}");
    }
}

#[derive(Deserialize)]
pub struct AuditQuery {
    /// Page size, 1..=500 (default 100).
    limit: Option<i64>,
    /// Cursor: only rows with a smaller id (`next_before` of the previous page).
    before: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
struct AuditRow {
    id: i64,
    at: DateTime<Utc>,
    user_id: Option<Uuid>,
    username: Option<String>,
    action: String,
    entity: String,
    entity_id: Option<String>,
    details: Option<Value>,
    ip: Option<String>,
    method: Option<String>,
    path: Option<String>,
    status: Option<i16>,
    outcome: String,
}

/// `GET /api/audit?limit=&before=` — newest first, cursor-paginated by id.
pub async fn list(State(s): State<AppState>, Query(q): Query<AuditQuery>) -> ApiResult<Value> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let rows = sqlx::query_as::<_, AuditRow>(
        "SELECT a.id, a.at, a.user_id, u.username, a.action, a.entity, a.entity_id, a.details,
                host(a.ip) AS ip, a.method, a.path, a.status, a.outcome
         FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
         WHERE $1::bigint IS NULL OR a.id < $1
         ORDER BY a.id DESC LIMIT $2",
    )
    .bind(q.before)
    .bind(limit)
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    let next_before = (rows.len() as i64 == limit).then(|| rows.last().map(|r| r.id)).flatten();
    Ok(Json(json!({ "items": rows, "next_before": next_before })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_from_status() {
        assert_eq!(Outcome::of_status(200), Outcome::Success);
        assert_eq!(Outcome::of_status(201), Outcome::Success);
        assert_eq!(Outcome::of_status(401), Outcome::Denied);
        assert_eq!(Outcome::of_status(403), Outcome::Denied);
        assert_eq!(Outcome::of_status(429), Outcome::Denied);
        assert_eq!(Outcome::of_status(409), Outcome::Failure);
        assert_eq!(Outcome::of_status(500), Outcome::Failure);
    }
}
