//! Module 6 — HTTP API consumed by the Next.js frontend through its `/api` proxy.
//! Skeleton endpoints: health, tool inventory, targets (list/import), scans (list/create).
//! TODO(C): auth + RBAC extractor (rbac::Role::can) on every mutating route.

use crate::{engine::Tool, input, AppState};
use axum::{
    extract::State,
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/tools", get(tools))
        .route("/api/targets", get(list_targets).post(import_targets))
        .route("/api/scans", get(list_scans).post(create_scan))
        .with_state(state)
}

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<Value>)>;

fn internal(e: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    tracing::error!("{e}");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "detail": "internal error" })))
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

async fn import_targets(State(s): State<AppState>, Json(body): Json<ImportBody>) -> ApiResult<Value> {
    let (targets, errors) = input::parse_list(&body.text);
    let mut inserted = 0u64;
    for t in &targets {
        inserted += sqlx::query("INSERT INTO targets (kind, value) VALUES ($1, $2) ON CONFLICT (value) DO NOTHING")
            .bind(&t.kind)
            .bind(&t.value)
            .execute(&s.db)
            .await
            .map_err(internal)?
            .rows_affected();
    }
    let addresses: u128 = targets.iter().map(|t| t.address_count()).sum();
    Ok(Json(json!({
        "parsed": targets.len(),
        "inserted": inserted,
        "addresses": addresses.to_string(),
        "errors": errors.iter().map(|(line, e)| json!({ "line": line, "error": e.to_string() })).collect::<Vec<_>>(),
    })))
}

#[derive(Serialize, sqlx::FromRow)]
struct ScanRow {
    id: Uuid,
    name: String,
    status: String,
    rate_limit_pps: i32,
    window_minutes: Option<i32>,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn list_scans(State(s): State<AppState>) -> ApiResult<Vec<ScanRow>> {
    let rows = sqlx::query_as::<_, ScanRow>(
        "SELECT id, name, status::text AS status, rate_limit_pps, window_minutes, created_at \
         FROM scans ORDER BY created_at DESC LIMIT 100",
    )
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct CreateScan {
    name: String,
    #[serde(default = "default_rate")]
    rate_limit_pps: i32,
    window_minutes: Option<i32>,
    schedule_cron: Option<String>,
}
fn default_rate() -> i32 {
    100
}

async fn create_scan(State(s): State<AppState>, Json(b): Json<CreateScan>) -> ApiResult<Value> {
    if !(1..=10_000).contains(&b.rate_limit_pps) {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "detail": "rate_limit_pps must be 1..=10000" }))));
    }
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO scans (name, rate_limit_pps, window_minutes, schedule_cron) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&b.name)
    .bind(b.rate_limit_pps)
    .bind(b.window_minutes)
    .bind(&b.schedule_cron)
    .fetch_one(&s.db)
    .await
    .map_err(internal)?;
    // TODO(A): hand the scan to the scheduler queue.
    Ok(Json(json!({ "id": id, "status": "queued" })))
}
