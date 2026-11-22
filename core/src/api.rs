//! HTTP API consumed by the Next.js dashboard through its `/api/v1` proxy (the contract in
//! docs/API-CONTRACT.md). Every route goes through `auth::gate` (deny by default, rights from
//! `rbac::ROUTES`); `/api/health` is the only public route besides the login.

use crate::{auth, AppState};
use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    routing::{delete, get, patch, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router(state: AppState) -> Router {
    let api = Router::new().route("/api/health", get(health)).merge(v1_routes());
    // Add routes and `.merge(...)`s ABOVE this line: the gate covers only what exists when
    // it is installed. New routes also need a row in `rbac::ROUTES` (else admin-only).
    api.route_layer(middleware::from_fn_with_state(state.clone(), auth::gate)).with_state(state)
}

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
        .route("/api/v1/tags", get(v1::tags))
        .route("/api/v1/targets", get(v1::list_targets).post(v1::create_targets))
        .route("/api/v1/targets/export", get(v1::export_targets))
        .route(
            "/api/v1/targets/import",
            post(v1::import_targets).layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024)),
        )
        .route("/api/v1/targets/bulk", post(v1::bulk_targets))
        .route("/api/v1/targets/{id}", get(v1::get_target).patch(v1::update_target).delete(v1::delete_target))
        .route("/api/v1/findings", get(v1::list_findings))
        .route("/api/v1/findings/export", get(v1::export_findings))
        .route("/api/v1/findings/{id}", get(v1::get_finding).patch(v1::update_finding))
        .route("/api/v1/audit", get(v1::audit_list))
        .route("/api/v1/findings/defectdojo", post(crate::v1_admin::dojo_export))
        .route("/api/v1/findings/bulk", post(crate::v1_assets::findings_bulk))
        .route("/api/v1/users", get(crate::v1_admin::list_users).post(crate::v1_admin::create_user))
        .route("/api/v1/users/{id}", patch(crate::v1_admin::update_user).delete(crate::v1_admin::remove_user))
        .route("/api/v1/roles", get(crate::v1_admin::list_roles).post(crate::v1_admin::create_role))
        .route("/api/v1/permissions", get(crate::v1_admin::list_permissions))
        .route("/api/v1/roles/{id}", patch(crate::v1_admin::update_role).delete(crate::v1_admin::delete_role))
        .route("/api/v1/settings", get(crate::v1_admin::get_settings).patch(crate::v1_admin::update_settings))
        .route("/api/v1/security/encryption", get(crate::v1_admin::encryption))
        .route("/api/v1/security/encryption/rotate", post(crate::v1_admin::rotate_key))
        .route("/api/v1/engines", get(crate::v1_admin::engines))
        .route("/api/v1/integrations/defectdojo", get(crate::v1_admin::dojo_get).put(crate::v1_admin::dojo_put))
        .route("/api/v1/integrations/defectdojo/test", post(crate::v1_admin::dojo_test))
        .route("/api/v1/integrations/defectdojo/exports", get(crate::v1_admin::dojo_exports))
        .route("/api/v1/scans", get(crate::v1_scans::list).post(crate::v1_scans::create_scan))
        .route("/api/v1/scans/estimate", post(crate::v1_scans::estimate))
        .route(
            "/api/v1/scans/import",
            post(crate::v1_scans::import).layer(axum::extract::DefaultBodyLimit::max(50 * 1024 * 1024)),
        )
        .route(
            "/api/v1/scans/{id}",
            get(crate::v1_scans::get_scan).patch(crate::v1_scans::update_scan).delete(crate::v1_scans::delete_scan),
        )
        .route("/api/v1/scans/{id}/batches", get(crate::v1_scans::batches))
        .route("/api/v1/scans/{id}/logs", get(crate::v1_scans::logs))
        .route("/api/v1/scans/{id}/events", get(crate::v1_scans::events))
        .route("/api/v1/scans/{id}/export", get(crate::v1_scans::export))
        .route("/api/v1/scans/{id}/{action}", post(crate::v1_scans::control))
        .route("/api/v1/profiles", get(crate::v1_scans::list_profiles).post(crate::v1_scans::create_profile))
        .route("/api/v1/profiles/{id}", patch(crate::v1_scans::update_profile).delete(crate::v1_scans::delete_profile))
        .route("/api/v1/schedules", get(crate::v1_scans::list_schedules).post(crate::v1_scans::create_schedule))
        .route(
            "/api/v1/schedules/{id}",
            patch(crate::v1_scans::update_schedule).delete(crate::v1_scans::delete_schedule),
        )
        .route("/api/v1/hosts", get(crate::v1_assets::list_hosts))
        .route("/api/v1/hosts/unstable", get(crate::v1_assets::unstable_hosts))
        .route("/api/v1/hosts/{id}", get(crate::v1_assets::get_host).patch(crate::v1_assets::update_host))
        .route("/api/v1/hosts/{id}/overrides/{field}", delete(crate::v1_assets::revert_host))
        .route("/api/v1/hosts/{id}/history", get(crate::v1_assets::host_history))
        .route("/api/v1/hosts/{id}/recheck", post(crate::v1_assets::recheck_host))
        .route("/api/v1/services", get(crate::v1_assets::list_services))
        .route("/api/v1/services/{id}", get(crate::v1_assets::get_service).patch(crate::v1_assets::update_service))
        .route("/api/v1/services/{id}/cookies/{name}/reveal", post(crate::v1_assets::reveal_cookie))
        .route("/api/v1/service-groups", get(crate::v1_assets::service_groups))
        .route("/api/v1/diffs", get(crate::v1_assets::diffs))
        .route("/api/v1/signatures", get(crate::signatures::list).post(crate::signatures::create))
        .route("/api/v1/signatures/test", post(crate::signatures::test))
        .route("/api/v1/signatures/export", get(crate::signatures::export))
        .route("/api/v1/signatures/import", post(crate::signatures::import))
        .route(
            "/api/v1/signatures/{id}",
            get(crate::signatures::get).patch(crate::signatures::update).delete(crate::signatures::remove),
        )
}
pub(crate) type ApiError = (StatusCode, Json<Value>);
#[cfg(test)]
mod run_integrity_tests;
#[cfg(test)]
mod finding_identity_tests;
pub(crate) type ApiResult<T> = Result<Json<T>, ApiError>;

pub(crate) fn internal(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("{e}");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "detail": "internal error" })))
}

pub(crate) fn bad(msg: impl Into<String>) -> ApiError {
    (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "detail": msg.into() })))
}

async fn health(State(s): State<AppState>) -> ApiResult<Value> {
    sqlx::query("SELECT 1").execute(&s.db).await.map_err(internal)?;
    Ok(Json(json!({ "status": "ok" })))
}
/// `Some(value)` for a field that is present, also when it is null (to clear it).
pub(crate) fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
