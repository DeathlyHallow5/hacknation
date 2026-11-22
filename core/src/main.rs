//! Attack Surface Intelligence — core service (API + scan orchestrator).
//! Architecture and module map: see ../PROJECT.md.

mod api;
mod audit;
mod auth;
mod config;
mod diff;
mod engine;
mod fingerprint;
mod history;
mod input;
mod keyring;
mod parse;
mod pipeline;
mod presence;
mod rbac;
mod scheduler;
mod signatures;
mod v1;
mod v1_admin;
mod v1_assets;
mod v1_scans;

use anyhow::Result;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Arc<config::Config>,
    pub limiter: Arc<auth::LoginLimiter>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=info".into()))
        .init();

    let config = config::Config::from_env()?;
    // Each connection carries the previous data key (if any), for asi_decrypt (keyring.rs).
    let previous_key = config.data_key_previous.clone();
    let db = PgPoolOptions::new()
        .max_connections(16)
        .after_connect(move |conn, _| {
            let previous = previous_key.clone();
            Box::pin(async move { keyring::prepare_connection(conn, previous.as_deref()).await })
        })
        .connect(&config.database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    auth::bootstrap_admin(&db, &config).await?;
    let builtin = signatures::seed_builtin(&db).await?;
    tracing::info!(builtin, "built-in signatures loaded");

    let addr = config.bind_addr.clone();
    let state = AppState { db, config: Arc::new(config), limiter: Arc::default() };
    keyring::start_check(state.clone());
    if state.config.max_runs > 0 {
        tokio::spawn(scheduler::run(state.clone()));
    } else {
        tracing::info!("ASI_MAX_RUNS=0: API only, the scheduler is not started");
    }
    let app = api::router(state).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("asi-core listening on {addr}");
    // Client addresses feed the login limiter and the audit trail.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
