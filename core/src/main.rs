//! Attack Surface Intelligence — core service (API + scan orchestrator).
//! Architecture and module map: see ../PROJECT.md.

mod api;
mod config;
mod diff;
mod engine;
mod fingerprint;
mod input;
mod parse;
mod pipeline;
mod rbac;
mod scheduler;

use anyhow::Result;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Arc<config::Config>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=info".into()))
        .init();

    let config = config::Config::from_env()?;
    let db = PgPoolOptions::new()
        .max_connections(16)
        .connect(&config.database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&db).await?;

    let addr = config.bind_addr.clone();
    let state = AppState { db, config: Arc::new(config) };
    tokio::spawn(scheduler::run(state.clone()));
    let app = api::router(state).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("asi-core listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
