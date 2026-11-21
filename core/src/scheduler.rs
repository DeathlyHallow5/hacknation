//! Module 2 — scheduler (PROJECT.md §3.2). Polls Postgres every few seconds:
//! resumes paused runs whose next window has opened, and starts runs for due scans
//! (one-off or every `repeat_every_minutes`). At most `ASI_MAX_RUNS` run concurrently.

use crate::{pipeline, AppState};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use uuid::Uuid;

const TICK: Duration = Duration::from_secs(5);

pub async fn run(state: AppState) {
    // Runs left 'running' by a crash/restart resume from their checkpoint.
    match sqlx::query(
        "UPDATE scan_runs SET status = 'paused', resume_at = now() WHERE status = 'running'",
    )
    .execute(&state.db)
    .await
    {
        Ok(r) if r.rows_affected() > 0 => tracing::info!("recovering {} interrupted run(s)", r.rows_affected()),
        Ok(_) => {}
        Err(e) => tracing::error!("scheduler recovery failed: {e}"),
    }

    let slots = Arc::new(Semaphore::new(state.config.max_runs));
    loop {
        let free = slots.available_permits() as i64;
        if free > 0 {
            match claim(&state, free).await {
                Ok(ids) => {
                    for run_id in ids {
                        let permit = slots.clone().acquire_owned().await.expect("semaphore open");
                        let state = state.clone();
                        tokio::spawn(async move {
                            // Inner task so a panic is caught here instead of leaving the
                            // run 'running' until the next restart (R-02).
                            let error = match tokio::spawn(pipeline::execute_run(state.clone(), run_id)).await {
                                Ok(Ok(())) => None,
                                Ok(Err(e)) => Some(format!("{e:#}")),
                                Err(e) => Some(format!("run task crashed: {e}")),
                            };
                            if let Some(error) = error {
                                tracing::error!(%run_id, "run failed: {error}");
                                // A cancelled run stays cancelled (F-09): only the error and
                                // the end time are recorded.
                                let _ = sqlx::query(
                                    "UPDATE scan_runs SET error = $2, finished_at = COALESCE(finished_at, now()),
                                         status = CASE WHEN status = 'cancelled' THEN status ELSE 'failed' END
                                     WHERE id = $1 AND status IN ('running', 'cancelled')",
                                )
                                .bind(run_id)
                                .bind(error)
                                .execute(&state.db)
                                .await;
                            }
                            drop(permit);
                        });
                    }
                }
                Err(e) => tracing::error!("scheduler tick failed: {e}"),
            }
        }
        tokio::time::sleep(TICK).await;
    }
}

/// Claim up to `limit` runs to execute now: paused runs first, then new runs of due scans.
async fn claim(state: &AppState, limit: i64) -> sqlx::Result<Vec<Uuid>> {
    let mut ids: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE scan_runs SET status = 'running', window_started_at = now(), resume_at = NULL
         WHERE id IN (SELECT id FROM scan_runs WHERE status = 'paused' AND resume_at <= now()
                      ORDER BY resume_at LIMIT $1 FOR UPDATE SKIP LOCKED)
         RETURNING id",
    )
    .bind(limit)
    .fetch_all(&state.db)
    .await?;

    let left = limit - ids.len() as i64;
    if left > 0 {
        ids.extend(
            sqlx::query_scalar::<_, Uuid>(
                "WITH due AS (
                     SELECT s.id FROM scans s
                     WHERE s.enabled AND s.next_run_at <= now()
                       AND NOT EXISTS (SELECT 1 FROM scan_runs r WHERE r.scan_id = s.id
                                       AND r.status IN ('queued', 'running', 'paused'))
                     ORDER BY s.next_run_at LIMIT $1 FOR UPDATE SKIP LOCKED
                 ), bumped AS (
                     UPDATE scans s SET next_run_at = CASE WHEN s.repeat_every_minutes IS NULL THEN NULL
                         ELSE now() + make_interval(mins => s.repeat_every_minutes) END
                     FROM due WHERE s.id = due.id RETURNING s.id
                 )
                 INSERT INTO scan_runs (scan_id, status, window_started_at)
                 SELECT id, 'running', now() FROM bumped RETURNING id",
            )
            .bind(left)
            .fetch_all(&state.db)
            .await?,
        );
    }
    Ok(ids)
}
