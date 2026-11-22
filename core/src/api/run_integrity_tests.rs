use super::*;
use crate::{config::Config, engine::Tool, history, pipeline};
use uuid::Uuid;
use sqlx::PgPool;

// Run with DATABASE_URL pointing at a disposable PostgreSQL server. sqlx creates a
// separate migrated database. Missing tools simulate a failed batch without traffic.
#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn run_integrity(db: PgPool) -> anyhow::Result<()> {
    let state = AppState {
        db: db.clone(),
        config: Config { allowed_cidrs: vec!["192.0.2.1/32".parse()?], ..Config::for_tests() }.into(),
        limiter: Default::default(),
    };
    anyhow::ensure!(
        Tool::Naabu.resolve(&state.config.tools_dir).is_none(),
        "test requires naabu absent from PATH"
    );
    let scan: Uuid = sqlx::query_scalar("INSERT INTO scans(name,enabled,preflight,ports) VALUES ('fixture',false,false,'80') RETURNING id")
        .fetch_one(&db).await?;
    let target: Uuid = sqlx::query_scalar(
        "INSERT INTO targets(kind,value) VALUES ('ip','192.0.2.1') RETURNING id",
    )
    .fetch_one(&db)
    .await?;
    sqlx::query("INSERT INTO scan_targets(scan_id,target_id) VALUES ($1,$2)")
        .bind(scan)
        .bind(target)
        .execute(&db)
        .await?;
    let baseline: Uuid = sqlx::query_scalar("INSERT INTO scan_runs(scan_id,status,target_snapshot) VALUES ($1,'done','[{\"kind\":\"ip\",\"value\":\"192.0.2.1\"}]') RETURNING id")
        .bind(scan).fetch_one(&db).await?;
    sqlx::query("INSERT INTO hosts(run_id,address) VALUES ($1,'192.0.2.1')")
        .bind(baseline)
        .execute(&db)
        .await?;

    let new_run = |checkpoint: i64| {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO scan_runs(scan_id,checkpoint) VALUES ($1,$2) RETURNING id",
        )
        .bind(scan)
        .bind(checkpoint)
        .fetch_one(&db)
    };
    let result = |id| {
        sqlx::query_as::<_, (String, Value)>(
            "SELECT status::text, stats FROM scan_runs WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&db)
    };

    // T-07: the tool fails on both attempts. The uncovered host cannot disappear.
    let partial = new_run(0).await?;
    pipeline::execute_run(state.clone(), partial).await?;
    let (status, stats) = result(partial).await?;
    assert_eq!(status, "partial");
    assert_eq!(stats["failed_ranges"], json!([[0, 1]]));
    assert_eq!(stats["diff"]["gone"], 0);

    // T-10: a checkpoint at the end starts finalization directly. A previously
    // active host is missing, so finalization waits before its recheck.
    let pending = new_run(1).await?;
    assert_eq!(history::previous_run(&db, pending).await?, Some(baseline));
    let worker = tokio::spawn(pipeline::execute_run(state.clone(), pending));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !sqlx::query_scalar::<_, bool>(
            "SELECT config_snapshot IS NOT NULL FROM scan_runs WHERE id=$1",
        )
        .bind(pending)
        .fetch_one(&db)
        .await?
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        Ok::<_, sqlx::Error>(())
    })
    .await??;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // What `POST /api/v1/scans/{id}/cancel` does: the worker stops after its current batch.
    sqlx::query(
        "UPDATE scan_runs SET status = 'cancelled', resume_at = NULL, finished_at = COALESCE(finished_at, now())
         WHERE id = $1 AND status IN ('queued', 'running', 'paused')",
    )
    .bind(pending)
    .execute(&db)
    .await?;
    worker.await??;
    let (status, stats) = result(pending).await?;
    assert_eq!(status, "cancelled");
    assert_eq!(stats["rechecked"], 0);
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT finished_at IS NOT NULL FROM scan_runs WHERE id=$1")
            .bind(pending)
            .fetch_one(&db)
            .await?
    );

    // T-09: expire a window to persist the original settings, then edit the
    // definition and resume the same run from its saved checkpoint.
    sqlx::query("UPDATE scans SET window_minutes=1 WHERE id=$1")
        .bind(scan)
        .execute(&db)
        .await?;
    let resumed = new_run(0).await?;
    sqlx::query("UPDATE scan_runs SET window_started_at=now()-interval '2 minutes' WHERE id=$1")
        .bind(resumed)
        .execute(&db)
        .await?;
    pipeline::execute_run(state.clone(), resumed).await?;
    assert_eq!(result(resumed).await?.0, "paused");
    sqlx::query("UPDATE scans SET ports='22' WHERE id=$1")
        .bind(scan)
        .execute(&db)
        .await?;
    sqlx::query("UPDATE scan_runs SET status='running',window_started_at=now() WHERE id=$1")
        .bind(resumed)
        .execute(&db)
        .await?;
    pipeline::execute_run(state.clone(), resumed).await?;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT config_snapshot->>'ports' FROM scan_runs WHERE id=$1"
        )
        .bind(resumed)
        .fetch_one(&db)
        .await?,
        "80"
    );

    // T-08: a new run with a narrowed (empty) target set must skip the old host.
    sqlx::query("DELETE FROM scan_targets WHERE scan_id=$1")
        .bind(scan)
        .execute(&db)
        .await?;
    let narrowed = new_run(0).await?;
    pipeline::execute_run(state, narrowed).await?;
    let (status, stats) = result(narrowed).await?;
    assert_eq!(status, "done");
    assert_eq!(stats["diff"]["against"], json!(baseline));
    assert_eq!(stats["diff"]["not_comparable"], 1);
    assert_eq!(stats["diff"]["gone"], 0);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn protected_routes(db: PgPool) -> anyhow::Result<()> {
    use crate::rbac::{Role, Rule, ROUTES};
    let state = AppState { db: db.clone(), config: Config::for_tests().into(), limiter: Default::default() };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state).into_make_service_with_connect_info::<std::net::SocketAddr>()).await
    });
    let http = reqwest::Client::builder().no_proxy().build()?;
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users(username,password_hash,role,can_execute_scans) VALUES ('qa-viewer','unused','viewer',false) RETURNING id"
    ).fetch_one(&db).await?;
    let token = Uuid::new_v4().to_string();
    use sha2::{Digest, Sha256};
    sqlx::query("INSERT INTO sessions(user_id,token_hash,expires_at) VALUES ($1,$2,now()+interval '5 minutes')")
        .bind(user_id).bind(Sha256::digest(token.as_bytes()).to_vec()).execute(&db).await?;
    for &(method, pattern, rule) in ROUTES {
        if rule == Rule::Public { continue; }
        let path = pattern.split('/').map(|s| if s.starts_with('{') { "00000000-0000-0000-0000-000000000001" } else { s }).collect::<Vec<_>>().join("/");
        let url = format!("http://{address}{path}");
        let req = || http.request(method.parse().unwrap(), &url);
        assert_eq!(req().send().await?.status(), 401, "{method} {path}");
        if let Rule::Requires(action) = rule && !Role::Viewer.can(action,false) {
            assert_eq!(req().bearer_auth(&token).send().await?.status(),403,"{method} {path}");
        }
    }
    server.abort();
    Ok(())
}
