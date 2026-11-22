use crate::{config::Config, pipeline, v1, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

// Run with DATABASE_URL pointing at a disposable PostgreSQL server (like run_integrity_tests).

/// A finished one-off scan of 192.0.2.10 that saw the given ports, `hours_ago` hours ago.
async fn one_off_run(db: &PgPool, hours_ago: i32, scanned: &str, open: &[i32]) -> anyhow::Result<Uuid> {
    let scan: Uuid = sqlx::query_scalar("INSERT INTO scans(name,enabled,preflight,ports) VALUES ('one-off',false,false,$1) RETURNING id")
        .bind(scanned)
        .fetch_one(db)
        .await?;
    let run: Uuid = sqlx::query_scalar(
        "INSERT INTO scan_runs(scan_id,status,started_at,finished_at,target_snapshot,config_snapshot)
         VALUES ($1,'done',now()-make_interval(hours=>$2),now()-make_interval(hours=>$2),
                 '[{\"kind\":\"ip\",\"value\":\"192.0.2.10\"}]',jsonb_build_object('ports',$3::text)) RETURNING id",
    )
    .bind(scan)
    .bind(hours_ago)
    .bind(scanned)
    .fetch_one(db)
    .await?;
    let host: Uuid = sqlx::query_scalar(
        "INSERT INTO hosts(run_id,address,seen_at) VALUES ($1,'192.0.2.10',now()-make_interval(hours=>$2)) RETURNING id",
    )
    .bind(run)
    .bind(hours_ago)
    .fetch_one(db)
    .await?;
    for port in open {
        sqlx::query("INSERT INTO services(host_id,port,service,confidence) VALUES ($1,$2,'redis',0.9)")
            .bind(host)
            .bind(port)
            .execute(db)
            .await?;
    }
    Ok(run)
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn one_finding_per_problem_across_scans(db: PgPool) -> anyhow::Result<()> {
    let key = "test-only";
    let redis = v1::finding_id("exposure", "192.0.2.10:6379/tcp");
    one_off_run(&db, 5, "80,6379", &[6379]).await?;
    let second = one_off_run(&db, 4, "80,6379", &[6379, 80]).await?;
    // The analyst's state is keyed by the problem, not by the scan.
    sqlx::query("INSERT INTO finding_states(finding_id,category,entity_key,status) VALUES ($1,'exposure','192.0.2.10:6379/tcp','confirmed')")
        .bind(redis)
        .execute(&db)
        .await?;
    // A later scan of other ports only says nothing about 6379.
    one_off_run(&db, 3, "80", &[80]).await?;

    let all = v1::load_findings(&db, key).await.map_err(|e| anyhow::anyhow!("{:?}", e.1))?;
    let mine: Vec<&v1::Finding> = all.iter().filter(|f| f.ip == "192.0.2.10").collect();
    assert_eq!(mine.len(), 1, "two scans, one finding");
    let f = mine[0];
    assert_eq!((f.id, f.occurrences, f.run_id), (redis, 2, second));
    assert_eq!(f.status, "confirmed");
    assert_eq!(f.change, "unchanged");
    assert!(f.first_seen < f.last_seen);
    assert!(f.is_current());

    // A later scan that covered 6379 and saw the host without it: gone, not current.
    one_off_run(&db, 2, "80,6379", &[80]).await?;
    let all = v1::load_findings(&db, key).await.map_err(|e| anyhow::anyhow!("{:?}", e.1))?;
    let f = all.iter().find(|f| f.id == redis).expect("still listed");
    assert_eq!((f.change.as_str(), f.status.as_str(), f.occurrences), ("gone", "confirmed", 2));
    assert!(!f.is_current());
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires PostgreSQL"]
async fn excluded_addresses_are_cut_out_of_the_run(db: PgPool) -> anyhow::Result<()> {
    let state = AppState {
        db: db.clone(),
        config: Config {
            allowed_cidrs: vec!["192.0.2.0/29".parse()?],
            excluded_cidrs: vec!["192.0.2.5/32".parse()?],
            ..Config::for_tests()
        }
        .into(),
        limiter: Default::default(),
    };
    let scan: Uuid = sqlx::query_scalar("INSERT INTO scans(name,enabled,preflight,ports) VALUES ('cut',false,false,'80') RETURNING id")
        .fetch_one(&db)
        .await?;
    let cidr: Uuid = sqlx::query_scalar("INSERT INTO targets(kind,value) VALUES ('cidr','192.0.2.0/29') RETURNING id")
        .fetch_one(&db)
        .await?;
    // On the no-scan list, not part of this scan.
    sqlx::query("INSERT INTO targets(kind,value,excluded) VALUES ('ip','192.0.2.3',true)").execute(&db).await?;
    sqlx::query("INSERT INTO scan_targets(scan_id,target_id) VALUES ($1,$2)").bind(scan).bind(cidr).execute(&db).await?;
    let run: Uuid = sqlx::query_scalar("INSERT INTO scan_runs(scan_id) VALUES ($1) RETURNING id").bind(scan).fetch_one(&db).await?;
    // No scanner tools here: the batches fail without traffic, the snapshot stays.
    pipeline::execute_run(state, run).await?;
    let (snapshot, stats): (Value, Value) = sqlx::query_as("SELECT target_snapshot, stats FROM scan_runs WHERE id=$1")
        .bind(run)
        .fetch_one(&db)
        .await?;
    assert_eq!(snapshot, json!([{ "kind": "cidr", "value": "192.0.2.0/29", "except": ["192.0.2.3", "192.0.2.5"] }]));
    assert_eq!(stats["hosts_total"], 4, "6 hosts of the /29 minus 2 excluded");
    Ok(())
}
