//! Encryption-at-rest keys and their rotation (deploy/SECURITY.md, "Key rotation").
//!
//! Every sensitive column holds `pgp_sym_encrypt(value, ASI_DATA_KEY)` ([`COLUMNS`]). Keys come
//! from the environment only, so a rotation is: new key in `ASI_DATA_KEY`, the old one in
//! `ASI_DATA_KEY_PREVIOUS`, restart. Each pool connection then carries the previous key in the
//! session setting `asi.data_key_previous` ([`prepare_connection`]) and every read goes through
//! `asi_decrypt` (migration 0016), which falls back to it. [`start_rotation`] re-encrypts, column
//! by column in key order, every row still under the previous key: each batch is locked and
//! rewritten in its own transaction, rows already under the current key are left alone (so a
//! rotation can be repeated or resumed), rows neither key opens are counted, never touched.
//! Once nothing is left under the previous key, the operator removes `ASI_DATA_KEY_PREVIOUS`.

use crate::audit::{self, Event, Outcome};
use crate::AppState;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
// Dynamic SQL here is built only from the static `COLUMNS` table; values are always bound.
use sqlx::{AssertSqlSafe, Connection, PgConnection};
use std::sync::{LazyLock, Mutex};
use uuid::Uuid;

/// One encrypted column and the primary key used to walk it.
pub struct Column {
    pub table: &'static str,
    pub column: &'static str,
    /// Primary key columns and their SQL types, in key order.
    pub key: &'static [(&'static str, &'static str)],
    pub description: &'static str,
}

const ID: &[(&str, &str)] = &[("id", "uuid")];
const SERIAL: &[(&str, &str)] = &[("id", "bigint")];

/// Every pgcrypto column (a test checks the migrations declare no other `*_enc BYTEA`).
pub const COLUMNS: &[Column] = &[
    Column { table: "http_findings", column: "headers_enc", key: ID, description: "Nagłówki odpowiedzi HTTP" },
    Column { table: "http_findings", column: "cookies_enc", key: ID, description: "Ciasteczka (Set-Cookie)" },
    Column { table: "http_findings", column: "tls_enc", key: ID, description: "Szczegóły certyfikatów TLS" },
    Column { table: "http_findings", column: "raw_enc", key: ID, description: "Surowy wynik httpx" },
    Column { table: "http_findings", column: "body_enc", key: ID, description: "Treść stron (do sygnatur)" },
    Column { table: "http_probes", column: "body_enc", key: ID, description: "Treść odpowiedzi na sprawdzane ścieżki" },
    Column { table: "services", column: "banner_enc", key: ID, description: "Banery usług" },
    Column { table: "run_artifacts", column: "content_enc", key: SERIAL, description: "Surowe wyniki skanerów (nmap, naabu, httpx)" },
    Column { table: "diffs", column: "old_enc", key: ID, description: "Wartości w porównaniach przebiegów (przed)" },
    Column { table: "diffs", column: "new_enc", key: ID, description: "Wartości w porównaniach przebiegów (po)" },
    Column { table: "finding_states", column: "notes_enc", key: &[("finding_id", "uuid")], description: "Notatki analityków do znalezisk" },
    Column { table: "annotations", column: "notes_enc", key: ID, description: "Notatki w adnotacjach" },
    Column { table: "annotation_history", column: "notes_enc", key: SERIAL, description: "Historia notatek w adnotacjach" },
    Column { table: "targets", column: "notes_enc", key: ID, description: "Notatki do celów" },
    Column {
        table: "signature_hits",
        column: "evidence_enc",
        key: &[("signature_id", "uuid"), ("service_id", "uuid")],
        description: "Dowody dopasowań sygnatur",
    },
    Column { table: "settings", column: "secret_enc", key: &[("key", "text")], description: "Token API DefectDojo" },
];

/// Rows locked and re-encrypted per transaction.
const BATCH: i64 = 200;
/// Without a previous key, only this many rows per column are checked at startup.
const SAMPLE: i64 = 50;

/// Public identifier of a key: never the key, only a short digest of it.
pub fn key_id(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    format!("sha256:{}", digest[..6].iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Session setup of every pool connection: the previous key for `asi_decrypt` (empty = none).
pub async fn prepare_connection(conn: &mut PgConnection, previous: Option<&str>) -> sqlx::Result<()> {
    sqlx::query("SELECT set_config('asi.data_key_previous', $1, false)")
        .bind(previous.unwrap_or(""))
        .execute(conn)
        .await
        .map(drop)
}

/// State of the last key check or rotation of this process.
#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    /// idle | counting | rotating | done | failed
    pub state: &'static str,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    /// Rows still encrypted with the previous key; null until counted (or without one).
    pub remaining_previous: Option<u64>,
    /// Rows re-encrypted by the last rotation.
    pub rotated: u64,
    /// Rows that neither key decrypts (another, older key, or damaged data).
    pub unreadable: u64,
    /// `unreadable` comes from a sample (no previous key configured), not every row.
    pub sampled: bool,
    pub error: Option<String>,
}

static PROGRESS: LazyLock<Mutex<Progress>> = LazyLock::new(|| {
    Mutex::new(Progress {
        state: "idle",
        started_at: None,
        finished_at: None,
        remaining_previous: None,
        rotated: 0,
        unreadable: 0,
        sampled: false,
        error: None,
    })
});

/// One key job (check or rotation) at a time in this process; the advisory lock covers others.
static JOB: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(Default::default);
/// `pg_try_advisory_lock` key of the rotation ("ASIKEYRT").
const ADVISORY_LOCK: i64 = 0x4153_494b_4559_5254;

pub fn progress() -> Progress {
    PROGRESS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn update(f: impl FnOnce(&mut Progress)) {
    f(&mut PROGRESS.lock().unwrap_or_else(|e| e.into_inner()));
}

/// The `[current, previous]` keys (previous only when configured).
fn keys(s: &AppState) -> Vec<String> {
    std::iter::once(s.config.data_key.clone()).chain(s.config.data_key_previous.clone()).collect()
}

fn key_columns(c: &Column) -> String {
    c.key.iter().map(|(name, _)| *name).collect::<Vec<_>>().join(", ")
}

/// `SELECT` of a counting pass: (rows under the previous key, rows no key opens).
fn count_sql(c: &Column, sample: bool) -> String {
    let limit = if sample { format!(" LIMIT {SAMPLE}") } else { String::new() };
    format!(
        "SELECT count(*) FILTER (WHERE i = 2), count(*) FILTER (WHERE i = 0)
         FROM (SELECT asi_key_index({col}, $1) AS i FROM {table} WHERE {col} IS NOT NULL{limit}) s",
        col = c.column,
        table = c.table,
    )
}

/// Lock the next batch in key order after the cursor `$1` (key values as text; NULL = start).
fn lock_sql(c: &Column, first: bool) -> String {
    let cols = key_columns(c);
    let after = if first {
        String::new()
    } else {
        let bound: Vec<String> = c.key.iter().enumerate().map(|(i, (_, ty))| format!("$1[{}]::{ty}", i + 1)).collect();
        format!(" AND ({cols}) > ({})", bound.join(", "))
    };
    let as_text: Vec<String> = c.key.iter().map(|(name, _)| format!("{name}::text")).collect();
    format!(
        "SELECT ctid::text, ARRAY[{}] FROM {table} WHERE {col} IS NOT NULL{after}
         ORDER BY {cols} LIMIT {BATCH} FOR UPDATE",
        as_text.join(", "),
        table = c.table,
        col = c.column,
    )
}

/// Re-encrypt the locked rows `$1` (ctids) that only the previous key opens:
/// (rows re-encrypted, rows no key opens).
fn rotate_sql(c: &Column) -> String {
    format!(
        "WITH k AS (SELECT ctid AS row_id, asi_key_index({col}, $2) AS i FROM {table} WHERE ctid = ANY($1::text[]::tid[])),
              u AS (UPDATE {table} t SET {col} = pgp_sym_encrypt(pgp_sym_decrypt(t.{col}, $3), $4)
                    FROM k WHERE t.ctid = k.row_id AND k.i = 2 RETURNING 1)
         SELECT (SELECT count(*) FROM u), count(*) FILTER (WHERE i = 0) FROM k",
        col = c.column,
        table = c.table,
    )
}

/// Startup check, in the background. With a previous key: how many rows still need it (every
/// row is tried). Without one: a sample of each column, so a wrong `ASI_DATA_KEY` is reported
/// at once instead of as failing pages.
pub fn start_check(s: AppState) {
    tokio::spawn(async move {
        let _job = JOB.lock().await;
        let sample = s.config.data_key_previous.is_none();
        // A rotation requested meanwhile waits for this check and keeps its own state.
        let set_state = |p: &mut Progress, state| {
            if p.state != "rotating" {
                p.state = state;
            }
        };
        update(|p| {
            set_state(p, "counting");
            p.started_at = Some(Utc::now());
            p.error = None;
        });
        let keys = keys(&s);
        let mut previous = 0u64;
        let mut unreadable = 0u64;
        for c in COLUMNS {
            match sqlx::query_as::<_, (i64, i64)>(AssertSqlSafe(count_sql(c, sample))).bind(&keys).fetch_one(&s.db).await {
                Ok((p, u)) => {
                    previous += p as u64;
                    unreadable += u as u64;
                }
                Err(e) => {
                    tracing::error!(table = c.table, column = c.column, "encryption key check failed: {e}");
                    update(|p| {
                        set_state(p, "failed");
                        p.error = Some(format!("Sprawdzenie {}.{} nie powiodło się.", c.table, c.column));
                    });
                    return;
                }
            }
        }
        if unreadable > 0 {
            tracing::error!(
                unreadable,
                "rows that ASI_DATA_KEY{} cannot decrypt: if the key was changed, set the old one as ASI_DATA_KEY_PREVIOUS",
                if sample { "" } else { " / ASI_DATA_KEY_PREVIOUS" }
            );
        }
        if previous > 0 {
            tracing::info!(previous, "rows still encrypted with ASI_DATA_KEY_PREVIOUS: run the key rotation");
        }
        update(|p| {
            set_state(p, "idle");
            p.finished_at = Some(Utc::now());
            p.remaining_previous = (!sample).then_some(previous);
            p.unreadable = unreadable;
            p.sampled = sample;
        });
    });
}

#[derive(Debug, PartialEq, Eq)]
pub enum StartError {
    /// No `ASI_DATA_KEY_PREVIOUS`: nothing to rotate from.
    NoPreviousKey,
    /// A rotation is already running in this process.
    Running,
}

/// Start re-encrypting rows under the previous key, in the background.
pub fn start_rotation(s: AppState, user_id: Uuid) -> Result<(), StartError> {
    if s.config.data_key_previous.is_none() {
        return Err(StartError::NoPreviousKey);
    }
    {
        let mut p = PROGRESS.lock().unwrap_or_else(|e| e.into_inner());
        if p.state == "rotating" {
            return Err(StartError::Running);
        }
        p.state = "rotating";
        p.started_at = Some(Utc::now());
        p.finished_at = None;
        p.rotated = 0;
        p.error = None;
    }
    tokio::spawn(async move {
        let _job = JOB.lock().await;
        let result = rotate_all(&s).await;
        let (outcome, details) = match &result {
            Ok((rotated, unreadable)) => {
                tracing::info!(rotated, unreadable, "key rotation finished");
                update(|p| {
                    p.state = "done";
                    p.remaining_previous = Some(0);
                    p.unreadable = *unreadable;
                    p.sampled = false;
                });
                (Outcome::Success, json!({ "rotated": rotated, "unreadable": unreadable }))
            }
            Err(e) => {
                tracing::error!("key rotation failed: {e:#}");
                let message = "Rotacja przerwana — szczegóły w logach. Można ją bezpiecznie ponowić.".to_string();
                update(|p| {
                    p.state = "failed";
                    p.error = Some(message);
                });
                (Outcome::Failure, json!({ "rotated": progress().rotated }))
            }
        };
        update(|p| p.finished_at = Some(Utc::now()));
        let mut details = details;
        details["key_id"] = json!(key_id(&s.config.data_key));
        details["previous_key_id"] = json!(s.config.data_key_previous.as_deref().map(key_id));
        audit::record(
            &s.db,
            Event {
                user_id: Some(user_id),
                action: "encryption.rotate.finish".into(),
                entity: "encryption".into(),
                entity_id: None,
                details,
                ip: None,
                request: None,
                status: None,
                outcome,
            },
        )
        .await;
    });
    Ok(())
}

/// Every column, batch by batch: (rows re-encrypted, rows no key opens).
async fn rotate_all(s: &AppState) -> anyhow::Result<(u64, u64)> {
    let (Some(previous), current) = (s.config.data_key_previous.as_deref(), s.config.data_key.as_str()) else {
        anyhow::bail!("no previous key");
    };
    let keys = vec![current.to_string(), previous.to_string()];
    // Own connection, closed at the end, so the session advisory lock cannot outlive the job.
    let mut conn = s.db.acquire().await?.detach();
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)").bind(ADVISORY_LOCK).fetch_one(&mut conn).await?;
    anyhow::ensure!(locked, "another instance is rotating the key");
    let result = async {
        let (mut rotated, mut unreadable) = (0u64, 0u64);
        for c in COLUMNS {
            let (r, u) = rotate_column(&mut conn, c, &keys, previous, current).await?;
            rotated += r;
            unreadable += u;
        }
        anyhow::Ok((rotated, unreadable))
    }
    .await;
    let _ = conn.close().await;
    result
}

async fn rotate_column(
    conn: &mut PgConnection,
    c: &Column,
    keys: &[String],
    previous: &str,
    current: &str,
) -> anyhow::Result<(u64, u64)> {
    let (lock_first, lock_next, rotate) = (lock_sql(c, true), lock_sql(c, false), rotate_sql(c));
    let mut cursor: Option<Vec<String>> = None;
    let (mut rotated, mut unreadable) = (0u64, 0u64);
    loop {
        let mut tx = conn.begin().await?;
        // Lets the rotation through annotation_history's append-only trigger (0016).
        sqlx::query("SELECT set_config('asi.key_rotation', 'on', true)").execute(&mut *tx).await?;
        let rows: Vec<(String, Vec<String>)> = match &cursor {
            None => sqlx::query_as(AssertSqlSafe(lock_first.clone())).fetch_all(&mut *tx).await?,
            Some(after) => sqlx::query_as(AssertSqlSafe(lock_next.clone())).bind(after).fetch_all(&mut *tx).await?,
        };
        let Some((_, last)) = rows.last() else { break };
        cursor = Some(last.clone());
        let ctids: Vec<&String> = rows.iter().map(|(ctid, _)| ctid).collect();
        let (r, u): (i64, i64) =
            sqlx::query_as(AssertSqlSafe(rotate.clone())).bind(&ctids).bind(keys).bind(previous).bind(current).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        rotated += r as u64;
        unreadable += u as u64;
        update(|p| {
            p.rotated += r as u64;
            if let Some(left) = p.remaining_previous.as_mut() {
                *left = left.saturating_sub(r as u64);
            }
        });
        if (rows.len() as i64) < BATCH {
            break;
        }
    }
    if rotated > 0 || unreadable > 0 {
        tracing::info!(table = c.table, column = c.column, rotated, unreadable, "key rotation: column done");
    }
    Ok((rotated, unreadable))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// (table, column) of every `*_enc BYTEA` the migrations declare.
    fn declared() -> BTreeSet<(String, String)> {
        let table_re = regex::Regex::new(r"(?i)\b(?:CREATE TABLE(?: IF NOT EXISTS)?|ALTER TABLE(?: IF EXISTS)?)\s+(\w+)").unwrap();
        let col_re = regex::Regex::new(r"(?i)\b(\w+_enc)\s+BYTEA").unwrap();
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut out = BTreeSet::new();
        let mut files: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
        files.sort();
        for f in files {
            let mut table = String::new();
            for line in std::fs::read_to_string(f).unwrap().lines() {
                let line = line.split("--").next().unwrap_or("");
                if let Some(t) = table_re.captures(line) {
                    table = t[1].to_ascii_lowercase();
                }
                for c in col_re.captures_iter(line) {
                    out.insert((table.clone(), c[1].to_ascii_lowercase()));
                }
            }
        }
        out
    }

    #[test]
    fn every_encrypted_column_is_rotated() {
        let listed: BTreeSet<(String, String)> = COLUMNS.iter().map(|c| (c.table.into(), c.column.into())).collect();
        let declared = declared();
        assert!(declared.len() >= 16, "parser found too little: {declared:?}");
        let missing: Vec<_> = declared.difference(&listed).collect();
        assert!(missing.is_empty(), "encrypted columns missing from keyring::COLUMNS: {missing:?}");
        assert_eq!(listed.len(), COLUMNS.len(), "no duplicates");
    }

    #[test]
    fn key_ids_never_show_the_key() {
        let id = key_id("correct horse battery staple");
        assert!(id.starts_with("sha256:") && id.len() == 19, "{id}");
        assert_ne!(id, key_id("correct horse battery staplf"));
        assert!(!id.contains("horse"));
    }

    #[test]
    fn batch_sql_walks_the_primary_key() {
        let hits = COLUMNS.iter().find(|c| c.table == "signature_hits").unwrap();
        let next = lock_sql(hits, false);
        assert!(next.contains("AND (signature_id, service_id) > ($1[1]::uuid, $1[2]::uuid)"), "{next}");
        assert!(next.contains("ORDER BY signature_id, service_id LIMIT 200 FOR UPDATE"), "{next}");
        assert!(next.contains("ARRAY[signature_id::text, service_id::text]"), "{next}");
        let first = lock_sql(hits, true);
        assert!(!first.contains("$1"), "{first}");
        let settings = COLUMNS.iter().find(|c| c.table == "settings").unwrap();
        assert!(lock_sql(settings, false).contains("AND (key) > ($1[1]::text)"));
        // Only rows that the previous key (index 2), and not the current one, opens are rewritten.
        let r = rotate_sql(settings);
        assert!(r.contains("k.i = 2") && r.contains("pgp_sym_encrypt(pgp_sym_decrypt(t.secret_enc, $3), $4)"), "{r}");
        assert!(count_sql(settings, true).ends_with("LIMIT 50) s") && !count_sql(settings, false).contains("LIMIT"));
    }
}
