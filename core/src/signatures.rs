//! Custom detection signatures (AGH requirement 10; F-26; PROJECT.md §8).
//!
//! Declarative JSON rules in the dashboard's shape (`frontend/src/lib/api/types.ts`:
//! `Signature`, `SignatureCondition`). They are evaluated against evidence the scanners
//! already collected — status, title, headers, cookies, favicon hash, service/technology
//! versions — and **never send requests of their own**: a `path` probe is refused as unsafe.
//! Regexes use the `regex` crate (linear time) with size limits; inputs are truncated.
//!
//! Hits are stored per run (`signature_hits`) at the end of each run and whenever a
//! signature changes; `v1` turns them into findings (category of the signature).

use crate::{
    api::ApiError,
    audit::Note,
    auth::CurrentUser,
    AppState,
};
use axum::{
    extract::{Multipart, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

const MAX_CONDITIONS: usize = 20;
const MAX_PATTERN: usize = 512;
const MAX_VALUE: usize = 4096;
const CATEGORIES: [&str; 10] =
    ["admin_panel", "staging", "outdated", "header", "cookie", "tls", "exposure", "iot", "signature", "technology"];

fn err(status: StatusCode, code: &str, message: impl Into<String>) -> ApiError {
    let message = message.into();
    (status, Json(json!({ "error": { "code": code, "message": message }, "detail": message })))
}

fn fail(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("signatures: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "internal", "Błąd serwera. Szczegóły w logach.")
}

// ---------- rule model ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    pub op: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub expect_status: Option<i32>,
    #[serde(default)]
    pub extract: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    pub operator: String,
    pub conditions: Vec<Condition>,
}

/// `SignatureInput` of the contract (also the built-in file format).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub category: String,
    #[serde(default)]
    pub technology: Option<String>,
    #[serde(default = "ten")]
    pub score_weight: i32,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(rename = "match")]
    pub rule: Match,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Built-in file only: bump to update existing installations.
    #[serde(default, skip_serializing)]
    pub version: Option<i32>,
}

fn ten() -> i32 {
    10
}
fn yes() -> bool {
    true
}

/// A condition compiled for matching.
struct Compiled {
    cond: Condition,
    re: Option<Regex>,
    extract: Option<Regex>,
}

fn build_regex(p: &str) -> Result<Regex, String> {
    if p.len() > MAX_PATTERN {
        return Err(format!("wyrażenie dłuższe niż {MAX_PATTERN} znaków"));
    }
    RegexBuilder::new(p)
        .case_insensitive(true)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|e| format!("niepoprawne wyrażenie regularne: {e}"))
}

/// Validate and compile a rule. Errors are user-facing (Polish); the second list holds
/// non-blocking warnings shown in the tester.
fn compile(input: &SignatureInput) -> Result<(Vec<Compiled>, Vec<String>), Vec<String>> {
    let mut errors = Vec::new();
    let warnings: Vec<String> = Vec::new();
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 120 {
        errors.push("Nazwa: 1–120 znaków.".into());
    }
    if input.description.chars().count() > 2000 {
        errors.push("Opis: najwyżej 2000 znaków.".into());
    }
    if !CATEGORIES.contains(&input.category.as_str()) {
        errors.push(format!("Nieznana kategoria: {}.", input.category));
    }
    if !(0..=50).contains(&input.score_weight) {
        errors.push("Waga priorytetu: 0–50.".into());
    }
    if !matches!(input.rule.operator.as_str(), "and" | "or") {
        errors.push("Operator: and lub or.".into());
    }
    let n = input.rule.conditions.len();
    if n == 0 || n > MAX_CONDITIONS {
        errors.push(format!("Reguła musi mieć od 1 do {MAX_CONDITIONS} warunków."));
    }
    let mut out = Vec::new();
    for (i, c) in input.rule.conditions.iter().enumerate() {
        let at = format!("Warunek {}", i + 1);
        match c.kind.as_str() {
            "header" | "cookie" if c.name.as_deref().is_none_or(|n| n.trim().is_empty()) => {
                errors.push(format!("{at}: podaj nazwę nagłówka/ciasteczka."))
            }
            "header" | "cookie" | "favicon_hash" | "title" | "version" | "status" | "html" => {}
            // A safe probe: one GET of this path on web services the scan found (no login,
            // no body, no query, redirects not followed). `op` then tests the page it returns.
            "path" => {
                if !c.path.as_deref().is_some_and(valid_probe_path) {
                    errors.push(format!(
                        "{at}: ścieżka musi zaczynać się od „/”, mieć najwyżej 200 znaków, bez spacji, „..”, „?”, „#”, „@” i „\\”."
                    ));
                }
                if c.expect_status.is_some_and(|st| !(100..=599).contains(&st)) {
                    errors.push(format!("{at}: oczekiwany kod HTTP 100–599."));
                }
            }
            other => errors.push(format!("{at}: nieznany typ warunku „{other}”.")),
        }
        if !matches!(c.op.as_str(), "exists" | "equals" | "contains" | "regex") {
            errors.push(format!("{at}: operator exists, equals, contains lub regex."));
        }
        if c.op != "exists" && c.value.as_deref().is_none_or(str::is_empty) {
            errors.push(format!("{at}: podaj wartość."));
        }
        if c.value.as_deref().is_some_and(|v| v.len() > MAX_PATTERN) {
            errors.push(format!("{at}: wartość dłuższa niż {MAX_PATTERN} znaków."));
        }
        let re = if c.op == "regex" {
            match build_regex(c.value.as_deref().unwrap_or_default()) {
                Ok(r) => Some(r),
                Err(e) => {
                    errors.push(format!("{at}: {e}"));
                    None
                }
            }
        } else {
            None
        };
        let extract = match c.extract.as_deref().filter(|e| !e.is_empty()) {
            Some(p) => match build_regex(p) {
                Ok(r) if r.captures_len() >= 2 => Some(r),
                Ok(_) => {
                    errors.push(format!("{at}: wyrażenie „extract” musi mieć grupę przechwytującą."));
                    None
                }
                Err(e) => {
                    errors.push(format!("{at}: {e}"));
                    None
                }
            },
            None => None,
        };
        out.push(Compiled { cond: c.clone(), re, extract });
    }
    if errors.is_empty() { Ok((out, warnings)) } else { Err(errors) }
}

/// A path a "path" condition may probe: absolute, short, printable ASCII, no traversal, query,
/// fragment, credentials or backslashes — a plain GET of a fixed resource.
pub fn valid_probe_path(p: &str) -> bool {
    let p = p.trim();
    p.starts_with('/')
        && p.len() <= 200
        && p.bytes().all(|b| b.is_ascii_graphic())
        && !p.contains("..")
        && !p.contains(['?', '#', '@', '\\'])
}

/// Paths of the "path" conditions of enabled signatures (what the scanner will probe), at most
/// `MAX_PROBE_PATHS` per run so a signature set cannot turn into a directory scan.
pub async fn probe_paths(db: &sqlx::PgPool) -> sqlx::Result<Vec<String>> {
    let mut paths: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT trim(c->>'path') FROM signatures s, jsonb_array_elements(s.rule->'conditions') c
         WHERE s.enabled AND c->>'type' = 'path' AND c->>'path' IS NOT NULL",
    )
    .fetch_all(db)
    .await?;
    paths.retain(|p| valid_probe_path(p));
    paths.sort();
    paths.truncate(MAX_PROBE_PATHS);
    Ok(paths)
}

/// Upper bound of distinct probe paths per run.
pub const MAX_PROBE_PATHS: usize = 16;

/// Result of one GET probe of a path (from `http_probes`).
#[derive(Debug, Clone, Default)]
pub struct Probe {
    pub path: String,
    pub status: Option<i32>,
    pub title: Option<String>,
    pub body: Option<String>,
}

// ---------- evidence and matching ----------

/// What a signature can look at: one HTTP response (or a bare service).
#[derive(Default, Debug)]
pub struct Subject {
    pub status: Option<i32>,
    pub title: Option<String>,
    /// (lower-case name with `-`, value)
    pub headers: Vec<(String, String)>,
    /// (name, value) from Set-Cookie.
    pub cookies: Vec<(String, String)>,
    pub favicon: Option<String>,
    /// Version strings: service product + version, technologies, Server header.
    pub versions: Vec<String>,
    pub body: Option<String>,
    /// GET probes of signature paths on this service.
    pub probes: Vec<Probe>,
}

fn clip(s: &str) -> &str {
    match s.char_indices().nth(MAX_VALUE) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

fn norm_name(n: &str) -> String {
    n.trim().to_lowercase().replace('_', "-")
}

/// Does `value` satisfy the operator? Returns the matched text as evidence.
fn test_op(c: &Compiled, value: &str) -> Option<String> {
    let v = clip(value);
    let want = c.cond.value.as_deref().unwrap_or_default();
    let hit = match c.cond.op.as_str() {
        "exists" => true,
        "equals" => v.eq_ignore_ascii_case(want),
        "contains" => v.to_lowercase().contains(&want.to_lowercase()),
        "regex" => c.re.as_ref().is_some_and(|r| r.is_match(v)),
        _ => false,
    };
    hit.then(|| v.chars().take(200).collect())
}

/// One condition against a subject: (matched, evidence, extracted version).
fn eval_condition(c: &Compiled, s: &Subject) -> (bool, Option<String>, Option<String>) {
    let label = |k: &str, v: &str| format!("{k}: {v}");
    let mut candidates: Vec<(String, String)> = Vec::new();
    match c.cond.kind.as_str() {
        "header" => {
            let n = norm_name(c.cond.name.as_deref().unwrap_or_default());
            candidates.extend(s.headers.iter().filter(|(h, _)| *h == n).map(|(h, v)| (label(h, v), v.clone())));
        }
        "cookie" => {
            let n = c.cond.name.as_deref().unwrap_or_default().trim().to_lowercase();
            candidates.extend(
                s.cookies.iter().filter(|(k, _)| k.to_lowercase() == n).map(|(k, v)| (format!("cookie {k}"), v.clone())),
            );
        }
        "favicon_hash" => candidates.extend(s.favicon.iter().map(|f| (label("favicon", f), f.clone()))),
        "title" => candidates.extend(s.title.iter().map(|t| (label("title", t), t.clone()))),
        "status" => candidates.extend(s.status.map(|st| (label("status", &st.to_string()), st.to_string()))),
        "version" => candidates.extend(s.versions.iter().map(|v| (v.clone(), v.clone()))),
        "html" => candidates.extend(s.body.iter().map(|b| ("html".to_string(), b.clone()))),
        "path" => {
            let want = c.cond.path.as_deref().unwrap_or_default().trim();
            let Some(p) = s.probes.iter().find(|p| p.path == want) else { return (false, None, None) };
            let status_ok = match c.cond.expect_status {
                Some(e) => p.status == Some(e),
                None => p.status.is_some_and(|st| (200..300).contains(&st)),
            };
            if !status_ok {
                return (false, None, None);
            }
            let ev = format!("GET {} → HTTP {}", p.path, p.status.unwrap_or_default());
            let extract = |v: &str| c.extract.as_ref().and_then(|r| r.captures(clip(v))).and_then(|m| m.get(1)).map(|m| m.as_str().to_string());
            if c.cond.op == "exists" {
                return (true, Some(ev), p.body.as_deref().and_then(extract));
            }
            for value in [p.body.as_deref(), p.title.as_deref()].into_iter().flatten() {
                if let Some(hit) = test_op(c, value) {
                    return (true, Some(format!("{ev}: {}", hit.chars().take(160).collect::<String>())), extract(value));
                }
            }
            return (false, None, None);
        }
        _ => {}
    }
    for (ev, value) in &candidates {
        if test_op(c, value).is_some() {
            let extracted = c
                .extract
                .as_ref()
                .and_then(|r| r.captures(clip(value)))
                .and_then(|cap| cap.get(1))
                .map(|m| m.as_str().to_string());
            // A version condition with `extract` only matches when something was extracted.
            if c.cond.kind == "version" && c.extract.is_some() && extracted.is_none() {
                continue;
            }
            return (true, Some(ev.chars().take(240).collect()), extracted);
        }
    }
    (false, None, None)
}

pub struct Evaluation {
    pub matched: bool,
    pub conditions: Vec<(bool, Option<String>)>,
    pub version: Option<String>,
}

fn evaluate(operator: &str, compiled: &[Compiled], s: &Subject) -> Evaluation {
    let mut version = None;
    let conditions: Vec<(bool, Option<String>)> = compiled
        .iter()
        .map(|c| {
            let (m, ev, ex) = eval_condition(c, s);
            if version.is_none() {
                version = ex;
            }
            (m, ev)
        })
        .collect();
    let matched = if operator == "or" { conditions.iter().any(|c| c.0) } else { conditions.iter().all(|c| c.0) };
    Evaluation { matched, conditions, version }
}

/// Subject from stored (decrypted) evidence.
fn subject_from(
    status: Option<i32>,
    title: Option<String>,
    headers: Option<Value>,
    cookies: Option<Value>,
    favicon: Option<String>,
    mut versions: Vec<String>,
) -> Subject {
    let mut hs = Vec::new();
    if let Some(Value::Object(map)) = headers {
        for (k, v) in map {
            let name = norm_name(&k);
            match v {
                Value::String(s) => hs.push((name, s)),
                Value::Array(a) => hs.extend(a.into_iter().filter_map(|x| x.as_str().map(|s| (name.clone(), s.to_string())))),
                other => hs.push((name, other.to_string())),
            }
        }
    }
    let mut cs = Vec::new();
    if let Some(Value::Array(list)) = cookies {
        for c in list.iter().filter_map(Value::as_str) {
            if let Some((k, rest)) = c.split_once('=') {
                cs.push((k.trim().to_string(), rest.split(';').next().unwrap_or_default().trim().to_string()));
            }
        }
    }
    if let Some((_, server)) = hs.iter().find(|(h, _)| h == "server") {
        versions.push(server.clone());
    }
    Subject { status, title, headers: hs, cookies: cs, favicon, versions, body: None, probes: Vec::new() }
}

fn subject_from_raw(raw: &RawResponse) -> Subject {
    let mut headers = serde_json::Map::new();
    let mut cookies = Vec::new();
    for line in raw.headers.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if k.eq_ignore_ascii_case("set-cookie") {
                cookies.push(Value::String(v.to_string()));
            } else {
                headers.insert(k.to_lowercase(), Value::String(v.to_string()));
            }
        }
    }
    let title = Regex::new(r"(?is)<title[^>]*>(.*?)</title>").ok().and_then(|r| r.captures(clip(&raw.body))).map(|c| c[1].trim().to_string());
    let mut s = subject_from(
        Some(raw.status_code),
        title,
        Some(Value::Object(headers)),
        Some(Value::Array(cookies)),
        raw.favicon_hash.map(|f| f.to_string()),
        Vec::new(),
    );
    s.body = Some(raw.body.clone());
    s
}

// ---------- storage ----------

#[derive(sqlx::FromRow)]
struct SigRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    category: String,
    technology: Option<String>,
    score_weight: i32,
    enabled: bool,
    builtin: bool,
    rule: Value,
    tags: Vec<String>,
    author: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i32,
    matches_last_scan: i64,
}

const SIG_SELECT: &str = "WITH latest AS (SELECT DISTINCT ON (scan_id) id FROM scan_runs
        WHERE status IN ('done', 'partial') ORDER BY scan_id, started_at DESC)
    SELECT s.id, s.name, s.description, s.category, s.technology, s.score_weight, s.enabled, s.builtin, s.rule,
           s.tags, u.username AS author, s.created_at, s.updated_at, s.version,
           (SELECT count(*) FROM signature_hits h JOIN latest l ON l.id = h.run_id WHERE h.signature_id = s.id) AS matches_last_scan
    FROM signatures s LEFT JOIN users u ON u.id = s.created_by";

fn sig_json(r: &SigRow) -> Value {
    json!({
        "id": r.id, "name": r.name, "description": r.description.clone().unwrap_or_default(),
        "category": r.category, "technology": r.technology, "severity": "info", "score_weight": r.score_weight,
        "enabled": r.enabled, "source": if r.builtin { "builtin" } else { "custom" },
        "match": r.rule, "tags": r.tags,
        "author": r.author.clone().unwrap_or_else(|| if r.builtin { "ASI".into() } else { "—".into() }),
        "created_at": r.created_at, "updated_at": r.updated_at,
        "matches_last_scan": r.matches_last_scan, "version": r.version,
    })
}

/// A stored, enabled signature ready to evaluate.
struct Active {
    id: Uuid,
    version: i32,
    operator: String,
    compiled: Vec<Compiled>,
}

#[derive(sqlx::FromRow)]
struct ActiveRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    category: String,
    technology: Option<String>,
    score_weight: i32,
    rule: Value,
    version: i32,
}

async fn load_active(db: &sqlx::PgPool) -> sqlx::Result<Vec<Active>> {
    let rows: Vec<ActiveRow> = sqlx::query_as(
        "SELECT id, name, description, category, technology, score_weight, rule, version FROM signatures WHERE enabled",
    )
    .fetch_all(db)
    .await?;
    let mut out = Vec::new();
    for ActiveRow { id, name, description, category, technology, score_weight, rule, version } in rows {
        let Ok(rule) = serde_json::from_value::<Match>(rule) else {
            tracing::warn!(%name, "stored signature has an invalid rule, skipped");
            continue;
        };
        let input = SignatureInput {
            name,
            description: description.unwrap_or_default(),
            category,
            technology,
            score_weight,
            enabled: true,
            rule,
            tags: vec![],
            version: None,
        };
        if let Ok((compiled, _)) = compile(&input) {
            out.push(Active { id, version, operator: input.rule.operator, compiled });
        }
    }
    Ok(out)
}

#[derive(sqlx::FromRow)]
struct EvidenceRow {
    service_id: Uuid,
    url: Option<String>,
    status_code: Option<i32>,
    title: Option<String>,
    favicon_hash: Option<String>,
    technologies: Option<Vec<String>>,
    product: Option<String>,
    version: Option<String>,
    headers: Option<Value>,
    cookies: Option<Value>,
    body: Option<String>,
}

/// Probes of a run (or of one service), by service.
async fn load_probes(db: &sqlx::PgPool, key: &str, run: Option<Uuid>, service: Option<Uuid>) -> sqlx::Result<BTreeMap<Uuid, Vec<Probe>>> {
    type ProbeRow = (Uuid, String, Option<i32>, Option<String>, Option<String>);
    let rows: Vec<ProbeRow> = sqlx::query_as(
        "SELECT service_id, path, status_code, title, pgp_sym_decrypt(body_enc, $3) FROM http_probes
         WHERE ($1::uuid IS NULL OR run_id = $1) AND ($2::uuid IS NULL OR service_id = $2)",
    )
    .bind(run)
    .bind(service)
    .bind(key)
    .fetch_all(db)
    .await?;
    let mut out: BTreeMap<Uuid, Vec<Probe>> = BTreeMap::new();
    for (sid, path, status, title, body) in rows {
        out.entry(sid).or_default().push(Probe { path, status, title, body });
    }
    Ok(out)
}

/// Evaluate all enabled signatures on one run and replace its hits.
pub async fn evaluate_run(db: &sqlx::PgPool, key: &str, run_id: Uuid) -> sqlx::Result<usize> {
    let sigs = load_active(db).await?;
    let rows = sqlx::query_as::<_, EvidenceRow>(
        "SELECT s.id AS service_id, f.url, f.status_code, f.title, f.favicon_hash, f.technologies, s.product, s.version,
                pgp_sym_decrypt(f.headers_enc, $2)::jsonb AS headers, pgp_sym_decrypt(f.cookies_enc, $2)::jsonb AS cookies,
                pgp_sym_decrypt(f.body_enc, $2) AS body
         FROM hosts h JOIN services s ON s.host_id = h.id LEFT JOIN http_findings f ON f.service_id = s.id
         WHERE h.run_id = $1",
    )
    .bind(run_id)
    .bind(key)
    .fetch_all(db)
    .await?;
    let mut probes = load_probes(db, key, Some(run_id), None).await?;
    struct Acc {
        url: Option<String>,
        version: Option<String>,
        sig_version: i32,
        evidence: Vec<String>,
    }
    let mut hits: BTreeMap<(Uuid, Uuid), Acc> = BTreeMap::new();
    for r in rows {
        let mut versions: Vec<String> = r.technologies.clone().unwrap_or_default();
        let pv = [r.product.as_deref(), r.version.as_deref()].into_iter().flatten().collect::<Vec<_>>().join(" ");
        if !pv.is_empty() {
            versions.insert(0, pv);
        }
        let mut subject = subject_from(r.status_code, r.title.clone(), r.headers.clone(), r.cookies.clone(), r.favicon_hash.clone(), versions);
        subject.body = r.body.clone();
        subject.probes = probes.remove(&r.service_id).unwrap_or_default();
        for sig in &sigs {
            let ev = evaluate(&sig.operator, &sig.compiled, &subject);
            if ev.matched {
                let evidence: Vec<String> = ev.conditions.into_iter().filter_map(|c| c.1).collect();
                hits.entry((sig.id, r.service_id))
                    .or_insert(Acc { url: r.url.clone(), version: ev.version, sig_version: sig.version, evidence });
            }
        }
    }
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM signature_hits WHERE run_id = $1").bind(run_id).execute(&mut *tx).await?;
    for ((sig, service), Acc { url, version, sig_version, evidence }) in &hits {
        sqlx::query(
            "INSERT INTO signature_hits (signature_id, service_id, run_id, url, extracted_version, signature_version, evidence_enc)
             VALUES ($1, $2, $3, $4, $5, $6, pgp_sym_encrypt($7, $8))
             ON CONFLICT (signature_id, service_id) DO UPDATE SET url = EXCLUDED.url,
                 extracted_version = EXCLUDED.extracted_version, signature_version = EXCLUDED.signature_version,
                 evidence_enc = EXCLUDED.evidence_enc, matched_at = now()",
        )
        .bind(sig)
        .bind(service)
        .bind(run_id)
        .bind(url)
        .bind(version)
        .bind(sig_version)
        .bind(serde_json::to_string(evidence).unwrap_or_default())
        .bind(key)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(hits.len())
}

/// Re-evaluate the latest finished run of every scan (after a signature changed).
pub async fn reevaluate_latest(db: &sqlx::PgPool, key: &str) -> sqlx::Result<()> {
    let runs: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT ON (scan_id) id FROM scan_runs WHERE status IN ('done', 'partial') ORDER BY scan_id, started_at DESC",
    )
    .fetch_all(db)
    .await?;
    for r in runs {
        evaluate_run(db, key, r).await?;
    }
    Ok(())
}

/// Built-in signatures (`core/signatures/builtin.json`), upserted at startup by name; a
/// higher `version` in the file updates the rule, the admin's enabled flag is kept.
pub async fn seed_builtin(db: &sqlx::PgPool) -> anyhow::Result<usize> {
    let list: Vec<SignatureInput> = serde_json::from_str(include_str!("../signatures/builtin.json"))?;
    for s in &list {
        if let Err(e) = compile(s) {
            anyhow::bail!("built-in signature {:?} is invalid: {}", s.name, e.join("; "));
        }
        sqlx::query(
            "INSERT INTO signatures (name, description, kind, rule, enabled, category, technology, score_weight, tags, version, builtin)
             VALUES ($1, $2, 'builtin', $3, $4, $5, $6, $7, $8, $9, true)
             ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, rule = EXCLUDED.rule,
                 category = EXCLUDED.category, technology = EXCLUDED.technology, score_weight = EXCLUDED.score_weight,
                 tags = EXCLUDED.tags, version = EXCLUDED.version, builtin = true, updated_at = now()
             WHERE signatures.builtin AND signatures.version < EXCLUDED.version",
        )
        .bind(&s.name)
        .bind(&s.description)
        .bind(serde_json::to_value(&s.rule)?)
        .bind(s.enabled)
        .bind(&s.category)
        .bind(&s.technology)
        .bind(s.score_weight)
        .bind(&s.tags)
        .bind(s.version.unwrap_or(1))
        .execute(db)
        .await?;
    }
    Ok(list.len())
}

/// A signature hit of a finished run, for derived findings (evidence loaded separately,
/// only for the observations that are shown: `hit_evidence`).
pub struct Hit {
    pub service_id: Uuid,
    pub signature_id: Uuid,
    pub name: String,
    pub category: String,
    pub technology: Option<String>,
    pub score_weight: i32,
    pub url: Option<String>,
    pub version: Option<String>,
}

/// Hits of enabled signatures in every finished run.
pub async fn finished_hits(db: &sqlx::PgPool) -> sqlx::Result<Vec<Hit>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        service_id: Uuid,
        signature_id: Uuid,
        name: String,
        category: String,
        technology: Option<String>,
        score_weight: i32,
        url: Option<String>,
        version: Option<String>,
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT h.service_id, s.id AS signature_id, s.name, s.category, s.technology, s.score_weight, h.url,
                h.extracted_version AS version
         FROM signature_hits h JOIN scan_runs r ON r.id = h.run_id JOIN signatures s ON s.id = h.signature_id
         WHERE s.enabled AND r.status IN ('done', 'partial')",
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|Row { service_id, signature_id, name, category, technology, score_weight, url, version }| Hit {
            service_id,
            signature_id,
            name,
            category,
            technology,
            score_weight,
            url,
            version,
        })
        .collect())
}

/// Decrypted evidence of the given (signature, service) hits.
pub async fn hit_evidence(db: &sqlx::PgPool, key: &str, hits: &[(Uuid, Uuid)]) -> sqlx::Result<HashMap<(Uuid, Uuid), Vec<String>>> {
    let (sigs, services): (Vec<Uuid>, Vec<Uuid>) = hits.iter().copied().unzip();
    let rows: Vec<(Uuid, Uuid, Option<String>)> = sqlx::query_as(
        "SELECT h.signature_id, h.service_id, pgp_sym_decrypt(h.evidence_enc, $1)
         FROM signature_hits h JOIN UNNEST($2::uuid[], $3::uuid[]) AS w(sig, svc) ON w.sig = h.signature_id AND w.svc = h.service_id",
    )
    .bind(key)
    .bind(&sigs)
    .bind(&services)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(sig, svc, ev)| ((sig, svc), ev.and_then(|e| serde_json::from_str(&e).ok()).unwrap_or_default()))
        .collect())
}

// ---------- /api/v1/signatures ----------

#[derive(Deserialize)]
pub struct ListQuery {
    q: Option<String>,
    category: Option<String>,
    source: Option<String>,
}

/// `GET /api/v1/signatures`
pub async fn list(State(s): State<AppState>, Query(q): Query<ListQuery>) -> Result<Json<Vec<Value>>, ApiError> {
    let rows = sqlx::query_as::<_, SigRow>(sqlx::AssertSqlSafe(format!("{SIG_SELECT} ORDER BY s.builtin DESC, s.name")))
        .fetch_all(&s.db)
        .await
        .map_err(fail)?;
    let needle = q.q.as_deref().map(str::trim).filter(|v| !v.is_empty()).map(str::to_lowercase);
    Ok(Json(
        rows.iter()
            .filter(|r| needle.as_ref().is_none_or(|n| r.name.to_lowercase().contains(n) || r.technology.as_deref().is_some_and(|t| t.to_lowercase().contains(n))))
            .filter(|r| q.category.as_deref().filter(|c| !c.is_empty()).is_none_or(|c| r.category == c))
            .filter(|r| q.source.as_deref().filter(|c| !c.is_empty()).is_none_or(|c| (c == "builtin") == r.builtin))
            .map(sig_json)
            .collect(),
    ))
}

async fn one(db: &sqlx::PgPool, id: Uuid) -> Result<SigRow, ApiError> {
    sqlx::query_as::<_, SigRow>(sqlx::AssertSqlSafe(format!("{SIG_SELECT} WHERE s.id = $1")))
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(fail)?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "Nie znaleziono sygnatury."))
}

/// `GET /api/v1/signatures/{id}`
pub async fn get(State(s): State<AppState>, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    Ok(Json(sig_json(&one(&s.db, id).await?)))
}

fn rejected(errors: Vec<String>) -> ApiError {
    let message = errors.join(" ");
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({ "error": { "code": "validation", "message": message, "details": errors }, "detail": message })),
    )
}

/// `POST /api/v1/signatures`
pub async fn create(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(b): Json<SignatureInput>,
) -> Result<(StatusCode, Extension<Note>, Json<Value>), ApiError> {
    compile(&b).map_err(rejected)?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO signatures (name, description, kind, rule, enabled, category, technology, score_weight, tags, created_by)
         VALUES ($1, $2, 'custom', $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (name) DO NOTHING RETURNING id",
    )
    .bind(b.name.trim())
    .bind(&b.description)
    .bind(serde_json::to_value(&b.rule).map_err(fail)?)
    .bind(b.enabled)
    .bind(&b.category)
    .bind(&b.technology)
    .bind(b.score_weight)
    .bind(&b.tags)
    .bind(user.id)
    .fetch_optional(&s.db)
    .await
    .map_err(fail)?
    .ok_or_else(|| err(StatusCode::CONFLICT, "conflict", "Sygnatura o tej nazwie już istnieje."))?;
    reevaluate_latest(&s.db, &s.config.data_key).await.map_err(fail)?;
    let note = Note::new("signature.create", "signature", id, json!({ "name": b.name.trim() }));
    Ok((StatusCode::CREATED, Extension(note), Json(sig_json(&one(&s.db, id).await?))))
}

/// `PATCH /api/v1/signatures/{id}` — partial input; the rule version goes up. Built-in
/// signatures can only be enabled or disabled.
pub async fn update(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    Json(patch): Json<serde_json::Map<String, Value>>,
) -> Result<(Extension<Note>, Json<Value>), ApiError> {
    let cur = one(&s.db, id).await?;
    if cur.builtin && patch.keys().any(|k| k != "enabled") {
        return Err(err(
            StatusCode::CONFLICT,
            "builtin",
            "Sygnatury wbudowanej nie można edytować — można ją wyłączyć albo skopiować jako własną.",
        ));
    }
    let mut merged = json!({
        "name": cur.name, "description": cur.description.clone().unwrap_or_default(), "category": cur.category,
        "technology": cur.technology, "score_weight": cur.score_weight, "enabled": cur.enabled, "match": cur.rule, "tags": cur.tags,
    });
    for (k, v) in &patch {
        merged[k] = v.clone();
    }
    let input: SignatureInput = serde_json::from_value(merged)
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, "validation", format!("Niepoprawne pola: {e}")))?;
    compile(&input).map_err(rejected)?;
    let bump = patch.keys().any(|k| k != "enabled");
    sqlx::query(
        "UPDATE signatures SET name = $2, description = $3, rule = $4, enabled = $5, category = $6, technology = $7,
             score_weight = $8, tags = $9, version = version + CASE WHEN $10 THEN 1 ELSE 0 END, updated_at = now()
         WHERE id = $1",
    )
    .bind(id)
    .bind(input.name.trim())
    .bind(&input.description)
    .bind(serde_json::to_value(&input.rule).map_err(fail)?)
    .bind(input.enabled)
    .bind(&input.category)
    .bind(&input.technology)
    .bind(input.score_weight)
    .bind(&input.tags)
    .bind(bump)
    .execute(&s.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => err(StatusCode::CONFLICT, "conflict", "Sygnatura o tej nazwie już istnieje."),
        e => fail(e),
    })?;
    reevaluate_latest(&s.db, &s.config.data_key).await.map_err(fail)?;
    let fields: Vec<&String> = patch.keys().collect();
    let note = Note::new("signature.update", "signature", id, json!({ "name": input.name, "fields": fields }));
    Ok((Extension(note), Json(sig_json(&one(&s.db, id).await?))))
}

/// `DELETE /api/v1/signatures/{id}` → 204 (built-in: 409, disable instead).
pub async fn remove(State(s): State<AppState>, Path(id): Path<Uuid>) -> Result<(StatusCode, Extension<Note>), ApiError> {
    let cur = one(&s.db, id).await?;
    if cur.builtin {
        return Err(err(StatusCode::CONFLICT, "builtin", "Sygnatury wbudowanej nie można usunąć — można ją wyłączyć."));
    }
    sqlx::query("DELETE FROM signatures WHERE id = $1").bind(id).execute(&s.db).await.map_err(fail)?;
    Ok((StatusCode::NO_CONTENT, Extension(Note::new("signature.delete", "signature", id, json!({ "name": cur.name })))))
}

#[derive(Deserialize)]
pub struct RawResponse {
    status_code: i32,
    #[serde(default)]
    headers: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    favicon_hash: Option<i64>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum TestTarget {
    Service { service_id: Uuid },
    Raw { raw: RawResponse },
}

#[derive(Deserialize)]
pub struct TestBody {
    signature: SignatureInput,
    target: TestTarget,
}

/// `POST /api/v1/signatures/test` — dry run on a stored service or a pasted response.
pub async fn test(State(s): State<AppState>, Json(b): Json<TestBody>) -> Result<Json<Value>, ApiError> {
    let (compiled, warnings) = match compile(&b.signature) {
        Ok(c) => c,
        Err(errors) => {
            return Ok(Json(json!({
                "matched": false, "conditions": [], "extracted_version": null,
                "safety": { "ok": false, "issues": errors }, "target_label": "",
            })))
        }
    };
    let is_raw = matches!(b.target, TestTarget::Raw { .. });
    let (subject, label) = match b.target {
        TestTarget::Raw { raw } => (subject_from_raw(&raw), format!("Surowa odpowiedź (HTTP {})", raw.status_code)),
        TestTarget::Service { service_id } => {
            let r = sqlx::query_as::<_, EvidenceRow>(
                "SELECT s.id AS service_id, f.url, f.status_code, f.title, f.favicon_hash, f.technologies, s.product, s.version,
                        pgp_sym_decrypt(f.headers_enc, $2)::jsonb AS headers, pgp_sym_decrypt(f.cookies_enc, $2)::jsonb AS cookies,
                        pgp_sym_decrypt(f.body_enc, $2) AS body
                 FROM services s LEFT JOIN http_findings f ON f.service_id = s.id WHERE s.id = $1 LIMIT 1",
            )
            .bind(service_id)
            .bind(&s.config.data_key)
            .fetch_optional(&s.db)
            .await
            .map_err(fail)?
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "Nie znaleziono usługi."))?;
            let label = r.url.clone().unwrap_or_else(|| format!("usługa {service_id}"));
            let mut versions = r.technologies.clone().unwrap_or_default();
            let pv = [r.product.as_deref(), r.version.as_deref()].into_iter().flatten().collect::<Vec<_>>().join(" ");
            if !pv.is_empty() {
                versions.insert(0, pv);
            }
            let mut subject = subject_from(r.status_code, r.title, r.headers, r.cookies, r.favicon_hash, versions);
            subject.body = r.body;
            subject.probes = load_probes(&s.db, &s.config.data_key, None, Some(service_id))
                .await
                .map_err(fail)?
                .remove(&service_id)
                .unwrap_or_default();
            (subject, label)
        }
    };
    let mut warnings = warnings;
    if is_raw && b.signature.rule.conditions.iter().any(|c| c.kind == "path") {
        warnings.push("Warunek „path” sprawdza wynik próby GET z ostatniego skanu — w teście na surowej odpowiedzi nie jest spełniony; wybierz usługę.".into());
    }
    let ev = evaluate(&b.signature.rule.operator, &compiled, &subject);
    Ok(Json(json!({
        "matched": ev.matched,
        "conditions": ev.conditions.iter().enumerate()
            .map(|(i, (m, e))| json!({ "index": i, "matched": m, "evidence": e })).collect::<Vec<_>>(),
        "extracted_version": ev.version,
        "safety": { "ok": true, "issues": warnings },
        "target_label": label,
    })))
}

#[derive(Deserialize)]
pub struct FormatQuery {
    format: Option<String>,
}

/// `GET /api/v1/signatures/export?format=json` (YAML is not supported: 422).
pub async fn export(State(s): State<AppState>, Query(q): Query<FormatQuery>) -> Result<Response, ApiError> {
    if q.format.as_deref() == Some("yaml") {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "validation", "Eksport YAML nie jest obsługiwany — wybierz JSON."));
    }
    let rows = sqlx::query_as::<_, SigRow>(sqlx::AssertSqlSafe(format!("{SIG_SELECT} WHERE NOT s.builtin ORDER BY s.name")))
        .fetch_all(&s.db)
        .await
        .map_err(fail)?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| json!({
            "name": r.name, "description": r.description.clone().unwrap_or_default(), "category": r.category,
            "technology": r.technology, "score_weight": r.score_weight, "enabled": r.enabled, "match": r.rule, "tags": r.tags,
        }))
        .collect();
    let body = serde_json::to_vec_pretty(&json!({ "format": "asi-signatures", "version": 1, "items": items })).map_err(fail)?;
    let note = Note { action: "signature.export", entity: "signature", entity_id: None, details: json!({ "count": items.len() }) };
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"asi-signatures.json\"".to_string()),
        ],
        Extension(note),
        body,
    )
        .into_response())
}

/// `POST /api/v1/signatures/import` (multipart `file`: JSON list or `{items: [...]}`).
pub async fn import(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    mut form: Multipart,
) -> Result<(Extension<Note>, Json<Value>), ApiError> {
    let mut bytes = None;
    while let Some(field) = form.next_field().await.map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, "validation", e.to_string()))? {
        if field.name() == Some("file") {
            bytes = Some(field.bytes().await.map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, "validation", e.to_string()))?);
        }
    }
    let bytes = bytes.ok_or_else(|| err(StatusCode::UNPROCESSABLE_ENTITY, "validation", "Brak pliku."))?;
    let v: Value = serde_json::from_slice(&bytes)
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, "validation", format!("Oczekiwano JSON: {e}")))?;
    let list = match v {
        Value::Array(a) => a,
        Value::Object(mut o) => o.remove("items").and_then(|i| i.as_array().cloned()).unwrap_or_default(),
        _ => vec![],
    };
    let (mut created, mut updated, mut errors) = (0, 0, Vec::new());
    for (i, item) in list.into_iter().take(500).enumerate() {
        let input: SignatureInput = match serde_json::from_value(item) {
            Ok(x) => x,
            Err(e) => {
                errors.push(format!("#{}: {e}", i + 1));
                continue;
            }
        };
        if let Err(e) = compile(&input) {
            errors.push(format!("#{} {}: {}", i + 1, input.name, e.join(" ")));
            continue;
        }
        let inserted: Option<bool> = sqlx::query_scalar(
            "INSERT INTO signatures (name, description, kind, rule, enabled, category, technology, score_weight, tags, created_by)
             VALUES ($1, $2, 'custom', $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, rule = EXCLUDED.rule,
                 category = EXCLUDED.category, technology = EXCLUDED.technology, score_weight = EXCLUDED.score_weight,
                 tags = EXCLUDED.tags, version = signatures.version + 1, updated_at = now()
             WHERE NOT signatures.builtin
             RETURNING (xmax = 0)",
        )
        .bind(input.name.trim())
        .bind(&input.description)
        .bind(serde_json::to_value(&input.rule).map_err(fail)?)
        .bind(input.enabled)
        .bind(&input.category)
        .bind(&input.technology)
        .bind(input.score_weight)
        .bind(&input.tags)
        .bind(user.id)
        .fetch_optional(&s.db)
        .await
        .map_err(fail)?;
        match inserted {
            Some(true) => created += 1,
            Some(false) => updated += 1,
            None => errors.push(format!("#{} {}: nazwa zajęta przez sygnaturę wbudowaną", i + 1, input.name)),
        }
    }
    reevaluate_latest(&s.db, &s.config.data_key).await.map_err(fail)?;
    let note = Note { action: "signature.import", entity: "signature", entity_id: None, details: json!({ "created": created, "updated": updated, "errors": errors.len() }) };
    Ok((Extension(note), Json(json!({ "created": created, "updated": updated, "errors": errors }))))
}

/// For tests and the tester: does a rule pass validation?
#[cfg(test)]
fn parse(v: Value) -> SignatureInput {
    serde_json::from_value(v).unwrap()
}


#[cfg(test)]
mod tests {
    use super::*;

    fn sig(conds: Value, op: &str) -> SignatureInput {
        parse(json!({ "name": "t", "category": "technology", "match": { "operator": op, "conditions": conds } }))
    }

    fn subject() -> Subject {
        subject_from(
            Some(200),
            Some("Grafana".into()),
            Some(json!({ "server": "nginx/1.27.5", "x_powered_by": "PHP/8.1" })),
            Some(json!(["grafana_session=abc; Path=/; HttpOnly"])),
            Some("-1234".into()),
            vec!["Apache Tomcat 9.0.80".into(), "Grafana:10.2".into()],
        )
    }

    #[test]
    fn matching() {
        let s = sig(json!([{ "type": "title", "op": "contains", "value": "grafana" },
                           { "type": "cookie", "name": "grafana_session", "op": "exists" }]), "and");
        let (c, _) = compile(&s).unwrap();
        let ev = evaluate("and", &c, &subject());
        assert!(ev.matched);
        assert_eq!(ev.conditions[1].1.as_deref(), Some("cookie grafana_session"));

        let s = sig(json!([{ "type": "header", "name": "X-Powered-By", "op": "regex", "value": "^php/8" }]), "and");
        assert!(evaluate("and", &compile(&s).unwrap().0, &subject()).matched, "header names normalised");

        let s = sig(json!([{ "type": "version", "op": "contains", "value": "tomcat", "extract": "Tomcat ([0-9.]+)" }]), "and");
        let ev = evaluate("and", &compile(&s).unwrap().0, &subject());
        assert_eq!(ev.version.as_deref(), Some("9.0.80"));

        let s = sig(json!([{ "type": "status", "op": "equals", "value": "404" },
                           { "type": "favicon_hash", "op": "equals", "value": "-1234" }]), "or");
        assert!(evaluate("or", &compile(&s).unwrap().0, &subject()).matched);
        let s = sig(json!([{ "type": "status", "op": "equals", "value": "404" }]), "and");
        assert!(!evaluate("and", &compile(&s).unwrap().0, &subject()).matched);
    }

    #[test]
    fn unsafe_or_invalid_rules_are_rejected() {
        // A path probe is allowed, but only a plain absolute path.
        assert!(compile(&sig(json!([{ "type": "path", "path": "/phpmyadmin/", "op": "exists" }]), "and")).is_ok());
        for bad in ["phpmyadmin", "/../etc/passwd", "/a?user=admin", "/a b", "/x@evil", "/a#b", r"/a\b"] {
            let p = sig(json!([{ "type": "path", "path": bad, "op": "exists" }]), "and");
            assert!(compile(&p).is_err(), "{bad} must be refused");
        }
        let status = sig(json!([{ "type": "path", "path": "/x", "op": "exists", "expect_status": 999 }]), "and");
        assert!(compile(&status).is_err());
        let huge = sig(json!([{ "type": "title", "op": "regex", "value": "a".repeat(600) }]), "and");
        assert!(compile(&huge).is_err());
        let bad = sig(json!([{ "type": "title", "op": "regex", "value": "(" }]), "and");
        assert!(compile(&bad).is_err());
        let many: Vec<Value> = (0..21).map(|_| json!({ "type": "title", "op": "exists" })).collect();
        assert!(compile(&sig(Value::Array(many), "and")).is_err());
        let no_group = sig(json!([{ "type": "version", "op": "exists", "extract": "Tomcat" }]), "and");
        assert!(compile(&no_group).is_err());
        assert!(serde_json::from_value::<SignatureInput>(json!({
            "name": "x", "category": "technology", "command": "rm -rf /",
            "match": { "operator": "and", "conditions": [] } })).is_err(), "unknown fields refused");
        // Catastrophic-backtracking patterns are linear in the regex crate.
        let redos = sig(json!([{ "type": "title", "op": "regex", "value": "(a+)+$" }]), "and");
        let (c, _) = compile(&redos).unwrap();
        let mut s = subject();
        s.title = Some(format!("{}!", "a".repeat(5000)));
        let t = std::time::Instant::now();
        let _ = evaluate("and", &c, &s);
        assert!(t.elapsed() < std::time::Duration::from_millis(200));
    }

    #[test]
    fn builtin_set_is_valid() {
        let list: Vec<SignatureInput> = serde_json::from_str(include_str!("../signatures/builtin.json")).unwrap();
        assert!(list.len() >= 15);
        for s in &list {
            compile(s).unwrap_or_else(|e| panic!("{}: {e:?}", s.name));
        }
    }

    #[test]
    fn raw_responses() {
        let raw = RawResponse {
            status_code: 200,
            headers: "Server: Apache-Coyote/1.1\nSet-Cookie: JSESSIONID=1; Path=/".into(),
            body: "<html><title>Apache Tomcat/9.0.80</title></html>".into(),
            favicon_hash: None,
        };
        let s = subject_from_raw(&raw);
        assert_eq!(s.title.as_deref(), Some("Apache Tomcat/9.0.80"));
        assert_eq!(s.cookies[0].0, "JSESSIONID");
        assert!(s.versions.iter().any(|v| v.contains("Coyote")));
    }

    #[test]
    fn path_probes_and_page_content() {
        let git = sig(json!([{ "type": "path", "path": "/.git/HEAD", "op": "contains", "value": "ref:" }]), "and");
        let (c, _) = compile(&git).unwrap();
        let mut s = subject();
        assert!(!evaluate("and", &c, &s).matched, "no probe, no match");
        s.probes.push(Probe { path: "/.git/HEAD".into(), status: Some(200), title: None, body: Some("ref: refs/heads/main
".into()) });
        let ev = evaluate("and", &c, &s);
        assert!(ev.matched);
        assert!(ev.conditions[0].1.as_deref().unwrap().starts_with("GET /.git/HEAD → HTTP 200"));
        s.probes[0].status = Some(404);
        assert!(!evaluate("and", &c, &s).matched, "2xx expected by default");
        let forbidden = sig(json!([{ "type": "path", "path": "/.git/HEAD", "op": "exists", "expect_status": 404 }]), "and");
        assert!(evaluate("and", &compile(&forbidden).unwrap().0, &s).matched, "explicit expected status");

        let footer = sig(json!([{ "type": "html", "op": "regex", "value": r"(?i)powered\s+by",
            "extract": r"(?i)powered\s+by\s+(?:<[^>]+>\s*)?([A-Za-z][\w.-]*(?:\s+|/)v?\d+(?:\.\d+)+)" }]), "and");
        s.body = Some("<html><footer>Powered by <a href=/>WordPress 6.4.2</a></footer></html>".into());
        let ev = evaluate("and", &compile(&footer).unwrap().0, &s);
        assert!(ev.matched);
        assert_eq!(ev.version.as_deref(), Some("WordPress 6.4.2"));
    }

    #[test]
    fn builtin_signatures_compile() {
        let list: Vec<SignatureInput> = serde_json::from_str(include_str!("../signatures/builtin.json")).unwrap();
        for s in &list {
            assert!(compile(s).is_ok(), "{}", s.name);
        }
        assert!(list.iter().any(|s| s.rule.conditions.iter().any(|c| c.kind == "path")));
    }
}
