//! `/api/v1` assets and changes: hosts and services of the current state (latest finished
//! run of every scan), manual overrides that survive rescans (requirement 14), host
//! history and instability, service groups, cookie reveal, run-to-run changes, and bulk
//! actions on findings.

use crate::{
    audit::Note,
    auth::CurrentUser,
    rbac::Action,
    v1::{self, clean_tags, err, fail, forbidden, invalid, missing, opt, paginated, text, V1, LATEST},
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use uuid::Uuid;

// ---------- loading ----------

#[derive(sqlx::FromRow, Clone)]
struct HostRow {
    id: Uuid,
    run_id: Uuid,
    scan_id: Uuid,
    ip: String,
    hostname: Option<String>,
    state: String,
    miss_count: i32,
    first_seen_at: DateTime<Utc>,
    seen_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Clone)]
struct ServiceRow {
    id: Uuid,
    host_id: Uuid,
    port: i32,
    protocol: String,
    service: Option<String>,
    product: Option<String>,
    version: Option<String>,
    confidence: f32,
}

#[derive(sqlx::FromRow, Clone)]
struct HttpRow {
    service_id: Uuid,
    url: String,
    status_code: Option<i32>,
    title: Option<String>,
    redirects: Option<Vec<String>>,
    technologies: Option<Vec<String>>,
    cms: Option<String>,
    favicon_hash: Option<String>,
    is_admin: bool,
    is_staging: bool,
    headers: Option<Value>,
    cookies: Option<Value>,
    tls: Option<Value>,
}

/// Override of one field: (value, scanner value, author, time).
type Overrides = HashMap<(String, String), BTreeMap<String, Value>>;

struct State_ {
    hosts: Vec<HostRow>,
    services: Vec<ServiceRow>,
    http: Vec<HttpRow>,
    /// (run, kind, entity) → change
    changes: HashMap<(Uuid, String, String), String>,
    overrides: Overrides,
    findings: Vec<v1::Finding>,
    criticality: Vec<(ipnet::IpNet, String, Option<String>, Vec<String>)>,
}

/// The current state: one row per address (the most recent scan that saw it).
async fn load(s: &AppState, evidence: bool, host_filter: Option<Uuid>) -> V1<State_> {
    let key = s.config.data_key.as_str();
    let hosts = sqlx::query_as::<_, HostRow>(sqlx::AssertSqlSafe(format!(
        "WITH latest AS ({LATEST})
         SELECT DISTINCT ON (h.address) h.id, h.run_id, l.scan_id, host(h.address) AS ip, h.hostname, h.state::text AS state,
                h.miss_count, h.first_seen_at, h.seen_at
         FROM latest l JOIN hosts h ON h.run_id = l.id
         WHERE $1::uuid IS NULL OR h.id = $1
         ORDER BY h.address, l.started_at DESC"
    )))
    .bind(host_filter)
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    let host_ids: Vec<Uuid> = hosts.iter().map(|h| h.id).collect();
    let services = sqlx::query_as::<_, ServiceRow>(
        "SELECT id, host_id, port, protocol, service, product, version, confidence FROM services WHERE host_id = ANY($1) ORDER BY port",
    )
    .bind(&host_ids)
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    let service_ids: Vec<Uuid> = services.iter().map(|x| x.id).collect();
    let http = sqlx::query_as::<_, HttpRow>(
        "SELECT service_id, url, status_code, title, redirects, technologies, cms, favicon_hash, is_admin, is_staging,
                CASE WHEN $3 THEN asi_decrypt(headers_enc, $2)::jsonb END AS headers,
                CASE WHEN $3 THEN asi_decrypt(cookies_enc, $2)::jsonb END AS cookies,
                CASE WHEN $3 THEN asi_decrypt(tls_enc, $2)::jsonb END AS tls
         FROM http_findings WHERE service_id = ANY($1)",
    )
    .bind(&service_ids)
    .bind(key)
    .bind(evidence)
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    let runs: Vec<Uuid> = hosts.iter().map(|h| h.run_id).collect::<BTreeSet<_>>().into_iter().collect();
    let changes = sqlx::query_as::<_, (Uuid, String, String, String)>(
        "SELECT run_b, kind, entity, change::text FROM diffs WHERE run_b = ANY($1)",
    )
    .bind(&runs)
    .fetch_all(&s.db)
    .await
    .map_err(fail)?
    .into_iter()
    .map(|(r, k, e, c)| ((r, k, e), c))
    .collect();
    let mut overrides: Overrides = HashMap::new();
    type Row = (String, String, String, Value, Option<Value>, Option<String>, DateTime<Utc>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT o.entity_kind, o.entity_key, o.field, o.value, o.scanner_value, COALESCE(u.display_name, u.username), o.updated_at
         FROM asset_overrides o LEFT JOIN users u ON u.id = o.updated_by",
    )
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    for (kind, key, field, value, scanner, by, at) in rows {
        overrides
            .entry((kind, key))
            .or_default()
            .insert(field, json!({ "value": value, "scanner_value": scanner, "by": by.unwrap_or_default(), "at": at }));
    }
    let findings = v1::load_findings(&s.db, key).await?;
    let criticality = sqlx::query_as::<_, (String, String, Option<String>, Vec<String>)>(
        "SELECT value, criticality, owner, tags FROM targets WHERE kind <> 'domain'",
    )
    .fetch_all(&s.db)
    .await
    .map_err(fail)?
    .into_iter()
    .filter_map(|(v, c, o, t)| {
        let net = v.parse::<ipnet::IpNet>().ok().or_else(|| v.parse::<std::net::IpAddr>().ok().map(ipnet::IpNet::from))?;
        Some((net, c, o, t))
    })
    .collect();
    Ok(State_ { hosts, services, http, changes, overrides, findings, criticality })
}

fn tech_names(http: &[&HttpRow]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in http.iter().flat_map(|h| h.technologies.iter().flatten()) {
        let n = t.split(':').next().unwrap_or(t).trim().to_string();
        if !n.is_empty() && !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

fn device_type(services: &[&ServiceRow], techs: &[String], http: &[&HttpRow]) -> &'static str {
    let ports: BTreeSet<i32> = services.iter().map(|s| s.port).collect();
    let hay = format!(
        "{} {}",
        techs.join(" ").to_lowercase(),
        http.iter().filter_map(|h| h.title.as_deref()).collect::<Vec<_>>().join(" ").to_lowercase()
    );
    if ports.contains(&9100) || ports.contains(&631) || hay.contains("printer") || hay.contains("laserjet") {
        "printer"
    } else if ports.contains(&554) || hay.contains("hikvision") || hay.contains("camera") || hay.contains("dahua") {
        "camera"
    } else if ports.contains(&623) || hay.contains("idrac") || hay.contains("ilo") {
        "bmc"
    } else if hay.contains("mikrotik") || hay.contains("routeros") || hay.contains("unifi") || ports.contains(&161) {
        "network"
    } else if ports.contains(&3389) && ports.len() <= 3 {
        "workstation"
    } else if !services.is_empty() {
        "server"
    } else {
        "unknown"
    }
}

impl State_ {
    fn services_of(&self, host: Uuid) -> Vec<&ServiceRow> {
        self.services.iter().filter(|s| s.host_id == host).collect()
    }
    fn http_of(&self, service: Uuid) -> Vec<&HttpRow> {
        self.http.iter().filter(|h| h.service_id == service).collect()
    }
    fn host_change(&self, h: &HostRow) -> String {
        match h.state.as_str() {
            "unstable" => return "unstable".into(),
            "inactive" => return "gone".into(),
            _ => {}
        }
        if let Some(c) = self.changes.get(&(h.run_id, "host".into(), h.ip.clone())) {
            return if c == "gone" { "gone".into() } else { c.clone() };
        }
        let prefix = format!("{}:", h.ip);
        let touched = self.changes.keys().any(|(r, k, e)| {
            *r == h.run_id && (e.starts_with(&prefix) || (k == "http" && e.contains(&format!("//{}", h.ip))))
        });
        if touched { "changed".into() } else { "unchanged".into() }
    }
    fn target_info(&self, ip: &str) -> (String, Option<String>, Vec<String>) {
        let Ok(addr) = ip.parse::<std::net::IpAddr>() else { return ("medium".into(), None, vec![]) };
        let rank = |c: &str| ["low", "medium", "high", "critical"].iter().position(|x| *x == c).unwrap_or(1);
        let matching: Vec<_> = self.criticality.iter().filter(|(n, ..)| n.contains(&addr)).collect();
        // The most specific target wins for owner/tags; criticality takes the maximum.
        let crit = matching.iter().map(|m| m.1.clone()).max_by_key(|c| rank(c)).unwrap_or_else(|| "medium".into());
        let specific = matching.iter().max_by_key(|m| m.0.prefix_len());
        (crit, specific.and_then(|m| m.2.clone()), specific.map(|m| m.3.clone()).unwrap_or_default())
    }
}

fn ov<'a>(o: Option<&'a BTreeMap<String, Value>>, field: &str) -> Option<&'a Value> {
    o.and_then(|m| m.get(field)).map(|v| &v["value"])
}

fn host_summary(st: &State_, h: &HostRow, pattern: &[bool]) -> Value {
    let services = st.services_of(h.id);
    let http: Vec<&HttpRow> = services.iter().flat_map(|s| st.http_of(s.id)).collect();
    let techs = tech_names(&http);
    let o = st.overrides.get(&("host".into(), h.ip.clone()));
    let (crit, owner, tags) = st.target_info(&h.ip);
    let mine: Vec<&v1::Finding> =
        st.findings.iter().filter(|f| f.ip == h.ip && f.status != "false_positive" && f.is_current()).collect();
    let score = mine.iter().map(|f| f.score_override.map_or(f.score, i32::from)).max().unwrap_or(0);
    let subnet = match h.ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => format!("{}.{}.{}.0/24", a.octets()[0], a.octets()[1], a.octets()[2]),
        _ => h.ip.clone(),
    };
    let availability = match h.state.as_str() {
        "active" => "active",
        "unstable" => "unstable",
        _ => "inactive",
    };
    json!({
        "id": h.id, "ip": h.ip,
        "hostnames": ov(o, "hostnames").cloned().unwrap_or_else(|| json!(h.hostname.iter().collect::<Vec<_>>())),
        "availability": availability, "change": st.host_change(h), "response_pattern": pattern,
        "miss_count": h.miss_count, "open_ports": services.iter().map(|s| s.port).collect::<Vec<_>>(),
        "services_count": services.len(), "technologies": techs,
        "device_type": ov(o, "device_type").cloned().unwrap_or_else(|| json!(device_type(&services, &techs, &http))),
        "subnet": subnet,
        "owner": ov(o, "owner").cloned().unwrap_or_else(|| json!(owner)),
        "criticality": ov(o, "criticality").cloned().unwrap_or_else(|| json!(crit)),
        "tags": ov(o, "tags").cloned().unwrap_or_else(|| json!(tags)),
        "score": score, "findings_count": mine.len(), "has_manual_overrides": o.is_some_and(|m| !m.is_empty()),
        "first_seen": h.first_seen_at, "last_seen": h.seen_at,
    })
}

/// Response pattern per address: answered (true) in each of the last 8 finished runs of its scan.
async fn patterns(db: &sqlx::PgPool, hosts: &[HostRow]) -> V1<HashMap<String, Vec<bool>>> {
    let scans: Vec<Uuid> = hosts.iter().map(|h| h.scan_id).collect::<BTreeSet<_>>().into_iter().collect();
    let rows: Vec<(Uuid, Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, scan_id, started_at FROM (
             SELECT id, scan_id, started_at, row_number() OVER (PARTITION BY scan_id ORDER BY started_at DESC) AS n
             FROM scan_runs WHERE status IN ('done', 'partial') AND scan_id = ANY($1)) x
         WHERE n <= 8 ORDER BY started_at",
    )
    .bind(&scans)
    .fetch_all(db)
    .await
    .map_err(fail)?;
    let run_ids: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
    let seen: BTreeSet<(Uuid, String)> = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT run_id, host(address) FROM hosts WHERE run_id = ANY($1) AND state = 'active'",
    )
    .bind(&run_ids)
    .fetch_all(db)
    .await
    .map_err(fail)?
    .into_iter()
    .collect();
    let mut out = HashMap::new();
    for h in hosts {
        let p: Vec<bool> = rows.iter().filter(|r| r.1 == h.scan_id).map(|r| seen.contains(&(r.0, h.ip.clone()))).collect();
        out.insert(h.ip.clone(), p);
    }
    Ok(out)
}

// ---------- hosts ----------

#[derive(Deserialize)]
pub struct HostsQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    q: Option<String>,
    availability: Option<String>,
    change: Option<String>,
    device_type: Option<String>,
    sort: Option<String>,
}

/// `GET /api/v1/hosts`
pub async fn list_hosts(State(s): State<AppState>, Extension(user): Extension<CurrentUser>, Query(q): Query<HostsQuery>) -> V1<Json<Value>> {
    let st = load(&s, user.can(Action::ReadEvidence), None).await?;
    let pats = patterns(&s.db, &st.hosts).await?;
    let mut items: Vec<Value> = st.hosts.iter().map(|h| host_summary(&st, h, pats.get(&h.ip).map(Vec::as_slice).unwrap_or(&[]))).collect();
    if let Some(n) = opt(&q.q).map(str::to_lowercase) {
        items.retain(|h| h.to_string().to_lowercase().contains(&n));
    }
    for (field, val) in [("availability", &q.availability), ("change", &q.change), ("device_type", &q.device_type)] {
        if let Some(v) = opt(val) {
            let wanted: Vec<&str> = v.split(',').collect();
            items.retain(|h| h[field].as_str().is_some_and(|x| wanted.contains(&x)));
        }
    }
    let (field, desc) = v1::sort_spec(opt(&q.sort), "-score");
    items.sort_by(|a, b| {
        let o = match field.as_str() {
            "ip" => ip_key(&a["ip"]).cmp(&ip_key(&b["ip"])),
            "last_seen" | "first_seen" => a[field.as_str()].as_str().cmp(&b[field.as_str()].as_str()),
            "services_count" | "findings_count" | "miss_count" | "score" => {
                a[field.as_str()].as_i64().cmp(&b[field.as_str()].as_i64())
            }
            other => a[other].to_string().cmp(&b[other].to_string()),
        };
        let o = if desc { o.reverse() } else { o };
        o.then_with(|| ip_key(&a["ip"]).cmp(&ip_key(&b["ip"])))
    });
    Ok(Json(paginated(items, q.page, q.page_size)))
}

fn ip_key(v: &Value) -> Option<std::net::IpAddr> {
    v.as_str().and_then(|s| s.parse().ok())
}

fn fingerprint(h: &HttpRow, evidence: bool) -> Value {
    let headers: Vec<Value> = match &h.headers {
        Some(Value::Object(m)) => m
            .iter()
            .filter(|(k, _)| k.as_str() != "set_cookie")
            .map(|(k, v)| {
                let name = k.replace('_', "-");
                let note = match name.as_str() {
                    "server" | "x-powered-by" | "x-aspnet-version" => Some("Ujawnia technologię lub wersję"),
                    "strict-transport-security" => Some("HSTS"),
                    "content-security-policy" => Some("CSP"),
                    _ => None,
                };
                json!({ "name": name, "value": v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()), "note": note })
            })
            .collect(),
        _ => vec![],
    };
    let cookies: Vec<Value> = match &h.cookies {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(|c| {
                let mut parts = c.split(';').map(str::trim);
                let (name, value) = parts.next().and_then(|p| p.split_once('=')).unwrap_or((c, ""));
                let attrs: Vec<String> = parts.map(str::to_lowercase).collect();
                let attr = |k: &str| attrs.iter().find_map(|a| a.strip_prefix(&format!("{k}=")).map(str::to_string));
                let same_site = attr("samesite").map(|v| match v.as_str() {
                    "strict" => "Strict",
                    "lax" => "Lax",
                    _ => "None",
                });
                json!({
                    "name": name, "value_masked": format!("{}••••", value.chars().take(2).collect::<String>()),
                    "domain": attr("domain"), "path": attr("path").unwrap_or_else(|| "/".into()),
                    "secure": attrs.iter().any(|a| a == "secure"), "http_only": attrs.iter().any(|a| a == "httponly"),
                    "same_site": same_site, "expires": null,
                    "note": if !attrs.iter().any(|a| a == "httponly") { Some("Brak HttpOnly") } else { None },
                })
            })
            .collect(),
        _ => vec![],
    };
    let tls = h.tls.as_ref().filter(|t| t.is_object()).map(|t| {
        let s = |k: &str| t.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let not_after = s("not_after");
        let days_left = DateTime::parse_from_rfc3339(&not_after).map(|d| (d.with_timezone(&Utc) - Utc::now()).num_days()).unwrap_or(0);
        json!({
            "version": s("tls_version"), "cipher": s("cipher"), "subject_cn": s("subject_cn"), "issuer": s("issuer_cn"),
            "san": t.get("subject_an").cloned().unwrap_or(json!([])), "not_before": s("not_before"), "not_after": not_after,
            "days_left": days_left, "self_signed": t.get("self_signed").and_then(Value::as_bool).unwrap_or(false),
            "expired": t.get("expired").and_then(Value::as_bool).unwrap_or(days_left < 0),
            "sha256": t.pointer("/fingerprint_hash/sha256").and_then(Value::as_str).unwrap_or_default(),
        })
    });
    let technologies: Vec<Value> = h
        .technologies
        .iter()
        .flatten()
        .map(|t| {
            let (name, version) = t.split_once(':').map_or((t.as_str(), None), |(n, v)| (n, Some(v)));
            json!({ "name": name, "version": version, "category": "other", "confidence": 0.9,
                    "sources": [{ "type": "header", "detail": "httpx -td" }] })
        })
        .collect();
    json!({
        "url": h.url, "status_code": h.status_code.unwrap_or(0), "title": h.title, "content_type": null,
        "content_length": null, "response_time_ms": 0,
        "headers": if evidence { headers } else { vec![] }, "cookies": if evidence { cookies } else { vec![] },
        "tls": if evidence { tls } else { None },
        "redirects": h.redirects.iter().flatten().map(|u| json!({ "url": u, "status_code": 302 })).collect::<Vec<_>>(),
        "favicon_hash": h.favicon_hash.as_deref().and_then(|f| f.parse::<i64>().ok()),
        "technologies": technologies,
        "environment": if h.is_staging { Some("staging") } else { None },
        "admin_panel": if h.is_admin { Some(json!({ "path": h.url, "title": h.title.clone().unwrap_or_default() })) } else { None },
        "body_excerpt": null, "redacted": !evidence,
        "cms": h.cms,
    })
}

fn service_json(st: &State_, h: &HostRow, s: &ServiceRow, evidence: bool) -> Value {
    let key = format!("{}:{}/{}", h.ip, s.port, s.protocol);
    let o = st.overrides.get(&("service".into(), key.clone()));
    let http = st.http_of(s.id);
    let change = st.changes.get(&(h.run_id, "service".into(), key.clone())).cloned().unwrap_or_else(|| "unchanged".into());
    json!({
        "id": s.id, "host_id": h.id, "ip": h.ip, "port": s.port, "protocol": s.protocol,
        "name": s.service.clone().unwrap_or_else(|| "unknown".into()),
        "product": ov(o, "product").cloned().unwrap_or_else(|| json!(s.product)),
        "version": ov(o, "version").cloned().unwrap_or_else(|| json!(s.version)),
        "confidence": s.confidence,
        "tls": s.port == 443 || s.port == 8443 || http.iter().any(|x| x.url.starts_with("https://")),
        "banner": null, "change": change,
        "http": http.first().map(|x| fingerprint(x, evidence)),
        "tags": ov(o, "tags").cloned().unwrap_or(json!([])),
        "notes": ov(o, "notes").cloned().unwrap_or(Value::Null),
        "manual_overrides": o.map(|m| json!(m)).unwrap_or(json!({})),
        "first_seen": h.first_seen_at, "last_seen": h.seen_at,
    })
}

async fn host_detail(s: &AppState, id: Uuid, evidence: bool) -> V1<Value> {
    let st = load(s, evidence, Some(id)).await?;
    let h = st.hosts.first().ok_or_else(missing)?;
    let pats = patterns(&s.db, &st.hosts).await?;
    let mut v = host_summary(&st, h, pats.get(&h.ip).map(Vec::as_slice).unwrap_or(&[]));
    let o = st.overrides.get(&("host".into(), h.ip.clone()));
    v["os_guess"] = Value::Null;
    v["notes"] = ov(o, "notes").cloned().unwrap_or(Value::Null);
    v["services"] = json!(st.services_of(h.id).iter().map(|x| service_json(&st, h, x, evidence)).collect::<Vec<_>>());
    v["manual_overrides"] = o.map(|m| json!(m)).unwrap_or(json!({}));
    Ok(v)
}

/// `GET /api/v1/hosts/{id}`
pub async fn get_host(State(s): State<AppState>, Extension(user): Extension<CurrentUser>, Path(id): Path<Uuid>) -> V1<Json<Value>> {
    Ok(Json(host_detail(&s, id, user.can(Action::ReadEvidence)).await?))
}

const HOST_FIELDS: [&str; 6] = ["owner", "criticality", "tags", "notes", "device_type", "hostnames"];
const SERVICE_FIELDS: [&str; 4] = ["product", "version", "tags", "notes"];

/// Validate one override value.
fn check_value(field: &str, v: &Value) -> V1<Value> {
    Ok(match field {
        "owner" => json!(text(v.as_str(), "owner", 200, false)?),
        "notes" => json!(text(v.as_str(), "notes", 10_000, true)?),
        "product" | "version" => json!(text(v.as_str(), field, 200, false)?),
        "criticality" => {
            let c = v.as_str().unwrap_or_default();
            if !["low", "medium", "high", "critical"].contains(&c) {
                return Err(invalid("Krytyczność: low, medium, high lub critical."));
            }
            json!(c)
        }
        "device_type" => {
            let d = v.as_str().unwrap_or_default();
            if !["server", "workstation", "printer", "camera", "network", "bmc", "storage", "iot", "unknown"].contains(&d) {
                return Err(invalid("Nieznany typ urządzenia."));
            }
            json!(d)
        }
        "tags" | "hostnames" => {
            let list: Vec<String> = serde_json::from_value(v.clone()).map_err(|_| invalid(format!("{field}: oczekiwano listy")))?;
            json!(clean_tags(&list)?)
        }
        _ => return Err(invalid(format!("Pole {field} nie jest edytowalne."))),
    })
}

async fn save_overrides(
    s: &AppState,
    kind: &str,
    key: &str,
    patch: &Value,
    allowed: &[&str],
    scanner: &Value,
    user: Uuid,
) -> V1<Vec<String>> {
    let obj = patch.as_object().ok_or_else(|| invalid("Oczekiwano obiektu JSON."))?;
    let mut changed = Vec::new();
    let mut tx = s.db.begin().await.map_err(fail)?;
    for (field, v) in obj {
        if !allowed.contains(&field.as_str()) {
            return Err(invalid(format!("Pole {field} nie jest edytowalne.")));
        }
        let value = check_value(field, v)?;
        sqlx::query(
            "INSERT INTO asset_overrides (entity_kind, entity_key, field, value, scanner_value, updated_by)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (entity_kind, entity_key, field) DO UPDATE SET value = EXCLUDED.value,
                 updated_by = EXCLUDED.updated_by, updated_at = now()",
        )
        .bind(kind)
        .bind(key)
        .bind(field)
        .bind(&value)
        .bind(scanner.get(field))
        .bind(user)
        .execute(&mut *tx)
        .await
        .map_err(fail)?;
        changed.push(field.clone());
    }
    tx.commit().await.map_err(fail)?;
    Ok(changed)
}

/// `PATCH /api/v1/hosts/{id}` — manual values that scanners never overwrite.
pub async fn update_host(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(patch): Json<Value>,
) -> V1<(Extension<Note>, Json<Value>)> {
    let evidence = user.can(Action::ReadEvidence);
    let current = host_detail(&s, id, evidence).await?;
    let ip = current["ip"].as_str().unwrap_or_default().to_string();
    let changed = save_overrides(&s, "host", &ip, &patch, &HOST_FIELDS, &current, user.id).await?;
    let note = Note::new("host.update", "host", &ip, json!({ "fields": changed }));
    Ok((Extension(note), Json(host_detail(&s, id, evidence).await?)))
}

/// `DELETE /api/v1/hosts/{id}/overrides/{field}` — back to the scanner's value.
pub async fn revert_host(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path((id, field)): Path<(Uuid, String)>,
) -> V1<(Extension<Note>, Json<Value>)> {
    let evidence = user.can(Action::ReadEvidence);
    let current = host_detail(&s, id, evidence).await?;
    let ip = current["ip"].as_str().unwrap_or_default().to_string();
    sqlx::query("DELETE FROM asset_overrides WHERE entity_kind = 'host' AND entity_key = $1 AND field = $2")
        .bind(&ip)
        .bind(&field)
        .execute(&s.db)
        .await
        .map_err(fail)?;
    let note = Note::new("host.revert", "host", &ip, json!({ "field": field }));
    Ok((Extension(note), Json(host_detail(&s, id, evidence).await?)))
}

/// `GET /api/v1/hosts/{id}/history` — every finished run of the scan that covered the host.
pub async fn host_history(State(s): State<AppState>, Path(id): Path<Uuid>) -> V1<Json<Vec<Value>>> {
    let (ip, scan): (String, Uuid) = sqlx::query_as(
        "SELECT host(h.address), r.scan_id FROM hosts h JOIN scan_runs r ON r.id = h.run_id WHERE h.id = $1",
    )
    .bind(id)
    .fetch_optional(&s.db)
    .await
    .map_err(fail)?
    .ok_or_else(missing)?;
    let numbers: HashMap<Uuid, i64> = sqlx::query_as::<_, (Uuid, i64)>("SELECT id, row_number() OVER (ORDER BY started_at) FROM scan_runs")
        .fetch_all(&s.db)
        .await
        .map_err(fail)?
        .into_iter()
        .collect();
    type RunObs = (Uuid, DateTime<Utc>, Option<String>, Option<Vec<i32>>);
    let runs: Vec<RunObs> = sqlx::query_as(
        "SELECT r.id, COALESCE(r.finished_at, r.started_at), h.state::text,
                (SELECT array_agg(sv.port ORDER BY sv.port) FROM services sv WHERE sv.host_id = h.id)
         FROM scan_runs r LEFT JOIN hosts h ON h.run_id = r.id AND host(h.address) = $2
         WHERE r.scan_id = $1 AND r.status IN ('done', 'partial') ORDER BY r.started_at DESC LIMIT 50",
    )
    .bind(scan)
    .bind(&ip)
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    let mut out = Vec::new();
    for (run, at, state, ports) in runs {
        type DiffObs = (String, String, Option<String>, Option<String>, Option<String>);
        let diffs: Vec<DiffObs> = sqlx::query_as(
            "SELECT entity, change::text, field, asi_decrypt(old_enc, $3), asi_decrypt(new_enc, $3)
             FROM diffs WHERE run_b = $1 AND (entity = $2 OR entity LIKE $2 || ':%' OR entity LIKE '%//' || $2 || '%')",
        )
        .bind(run)
        .bind(&ip)
        .bind(&s.config.data_key)
        .fetch_all(&s.db)
        .await
        .map_err(fail)?;
        out.push(json!({
            "scan_id": run, "scan_number": numbers.get(&run).copied().unwrap_or(0), "at": at,
            "responded": state.as_deref() == Some("active"), "open_ports": ports.unwrap_or_default(),
            "changes": diffs.into_iter().map(|(e, c, f, a, b)| json!({
                "field": f.clone().unwrap_or_else(|| c.clone()),
                "label": format!("{} {}", label_of(f.as_deref(), &c), if e == ip { String::new() } else { e.clone() }).trim().to_string(),
                "before": a, "after": b,
            })).collect::<Vec<_>>(),
        }));
    }
    Ok(Json(out))
}

fn label_of(field: Option<&str>, change: &str) -> String {
    match (field, change) {
        (None, "new") => "Nowy".into(),
        (None, "gone") => "Zniknął".into(),
        (None, _) => "Zmiana".into(),
        (Some("state"), _) => "Stan".into(),
        (Some("version"), _) => "Wersja".into(),
        (Some("product"), _) => "Produkt".into(),
        (Some("title"), _) => "Tytuł".into(),
        (Some("status"), _) => "Kod HTTP".into(),
        (Some("tech"), _) => "Technologie".into(),
        (Some("headers"), _) => "Nagłówki".into(),
        (Some("cookies"), _) => "Ciasteczka".into(),
        (Some(f), _) if f.starts_with("tls.") => format!("TLS {}", &f[4..]),
        (Some(f), _) => f.to_string(),
    }
}

/// `POST /api/v1/hosts/{id}/recheck` — a one-off quick scan of this address, now.
pub async fn recheck_host(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> V1<(Extension<Note>, Json<Value>)> {
    let ip: String = sqlx::query_scalar("SELECT host(address) FROM hosts WHERE id = $1")
        .bind(id)
        .fetch_optional(&s.db)
        .await
        .map_err(fail)?
        .ok_or_else(missing)?;
    let mut tx = s.db.begin().await.map_err(fail)?;
    let target: Uuid = sqlx::query_scalar(
        "INSERT INTO targets (kind, value, source) VALUES ('ip', $1, 'manual')
         ON CONFLICT (value) DO UPDATE SET value = EXCLUDED.value RETURNING id",
    )
    .bind(&ip)
    .fetch_one(&mut *tx)
    .await
    .map_err(fail)?;
    let scan: Uuid = sqlx::query_scalar(
        "INSERT INTO scans (name, enabled, rate_limit_pps, ports, batch_size, created_by, tags)
         SELECT $1, false, LEAST((p.config->>'rate_limit_rps')::int, 1000), '100', 1, $2, '{recheck}'
         FROM scan_profiles p WHERE p.builtin ORDER BY p.name DESC LIMIT 1 RETURNING id",
    )
    .bind(format!("Ponowny pomiar {ip}"))
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(fail)?;
    sqlx::query("INSERT INTO scan_targets (scan_id, target_id) VALUES ($1, $2)").bind(scan).bind(target).execute(&mut *tx).await.map_err(fail)?;
    sqlx::query("INSERT INTO scan_runs (scan_id, status, resume_at, tags) VALUES ($1, 'paused', now(), '{recheck}')")
        .bind(scan)
        .execute(&mut *tx)
        .await
        .map_err(fail)?;
    tx.commit().await.map_err(fail)?;
    Ok((Extension(Note::new("host.recheck", "host", &ip, json!({ "scan_id": scan }))), Json(json!({ "queued": true }))))
}

/// `GET /api/v1/hosts/unstable` — hosts with misses or flaps, or whose presence depends on the
/// time of day; response rate by hour. Measurements are every finished scanner run that
/// covered the address, whichever scan it belonged to (`presence::Presence`).
pub async fn unstable_hosts(State(s): State<AppState>) -> V1<Json<Vec<Value>>> {
    let rows: Vec<(Uuid, String, Option<String>, i32, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "WITH latest AS ({LATEST})
         SELECT DISTINCT ON (h.address) h.id, host(h.address), h.hostname, h.flaps, h.state::text
         FROM latest l JOIN hosts h ON h.run_id = l.id ORDER BY h.address, l.started_at DESC"
    )))
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    let presence = crate::presence::Presence::load(&s.db).await.map_err(fail)?;
    let mut out = Vec::new();
    for (id, ip, hostname, flaps, state) in rows {
        let samples = presence.samples(&ip, hostname.as_deref());
        let time_pattern = crate::presence::time_of_day_pattern(&samples);
        if flaps == 0 && state == "active" && time_pattern.is_none() {
            continue;
        }
        let mut by_hour = vec![Value::Null; 24];
        for hr in 0..24u8 {
            let xs: Vec<bool> = samples.iter().filter(|x| x.hour == hr).map(|x| x.present).collect();
            if !xs.is_empty() {
                by_hour[hr as usize] = json!(xs.iter().filter(|x| **x).count() as f64 / xs.len() as f64);
            }
        }
        let pattern: Vec<bool> = samples.iter().rev().take(12).rev().map(|x| x.present).collect();
        let rate = if samples.is_empty() { 0.0 } else { samples.iter().filter(|x| x.present).count() as f64 / samples.len() as f64 };
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM scans s JOIN scan_runs r ON r.scan_id = s.id
                 WHERE 'recheck' = ANY(s.tags) AND s.name = $1 AND r.status IN ('running', 'paused', 'queued'))",
        )
        .bind(format!("Ponowny pomiar {ip}"))
        .fetch_one(&s.db)
        .await
        .map_err(fail)?;
        out.push(json!({
            "host_id": id, "ip": ip, "hostname": hostname, "pattern": pattern, "response_rate": (rate * 100.0).round() / 100.0,
            "by_hour": by_hour, "last_recheck_at": null, "recheck_pending": pending, "time_pattern": time_pattern,
        }));
    }
    // Hosts with a time-of-day pattern first: they explain themselves.
    out.sort_by_key(|u| u["time_pattern"].is_null());
    Ok(Json(out))
}

// ---------- services ----------

#[derive(Deserialize)]
pub struct ServicesQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    q: Option<String>,
    port: Option<i32>,
    product: Option<String>,
    change: Option<String>,
    sort: Option<String>,
}

/// `GET /api/v1/services`
pub async fn list_services(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(q): Query<ServicesQuery>,
) -> V1<Json<Value>> {
    let st = load(&s, user.can(Action::ReadEvidence), None).await?;
    let by_id: HashMap<Uuid, &HostRow> = st.hosts.iter().map(|h| (h.id, h)).collect();
    let mut items: Vec<Value> = st
        .services
        .iter()
        .filter_map(|sv| {
            let h = by_id.get(&sv.host_id)?;
            let mut v = service_json(&st, h, sv, false);
            let http = st.http_of(sv.id);
            v["hostname"] = json!(h.hostname);
            v["title"] = json!(http.first().and_then(|x| x.title.clone()));
            v["technologies"] = json!(tech_names(&http));
            v["has_manual_overrides"] = json!(v["manual_overrides"].as_object().is_some_and(|m| !m.is_empty()));
            if let Some(o) = v.as_object_mut() {
                o.remove("http");
                o.remove("manual_overrides");
            }
            Some(v)
        })
        .collect();
    if let Some(n) = opt(&q.q).map(str::to_lowercase) {
        items.retain(|v| v.to_string().to_lowercase().contains(&n));
    }
    if let Some(p) = q.port {
        items.retain(|v| v["port"] == json!(p));
    }
    if let Some(p) = opt(&q.product).map(str::to_lowercase) {
        items.retain(|v| v["product"].as_str().is_some_and(|x| x.to_lowercase().contains(&p)));
    }
    if let Some(c) = opt(&q.change) {
        items.retain(|v| v["change"] == json!(c));
    }
    let (field, desc) = v1::sort_spec(opt(&q.sort), "ip");
    items.sort_by(|a, b| {
        let o = match field.as_str() {
            "port" | "confidence" => a[field.as_str()].as_f64().partial_cmp(&b[field.as_str()].as_f64()).unwrap_or(std::cmp::Ordering::Equal),
            "ip" => ip_key(&a["ip"]).cmp(&ip_key(&b["ip"])).then(a["port"].as_i64().cmp(&b["port"].as_i64())),
            other => a[other].to_string().cmp(&b[other].to_string()),
        };
        if desc { o.reverse() } else { o }
    });
    Ok(Json(paginated(items, q.page, q.page_size)))
}

async fn service_detail(s: &AppState, id: Uuid, evidence: bool) -> V1<Value> {
    let host: Uuid = sqlx::query_scalar("SELECT host_id FROM services WHERE id = $1")
        .bind(id)
        .fetch_optional(&s.db)
        .await
        .map_err(fail)?
        .ok_or_else(missing)?;
    let st = load(s, evidence, Some(host)).await?;
    let h = st.hosts.first().ok_or_else(missing)?;
    let sv = st.services.iter().find(|x| x.id == id).ok_or_else(missing)?;
    Ok(service_json(&st, h, sv, evidence))
}

/// `GET /api/v1/services/{id}`
pub async fn get_service(State(s): State<AppState>, Extension(user): Extension<CurrentUser>, Path(id): Path<Uuid>) -> V1<Json<Value>> {
    Ok(Json(service_detail(&s, id, user.can(Action::ReadEvidence)).await?))
}

/// `PATCH /api/v1/services/{id}` — product, version, tags, notes (kept across rescans).
pub async fn update_service(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(patch): Json<Value>,
) -> V1<(Extension<Note>, Json<Value>)> {
    let evidence = user.can(Action::ReadEvidence);
    let current = service_detail(&s, id, evidence).await?;
    let key = format!("{}:{}/{}", current["ip"].as_str().unwrap_or_default(), current["port"], current["protocol"].as_str().unwrap_or("tcp"));
    let changed = save_overrides(&s, "service", &key, &patch, &SERVICE_FIELDS, &current, user.id).await?;
    let note = Note::new("service.update", "service", &key, json!({ "fields": changed }));
    Ok((Extension(note), Json(service_detail(&s, id, evidence).await?)))
}

/// `POST /api/v1/services/{id}/cookies/{name}/reveal` — the full cookie value (audited).
pub async fn reveal_cookie(State(s): State<AppState>, Path((id, name)): Path<(Uuid, String)>) -> V1<(Extension<Note>, Json<Value>)> {
    let cookies: Vec<Option<Value>> = sqlx::query_scalar(
        "SELECT asi_decrypt(cookies_enc, $2)::jsonb FROM http_findings WHERE service_id = $1",
    )
    .bind(id)
    .bind(&s.config.data_key)
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    let value = cookies
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_array().cloned())
        .flatten()
        .filter_map(|c| c.as_str().map(str::to_string))
        .find_map(|c| {
            let first = c.split(';').next()?.trim().to_string();
            let (n, v) = first.split_once('=')?;
            (n.trim() == name).then(|| v.trim().to_string())
        })
        .ok_or_else(missing)?;
    let note = Note::new("service.reveal_cookie", "service", id, json!({ "cookie": name }));
    Ok((Extension(note), Json(json!({ "value": value }))))
}

#[derive(Deserialize)]
pub struct GroupsQuery {
    q: Option<String>,
}

/// `GET /api/v1/service-groups` — the same product across hosts, by version.
pub async fn service_groups(State(s): State<AppState>, Query(q): Query<GroupsQuery>) -> V1<Json<Vec<Value>>> {
    let st = load(&s, false, None).await?;
    let by_id: HashMap<Uuid, &HostRow> = st.hosts.iter().map(|h| (h.id, h)).collect();
    /// versions → count, ports, sample hosts
    type Group = (BTreeMap<Option<String>, usize>, BTreeSet<i32>, Vec<(Uuid, String)>);
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for sv in &st.services {
        let Some(h) = by_id.get(&sv.host_id) else { continue };
        let product = sv.product.clone().or_else(|| sv.service.clone()).unwrap_or_else(|| "nieznana usługa".into());
        let g = groups.entry(product).or_default();
        *g.0.entry(sv.version.clone()).or_default() += 1;
        g.1.insert(sv.port);
        if g.2.len() < 5 && !g.2.iter().any(|(_, ip)| *ip == h.ip) {
            g.2.push((h.id, h.ip.clone()));
        }
    }
    let needle = opt(&q.q).map(str::to_lowercase);
    Ok(Json(
        groups
            .into_iter()
            .filter(|(p, _)| needle.as_ref().is_none_or(|n| p.to_lowercase().contains(n)))
            .map(|(product, (versions, ports, sample))| {
                let count: usize = versions.values().sum();
                json!({
                    "key": product.to_lowercase().replace(' ', "-"), "label": product, "product": product,
                    "versions": versions.iter().map(|(v, c)| json!({ "version": v, "count": c })).collect::<Vec<_>>(),
                    "port_set": ports, "count": count,
                    "hosts_sample": sample.iter().map(|(id, ip)| json!({ "id": id, "ip": ip })).collect::<Vec<_>>(),
                    // Several versions of one product side by side: the older ones are worth a look.
                    "outdated": versions.len() > 1,
                })
            })
            .collect(),
    ))
}

// ---------- changes (diffs) ----------

#[derive(Deserialize)]
pub struct DiffsQuery {
    base: Option<Uuid>,
    head: Option<Uuid>,
    kind: Option<String>,
    entity: Option<String>,
    q: Option<String>,
    page: Option<usize>,
    page_size: Option<usize>,
}

/// `GET /api/v1/diffs?base=&head=&kind=` — changes between two runs (default: the latest
/// finished run against the previous one of its scan).
pub async fn diffs(State(s): State<AppState>, Extension(user): Extension<CurrentUser>, Query(q): Query<DiffsQuery>) -> V1<Json<Value>> {
    let key = s.config.data_key.as_str();
    let evidence = user.can(Action::ReadEvidence);
    let head = match q.head {
        Some(h) => h,
        None => sqlx::query_scalar(
            // The latest run that was compared with an earlier one (a first run has nothing to show).
            "SELECT id FROM scan_runs WHERE status IN ('done', 'partial') AND source = 'scanner'
             ORDER BY (stats->'diff'->>'against') IS NULL, started_at DESC LIMIT 1",
        )
        .fetch_optional(&s.db)
        .await
        .map_err(fail)?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "Brak zakończonych skanowań do porównania."))?,
    };
    let base = match q.base {
        Some(b) => Some(b),
        None => crate::history::previous_run(&s.db, head).await.map_err(fail)?,
    };
    let Some(base) = base else {
        return Err(err(StatusCode::NOT_FOUND, "not_found", "To pierwszy przebieg tego skanowania — nie ma z czym porównać."));
    };
    let (entries, _) = crate::history::compare(&s.db, base, head, key).await.map_err(|e| match e {
        sqlx::Error::RowNotFound => missing(),
        e => fail(e),
    })?;
    let runs = v1::load_runs(&s.db, &format!("WHERE id IN ('{base}', '{head}')"), 2).await?;
    let scan_ref = |id: Uuid| {
        runs.iter().find(|r| r.id == id).map(|r| {
            let v = v1::run_json(r);
            json!({ "id": v["id"], "number": v["number"], "name": v["name"], "started_at": v["started_at"], "finished_at": v["finished_at"], "status": v["status"] })
        })
    };
    let detected = runs.iter().find(|r| r.id == head).and_then(|r| r.finished_at).unwrap_or_else(Utc::now);
    let host_ids: HashMap<String, Uuid> = sqlx::query_as::<_, (String, Uuid, Option<String>)>(
        "SELECT host(address), id, hostname FROM hosts WHERE run_id = $1",
    )
    .bind(head)
    .fetch_all(&s.db)
    .await
    .map_err(fail)?
    .into_iter()
    .map(|(ip, id, _)| (ip, id))
    .collect();
    // Group the per-field entries into one change per entity.
    let mut grouped: BTreeMap<(String, String, String), Vec<&crate::diff::DiffEntry>> = BTreeMap::new();
    for e in &entries {
        let kind = serde_json::to_value(e.kind).unwrap_or_default().as_str().unwrap_or_default().to_string();
        let change = serde_json::to_value(e.change).unwrap_or_default().as_str().unwrap_or_default().to_string();
        grouped.entry((kind, e.entity.clone(), change)).or_default().push(e);
    }
    let mut items: Vec<Value> = Vec::new();
    for ((kind, entity, change), es) in grouped {
        let ip = match kind.as_str() {
            "http" => entity.split("://").nth(1).and_then(|r| r.split([':', '/']).next()).unwrap_or_default().to_string(),
            _ => entity.split([':', '/']).next().unwrap_or_default().to_string(),
        };
        let ip = if ip.contains('[') || entity.matches(':').count() > 2 { entity.rsplit_once(':').map_or(ip.clone(), |x| x.0.to_string()) } else { ip };
        let port: Option<i64> = match kind.as_str() {
            "service" => entity.rsplit_once(':').and_then(|(_, p)| p.split('/').next()).and_then(|p| p.parse().ok()),
            "http" => entity.split("://").nth(1).and_then(|r| r.split('/').next()).and_then(|hp| hp.rsplit_once(':')).and_then(|(_, p)| p.parse().ok()),
            _ => None,
        };
        let unstable = kind == "host" && es.iter().any(|e| e.new_value.as_deref() == Some("unstable"));
        let ckind = if unstable { "unstable" } else { change.as_str() };
        let fields: Vec<Value> = es
            .iter()
            .filter(|e| e.field.is_some())
            .map(|e| {
                let f = e.field.clone().unwrap_or_default();
                let hide = !evidence && (f == "headers" || f == "cookies" || f.starts_with("tls."));
                json!({
                    "field": f, "label": label_of(Some(&f), &change),
                    "before": if hide { None } else { e.old_value.clone() }, "after": if hide { None } else { e.new_value.clone() },
                })
            })
            .collect();
        let entity_kind = if es.iter().all(|e| e.field.as_deref().is_some_and(|f| f.starts_with("tls."))) && !fields.is_empty() {
            "tls"
        } else if es.iter().all(|e| e.field.as_deref() == Some("tech")) && !fields.is_empty() {
            "technology"
        } else {
            kind.as_str()
        };
        let what = match kind.as_str() {
            "host" => format!("host {ip}"),
            "service" => format!("usługa {entity}"),
            _ => entity.clone(),
        };
        let summary = match ckind {
            "new" => format!("Nowy: {what}"),
            "gone" => format!("Zniknął: {what}"),
            "unstable" => format!("Niestabilny: {what} (nie odpowiedział, niepotwierdzone)"),
            _ => format!(
                "Zmiana: {what} — {}",
                fields.iter().filter_map(|f| f["label"].as_str()).collect::<Vec<_>>().join(", ")
            ),
        };
        let confidence = es.iter().map(|e| e.confidence).fold(0.0f32, f32::max);
        let id = Uuid::new_v5(&Uuid::NAMESPACE_URL, format!("asi:change:{base}:{head}:{kind}:{entity}:{change}").as_bytes());
        items.push(json!({
            "id": id, "kind": ckind, "entity": entity_kind, "host_id": host_ids.get(&ip),
            "ip": ip, "hostname": null, "port": port, "summary": summary, "fields": fields,
            "confidence": confidence, "measurements": { "responded": if ckind == "gone" { 0 } else { 1 }, "total": 1 },
            "detected_at": detected, "interest": es.iter().map(|e| e.interest).max().unwrap_or(1),
        }));
    }
    items.sort_by(|a, b| b["interest"].as_u64().cmp(&a["interest"].as_u64()).then(a["ip"].as_str().cmp(&b["ip"].as_str())));
    let mut summary = json!({ "new": 0, "changed": 0, "gone": 0, "unstable": 0 });
    for i in &items {
        let k = i["kind"].as_str().unwrap_or("changed").to_string();
        summary[&k] = json!(summary[&k].as_i64().unwrap_or(0) + 1);
    }
    if let Some(k) = opt(&q.kind) {
        let wanted: Vec<&str> = k.split(',').collect();
        items.retain(|i| i["kind"].as_str().is_some_and(|x| wanted.contains(&x)));
    }
    if let Some(e) = opt(&q.entity) {
        items.retain(|i| i["entity"] == json!(e));
    }
    if let Some(n) = opt(&q.q).map(str::to_lowercase) {
        items.retain(|i| i["summary"].as_str().is_some_and(|x| x.to_lowercase().contains(&n)) || i["ip"].as_str().is_some_and(|x| x.contains(&n)));
    }
    let mut out = paginated(items, q.page, q.page_size.or(Some(50)));
    out["base"] = scan_ref(base).unwrap_or(Value::Null);
    out["head"] = scan_ref(head).unwrap_or(Value::Null);
    out["summary"] = summary;
    Ok(Json(out))
}

// ---------- findings bulk ----------

#[derive(Deserialize)]
pub struct BulkBody {
    ids: Vec<Uuid>,
    action: String,
    #[serde(default)]
    payload: Value,
}

/// `POST /api/v1/findings/bulk` — set_status, tag, untag, assign.
pub async fn findings_bulk(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(b): Json<BulkBody>,
) -> V1<(Extension<Note>, Json<Value>)> {
    if !user.can(Action::Update) {
        return Err(forbidden());
    }
    if b.ids.is_empty() || b.ids.len() > 5000 {
        return Err(invalid("Zaznacz od 1 do 5000 znalezisk."));
    }
    let all = v1::load_findings(&s.db, &s.config.data_key).await?;
    let mut affected = 0;
    for f in all.iter().filter(|f| b.ids.contains(&f.id)) {
        let (mut status, mut tags, mut assignee) = (f.status.clone(), f.tags.clone(), f.assignee.clone());
        match b.action.as_str() {
            "set_status" => {
                let st = b.payload["status"].as_str().unwrap_or_default();
                if !["open", "in_review", "confirmed", "false_positive", "accepted"].contains(&st) {
                    return Err(invalid("Nieznany status."));
                }
                status = st.into();
            }
            "tag" | "untag" => {
                let tag = clean_tags(&[b.payload["tag"].as_str().unwrap_or_default().to_string()])?.pop().ok_or_else(|| invalid("Podaj tag."))?;
                if b.action == "tag" {
                    if !tags.contains(&tag) {
                        tags.push(tag);
                    }
                } else {
                    tags.retain(|t| *t != tag);
                }
            }
            "assign" => assignee = text(b.payload["assignee"].as_str(), "assignee", 200, false)?,
            _ => return Err(invalid("Nieznana operacja.")),
        }
        sqlx::query(
            "INSERT INTO finding_states (finding_id, scan_id, category, entity_key, status, tags, assignee, updated_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (finding_id) DO UPDATE SET status = EXCLUDED.status, tags = EXCLUDED.tags,
                 assignee = EXCLUDED.assignee, updated_by = EXCLUDED.updated_by, updated_at = now()",
        )
        .bind(f.id)
        .bind(f.scan_id)
        .bind(f.category)
        .bind(&f.entity_key)
        .bind(&status)
        .bind(&tags)
        .bind(&assignee)
        .bind(user.id)
        .execute(&s.db)
        .await
        .map_err(fail)?;
        affected += 1;
    }
    let note = Note { action: "finding.update", entity: "finding", entity_id: None, details: json!({ "bulk": b.action, "affected": affected }) };
    Ok((Extension(note), Json(json!({ "affected": affected }))))
}
