//! `/api/v1` administration: users, the four fixed roles, settings, encryption status,
//! scanning engines and the DefectDojo integration (export of findings via `import-scan`).

use crate::{
    audit::Note,
    auth::{self, CurrentUser},
    engine::Tool,
    rbac::Role,
    v1::{err, fail, invalid, missing, permissions, role_meta, text, V1},
    AppState,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use uuid::Uuid;

// ---------- settings ----------

/// Defaults of the `Settings` contract; stored values are merged over them.
fn default_settings() -> Value {
    json!({
        "scan_safety": {
            "max_rate_rps": 1000,
            "max_concurrency": 256,
            "allowed_ports": "21-23,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2375,3000,3306,3389,5000-5001,5432,5601,5900,5985,6379,8000-8099,8443,8888,9000-9100,9200,11211,27017",
            "excluded_cidrs": [],
            "user_agent": "ASI/0.1 (CBI AGH, HackNation)",
            "max_http_requests_per_host": 12
        },
        "change_detection": {
            "inactive_after_misses": 3,
            "unstable_retries": 1,
            "change_confidence_threshold": 0.5,
            "recheck_interval_minutes": 60
        },
        "retention": { "scans_days": 365, "audit_days": 730 },
        "default_window": { "start": "22:00", "end": "06:00", "timezone": "Europe/Warsaw" }
    })
}

fn merge(base: &mut Value, over: &Value) {
    match (base, over) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(k) {
                    Some(slot) if slot.is_object() && v.is_object() => merge(slot, v),
                    _ => {
                        b.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (b, o) => *b = o.clone(),
    }
}

pub(crate) async fn load_settings(db: &sqlx::PgPool) -> V1<Value> {
    let stored: Option<Value> = sqlx::query_scalar("SELECT value FROM settings WHERE key = 'system'")
        .fetch_optional(db)
        .await
        .map_err(fail)?;
    let mut s = default_settings();
    if let Some(v) = stored {
        merge(&mut s, &v);
    }
    Ok(s)
}

/// `GET /api/v1/settings`
pub async fn get_settings(State(s): State<AppState>) -> V1<Json<Value>> {
    Ok(Json(load_settings(&s.db).await?))
}

fn hhmm(v: &Value) -> bool {
    v.as_str().is_some_and(|t| {
        let b = t.as_bytes();
        b.len() == 5 && b[2] == b':' && t[..2].parse::<u8>().is_ok_and(|h| h < 24) && t[3..].parse::<u8>().is_ok_and(|m| m < 60)
    })
}

/// `PATCH /api/v1/settings`
pub async fn update_settings(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(patch): Json<Value>,
) -> V1<(Extension<Note>, Json<Value>)> {
    if !patch.is_object() {
        return Err(invalid("Oczekiwano obiektu JSON."));
    }
    let mut next = load_settings(&s.db).await?;
    merge(&mut next, &patch);
    let mut fields = serde_json::Map::new();
    let num = |p: &str| next.pointer(p).and_then(Value::as_f64);
    if !num("/scan_safety/max_rate_rps").is_some_and(|v| (1.0..=10_000.0).contains(&v)) {
        fields.insert("max_rate_rps".into(), json!("Zakres 1–10000"));
    }
    if !num("/scan_safety/max_concurrency").is_some_and(|v| (1.0..=512.0).contains(&v)) {
        fields.insert("max_concurrency".into(), json!("Zakres 1–512"));
    }
    if !crate::pipeline::valid_ports(next.pointer("/scan_safety/allowed_ports").and_then(Value::as_str).unwrap_or("")) {
        fields.insert("allowed_ports".into(), json!("Lista portów, np. 22,80,8000-8100"));
    }
    let cidrs_ok = next
        .pointer("/scan_safety/excluded_cidrs")
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().all(|c| c.as_str().is_some_and(|c| c.parse::<ipnet::IpNet>().is_ok())));
    if !cidrs_ok {
        fields.insert("excluded_cidrs".into(), json!("Każdy wpis musi być zakresem CIDR"));
    }
    if !num("/change_detection/inactive_after_misses").is_some_and(|v| (1.0..=100.0).contains(&v)) {
        fields.insert("inactive_after_misses".into(), json!("Zakres 1–100"));
    }
    if !(hhmm(&next["default_window"]["start"]) && hhmm(&next["default_window"]["end"])) {
        fields.insert("default_window".into(), json!("Format GG:MM"));
    }
    if !fields.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": { "code": "validation", "message": "Popraw zaznaczone pola.", "fields": fields }, "detail": "validation" })),
        ));
    }
    sqlx::query(
        "INSERT INTO settings (key, value, updated_by) VALUES ('system', $1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()",
    )
    .bind(&next)
    .bind(user.id)
    .execute(&s.db)
    .await
    .map_err(fail)?;
    let changed: Vec<&String> = patch.as_object().map(|o| o.keys().collect()).unwrap_or_default();
    let note = Note { action: "settings.update", entity: "settings", entity_id: None, details: json!({ "sections": changed }) };
    Ok((Extension(note), Json(next)))
}

/// `GET /api/v1/security/encryption` — what is actually encrypted and with which key.
pub async fn encryption(State(s): State<AppState>) -> V1<Json<Value>> {
    let key_id = format!("sha256:{}", &hex(&Sha256::digest(s.config.data_key.as_bytes()))[..12]);
    let since: Option<DateTime<Utc>> = sqlx::query_scalar("SELECT min(installed_on) FROM _sqlx_migrations")
        .fetch_one(&s.db)
        .await
        .map_err(fail)?;
    // A live round-trip proves the key works in this database.
    let ok: bool = sqlx::query_scalar("SELECT pgp_sym_decrypt(pgp_sym_encrypt('asi', $1), $1) = 'asi'")
        .bind(&s.config.data_key)
        .fetch_one(&s.db)
        .await
        .map_err(fail)?;
    let fields = [
        ("http_findings", "headers_enc", "Nagłówki odpowiedzi HTTP"),
        ("http_findings", "cookies_enc", "Ciasteczka (Set-Cookie)"),
        ("http_findings", "tls_enc", "Szczegóły certyfikatów TLS"),
        ("http_findings", "raw_enc", "Surowy wynik httpx"),
        ("services", "banner_enc", "Banery usług"),
        ("run_artifacts", "content_enc", "Surowe wyniki skanerów (nmap, naabu, httpx)"),
        ("diffs", "old_enc / new_enc", "Wartości w porównaniach przebiegów"),
        ("finding_states", "notes_enc", "Notatki analityków do znalezisk"),
        ("annotations", "notes_enc", "Notatki w adnotacjach"),
        ("targets", "notes_enc", "Notatki do celów"),
        ("signature_hits", "evidence_enc", "Dowody dopasowań sygnatur"),
        ("settings", "secret_enc", "Token API DefectDojo"),
    ];
    Ok(Json(json!({
        "enabled": ok,
        "algorithm": "OpenPGP symetryczny (pgcrypto pgp_sym_encrypt, AES-128)",
        "provider": "PostgreSQL pgcrypto; klucz ASI_DATA_KEY tylko w zmiennych środowiska aplikacji",
        "key_id": key_id,
        "key_created_at": since,
        "rotated_at": since,
        "encrypted_fields": fields.iter().map(|(t, c, d)| json!({ "table": t, "column": c, "description": d })).collect::<Vec<_>>(),
        "last_check_at": Utc::now(),
    })))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `POST /api/v1/security/encryption/rotate` — not implemented: says so.
pub async fn rotate_key() -> crate::api::ApiError {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "not_implemented",
        "Rotacja klucza nie jest jeszcze dostępna: wymaga ponownego zaszyfrowania wszystkich pól nowym kluczem.",
    )
}

/// `GET /api/v1/engines` — installed scanners and their versions.
pub async fn engines(State(s): State<AppState>) -> V1<Json<Vec<Value>>> {
    let last_used: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT max(started_at) FROM scan_runs WHERE source = 'scanner'").fetch_one(&s.db).await.map_err(fail)?;
    let mut out = Vec::new();
    for t in Tool::ALL {
        let (name, purpose, args): (&str, &str, &[&str]) = match t {
            Tool::Nmap => ("nmap", "Wykrywanie hostów i identyfikacja usług (-sn, -sV)", &["--version"]),
            Tool::Naabu if s.config.syn_scan.is_some() => {
                ("naabu", "Szybkie skanowanie portów (SYN, półotwarte, z limitem tempa)", &["-version"])
            }
            Tool::Naabu => ("naabu", "Szybkie skanowanie portów (connect, z limitem tempa)", &["-version"]),
            Tool::Httpx => ("httpx", "Odcisk HTTP/HTTPS: tytuł, nagłówki, TLS, technologie", &["-version"]),
            Tool::Tlsx => ("tlsx", "Certyfikaty i parametry TLS", &["-version"]),
            Tool::Nuclei => ("nuclei", "Zainstalowany; sygnatury ASI działają bez niego (tylko dane pasywne)", &["-version"]),
        };
        let path = t.resolve(&s.config.tools_dir);
        let version = match &path {
            Some(p) => tool_version(p, args).await,
            None => None,
        };
        out.push(json!({
            "name": name, "version": version,
            "status": if path.is_none() { "missing" } else if version.is_some() { "ok" } else { "error" },
            "path": path.map(|p| p.display().to_string()), "purpose": purpose, "last_used_at": last_used,
        }));
    }
    Ok(Json(out))
}

async fn tool_version(path: &std::path::Path, args: &[&str]) -> Option<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new(path).args(args).kill_on_drop(true).output(),
    )
    .await
    .ok()?
    .ok()?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    regex::Regex::new(r"v?(\d+\.\d+(?:\.\d+)?)").ok()?.captures(&text).map(|c| c[1].to_string())
}

// ---------- users and roles ----------

const ROLE_KEYS: [(&str, Role); 4] =
    [("admin", Role::Admin), ("operator", Role::Editor), ("analyst", Role::Modifier), ("viewer", Role::Viewer)];

fn role_of(key: &str) -> Option<Role> {
    ROLE_KEYS.iter().find(|(k, _)| *k == key).map(|(_, r)| *r)
}

#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    username: String,
    display_name: Option<String>,
    email: Option<String>,
    role: Role,
    disabled: bool,
    last_login_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

const USER_SELECT: &str =
    "SELECT id, username, display_name, email, role, disabled, last_login_at, created_at FROM users";

fn user_json(u: &UserRow) -> Value {
    let (key, name, _) = role_meta(u.role);
    json!({
        "id": u.id, "login": u.username, "name": u.display_name.clone().unwrap_or_else(|| u.username.clone()),
        "email": u.email.clone().unwrap_or_default(), "role_id": key, "role_name": name, "active": !u.disabled,
        "last_login_at": u.last_login_at, "created_at": u.created_at,
    })
}

async fn user_by_id(db: &sqlx::PgPool, id: Uuid) -> V1<UserRow> {
    sqlx::query_as::<_, UserRow>(sqlx::AssertSqlSafe(format!("{USER_SELECT} WHERE id = $1")))
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(fail)?
        .ok_or_else(missing)
}

/// `GET /api/v1/users`
pub async fn list_users(State(s): State<AppState>) -> V1<Json<Vec<Value>>> {
    let rows = sqlx::query_as::<_, UserRow>(sqlx::AssertSqlSafe(format!("{USER_SELECT} ORDER BY username")))
        .fetch_all(&s.db)
        .await
        .map_err(fail)?;
    Ok(Json(rows.iter().map(user_json).collect()))
}

fn clean_email(e: Option<&str>) -> V1<Option<String>> {
    let e = text(e, "email", 254, false)?;
    if e.as_deref().is_some_and(|e| !e.contains('@') || e.contains(char::is_whitespace)) {
        return Err(invalid("Niepoprawny adres e-mail."));
    }
    Ok(e)
}

#[derive(Deserialize)]
pub struct CreateUser {
    login: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    role_id: String,
    password: String,
}

/// `POST /api/v1/users`
pub async fn create_user(
    State(s): State<AppState>,
    Json(b): Json<CreateUser>,
) -> V1<(StatusCode, Extension<Note>, Json<Value>)> {
    let login = auth::normalize_username(&b.login).map_err(|_| invalid("Login: 3–64 znaki a-z, 0-9, „.”, „_”, „-”."))?;
    let role = role_of(&b.role_id).ok_or_else(|| invalid("Wybierz rolę."))?;
    auth::check_password_policy(&b.password).map_err(|_| invalid("Hasło musi mieć od 12 do 256 znaków."))?;
    let name = text(b.name.as_deref(), "name", 120, false)?;
    let email = clean_email(b.email.as_deref())?;
    let hash = auth::hash_blocking(b.password).await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role, can_execute_scans, display_name, email)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (username) DO NOTHING RETURNING id",
    )
    .bind(&login)
    .bind(hash)
    .bind(role)
    .bind(role.default_execute_flag())
    .bind(&name)
    .bind(&email)
    .fetch_optional(&s.db)
    .await
    .map_err(fail)?
    .ok_or_else(|| err(StatusCode::CONFLICT, "conflict", "Użytkownik o tym loginie już istnieje."))?;
    let note = Note::new("user.create", "user", id, json!({ "username": login, "role": b.role_id }));
    Ok((StatusCode::CREATED, Extension(note), Json(user_json(&user_by_id(&s.db, id).await?))))
}

#[derive(Deserialize)]
pub struct PatchUser {
    name: Option<String>,
    email: Option<String>,
    role_id: Option<String>,
    active: Option<bool>,
}

/// `PATCH /api/v1/users/{id}` — name, e-mail, role, active. Role change or deactivation
/// ends the user's sessions; nobody demotes or deactivates themselves or the last admin.
pub async fn update_user(
    State(s): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(b): Json<PatchUser>,
) -> V1<(Extension<Note>, Json<Value>)> {
    let mut tx = s.db.begin().await.map_err(fail)?;
    let (role, disabled): (Role, bool) = sqlx::query_as("SELECT role, disabled FROM users WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(fail)?
        .ok_or_else(missing)?;
    let new_role = match b.role_id.as_deref() {
        Some(k) => role_of(k).ok_or_else(|| invalid("Nieznana rola."))?,
        None => role,
    };
    let new_disabled = b.active.map_or(disabled, |a| !a);
    if id == me.id && (new_role != role || new_disabled) {
        return Err(invalid("Nie możesz zmienić własnej roli ani dezaktywować własnego konta."));
    }
    if role == Role::Admin && !disabled && (new_role != Role::Admin || new_disabled) {
        auth::keep_an_admin(&mut tx, id).await.map_err(|_| err(StatusCode::CONFLICT, "conflict", "Musi zostać co najmniej jeden aktywny administrator."))?;
    }
    let name = match &b.name {
        Some(n) => Some(text(Some(n), "name", 120, false)?),
        None => None,
    };
    let email = match &b.email {
        Some(e) => Some(clean_email(Some(e))?),
        None => None,
    };
    sqlx::query(
        "UPDATE users SET role = $2, can_execute_scans = CASE WHEN $2 = 'viewer' THEN false
                 WHEN $2 <> role THEN $5 ELSE can_execute_scans END,
             disabled = $3, display_name = CASE WHEN $4 THEN $6 ELSE display_name END,
             email = CASE WHEN $7 THEN $8 ELSE email END, updated_at = now()
         WHERE id = $1",
    )
    .bind(id)
    .bind(new_role)
    .bind(new_disabled)
    .bind(name.is_some())
    .bind(new_role.default_execute_flag())
    .bind(name.flatten())
    .bind(email.is_some())
    .bind(email.flatten())
    .execute(&mut *tx)
    .await
    .map_err(fail)?;
    if new_role != role || new_disabled != disabled {
        auth::revoke_sessions(&mut tx, id).await.map_err(fail)?;
    }
    tx.commit().await.map_err(fail)?;
    let u = user_by_id(&s.db, id).await?;
    let note = Note::new("user.update", "user", id, json!({ "username": u.username, "role": role_meta(new_role).0, "active": !new_disabled }));
    Ok((Extension(note), Json(user_json(&u))))
}

/// `DELETE /api/v1/users/{id}` — deactivates (audit rows keep referring to the user).
pub async fn remove_user(
    State(s): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> V1<(StatusCode, Extension<Note>)> {
    if id == me.id {
        return Err(invalid("Nie możesz usunąć własnego konta."));
    }
    let mut tx = s.db.begin().await.map_err(fail)?;
    let (role, disabled, username): (Role, bool, String) =
        sqlx::query_as("SELECT role, disabled, username FROM users WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(fail)?
            .ok_or_else(missing)?;
    if role == Role::Admin && !disabled {
        auth::keep_an_admin(&mut tx, id).await.map_err(|_| err(StatusCode::CONFLICT, "conflict", "Musi zostać co najmniej jeden aktywny administrator."))?;
    }
    sqlx::query("UPDATE users SET disabled = true, updated_at = now() WHERE id = $1").bind(id).execute(&mut *tx).await.map_err(fail)?;
    auth::revoke_sessions(&mut tx, id).await.map_err(fail)?;
    tx.commit().await.map_err(fail)?;
    Ok((StatusCode::NO_CONTENT, Extension(Note::new("user.disable", "user", id, json!({ "username": username })))))
}

/// `GET /api/v1/roles` — the four roles of the task with their effective permissions.
pub async fn list_roles(State(s): State<AppState>) -> V1<Json<Vec<Value>>> {
    let counts: Vec<(Role, i64)> = sqlx::query_as("SELECT role, count(*) FROM users WHERE NOT disabled GROUP BY role")
        .fetch_all(&s.db)
        .await
        .map_err(fail)?;
    Ok(Json(
        ROLE_KEYS
            .iter()
            .map(|(_, role)| {
                let (key, name, description) = role_meta(*role);
                let probe = CurrentUser {
                    id: Uuid::nil(),
                    username: String::new(),
                    role: *role,
                    can_execute_scans: role.default_execute_flag(),
                    session_id: Uuid::nil(),
                };
                json!({
                    "id": key, "key": key, "name": name, "description": description, "builtin": true,
                    "permissions": permissions(&probe),
                    "users_count": counts.iter().find(|(r, _)| r == role).map_or(0, |c| c.1),
                })
            })
            .collect(),
    ))
}

/// Role create/update/delete: the matrix is fixed by the task (4 roles).
pub async fn roles_fixed() -> crate::api::ApiError {
    err(
        StatusCode::CONFLICT,
        "builtin_roles",
        "Role są wbudowane (cztery role z wymagań AGH) — ich uprawnienia są stałe. Przypisz użytkownikowi inną rolę.",
    )
}

// ---------- DefectDojo ----------

#[derive(Debug)]
pub(crate) struct DojoConfig {
    pub cfg: Value,
    pub token: Option<String>,
}

fn dojo_defaults(s: &AppState) -> Value {
    json!({
        "enabled": s.config.defectdojo_url.is_some(),
        "url": s.config.defectdojo_url.clone().unwrap_or_default(),
        "product_id": null, "product_name": null, "engagement_id": null, "engagement_name": null,
        "auto_export": false, "min_score": 70, "export_as": "finding", "verify_tls": true, "last_test": null,
    })
}

pub(crate) async fn dojo_config(s: &AppState) -> V1<DojoConfig> {
    let row: Option<(Value, Option<String>)> =
        sqlx::query_as("SELECT value, pgp_sym_decrypt(secret_enc, $1) FROM settings WHERE key = 'defectdojo'")
            .bind(&s.config.data_key)
            .fetch_optional(&s.db)
            .await
            .map_err(fail)?;
    let mut cfg = dojo_defaults(s);
    let mut token = s.config.defectdojo_token.clone();
    if let Some((v, t)) = row {
        merge(&mut cfg, &v);
        if t.is_some() {
            token = t;
        }
    }
    Ok(DojoConfig { cfg, token })
}

fn dojo_public(c: &DojoConfig) -> Value {
    let mut v = c.cfg.clone();
    v["api_token_set"] = json!(c.token.is_some());
    v["api_token_masked"] = json!(c.token.as_ref().map(|t| format!("••••••••{}", t.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect::<String>())));
    v
}

async fn save_dojo(s: &AppState, cfg: &Value, token: Option<&str>, user: Uuid) -> V1<()> {
    sqlx::query(
        "INSERT INTO settings (key, value, secret_enc, updated_by) VALUES ('defectdojo', $1,
             CASE WHEN $2::text IS NULL THEN NULL ELSE pgp_sym_encrypt($2, $3) END, $4)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value,
             secret_enc = COALESCE(EXCLUDED.secret_enc, settings.secret_enc), updated_by = EXCLUDED.updated_by, updated_at = now()",
    )
    .bind(cfg)
    .bind(token)
    .bind(&s.config.data_key)
    .bind(user)
    .execute(&s.db)
    .await
    .map_err(fail)?;
    Ok(())
}

/// `GET /api/v1/integrations/defectdojo`
pub async fn dojo_get(State(s): State<AppState>) -> V1<Json<Value>> {
    Ok(Json(dojo_public(&dojo_config(&s).await?)))
}

/// `PUT /api/v1/integrations/defectdojo` — the token is stored encrypted and never returned.
pub async fn dojo_put(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(body): Json<Value>,
) -> V1<(Extension<Note>, Json<Value>)> {
    let mut c = dojo_config(&s).await?;
    let token = body.get("api_token").and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty()).map(str::to_string);
    let mut patch = body.clone();
    if let Some(o) = patch.as_object_mut() {
        o.remove("api_token");
        o.remove("api_token_set");
        o.remove("api_token_masked");
        o.remove("last_test");
    }
    merge(&mut c.cfg, &patch);
    let url = c.cfg["url"].as_str().unwrap_or_default();
    if !url.is_empty() && !(url.starts_with("http://") || url.starts_with("https://")) || url.contains(char::is_whitespace) {
        return Err(invalid("Podaj adres URL instancji DefectDojo, np. https://defectdojo.example."));
    }
    if c.cfg["export_as"].as_str().is_some_and(|e| !matches!(e, "finding" | "evidence")) {
        return Err(invalid("export_as: finding lub evidence."));
    }
    save_dojo(&s, &c.cfg, token.as_deref(), user.id).await?;
    if token.is_some() {
        c.token = token.clone();
    }
    let note = Note {
        action: "integration.update",
        entity: "integration",
        entity_id: Some("defectdojo".into()),
        details: json!({ "url": c.cfg["url"], "token_changed": token.is_some() }),
    };
    Ok((Extension(note), Json(dojo_public(&c))))
}

fn dojo_client(c: &DojoConfig) -> V1<(reqwest::Client, String, String)> {
    let url = c.cfg["url"].as_str().unwrap_or_default().trim_end_matches('/').to_string();
    let token = c.token.clone().ok_or_else(|| err(StatusCode::CONFLICT, "not_configured", "Brak tokenu API DefectDojo."))?;
    if url.is_empty() {
        return Err(err(StatusCode::CONFLICT, "not_configured", "Brak adresu DefectDojo (Administracja → Integracje)."));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(c.cfg["verify_tls"] == json!(false))
        .build()
        .map_err(fail)?;
    Ok((client, url, token))
}

/// `POST /api/v1/integrations/defectdojo/test` — token, reachability, product.
pub async fn dojo_test(State(s): State<AppState>, Extension(user): Extension<CurrentUser>) -> V1<Json<Value>> {
    let mut c = dojo_config(&s).await?;
    let started = Instant::now();
    let result = match dojo_client(&c) {
        Err((_, Json(e))) => Err(e["error"]["message"].as_str().unwrap_or("Brak konfiguracji").to_string()),
        Ok((client, url, token)) => {
            let product = c.cfg["product_id"].as_i64();
            let path = match product {
                Some(p) => format!("{url}/api/v2/products/{p}/"),
                None => format!("{url}/api/v2/users/?limit=1"),
            };
            match client.get(&path).header("Authorization", format!("Token {token}")).send().await {
                Err(e) => Err(format!("Brak połączenia z {url}: {e}")),
                Ok(r) if r.status().is_success() => {
                    let body: Value = r.json().await.unwrap_or(Value::Null);
                    if let Some(name) = body.get("name").and_then(Value::as_str) {
                        c.cfg["product_name"] = json!(name);
                    }
                    Ok(format!("Połączono z {url} — token ważny"))
                }
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED || r.status() == reqwest::StatusCode::FORBIDDEN => {
                    Err(format!("Token odrzucony (HTTP {})", r.status().as_u16()))
                }
                Ok(r) => Err(format!("DefectDojo odpowiedział HTTP {}", r.status().as_u16())),
            }
        }
    };
    let ok = result.is_ok();
    c.cfg["last_test"] = json!({
        "ok": ok, "at": Utc::now(), "version": null,
        "latency_ms": ok.then(|| started.elapsed().as_millis() as u64),
        "message": result.unwrap_or_else(|e| e),
    });
    save_dojo(&s, &c.cfg, None, user.id).await?;
    Ok(Json(dojo_public(&c)))
}

/// `GET /api/v1/integrations/defectdojo/exports`
pub async fn dojo_exports(State(s): State<AppState>) -> V1<Json<Vec<Value>>> {
    type Row = (Uuid, DateTime<Utc>, Option<String>, i32, String, String, String);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT e.id, e.at, COALESCE(u.display_name, u.username), e.count, e.as_kind, e.status, e.message
         FROM defectdojo_exports e LEFT JOIN users u ON u.id = e.by_user ORDER BY e.at DESC LIMIT 100",
    )
    .fetch_all(&s.db)
    .await
    .map_err(fail)?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, at, by, count, as_kind, status, message)| {
                json!({ "id": id, "at": at, "by": by.unwrap_or_default(), "count": count, "as": as_kind, "status": status, "message": message })
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct DojoExportBody {
    ids: Vec<Uuid>,
    #[serde(rename = "as", default)]
    as_kind: Option<String>,
}

/// `POST /api/v1/findings/defectdojo` — send findings as informational findings with the
/// "Generic Findings Import" parser (`/api/v2/import-scan/`) into the configured engagement.
pub async fn dojo_export(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(b): Json<DojoExportBody>,
) -> V1<(Extension<Note>, Json<Value>)> {
    if b.ids.is_empty() || b.ids.len() > 500 {
        return Err(invalid("Wybierz od 1 do 500 znalezisk."));
    }
    let c = dojo_config(&s).await?;
    if c.cfg["enabled"] != json!(true) {
        return Err(err(StatusCode::CONFLICT, "not_configured", "Integracja z DefectDojo jest wyłączona (Administracja → Integracje)."));
    }
    let engagement = c.cfg["engagement_id"]
        .as_i64()
        .ok_or_else(|| err(StatusCode::CONFLICT, "not_configured", "Podaj identyfikator engagementu DefectDojo."))?;
    let (client, url, token) = dojo_client(&c)?;
    let as_kind = b.as_kind.unwrap_or_else(|| "finding".into());
    let all = crate::v1::load_findings(&s.db, &s.config.data_key).await?;
    let chosen: Vec<&crate::v1::Finding> = all.iter().filter(|f| b.ids.contains(&f.id)).collect();
    if chosen.is_empty() {
        return Err(missing());
    }
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let findings: Vec<Value> = chosen
        .iter()
        .map(|f| {
            let evidence: Vec<String> = f.evidence.iter().filter_map(|e| e["snippet"].as_str().map(str::to_string)).collect();
            json!({
                "title": f.title,
                "description": format!(
                    "Kategoria: {}\nHost: {}{}\nUsługa: {}\nStatus zmiany: {}\nPewność: {:.0}%\n\nDowody:\n- {}",
                    f.category, f.ip, f.hostname.as_deref().map(|h| format!(" ({h})")).unwrap_or_default(),
                    f.service_label.clone().unwrap_or_default(), f.change, f.confidence * 100.0, evidence.join("\n- ")
                ),
                "severity": "Info",
                "date": today,
                "unique_id_from_tool": f.id.to_string(),
                "vuln_id_from_tool": f.category,
                "component_name": f.technologies.first(),
                "endpoints": [match f.port { Some(p) => format!("{}:{p}", f.ip), None => f.ip.clone() }],
                "tags": ["asi", f.category],
            })
        })
        .collect();
    let file = serde_json::to_vec(&json!({ "findings": findings })).map_err(fail)?;
    let form = reqwest::multipart::Form::new()
        .text("scan_type", "Generic Findings Import")
        .text("engagement", engagement.to_string())
        .text("active", "true")
        .text("verified", "false")
        .text("minimum_severity", "Info")
        .text("close_old_findings", "false")
        .text("test_title", format!("ASI {}", Utc::now().format("%Y-%m-%d %H:%M")))
        .part("file", reqwest::multipart::Part::bytes(file).file_name("asi-findings.json").mime_str("application/json").map_err(fail)?);
    let sent = client.post(format!("{url}/api/v2/import-scan/")).header("Authorization", format!("Token {token}")).multipart(form).send().await;
    let (status, message, test_id) = match sent {
        Err(e) => ("failed", format!("Brak połączenia z DefectDojo: {e}"), None),
        Ok(r) if r.status().is_success() => {
            let body: Value = r.json().await.unwrap_or(Value::Null);
            let test = body.get("test").and_then(Value::as_i64).or_else(|| body.get("test_id").and_then(Value::as_i64));
            ("success", format!("Wysłano {} znalezisk do engagementu {engagement}", chosen.len()), test)
        }
        Ok(r) => {
            let code = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            ("failed", format!("DefectDojo odrzucił import (HTTP {code}): {}", text.chars().take(300).collect::<String>()), None)
        }
    };
    let link = test_id.map(|t| format!("{url}/test/{t}")).unwrap_or_else(|| format!("{url}/engagement/{engagement}"));
    let export_id: Uuid = sqlx::query_scalar(
        "INSERT INTO defectdojo_exports (by_user, count, as_kind, status, message, links) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(user.id)
    .bind(chosen.len() as i32)
    .bind(&as_kind)
    .bind(status)
    .bind(&message)
    .bind(json!([link]))
    .fetch_one(&s.db)
    .await
    .map_err(fail)?;
    if status == "success" {
        for f in &chosen {
            let mark = json!({ "exported_at": Utc::now(), "finding_id": test_id.unwrap_or(0), "url": link });
            sqlx::query(
                "INSERT INTO finding_states (finding_id, scan_id, category, entity_key, defectdojo, updated_by)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (finding_id) DO UPDATE SET defectdojo = EXCLUDED.defectdojo, updated_at = now()",
            )
            .bind(f.id)
            .bind(f.scan_id)
            .bind(f.category)
            .bind(&f.entity_key)
            .bind(&mark)
            .bind(user.id)
            .execute(&s.db)
            .await
            .map_err(fail)?;
        }
    }
    let note = Note {
        action: "finding.defectdojo_export",
        entity: "finding",
        entity_id: Some(export_id.to_string()),
        details: json!({ "count": chosen.len(), "status": status }),
    };
    if status != "success" {
        return Err(err(StatusCode::BAD_GATEWAY, "defectdojo_failed", message));
    }
    Ok((
        Extension(note),
        Json(json!({
            "exported": chosen.len(), "failed": 0, "export_id": export_id,
            "links": chosen.iter().map(|f| json!({ "finding_id": f.id, "url": link })).collect::<Vec<_>>(),
        })),
    ))
}
