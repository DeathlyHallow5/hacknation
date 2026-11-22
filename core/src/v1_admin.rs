//! `/api/v1` administration: users, the four fixed roles, settings, encryption status,
//! scanning engines and the DefectDojo integration (export of findings via `import-scan`).

use crate::{
    audit::Note,
    auth::{self, CurrentUser, CustomRole},
    engine::Tool,
    rbac::{self, Role},
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

/// A role picked for a user: built-in (by key) or custom (by id).
#[derive(Clone, Copy, PartialEq)]
enum RoleChoice {
    Builtin(Role),
    Custom(Uuid),
}

impl RoleChoice {
    /// `users.role`: a custom role keeps `viewer` as its base (migration 0010).
    fn base(self) -> Role {
        match self {
            RoleChoice::Builtin(r) => r,
            RoleChoice::Custom(_) => Role::Viewer,
        }
    }
    fn custom(self) -> Option<Uuid> {
        match self {
            RoleChoice::Builtin(_) => None,
            RoleChoice::Custom(id) => Some(id),
        }
    }
    fn key(self) -> String {
        match self {
            RoleChoice::Builtin(r) => role_meta(r).0.to_string(),
            RoleChoice::Custom(id) => id.to_string(),
        }
    }
}

async fn resolve_role(db: &sqlx::PgPool, key: &str) -> V1<RoleChoice> {
    if let Some(r) = role_of(key) {
        return Ok(RoleChoice::Builtin(r));
    }
    let id = Uuid::parse_str(key).map_err(|_| invalid("Nieznana rola."))?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM custom_roles WHERE id = $1)")
        .bind(id)
        .fetch_one(db)
        .await
        .map_err(fail)?;
    if exists { Ok(RoleChoice::Custom(id)) } else { Err(invalid("Nieznana rola.")) }
}

/// Only a built-in administrator hands out the administrator role (a custom role with
/// `users:manage` must not be a way to become admin).
fn may_grant(me: &CurrentUser, choice: RoleChoice) -> V1<()> {
    if choice == RoleChoice::Builtin(Role::Admin) && (me.role != Role::Admin || me.custom.is_some()) {
        return Err(err(StatusCode::FORBIDDEN, "forbidden", "Rolę administratora może nadać tylko administrator."));
    }
    Ok(())
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
    custom_role_id: Option<Uuid>,
    custom_role_name: Option<String>,
}

const USER_SELECT: &str = "SELECT u.id, u.username, u.display_name, u.email, u.role, u.disabled, u.last_login_at,
        u.created_at, u.custom_role_id, r.name AS custom_role_name
    FROM users u LEFT JOIN custom_roles r ON r.id = u.custom_role_id";

fn user_json(u: &UserRow) -> Value {
    let (key, name) = match (u.custom_role_id, &u.custom_role_name) {
        (Some(id), Some(name)) => (id.to_string(), name.clone()),
        _ => {
            let (k, n, _) = role_meta(u.role);
            (k.to_string(), n.to_string())
        }
    };
    json!({
        "id": u.id, "login": u.username, "name": u.display_name.clone().unwrap_or_else(|| u.username.clone()),
        "email": u.email.clone().unwrap_or_default(), "role_id": key, "role_name": name, "active": !u.disabled,
        "last_login_at": u.last_login_at, "created_at": u.created_at,
    })
}

async fn user_by_id(db: &sqlx::PgPool, id: Uuid) -> V1<UserRow> {
    sqlx::query_as::<_, UserRow>(sqlx::AssertSqlSafe(format!("{USER_SELECT} WHERE u.id = $1")))
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(fail)?
        .ok_or_else(missing)
}

/// `GET /api/v1/users`
pub async fn list_users(State(s): State<AppState>) -> V1<Json<Vec<Value>>> {
    let rows = sqlx::query_as::<_, UserRow>(sqlx::AssertSqlSafe(format!("{USER_SELECT} ORDER BY u.username")))
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
    Extension(me): Extension<CurrentUser>,
    Json(b): Json<CreateUser>,
) -> V1<(StatusCode, Extension<Note>, Json<Value>)> {
    let login = auth::normalize_username(&b.login).map_err(|_| invalid("Login: 3–64 znaki a-z, 0-9, „.”, „_”, „-”."))?;
    let choice = resolve_role(&s.db, &b.role_id).await.map_err(|_| invalid("Wybierz rolę."))?;
    may_grant(&me, choice)?;
    let role = choice.base();
    auth::check_password_policy(&b.password).map_err(|_| invalid("Hasło musi mieć od 12 do 256 znaków."))?;
    let name = text(b.name.as_deref(), "name", 120, false)?;
    let email = clean_email(b.email.as_deref())?;
    let hash = auth::hash_blocking(b.password).await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role, can_execute_scans, display_name, email, custom_role_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (username) DO NOTHING RETURNING id",
    )
    .bind(&login)
    .bind(hash)
    .bind(role)
    .bind(choice.custom().is_none() && role.default_execute_flag())
    .bind(&name)
    .bind(&email)
    .bind(choice.custom())
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
    let (role, disabled, custom): (Role, bool, Option<Uuid>) =
        sqlx::query_as("SELECT role, disabled, custom_role_id FROM users WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(fail)?
            .ok_or_else(missing)?;
    let current = match custom {
        Some(c) => RoleChoice::Custom(c),
        None => RoleChoice::Builtin(role),
    };
    let choice = match b.role_id.as_deref() {
        Some(k) => resolve_role(&s.db, k).await?,
        None => current,
    };
    if choice != current {
        may_grant(&me, choice)?;
    }
    let new_role = choice.base();
    let role_changed = choice != current;
    let new_disabled = b.active.map_or(disabled, |a| !a);
    if id == me.id && (role_changed || new_disabled) {
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
             email = CASE WHEN $7 THEN $8 ELSE email END, custom_role_id = $9, updated_at = now()
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
    .bind(choice.custom())
    .execute(&mut *tx)
    .await
    .map_err(fail)?;
    if role_changed || new_disabled != disabled {
        auth::revoke_sessions(&mut tx, id).await.map_err(fail)?;
    }
    tx.commit().await.map_err(fail)?;
    let u = user_by_id(&s.db, id).await?;
    let note = Note::new("user.update", "user", id, json!({ "username": u.username, "role": choice.key(), "active": !new_disabled }));
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

/// `GET /api/v1/roles` — the four built-in roles of the task, then the custom ones.
pub async fn list_roles(State(s): State<AppState>) -> V1<Json<Vec<Value>>> {
    let counts: Vec<(Role, i64)> =
        sqlx::query_as("SELECT role, count(*) FROM users WHERE NOT disabled AND custom_role_id IS NULL GROUP BY role")
        .fetch_all(&s.db)
        .await
        .map_err(fail)?;
    let mut out: Vec<Value> = ROLE_KEYS
            .iter()
            .map(|(_, role)| {
                let (key, name, description) = role_meta(*role);
                let probe = CurrentUser {
                    id: Uuid::nil(),
                    username: String::new(),
                    role: *role,
                    can_execute_scans: role.default_execute_flag(),
                    session_id: Uuid::nil(),
                    custom: None,
                };
                json!({
                    "id": key, "key": key, "name": name, "description": description, "builtin": true,
                    "permissions": permissions(&probe),
                    "users_count": counts.iter().find(|(r, _)| r == role).map_or(0, |c| c.1),
                })
            })
            .collect();
    for (role, users) in custom_roles(&s.db).await? {
        out.push(custom_role_json(&role, users));
    }
    Ok(Json(out))
}


pub(crate) fn custom_role_json(r: &CustomRole, users: i64) -> Value {
    json!({
        "id": r.id, "key": format!("custom-{}", &r.id.simple().to_string()[..8]), "name": r.name,
        "description": r.description, "builtin": false, "permissions": r.permissions, "users_count": users,
    })
}

async fn custom_roles(db: &sqlx::PgPool) -> V1<Vec<(CustomRole, i64)>> {
    let rows: Vec<(Uuid, String, String, Vec<String>, i64)> = sqlx::query_as(
        "SELECT r.id, r.name, r.description, r.permissions,
                (SELECT count(*) FROM users u WHERE u.custom_role_id = r.id AND NOT u.disabled)
         FROM custom_roles r ORDER BY r.created_at",
    )
    .fetch_all(db)
    .await
    .map_err(fail)?;
    Ok(rows.into_iter().map(|(id, name, description, permissions, n)| (CustomRole { id, name, description, permissions }, n)).collect())
}

/// `GET /api/v1/permissions` — the permissions a custom role can be built from.
pub async fn list_permissions() -> Json<&'static [&'static str]> {
    Json(&rbac::PERMISSIONS)
}

fn clean_permissions(p: &[String]) -> V1<Vec<String>> {
    if let Some(bad) = p.iter().find(|x| !rbac::PERMISSIONS.contains(&x.as_str())) {
        return Err(invalid(format!("Nieznane uprawnienie: {bad}.")));
    }
    // Contract order, no duplicates.
    let out: Vec<String> = rbac::PERMISSIONS.iter().filter(|k| p.iter().any(|x| x == *k)).map(|k| k.to_string()).collect();
    if out.is_empty() {
        return Err(invalid("Wybierz co najmniej jedno uprawnienie."));
    }
    Ok(out)
}

fn builtin_role(id: &str) -> V1<Uuid> {
    if role_of(id).is_some() {
        return Err(err(StatusCode::CONFLICT, "conflict", "Ról wbudowanych nie można zmieniać ani usuwać — utwórz rolę własną."));
    }
    Uuid::parse_str(id).map_err(|_| missing())
}

fn name_taken(e: sqlx::Error) -> crate::api::ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => err(StatusCode::CONFLICT, "conflict", "Rola o tej nazwie już istnieje."),
        _ => fail(e),
    }
}

#[derive(Deserialize)]
pub struct RoleBody {
    name: Option<String>,
    description: Option<String>,
    permissions: Option<Vec<String>>,
}

/// `POST /api/v1/roles` — a custom role.
pub async fn create_role(State(s): State<AppState>, Json(b): Json<RoleBody>) -> V1<(StatusCode, Extension<Note>, Json<Value>)> {
    let name = text(b.name.as_deref(), "name", 64, true)?.ok_or_else(|| invalid("Podaj nazwę roli."))?;
    let description = text(b.description.as_deref(), "description", 500, false)?.unwrap_or_default();
    let permissions = clean_permissions(b.permissions.as_deref().unwrap_or_default())?;
    let id: Uuid = sqlx::query_scalar("INSERT INTO custom_roles (name, description, permissions) VALUES ($1, $2, $3) RETURNING id")
        .bind(&name)
        .bind(&description)
        .bind(&permissions)
        .fetch_one(&s.db)
        .await
        .map_err(name_taken)?;
    let role = CustomRole { id, name, description, permissions };
    let note = Note::new("role.create", "role", id, json!({ "name": role.name, "permissions": role.permissions.len() }));
    Ok((StatusCode::CREATED, Extension(note), Json(custom_role_json(&role, 0))))
}

/// `PATCH /api/v1/roles/{id}` — custom roles only. Takes effect on the users' next request.
pub async fn update_role(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(b): Json<RoleBody>,
) -> V1<(Extension<Note>, Json<Value>)> {
    let id = builtin_role(&id)?;
    let name = match &b.name {
        Some(n) => Some(text(Some(n), "name", 64, true)?.ok_or_else(|| invalid("Podaj nazwę roli."))?),
        None => None,
    };
    let description = match &b.description {
        Some(d) => Some(text(Some(d), "description", 500, false)?.unwrap_or_default()),
        None => None,
    };
    let permissions = match &b.permissions {
        Some(p) => Some(clean_permissions(p)?),
        None => None,
    };
    let row: Option<(String, String, Vec<String>)> = sqlx::query_as(
        "UPDATE custom_roles SET name = coalesce($2, name), description = coalesce($3, description),
             permissions = coalesce($4, permissions), updated_at = now()
         WHERE id = $1 RETURNING name, description, permissions",
    )
    .bind(id)
    .bind(&name)
    .bind(&description)
    .bind(&permissions)
    .fetch_optional(&s.db)
    .await
    .map_err(name_taken)?;
    let (name, description, permissions) = row.ok_or_else(missing)?;
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE custom_role_id = $1 AND NOT disabled")
        .bind(id)
        .fetch_one(&s.db)
        .await
        .map_err(fail)?;
    let role = CustomRole { id, name, description, permissions };
    let note = Note::new("role.update", "role", id, json!({ "name": role.name, "permissions": role.permissions.len() }));
    Ok((Extension(note), Json(custom_role_json(&role, users))))
}

/// `DELETE /api/v1/roles/{id}` — custom roles nobody has (deactivated accounts included).
pub async fn delete_role(State(s): State<AppState>, Path(id): Path<String>) -> V1<(StatusCode, Extension<Note>)> {
    let id = builtin_role(&id)?;
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE custom_role_id = $1")
        .bind(id)
        .fetch_one(&s.db)
        .await
        .map_err(fail)?;
    if users > 0 {
        return Err(err(StatusCode::CONFLICT, "conflict", "Rola jest przypisana do użytkowników. Zmień im rolę przed usunięciem."));
    }
    let name: String = sqlx::query_scalar("DELETE FROM custom_roles WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&s.db)
        .await
        .map_err(fail)?
        .ok_or_else(missing)?;
    Ok((StatusCode::NO_CONTENT, Extension(Note::new("role.delete", "role", id, json!({ "name": name })))))
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
    // The dashboard form has no on/off switch: an address turns the integration on, an empty
    // one off (an explicit "enabled" in the request still wins).
    if body.get("enabled").is_none() && body.get("url").is_some() {
        c.cfg["enabled"] = json!(!c.cfg["url"].as_str().unwrap_or_default().trim().is_empty());
    }
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

/// Names ASI uses in DefectDojo when the configuration names no product or engagement.
const DOJO_PRODUCT_TYPE: &str = "ASI";
const DOJO_PRODUCT: &str = "ASI — CBI AGH";
const DOJO_ENGAGEMENT: &str = "ASI — skanowanie ciągłe";

/// Base of the links shown in the dashboard. The core may reach DefectDojo under an internal
/// name (compose.yaml: http://dojo-nginx:8080) the browser cannot open, so
/// DEFECTDOJO_PUBLIC_URL (e.g. http://localhost:8081) takes precedence.
fn dojo_link_base(url: &str) -> String {
    std::env::var("DEFECTDOJO_PUBLIC_URL")
        .ok()
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| url.to_string())
}

async fn dojo_call(req: reqwest::RequestBuilder, token: &str, what: &str) -> Result<Value, String> {
    let r = req.header("Authorization", format!("Token {token}")).send().await.map_err(|e| format!("{what}: brak połączenia ({e})"))?;
    let code = r.status();
    if code == reqwest::StatusCode::UNAUTHORIZED || code == reqwest::StatusCode::FORBIDDEN {
        return Err(format!("Token odrzucony przez DefectDojo (HTTP {})", code.as_u16()));
    }
    if !code.is_success() {
        let text = r.text().await.unwrap_or_default();
        return Err(format!("{what}: HTTP {} {}", code.as_u16(), text.chars().take(200).collect::<String>()));
    }
    r.json().await.map_err(|e| format!("{what}: niepoprawna odpowiedź ({e})"))
}

/// First object named `name` from a DefectDojo list endpoint (`?name=` filters, exact match kept).
async fn dojo_find(client: &reqwest::Client, url: &str, token: &str, path: &str, query: &[(&str, String)], name: &str) -> Result<Option<Value>, String> {
    let endpoint = reqwest::Url::parse_with_params(&format!("{url}{path}"), query).map_err(|e| format!("{path}: {e}"))?;
    let list = dojo_call(client.get(endpoint), token, path).await?;
    Ok(list["results"].as_array().and_then(|r| r.iter().find(|o| o["name"] == json!(name)).cloned()))
}

/// Product and engagement the exports go to: the configured engagement while it exists, else
/// found by name or created — product type "ASI", product "ASI — CBI AGH" (or the configured
/// product name), engagement "ASI — skanowanie ciągłe". The dashboard only shows them.
async fn dojo_context(client: &reqwest::Client, url: &str, token: &str, cfg: &mut Value) -> Result<(), String> {
    if let Some(e) = cfg["engagement_id"].as_i64()
        && let Ok(eng) = dojo_call(client.get(format!("{url}/api/v2/engagements/{e}/")), token, "engagement").await
    {
        cfg["engagement_name"] = eng["name"].clone();
        if let Some(p) = eng["product"].as_i64() {
            cfg["product_id"] = json!(p);
            if let Ok(prod) = dojo_call(client.get(format!("{url}/api/v2/products/{p}/")), token, "product").await {
                cfg["product_name"] = prod["name"].clone();
            }
        }
        return Ok(());
    }
    let product_name = cfg["product_name"].as_str().filter(|n| !n.trim().is_empty()).unwrap_or(DOJO_PRODUCT).to_string();
    let product = match dojo_find(client, url, token, "/api/v2/products/", &[("name", product_name.clone())], &product_name).await? {
        Some(p) => p,
        None => {
            let kind = match dojo_find(client, url, token, "/api/v2/product_types/", &[("name", DOJO_PRODUCT_TYPE.into())], DOJO_PRODUCT_TYPE).await? {
                Some(t) => t,
                None => {
                    let body = json!({ "name": DOJO_PRODUCT_TYPE, "description": "Attack Surface Intelligence (CBI AGH)" });
                    dojo_call(client.post(format!("{url}/api/v2/product_types/")).json(&body), token, "product type").await?
                }
            };
            let body = json!({
                "name": product_name, "prod_type": kind["id"],
                "description": "Zasoby i usługi wykryte przez Attack Surface Intelligence (CBI AGH): panele administracyjne, staging, usługi i zmiany w czasie.",
            });
            dojo_call(client.post(format!("{url}/api/v2/products/")).json(&body), token, "product").await?
        }
    };
    let pid = product["id"].as_i64().ok_or("DefectDojo nie zwrócił identyfikatora produktu")?;
    let query = [("product", pid.to_string()), ("name", DOJO_ENGAGEMENT.to_string())];
    let engagement = match dojo_find(client, url, token, "/api/v2/engagements/", &query, DOJO_ENGAGEMENT).await? {
        Some(e) => e,
        None => {
            let today = Utc::now().date_naive();
            let body = json!({
                "name": DOJO_ENGAGEMENT, "product": pid, "status": "In Progress", "engagement_type": "Interactive",
                "target_start": today.to_string(), "target_end": (today + chrono::Days::new(365)).to_string(),
                "description": "Eksport znalezisk ASI: każdy import to osobny test z datą skanu.",
            });
            dojo_call(client.post(format!("{url}/api/v2/engagements/")).json(&body), token, "engagement").await?
        }
    };
    cfg["product_id"] = json!(pid);
    cfg["product_name"] = product["name"].clone();
    cfg["engagement_id"] = engagement["id"].clone();
    cfg["engagement_name"] = engagement["name"].clone();
    Ok(())
}

/// `POST /api/v1/integrations/defectdojo/test` — reachability and token, then the product and
/// engagement for exports (found or created, see [`dojo_context`]).
pub async fn dojo_test(State(s): State<AppState>, Extension(user): Extension<CurrentUser>) -> V1<Json<Value>> {
    let mut c = dojo_config(&s).await?;
    let started = Instant::now();
    let result = match dojo_client(&c) {
        Err((_, Json(e))) => Err(e["error"]["message"].as_str().unwrap_or("Brak konfiguracji").to_string()),
        Ok((client, url, token)) => match dojo_call(client.get(format!("{url}/api/v2/users/?limit=1")), &token, &url).await {
            Err(e) => Err(e),
            Ok(_) => {
                let latency = started.elapsed().as_millis() as u64;
                match dojo_context(&client, &url, &token, &mut c.cfg).await {
                    Ok(()) => Ok((
                        format!(
                            "Połączono z {url} — token ważny. Produkt „{}” (#{}), engagement „{}” (#{}).",
                            c.cfg["product_name"].as_str().unwrap_or("?"), c.cfg["product_id"],
                            c.cfg["engagement_name"].as_str().unwrap_or("?"), c.cfg["engagement_id"]
                        ),
                        latency,
                    )),
                    Err(e) => Err(format!("Token ważny, ale nie udało się przygotować produktu/engagementu: {e}")),
                }
            }
        },
    };
    let ok = result.is_ok();
    let (message, latency) = match result {
        Ok((m, l)) => (m, Some(l)),
        Err(e) => (e, None),
    };
    c.cfg["last_test"] = json!({ "ok": ok, "at": Utc::now(), "version": null, "latency_ms": latency, "message": message });
    save_dojo(&s, &c.cfg, None, user.id).await?;
    Ok(Json(dojo_public(&c)))
}

/// `GET /api/v1/integrations/defectdojo/exports`
pub async fn dojo_exports(State(s): State<AppState>) -> V1<Json<Vec<Value>>> {
    type Row = (Uuid, DateTime<Utc>, Option<String>, i32, String, String, String);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT e.id, e.at, COALESCE(u.display_name, u.username, 'automatycznie (po skanie)'), e.count, e.as_kind, e.status, e.message
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

#[cfg(test)]
mod dojo_tests {
    #[test]
    fn severity_from_score() {
        let s: Vec<_> = [95, 80, 79, 60, 59, 40, 39, 0].into_iter().map(super::dojo_severity).collect();
        assert_eq!(s, ["High", "High", "Medium", "Medium", "Low", "Low", "Info", "Info"]);
    }
}

#[derive(Deserialize)]
pub struct DojoExportBody {
    ids: Vec<Uuid>,
    #[serde(rename = "as", default)]
    as_kind: Option<String>,
}

/// DefectDojo severity from the ASI score (attack surface, not vulnerabilities: the score says
/// how much a finding deserves attention). Stated in each finding's description.
fn dojo_severity(score: i32) -> &'static str {
    match score {
        80.. => "High",
        60..=79 => "Medium",
        40..=59 => "Low",
        _ => "Info",
    }
}

fn dojo_description(f: &crate::v1::Finding) -> String {
    let evidence: Vec<String> = f.evidence.iter().filter_map(|e| e["snippet"].as_str().map(str::to_string)).collect();
    format!(
        "Kategoria: {}\nHost: {}{}\nUsługa: {}\nStatus zmiany: {}\nOcena ASI: {} (ważność w DefectDojo: ≥80 High, ≥60 Medium, ≥40 Low)\nPewność: {:.0}%\n\nDowody:\n- {}",
        f.category, f.ip, f.hostname.as_deref().map(|h| format!(" ({h})")).unwrap_or_default(),
        f.service_label.clone().unwrap_or_default(), f.change, f.effective_score(), f.confidence * 100.0, evidence.join("\n- ")
    )
}

pub(crate) struct DojoExported {
    pub export_id: Uuid,
    pub link: String,
    pub status: &'static str,
    pub message: String,
    pub sent: usize,
}

/// Send findings to DefectDojo: `finding` — as findings of a new test (Generic Findings Import
/// via `/api/v2/import-scan/`); `evidence` — one JSON file per finding attached to the
/// engagement (`/api/v2/engagements/{id}/files/`). Recorded in `defectdojo_exports`; exported
/// findings are marked in `finding_states.defectdojo`. `by_user` None = automatic export.
pub(crate) async fn export_findings(
    s: &AppState,
    by_user: Option<Uuid>,
    chosen: &[&crate::v1::Finding],
    as_kind: &str,
) -> V1<DojoExported> {
    let mut c = dojo_config(s).await?;
    if c.cfg["enabled"] != json!(true) {
        return Err(err(StatusCode::CONFLICT, "not_configured", "Integracja z DefectDojo jest wyłączona (Administracja → Integracje)."));
    }
    let (client, url, token) = dojo_client(&c)?;
    if c.cfg["engagement_id"].as_i64().is_none() {
        dojo_context(&client, &url, &token, &mut c.cfg)
            .await
            .map_err(|e| err(StatusCode::BAD_GATEWAY, "defectdojo_failed", format!("DefectDojo: {e}")))?;
        save_dojo(s, &c.cfg, None, by_user.unwrap_or_else(Uuid::nil)).await.ok();
    }
    let engagement = c.cfg["engagement_id"].as_i64().unwrap_or_default();
    let base = dojo_link_base(&url);
    let now = Utc::now();
    let (status, message, link, sent) = if as_kind == "evidence" {
        let mut sent = 0;
        let mut last_error = None;
        for f in chosen {
            let file = serde_json::to_vec_pretty(&json!({
                "title": f.title, "category": f.category, "ip": f.ip, "hostname": f.hostname, "port": f.port,
                "service": f.service_label, "technologies": f.technologies, "change": f.change, "score": f.effective_score(),
                "confidence": f.confidence, "evidence": f.evidence, "first_seen": f.first_seen, "last_seen": f.last_seen,
                "asi_finding_id": f.id,
            }))
            .map_err(fail)?;
            let title: String = format!("ASI: {} — {}", f.title, f.ip).chars().take(100).collect();
            let form = reqwest::multipart::Form::new().text("title", title).part(
                "file",
                reqwest::multipart::Part::bytes(file)
                    .file_name(format!("asi-{}.json", f.id))
                    .mime_str("application/json")
                    .map_err(fail)?,
            );
            match dojo_call(client.post(format!("{url}/api/v2/engagements/{engagement}/files/")).multipart(form), &token, "evidence").await {
                Ok(_) => sent += 1,
                Err(e) => last_error = Some(e),
            }
        }
        let status = match (sent, chosen.len()) {
            (0, _) => "failed",
            (a, b) if a < b => "partial",
            _ => "success",
        };
        let message = match &last_error {
            None => format!("Dodano {sent} załączników (evidence) do engagementu {engagement}"),
            Some(e) => format!("Dodano {sent} z {} załączników; ostatni błąd: {e}", chosen.len()),
        };
        (status, message, format!("{base}/engagement/{engagement}"), sent)
    } else {
        let findings: Vec<Value> = chosen
            .iter()
            .map(|f| {
                json!({
                    "title": f.title,
                    "description": dojo_description(f),
                    "severity": dojo_severity(f.effective_score()),
                    "date": now.format("%Y-%m-%d").to_string(),
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
            .text("test_title", format!("ASI {}", now.format("%Y-%m-%d %H:%M")))
            .part("file", reqwest::multipart::Part::bytes(file).file_name("asi-findings.json").mime_str("application/json").map_err(fail)?);
        match dojo_call(client.post(format!("{url}/api/v2/import-scan/")).multipart(form), &token, "import-scan").await {
            Ok(body) => {
                let test = body.get("test").and_then(Value::as_i64).or_else(|| body.get("test_id").and_then(Value::as_i64));
                let link = test.map(|t| format!("{base}/test/{t}")).unwrap_or_else(|| format!("{base}/engagement/{engagement}"));
                ("success", format!("Wysłano {} znalezisk do engagementu {engagement}", chosen.len()), link, chosen.len())
            }
            Err(e) => ("failed", format!("DefectDojo odrzucił import: {e}"), format!("{base}/engagement/{engagement}"), 0),
        }
    };
    let export_id: Uuid = sqlx::query_scalar(
        "INSERT INTO defectdojo_exports (by_user, count, as_kind, status, message, links) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(by_user)
    .bind(chosen.len() as i32)
    .bind(if as_kind == "evidence" { "evidence" } else { "finding" })
    .bind(status)
    .bind(&message)
    .bind(json!([link]))
    .fetch_one(&s.db)
    .await
    .map_err(fail)?;
    if status != "failed" {
        for f in chosen {
            let mark = json!({ "exported_at": now, "as": as_kind, "url": link });
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
            .bind(by_user)
            .execute(&s.db)
            .await
            .map_err(fail)?;
        }
    }
    Ok(DojoExported { export_id, link, status, message, sent })
}

/// `POST /api/v1/findings/defectdojo`
pub async fn dojo_export(
    State(s): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(b): Json<DojoExportBody>,
) -> V1<(Extension<Note>, Json<Value>)> {
    if b.ids.is_empty() || b.ids.len() > 500 {
        return Err(invalid("Wybierz od 1 do 500 znalezisk."));
    }
    let all = crate::v1::load_findings(&s.db, &s.config.data_key).await?;
    let chosen: Vec<&crate::v1::Finding> = all.iter().filter(|f| b.ids.contains(&f.id)).collect();
    if chosen.is_empty() {
        return Err(missing());
    }
    let as_kind = match b.as_kind.as_deref() {
        Some("evidence") => "evidence",
        _ => "finding",
    };
    let out = export_findings(&s, Some(user.id), &chosen, as_kind).await?;
    if out.status == "failed" {
        return Err(err(StatusCode::BAD_GATEWAY, "defectdojo_failed", out.message));
    }
    let note = Note {
        action: "finding.defectdojo_export",
        entity: "finding",
        entity_id: Some(out.export_id.to_string()),
        details: json!({ "count": chosen.len(), "sent": out.sent, "status": out.status, "as": as_kind }),
    };
    Ok((
        Extension(note),
        Json(json!({
            "exported": out.sent, "failed": chosen.len() - out.sent, "export_id": out.export_id,
            "links": chosen.iter().map(|f| json!({ "finding_id": f.id, "url": out.link })).collect::<Vec<_>>(),
        })),
    ))
}

/// After a finished run: send its new findings with score ≥ `min_score` when the dashboard's
/// "automatic export" is on. Findings already exported are skipped; errors are only logged
/// (and recorded in the export history) — the scan itself is never affected.
pub(crate) async fn auto_export(s: AppState, run_id: Uuid) {
    let c = match dojo_config(&s).await {
        Ok(c) => c,
        Err(_) => return,
    };
    if c.cfg["enabled"] != json!(true) || c.cfg["auto_export"] != json!(true) {
        return;
    }
    let min = c.cfg["min_score"].as_i64().unwrap_or(70) as i32;
    let as_kind = if c.cfg["export_as"] == json!("evidence") { "evidence" } else { "finding" };
    let scan: Option<Uuid> = match sqlx::query_scalar("SELECT scan_id FROM scan_runs WHERE id = $1").bind(run_id).fetch_optional(&s.db).await {
        Ok(v) => v,
        Err(e) => return tracing::warn!(%run_id, "defectdojo auto-export: {e}"),
    };
    let all = match crate::v1::load_findings(&s.db, &s.config.data_key).await {
        Ok(a) => a,
        Err((_, Json(e))) => return tracing::warn!(%run_id, "defectdojo auto-export: {}", e["error"]["message"]),
    };
    let chosen: Vec<&crate::v1::Finding> = all
        .iter()
        .filter(|f| Some(f.scan_id) == scan && f.effective_score() >= min && f.is_open() && f.defectdojo.is_none())
        .take(500)
        .collect();
    if chosen.is_empty() {
        return;
    }
    match export_findings(&s, None, &chosen, as_kind).await {
        Ok(out) => tracing::info!(%run_id, sent = out.sent, status = out.status, "defectdojo auto-export"),
        Err((_, Json(e))) => tracing::warn!(%run_id, "defectdojo auto-export failed: {}", e["error"]["message"]),
    }
}
