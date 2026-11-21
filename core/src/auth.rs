//! Authentication and authorization (PROJECT.md §10; F-01, F-14; tests T-01, T-02).
//!
//! - Passwords: Argon2id (12..=256 characters). Unknown logins are checked against a dummy
//!   hash, so timing does not reveal which usernames exist.
//! - Sessions: 32 random bytes from the OS, base64url; the database keeps only SHA-256.
//!   Accepted as `Authorization: Bearer` or the `asi_session` cookie (HttpOnly,
//!   SameSite=Strict, Path=/api). Cookie requests with unsafe methods need `X-ASI-CSRF: 1`.
//! - `gate`: one middleware over every route (deny by default, `rbac::ROUTES`), which also
//!   writes the audit row of each changing request and of each 401/403.
//! - Login limiter: 5 failures per login or 20 per IP in 15 minutes → 429.

use crate::api::{bad, internal, not_found, ApiError, ApiResult};
use crate::audit::{self, Event, Note, Outcome};
use crate::rbac::{self, Action, Role, Rule};
use crate::AppState;
use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2,
};
use axum::{
    extract::{ConnectInfo, FromRequestParts, MatchedPath, Path, RawPathParams, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const SESSION_COOKIE: &str = "asi_session";
pub const CSRF_HEADER: &str = "x-asi-csrf";
const PASSWORD_LEN: std::ops::RangeInclusive<usize> = 12..=256;

/// The signed-in user, put into request extensions by `gate`.
#[derive(Debug, Clone, Serialize)]
pub struct CurrentUser {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
    pub can_execute_scans: bool,
    #[serde(skip)]
    pub session_id: Uuid,
}

impl CurrentUser {
    pub fn can(&self, action: Action) -> bool {
        self.role.can(action, self.can_execute_scans)
    }
}

/// Client address (from the TCP connection), put into request extensions by `gate`.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub Option<IpAddr>);

// ---------- passwords and tokens ----------

fn check_password_policy(password: &str) -> Result<(), ApiError> {
    if !PASSWORD_LEN.contains(&password.chars().count()) {
        return Err(bad(format!(
            "password must be {}..={} characters",
            PASSWORD_LEN.start(),
            PASSWORD_LEN.end()
        )));
    }
    Ok(())
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?
        .to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
}

/// Checked when the login does not exist, so a miss costs the same time as a wrong password.
static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| hash_password("not a real password, timing only").expect("argon2 works"));

/// Argon2 is deliberately slow: keep it off the async workers.
async fn hash_blocking(password: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || hash_password(&password)).await.map_err(internal)?.map_err(internal)
}

fn new_token() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("OS RNG: {e}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Session token from `Authorization: Bearer` (preferred) or the session cookie.
/// Returns the token and whether it came from the cookie. Never from the query string.
fn session_token(headers: &HeaderMap) -> Option<(String, bool)> {
    if let Some(auth) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        let (scheme, token) = auth.trim().split_once(' ')?;
        let token = token.trim();
        return (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then(|| (token.to_string(), false));
    }
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, value)| *name == SESSION_COOKIE && !value.is_empty())
        .map(|(_, value)| (value.to_string(), true))
}

fn session_cookie(token: &str, max_age_secs: i64, secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/api; Max-Age={max_age_secs}{secure}"
    ))
    .expect("cookie value is ASCII")
}

async fn session_user(db: &sqlx::PgPool, token: &str) -> sqlx::Result<Option<CurrentUser>> {
    let row: Option<(Uuid, Uuid, String, Role, bool)> = sqlx::query_as(
        "UPDATE sessions s SET last_seen_at = now()
         FROM users u
         WHERE s.token_hash = $1 AND u.id = s.user_id AND s.revoked_at IS NULL AND s.expires_at > now()
           AND NOT u.disabled
         RETURNING s.id, u.id, u.username, u.role, u.can_execute_scans",
    )
    .bind(token_hash(token))
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(session_id, id, username, role, can_execute_scans)| CurrentUser {
        id,
        username,
        role,
        can_execute_scans,
        session_id,
    }))
}

async fn revoke_sessions(conn: &mut sqlx::PgConnection, user_id: Uuid) -> sqlx::Result<()> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user_id)
        .execute(conn)
        .await
        .map(drop)
}

// ---------- login limiter ----------

const LIMIT_WINDOW: Duration = Duration::from_secs(15 * 60);
const LIMIT_PER_LOGIN: u32 = 5;
const LIMIT_PER_IP: u32 = 20;

/// Failed logins per username and per client IP, in memory (one core instance in the MVP).
#[derive(Default)]
pub struct LoginLimiter {
    failures: Mutex<HashMap<String, (Instant, u32)>>,
}

impl LoginLimiter {
    fn keys(username: &str, ip: Option<IpAddr>) -> [(String, u32); 2] {
        [
            (format!("u:{username}"), LIMIT_PER_LOGIN),
            (format!("ip:{}", ip.map_or("unknown".into(), |ip| ip.to_string())), LIMIT_PER_IP),
        ]
    }

    /// True while the login or the IP is over its limit; it lasts until the window ends.
    pub fn blocked(&self, username: &str, ip: Option<IpAddr>) -> bool {
        let map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        Self::keys(username, ip).iter().any(|(k, limit)| {
            map.get(k).is_some_and(|(since, n)| since.elapsed() < LIMIT_WINDOW && n >= limit)
        })
    }

    pub fn failure(&self, username: &str, ip: Option<IpAddr>) {
        let mut map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > 10_000 {
            map.retain(|_, (since, _)| since.elapsed() < LIMIT_WINDOW);
        }
        for (k, _) in Self::keys(username, ip) {
            let entry = map.entry(k).or_insert((Instant::now(), 0));
            if entry.0.elapsed() >= LIMIT_WINDOW {
                *entry = (Instant::now(), 0);
            }
            entry.1 += 1;
        }
    }

    /// A successful login clears the login's counter (not the IP's).
    pub fn success(&self, username: &str) {
        let mut map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(&format!("u:{username}"));
    }
}

// ---------- gate ----------

fn deny(status: StatusCode) -> Response {
    let detail = if status == StatusCode::UNAUTHORIZED { "authentication required" } else { "forbidden" };
    (status, Json(json!({ "detail": detail }))).into_response()
}

fn is_safe(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Deny-by-default middleware, installed with `route_layer` at the end of `api::router`
/// so it covers every route. Rules come from `rbac::ROUTES`; a route missing there is
/// admin-only and logged.
pub async fn gate(State(s): State<AppState>, req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    let ip = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    parts.extensions.insert(ClientIp(ip));
    let method = parts.method.clone();
    let Some(path) = parts.extensions.get::<MatchedPath>().map(|p| p.as_str().to_string()) else {
        // route_layer only runs on matched routes; refuse rather than guess.
        return deny(StatusCode::FORBIDDEN);
    };
    let rule = rbac::rule(method.as_str(), &path);
    if rule == Some(Rule::Public) {
        return next.run(Request::from_parts(parts, body)).await;
    }
    let params: Map<String, Value> = match RawPathParams::from_request_parts(&mut parts, &()).await {
        Ok(p) => p.iter().map(|(k, v)| (k.to_string(), Value::String(v.chars().take(128).collect()))).collect(),
        Err(_) => Map::new(),
    };
    let audit_row = |user: Option<&CurrentUser>, status: StatusCode, note: Option<Note>| {
        let (action, entity, entity_id, mut details) = match note {
            Some(n) => (n.action.to_string(), n.entity.to_string(), n.entity_id, n.details),
            None => (format!("{method} {path}"), "route".to_string(), None, json!({})),
        };
        if !params.is_empty()
            && let Value::Object(d) = &mut details
        {
            d.insert("params".into(), Value::Object(params.clone()));
        }
        Event {
            user_id: user.map(|u| u.id),
            action,
            entity,
            entity_id,
            details,
            ip,
            request: Some((method.to_string(), path.clone())),
            status: Some(status.as_u16()),
            outcome: Outcome::of_status(status.as_u16()),
        }
    };

    let token = session_token(&parts.headers);
    let user = match &token {
        Some((t, _)) => match session_user(&s.db, t).await {
            Ok(u) => u,
            Err(e) => return internal(e).into_response(),
        },
        None => None,
    };
    let Some(user) = user else {
        audit::record(&s.db, audit_row(None, StatusCode::UNAUTHORIZED, None)).await;
        return deny(StatusCode::UNAUTHORIZED);
    };
    // CSRF: a browser sends the cookie on its own; it cannot add this header cross-site.
    let via_cookie = token.is_some_and(|(_, c)| c);
    let csrf_ok = !via_cookie
        || is_safe(&method)
        || parts.headers.get(CSRF_HEADER).is_some_and(|v| v.as_bytes() == b"1");
    let allowed = match rule {
        Some(Rule::Public | Rule::Authenticated) => true,
        Some(Rule::Requires(action)) => user.can(action),
        None => {
            tracing::warn!(%method, %path, "route missing from rbac::ROUTES — admin only");
            user.role == Role::Admin
        }
    };
    if !csrf_ok || !allowed {
        audit::record(&s.db, audit_row(Some(&user), StatusCode::FORBIDDEN, None)).await;
        return deny(StatusCode::FORBIDDEN);
    }

    parts.extensions.insert(user.clone());
    let mut response = next.run(Request::from_parts(parts, body)).await;
    let note = response.extensions_mut().remove::<Note>();
    if !is_safe(&method) || note.is_some() {
        audit::record(&s.db, audit_row(Some(&user), response.status(), note)).await;
    }
    response
}


// ---------- auth API ----------

#[derive(Deserialize)]
pub struct LoginBody {
    username: String,
    password: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct UserOut {
    id: Uuid,
    username: String,
    role: Role,
    disabled: bool,
    can_execute_scans: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_login_at: Option<DateTime<Utc>>,
}

const USER_COLUMNS: &str = "id, username, role, disabled, can_execute_scans, created_at, updated_at, last_login_at";

/// Logins: 3..=64 of a-z 0-9 . _ - (lower-cased), starting with a letter or digit.
fn normalize_username(name: &str) -> Result<String, ApiError> {
    let name = name.trim().to_ascii_lowercase();
    let ok = (3..=64).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && name.as_bytes()[0].is_ascii_alphanumeric();
    if ok { Ok(name) } else { Err(bad("username must be 3..=64 characters: a-z, 0-9, '.', '_', '-'")) }
}

/// `POST /api/auth/login` → `{token, expires_at, user}` + session cookie.
pub async fn login(State(s): State<AppState>, Extension(ClientIp(ip)): Extension<ClientIp>, Json(b): Json<LoginBody>) -> Response {
    // Same reply for every failure: no hint whether the login exists.
    let invalid = || (StatusCode::UNAUTHORIZED, Json(json!({ "detail": "invalid credentials" }))).into_response();
    let username = b.username.trim().to_ascii_lowercase();
    let shown: String = username.chars().take(64).collect();
    let event = |user_id: Option<Uuid>, status: StatusCode, outcome: Outcome| Event {
        user_id,
        action: "auth.login".into(),
        entity: "user".into(),
        entity_id: user_id.map(|id| id.to_string()),
        details: json!({ "username": shown }),
        ip,
        request: Some(("POST".into(), "/api/auth/login".into())),
        status: Some(status.as_u16()),
        outcome,
    };

    if s.limiter.blocked(&username, ip) {
        audit::record(&s.db, event(None, StatusCode::TOO_MANY_REQUESTS, Outcome::Denied)).await;
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "detail": "too many failed logins, try later" })))
            .into_response();
    }
    if b.password.chars().count() > *PASSWORD_LEN.end() {
        s.limiter.failure(&username, ip);
        return invalid();
    }

    let row: Option<(Uuid, String, String, Role, bool, bool)> = match sqlx::query_as(
        "SELECT id, username, password_hash, role, can_execute_scans, disabled FROM users WHERE username = $1",
    )
    .bind(&username)
    .fetch_optional(&s.db)
    .await
    {
        Ok(r) => r,
        Err(e) => return internal(e).into_response(),
    };
    let hash = match &row {
        Some((_, _, h, _, _, false)) => h.clone(),
        _ => DUMMY_HASH.clone(),
    };
    let password = b.password;
    let verified = tokio::task::spawn_blocking(move || verify_password(&password, &hash)).await.unwrap_or(false);
    let Some((user_id, username, _, role, can_execute_scans, false)) = row.filter(|_| verified) else {
        s.limiter.failure(&username, ip);
        audit::record(&s.db, event(None, StatusCode::UNAUTHORIZED, Outcome::Failure)).await;
        return invalid();
    };
    s.limiter.success(&username);

    let token = match new_token() {
        Ok(t) => t,
        Err(e) => return internal(e).into_response(),
    };
    let ttl_hours = s.config.session_ttl_hours;
    let session: Result<DateTime<Utc>, sqlx::Error> = async {
        let mut tx = s.db.begin().await?;
        let expires_at: DateTime<Utc> = sqlx::query_scalar(
            "INSERT INTO sessions (user_id, token_hash, ip, expires_at)
             VALUES ($1, $2, $3::inet, now() + make_interval(hours => $4)) RETURNING expires_at",
        )
        .bind(user_id)
        .bind(token_hash(&token))
        .bind(ip.map(|ip| ip.to_string()))
        .bind(ttl_hours as i32)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1").bind(user_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(expires_at)
    }
    .await;
    let expires_at = match session {
        Ok(t) => t,
        Err(e) => return internal(e).into_response(),
    };
    audit::record(&s.db, event(Some(user_id), StatusCode::OK, Outcome::Success)).await;

    let user = json!({ "id": user_id, "username": username, "role": role, "can_execute_scans": can_execute_scans });
    let mut response = Json(json!({ "token": token, "expires_at": expires_at, "user": user })).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&token, ttl_hours * 3600, s.config.cookie_secure));
    response
}

/// `POST /api/auth/logout` — revokes the current session and clears the cookie.
pub async fn logout(State(s): State<AppState>, Extension(user): Extension<CurrentUser>) -> Response {
    if let Err(e) = sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
        .bind(user.session_id)
        .execute(&s.db)
        .await
    {
        return internal(e).into_response();
    }
    let note = Note::new("auth.logout", "user", user.id, json!({}));
    let mut response = (Extension(note), Json(json!({ "logged_out": true }))).into_response();
    response.headers_mut().insert(header::SET_COOKIE, session_cookie("", 0, s.config.cookie_secure));
    response
}

/// `GET /api/auth/me`
pub async fn me(Extension(user): Extension<CurrentUser>) -> Json<Value> {
    let rights: Vec<Action> = Action::ALL.into_iter().filter(|a| user.can(*a)).collect();
    Json(json!({ "user": user, "rights": rights }))
}

// ---------- users API (admin) ----------

/// `GET /api/users`
pub async fn list_users(State(s): State<AppState>) -> ApiResult<Vec<UserOut>> {
    let rows = sqlx::query_as::<_, UserOut>(sqlx::AssertSqlSafe(format!(
        "SELECT {USER_COLUMNS} FROM users ORDER BY username"
    )))
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct CreateUser {
    username: String,
    password: String,
    #[serde(default = "viewer")]
    role: Role,
    can_execute_scans: Option<bool>,
}

fn viewer() -> Role {
    Role::Viewer
}

/// `POST /api/users`
pub async fn create_user(
    State(s): State<AppState>,
    Json(b): Json<CreateUser>,
) -> Result<(StatusCode, Extension<Note>, Json<UserOut>), ApiError> {
    let username = normalize_username(&b.username)?;
    check_password_policy(&b.password)?;
    let flag = b.role.execute_flag(b.can_execute_scans.unwrap_or_else(|| b.role.default_execute_flag()));
    let hash = hash_blocking(b.password).await?;
    let user = sqlx::query_as::<_, UserOut>(sqlx::AssertSqlSafe(format!(
        "INSERT INTO users (username, password_hash, role, can_execute_scans) VALUES ($1, $2, $3, $4)
         ON CONFLICT (username) DO NOTHING RETURNING {USER_COLUMNS}"
    )))
    .bind(&username)
    .bind(hash)
    .bind(b.role)
    .bind(flag)
    .fetch_optional(&s.db)
    .await
    .map_err(internal)?
    .ok_or_else(|| (StatusCode::CONFLICT, Json(json!({ "detail": "username already exists" }))))?;
    let note = Note::new(
        "user.create",
        "user",
        user.id,
        json!({ "username": username, "role": b.role, "can_execute_scans": flag }),
    );
    Ok((StatusCode::CREATED, Extension(note), Json(user)))
}

#[derive(Deserialize)]
pub struct PatchUser {
    role: Option<Role>,
    password: Option<String>,
    disabled: Option<bool>,
    can_execute_scans: Option<bool>,
}

/// Refuse a change that would leave no active admin. Locks the admin rows, so two
/// concurrent demotions cannot both pass.
async fn keep_an_admin(conn: &mut sqlx::PgConnection, target: Uuid) -> Result<(), ApiError> {
    let admins: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE role = 'admin' AND NOT disabled ORDER BY id FOR UPDATE")
            .fetch_all(conn)
            .await
            .map_err(internal)?;
    if admins.iter().all(|id| *id == target) {
        return Err((StatusCode::CONFLICT, Json(json!({ "detail": "the last active admin cannot be removed" }))));
    }
    Ok(())
}

/// `PATCH /api/users/{id}` — role, password, disabled, can_execute_scans. Any change of
/// role, password or disabled revokes the user's sessions.
pub async fn update_user(
    State(s): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(b): Json<PatchUser>,
) -> Result<(Extension<Note>, Json<UserOut>), ApiError> {
    let hash = match b.password {
        Some(p) => {
            check_password_policy(&p)?;
            Some(hash_blocking(p).await?)
        }
        None => None,
    };
    let mut tx = s.db.begin().await.map_err(internal)?;
    let (role, flag, disabled): (Role, bool, bool) =
        sqlx::query_as("SELECT role, can_execute_scans, disabled FROM users WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?
            .ok_or_else(not_found)?;
    let new_role = b.role.unwrap_or(role);
    let new_disabled = b.disabled.unwrap_or(disabled);
    if id == me.id && (new_role != role || new_disabled) {
        return Err(bad("you cannot change your own role or disable yourself"));
    }
    if role == Role::Admin && !disabled && (new_role != Role::Admin || new_disabled) {
        keep_an_admin(&mut tx, id).await?;
    }
    let new_flag = new_role.execute_flag(b.can_execute_scans.unwrap_or(flag));
    let user = sqlx::query_as::<_, UserOut>(sqlx::AssertSqlSafe(format!(
        "UPDATE users SET role = $2, can_execute_scans = $3, disabled = $4,
             password_hash = COALESCE($5, password_hash), updated_at = now()
         WHERE id = $1 RETURNING {USER_COLUMNS}"
    )))
    .bind(id)
    .bind(new_role)
    .bind(new_flag)
    .bind(new_disabled)
    .bind(&hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(internal)?;
    if new_role != role || new_disabled != disabled || hash.is_some() {
        revoke_sessions(&mut tx, id).await.map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    let note = Note::new(
        "user.update",
        "user",
        id,
        json!({
            "role": new_role, "can_execute_scans": new_flag, "disabled": new_disabled,
            "password_changed": hash.is_some(),
        }),
    );
    Ok((Extension(note), Json(user)))
}

/// `DELETE /api/users/{id}` — users are disabled, never deleted (audit rows refer to them).
pub async fn disable_user(
    State(s): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> Result<(Extension<Note>, Json<Value>), ApiError> {
    if id == me.id {
        return Err(bad("you cannot disable yourself"));
    }
    let mut tx = s.db.begin().await.map_err(internal)?;
    let (role, disabled): (Role, bool) = sqlx::query_as("SELECT role, disabled FROM users WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?
        .ok_or_else(not_found)?;
    if role == Role::Admin && !disabled {
        keep_an_admin(&mut tx, id).await?;
    }
    sqlx::query("UPDATE users SET disabled = true, updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    revoke_sessions(&mut tx, id).await.map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    let note = Note::new("user.disable", "user", id, json!({}));
    Ok((Extension(note), Json(json!({ "id": id, "disabled": true }))))
}

// ---------- bootstrap ----------

/// Make sure an active admin exists: if none, create (or restore) `ASI_ADMIN_USER` with
/// `ASI_ADMIN_PASSWORD`. Without a usable password the service refuses to start.
pub async fn bootstrap_admin(db: &sqlx::PgPool, config: &crate::config::Config) -> anyhow::Result<()> {
    let has_admin: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin' AND NOT disabled)")
        .fetch_one(db)
        .await?;
    if has_admin {
        return Ok(());
    }
    let username = normalize_username(&config.admin_user)
        .map_err(|_| anyhow::anyhow!("ASI_ADMIN_USER is not a valid username"))?;
    let password = config
        .admin_password
        .as_deref()
        .filter(|p| PASSWORD_LEN.contains(&p.chars().count()))
        .ok_or_else(|| {
            anyhow::anyhow!("no active admin: set ASI_ADMIN_PASSWORD (12..=256 characters) to create '{username}'")
        })?;
    let hash = tokio::task::spawn_blocking({
        let p = password.to_string();
        move || hash_password(&p)
    })
    .await??;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role, can_execute_scans) VALUES ($1, $2, 'admin', true)
         ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin',
             can_execute_scans = true, disabled = false, updated_at = now()
         RETURNING id",
    )
    .bind(&username)
    .bind(hash)
    .fetch_one(db)
    .await?;
    audit::record(
        db,
        Event {
            user_id: Some(id),
            action: "user.bootstrap".into(),
            entity: "user".into(),
            entity_id: Some(id.to_string()),
            details: json!({ "username": username }),
            ip: None,
            request: None,
            status: None,
            outcome: Outcome::Success,
        },
    )
    .await;
    tracing::info!(%username, "created the first admin from ASI_ADMIN_USER / ASI_ADMIN_PASSWORD");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"), "{h}");
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("correct horse batterY", &h));
        assert!(!verify_password("x", "not a phc string"));
    }

    #[test]
    fn tokens_are_random_and_hashed() {
        let (a, b) = (new_token().unwrap(), new_token().unwrap());
        assert_ne!(a, b);
        assert_eq!(a.len(), 43, "32 bytes base64url without padding");
        assert_eq!(token_hash(&a).len(), 32);
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn token_sources() {
        assert_eq!(session_token(&headers(&[("authorization", "Bearer abc")])), Some(("abc".into(), false)));
        assert_eq!(session_token(&headers(&[("authorization", "Basic abc")])), None);
        assert_eq!(session_token(&headers(&[("cookie", "a=1; asi_session=xyz; b=2")])), Some(("xyz".into(), true)));
        assert_eq!(session_token(&headers(&[("cookie", "asi_session=")])), None);
        assert_eq!(
            session_token(&headers(&[("authorization", "Bearer t"), ("cookie", "asi_session=c")])),
            Some(("t".into(), false)),
            "an explicit bearer token wins"
        );
        assert_eq!(session_token(&headers(&[])), None);
    }

    #[test]
    fn cookie_attributes() {
        let c = session_cookie("tok", 3600, true);
        let c = c.to_str().unwrap();
        for part in ["asi_session=tok", "HttpOnly", "SameSite=Strict", "Path=/api", "Max-Age=3600", "Secure"] {
            assert!(c.contains(part), "{c} lacks {part}");
        }
        assert!(!session_cookie("tok", 3600, false).to_str().unwrap().contains("Secure"));
    }

    #[test]
    fn usernames() {
        assert_eq!(normalize_username(" Admin ").ok(), Some("admin".into()));
        assert!(normalize_username("ab").is_err());
        assert!(normalize_username("-admin").is_err());
        assert!(normalize_username("ad min").is_err());
        assert!(normalize_username("jan.kowalski_2").is_ok());
    }

    #[test]
    fn limiter_blocks_and_clears() {
        let l = LoginLimiter::default();
        let ip: Option<IpAddr> = Some("10.0.0.1".parse().unwrap());
        for _ in 0..LIMIT_PER_LOGIN {
            assert!(!l.blocked("alice", ip));
            l.failure("alice", ip);
        }
        assert!(l.blocked("alice", ip), "login over its limit");
        assert!(!l.blocked("bob", Some("10.0.0.2".parse().unwrap())), "others unaffected");
        l.success("alice");
        assert!(!l.blocked("alice", ip));
        for i in 0..LIMIT_PER_IP {
            l.failure(&format!("user{i}"), ip);
        }
        assert!(l.blocked("carol", ip), "IP over its limit blocks every login from it");
    }
}
