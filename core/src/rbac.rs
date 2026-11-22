//! RBAC — the four roles required by the task (PROJECT.md §10, review §7.2) and the
//! permission table of every API route. Enforced on the server by `auth::gate`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// 1. Administracja — everything, incl. users and integrations.
    Admin,
    /// 2. Dodawanie/usuwanie/modyfikacja.
    Editor,
    /// 3. Modyfikacja i odczyt (no create/delete).
    Modifier,
    /// 4. Odczyt.
    Viewer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Read,
    /// Decrypted evidence: banners, headers, cookies, TLS (F-14).
    ReadEvidence,
    Create,
    Update,
    Delete,
    /// Start or cancel scan runs — active network impact, a separate right (`scan.execute`).
    ExecuteScan,
    ManageUsers,
    ManageIntegrations,
    ReadAudit,
}

impl Action {
    pub const ALL: [Action; 9] = [
        Action::Read,
        Action::ReadEvidence,
        Action::Create,
        Action::Update,
        Action::Delete,
        Action::ExecuteScan,
        Action::ManageUsers,
        Action::ManageIntegrations,
        Action::ReadAudit,
    ];
}

impl Role {
    /// `can_execute_scans` is the per-user `scan.execute` grant; it only matters for
    /// editors and modifiers (admins always have it, viewers never).
    pub fn can(self, action: Action, can_execute_scans: bool) -> bool {
        use Action::*;
        match self {
            Role::Admin => true,
            Role::Editor => {
                matches!(action, Read | ReadEvidence | Create | Update | Delete)
                    || (action == ExecuteScan && can_execute_scans)
            }
            Role::Modifier => {
                matches!(action, Read | ReadEvidence | Update) || (action == ExecuteScan && can_execute_scans)
            }
            Role::Viewer => action == Read,
        }
    }

    /// `can_execute_scans` given to a new user when the request does not say.
    pub fn default_execute_flag(self) -> bool {
        matches!(self, Role::Admin | Role::Editor)
    }

    /// The flag as stored: viewers can never execute scans.
    pub fn execute_flag(self, requested: bool) -> bool {
        self != Role::Viewer && requested
    }
}

/// Who may call a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// No session required.
    Public,
    /// Any signed-in user.
    Authenticated,
    /// A signed-in user whose role grants the action.
    Requires(Action),
}

use Action::*;
use Rule::{Authenticated, Public, Requires};

/// (method, axum route template, rule) for every route of `api::router`. Deny by default:
/// a matched route missing here is admin-only and logged (`auth::gate`). Handlers add
/// finer checks: `POST /api/scans` with `start` also needs ExecuteScan, evidence in
/// findings/diff needs ReadEvidence, enabling or retuning a scheduled scan needs ExecuteScan.
pub const ROUTES: &[(&str, &str, Rule)] = &[
    ("GET", "/api/health", Public),
    ("POST", "/api/auth/login", Public),
    ("POST", "/api/auth/logout", Authenticated),
    ("GET", "/api/auth/me", Authenticated),
    ("GET", "/api/tools", Requires(Read)),
    ("GET", "/api/targets", Requires(Read)),
    ("POST", "/api/targets", Requires(Create)),
    ("PATCH", "/api/targets/{id}", Requires(Update)),
    ("DELETE", "/api/targets/{id}", Requires(Delete)),
    ("GET", "/api/scans", Requires(Read)),
    ("POST", "/api/scans", Requires(Create)),
    ("GET", "/api/scans/{id}", Requires(Read)),
    ("PATCH", "/api/scans/{id}", Requires(Update)),
    ("DELETE", "/api/scans/{id}", Requires(Delete)),
    ("POST", "/api/scans/{id}/run", Requires(ExecuteScan)),
    ("GET", "/api/scans/{id}/runs", Requires(Read)),
    ("GET", "/api/scans/{id}/annotations", Requires(Read)),
    ("PUT", "/api/scans/{id}/annotations", Requires(Update)),
    ("DELETE", "/api/scans/{id}/annotations/{annotation_id}", Requires(Delete)),
    ("GET", "/api/scans/{id}/annotations/{annotation_id}/history", Requires(Read)),
    ("GET", "/api/runs/{id}", Requires(Read)),
    ("GET", "/api/runs/{id}/findings", Requires(Read)),
    ("GET", "/api/runs/{id}/diff", Requires(Read)),
    ("POST", "/api/runs/{id}/cancel", Requires(ExecuteScan)),
    ("GET", "/api/users", Requires(ManageUsers)),
    ("POST", "/api/users", Requires(ManageUsers)),
    ("PATCH", "/api/users/{id}", Requires(ManageUsers)),
    ("DELETE", "/api/users/{id}", Requires(ManageUsers)),
    ("GET", "/api/audit", Requires(ReadAudit)),
    // Dashboard contract (/api/v1, v1.rs).
    ("POST", "/api/v1/auth/login", Public),
    ("POST", "/api/v1/auth/logout", Authenticated),
    ("GET", "/api/v1/auth/me", Authenticated),
    ("GET", "/api/v1/dashboard/summary", Requires(Read)),
    ("GET", "/api/v1/dashboard/top-findings", Requires(Read)),
    ("GET", "/api/v1/dashboard/changes-timeline", Requires(Read)),
    ("GET", "/api/v1/dashboard/availability", Requires(Read)),
    ("GET", "/api/v1/dashboard/technologies", Requires(Read)),
    ("GET", "/api/v1/dashboard/address-map", Requires(Read)),
    ("GET", "/api/v1/search", Requires(Read)),
    ("GET", "/api/v1/tags", Authenticated),
    ("GET", "/api/v1/targets", Requires(Read)),
    ("POST", "/api/v1/targets", Requires(Create)),
    ("GET", "/api/v1/targets/export", Requires(Read)),
    ("POST", "/api/v1/targets/import", Requires(Create)),
    ("POST", "/api/v1/targets/bulk", Requires(Update)),
    ("GET", "/api/v1/targets/{id}", Requires(Read)),
    ("PATCH", "/api/v1/targets/{id}", Requires(Update)),
    ("DELETE", "/api/v1/targets/{id}", Requires(Delete)),
    ("GET", "/api/v1/scans", Requires(Read)),
    ("POST", "/api/v1/scans", Requires(ExecuteScan)),
    ("POST", "/api/v1/scans/estimate", Requires(Read)),
    ("POST", "/api/v1/scans/import", Requires(Create)),
    ("GET", "/api/v1/scans/{id}", Requires(Read)),
    ("PATCH", "/api/v1/scans/{id}", Requires(Update)),
    ("DELETE", "/api/v1/scans/{id}", Requires(Delete)),
    ("GET", "/api/v1/scans/{id}/batches", Requires(Read)),
    ("GET", "/api/v1/scans/{id}/logs", Requires(Read)),
    ("GET", "/api/v1/scans/{id}/events", Requires(Read)),
    ("GET", "/api/v1/scans/{id}/export", Requires(Read)),
    ("POST", "/api/v1/scans/{id}/{action}", Requires(ExecuteScan)),
    ("GET", "/api/v1/profiles", Requires(Read)),
    ("POST", "/api/v1/profiles", Requires(Create)),
    ("PATCH", "/api/v1/profiles/{id}", Requires(Update)),
    ("DELETE", "/api/v1/profiles/{id}", Requires(Delete)),
    ("GET", "/api/v1/schedules", Requires(Read)),
    ("POST", "/api/v1/schedules", Requires(Create)),
    ("PATCH", "/api/v1/schedules/{id}", Requires(Update)),
    ("DELETE", "/api/v1/schedules/{id}", Requires(Delete)),
    ("GET", "/api/v1/hosts", Requires(Read)),
    ("GET", "/api/v1/hosts/unstable", Requires(Read)),
    ("GET", "/api/v1/hosts/{id}", Requires(Read)),
    ("PATCH", "/api/v1/hosts/{id}", Requires(Update)),
    ("DELETE", "/api/v1/hosts/{id}/overrides/{field}", Requires(Update)),
    ("GET", "/api/v1/hosts/{id}/history", Requires(Read)),
    ("POST", "/api/v1/hosts/{id}/recheck", Requires(ExecuteScan)),
    ("GET", "/api/v1/services", Requires(Read)),
    ("GET", "/api/v1/services/{id}", Requires(Read)),
    ("PATCH", "/api/v1/services/{id}", Requires(Update)),
    ("POST", "/api/v1/services/{id}/cookies/{name}/reveal", Requires(ReadEvidence)),
    ("GET", "/api/v1/service-groups", Requires(Read)),
    ("GET", "/api/v1/diffs", Requires(Read)),
    ("POST", "/api/v1/findings/bulk", Requires(Update)),
    ("GET", "/api/v1/users", Requires(ManageUsers)),
    ("POST", "/api/v1/users", Requires(ManageUsers)),
    ("PATCH", "/api/v1/users/{id}", Requires(ManageUsers)),
    ("DELETE", "/api/v1/users/{id}", Requires(ManageUsers)),
    ("GET", "/api/v1/roles", Requires(ManageUsers)),
    ("GET", "/api/v1/permissions", Requires(ManageUsers)),
    ("POST", "/api/v1/roles", Requires(ManageUsers)),
    ("PATCH", "/api/v1/roles/{id}", Requires(ManageUsers)),
    ("DELETE", "/api/v1/roles/{id}", Requires(ManageUsers)),
    ("GET", "/api/v1/settings", Requires(ManageIntegrations)),
    ("PATCH", "/api/v1/settings", Requires(ManageIntegrations)),
    ("GET", "/api/v1/security/encryption", Requires(ManageIntegrations)),
    ("POST", "/api/v1/security/encryption/rotate", Requires(ManageIntegrations)),
    ("GET", "/api/v1/engines", Requires(ManageIntegrations)),
    ("GET", "/api/v1/integrations/defectdojo", Requires(ManageIntegrations)),
    ("PUT", "/api/v1/integrations/defectdojo", Requires(ManageIntegrations)),
    ("POST", "/api/v1/integrations/defectdojo/test", Requires(ManageIntegrations)),
    ("GET", "/api/v1/integrations/defectdojo/exports", Requires(ManageIntegrations)),
    ("GET", "/api/v1/findings", Requires(Read)),
    ("GET", "/api/v1/findings/export", Requires(Read)),
    ("POST", "/api/v1/findings/defectdojo", Requires(ManageIntegrations)),
    ("GET", "/api/v1/findings/{id}", Requires(Read)),
    ("PATCH", "/api/v1/findings/{id}", Requires(Update)),
    ("GET", "/api/v1/audit", Requires(ReadAudit)),
    ("GET", "/api/v1/signatures", Requires(Read)),
    ("POST", "/api/v1/signatures", Requires(Create)),
    ("POST", "/api/v1/signatures/test", Requires(Update)),
    ("GET", "/api/v1/signatures/export", Requires(Read)),
    ("POST", "/api/v1/signatures/import", Requires(Create)),
    ("GET", "/api/v1/signatures/{id}", Requires(Read)),
    ("PATCH", "/api/v1/signatures/{id}", Requires(Update)),
    ("DELETE", "/api/v1/signatures/{id}", Requires(Delete)),
];

/// Dashboard permissions (frontend/src/lib/api/types.ts `PERMISSIONS`), the vocabulary of
/// custom roles. Same order as the frontend.
pub const PERMISSIONS: [&str; 41] = [
    "dashboard:read", "targets:read", "targets:create", "targets:update", "targets:delete",
    "targets:import", "targets:export", "scans:read", "scans:create", "scans:update",
    "scans:delete", "scans:control", "scans:import", "scans:export", "schedules:read",
    "schedules:create", "schedules:update", "schedules:delete", "assets:read", "assets:update",
    "assets:recheck", "findings:read", "findings:update", "findings:export", "findings:defectdojo",
    "changes:read", "signatures:read", "signatures:create", "signatures:update", "signatures:delete",
    "signatures:test", "sensitive:reveal", "users:read", "users:manage", "roles:read",
    "roles:manage", "integrations:read", "integrations:manage", "audit:read", "settings:read",
    "settings:manage",
];

/// Permission a custom role needs for each `/api/v1` route (the dashboard contract's endpoint
/// list). Built-in roles keep the action matrix of [`Role::can`].
pub const V1_PERMS: &[(&str, &str, &str)] = &[
    ("GET", "/api/v1/dashboard/summary", "dashboard:read"),
    ("GET", "/api/v1/dashboard/top-findings", "findings:read"),
    ("GET", "/api/v1/dashboard/changes-timeline", "changes:read"),
    ("GET", "/api/v1/dashboard/availability", "changes:read"),
    ("GET", "/api/v1/dashboard/technologies", "assets:read"),
    ("GET", "/api/v1/dashboard/address-map", "assets:read"),
    ("GET", "/api/v1/search", "dashboard:read"),
    ("GET", "/api/v1/targets", "targets:read"),
    ("POST", "/api/v1/targets", "targets:create"),
    ("GET", "/api/v1/targets/{id}", "targets:read"),
    ("PATCH", "/api/v1/targets/{id}", "targets:update"),
    ("DELETE", "/api/v1/targets/{id}", "targets:delete"),
    ("POST", "/api/v1/targets/bulk", "targets:update"),
    ("POST", "/api/v1/targets/import", "targets:import"),
    ("GET", "/api/v1/targets/export", "targets:export"),
    ("GET", "/api/v1/scans", "scans:read"),
    ("POST", "/api/v1/scans", "scans:create"),
    ("POST", "/api/v1/scans/estimate", "scans:read"),
    ("POST", "/api/v1/scans/import", "scans:import"),
    ("GET", "/api/v1/scans/{id}", "scans:read"),
    ("PATCH", "/api/v1/scans/{id}", "scans:update"),
    ("DELETE", "/api/v1/scans/{id}", "scans:delete"),
    ("POST", "/api/v1/scans/{id}/{action}", "scans:control"),
    ("GET", "/api/v1/scans/{id}/batches", "scans:read"),
    ("GET", "/api/v1/scans/{id}/logs", "scans:read"),
    ("GET", "/api/v1/scans/{id}/events", "scans:read"),
    ("GET", "/api/v1/scans/{id}/export", "scans:export"),
    ("GET", "/api/v1/profiles", "scans:read"),
    ("POST", "/api/v1/profiles", "scans:create"),
    ("PATCH", "/api/v1/profiles/{id}", "scans:update"),
    ("DELETE", "/api/v1/profiles/{id}", "scans:delete"),
    ("GET", "/api/v1/schedules", "schedules:read"),
    ("POST", "/api/v1/schedules", "schedules:create"),
    ("PATCH", "/api/v1/schedules/{id}", "schedules:update"),
    ("DELETE", "/api/v1/schedules/{id}", "schedules:delete"),
    ("GET", "/api/v1/hosts", "assets:read"),
    ("GET", "/api/v1/hosts/unstable", "changes:read"),
    ("GET", "/api/v1/hosts/{id}", "assets:read"),
    ("PATCH", "/api/v1/hosts/{id}", "assets:update"),
    ("DELETE", "/api/v1/hosts/{id}/overrides/{field}", "assets:update"),
    ("GET", "/api/v1/hosts/{id}/history", "assets:read"),
    ("POST", "/api/v1/hosts/{id}/recheck", "assets:recheck"),
    ("GET", "/api/v1/services", "assets:read"),
    ("GET", "/api/v1/services/{id}", "assets:read"),
    ("PATCH", "/api/v1/services/{id}", "assets:update"),
    ("POST", "/api/v1/services/{id}/cookies/{name}/reveal", "sensitive:reveal"),
    ("GET", "/api/v1/service-groups", "assets:read"),
    ("GET", "/api/v1/findings", "findings:read"),
    ("GET", "/api/v1/findings/{id}", "findings:read"),
    ("PATCH", "/api/v1/findings/{id}", "findings:update"),
    ("POST", "/api/v1/findings/bulk", "findings:update"),
    ("GET", "/api/v1/findings/export", "findings:export"),
    ("POST", "/api/v1/findings/defectdojo", "findings:defectdojo"),
    ("GET", "/api/v1/diffs", "changes:read"),
    ("GET", "/api/v1/signatures", "signatures:read"),
    ("POST", "/api/v1/signatures", "signatures:create"),
    ("GET", "/api/v1/signatures/{id}", "signatures:read"),
    ("PATCH", "/api/v1/signatures/{id}", "signatures:update"),
    ("DELETE", "/api/v1/signatures/{id}", "signatures:delete"),
    ("POST", "/api/v1/signatures/test", "signatures:test"),
    ("POST", "/api/v1/signatures/import", "signatures:create"),
    ("GET", "/api/v1/signatures/export", "signatures:read"),
    ("GET", "/api/v1/users", "users:read"),
    ("POST", "/api/v1/users", "users:manage"),
    ("PATCH", "/api/v1/users/{id}", "users:manage"),
    ("DELETE", "/api/v1/users/{id}", "users:manage"),
    ("GET", "/api/v1/roles", "roles:read"),
    ("POST", "/api/v1/roles", "roles:manage"),
    ("PATCH", "/api/v1/roles/{id}", "roles:manage"),
    ("DELETE", "/api/v1/roles/{id}", "roles:manage"),
    ("GET", "/api/v1/permissions", "roles:read"),
    ("GET", "/api/v1/integrations/defectdojo", "integrations:read"),
    ("PUT", "/api/v1/integrations/defectdojo", "integrations:manage"),
    ("POST", "/api/v1/integrations/defectdojo/test", "integrations:manage"),
    ("GET", "/api/v1/integrations/defectdojo/exports", "integrations:read"),
    ("GET", "/api/v1/engines", "integrations:read"),
    ("GET", "/api/v1/audit", "audit:read"),
    ("GET", "/api/v1/settings", "settings:read"),
    ("PATCH", "/api/v1/settings", "settings:manage"),
    ("GET", "/api/v1/security/encryption", "settings:read"),
    ("POST", "/api/v1/security/encryption/rotate", "settings:manage"),
];

/// Permission a custom role needs for a matched `/api/v1` route; `None` = custom roles may
/// not call it (they reach only `Public`/`Authenticated` routes and this table).
pub fn v1_perm(method: &str, path: &str) -> Option<&'static str> {
    let method = if method == "HEAD" { "GET" } else { method };
    V1_PERMS.iter().find(|(m, p, _)| *m == method && *p == path).map(|&(_, _, perm)| perm)
}

/// What an action check inside a handler means for a custom role (the route itself was
/// already checked against [`V1_PERMS`] by the gate).
pub fn custom_can(perms: &[String], action: Action) -> bool {
    let has = |p: &str| perms.iter().any(|x| x == p);
    let any = |suffix: &str| perms.iter().any(|x| x.ends_with(suffix));
    match action {
        Action::Read => any(":read"),
        Action::ReadEvidence => has("sensitive:reveal"),
        Action::Create => any(":create") || any(":import"),
        Action::Update => any(":update"),
        Action::Delete => any(":delete"),
        Action::ExecuteScan => has("scans:create") || has("scans:control") || has("assets:recheck"),
        Action::ManageUsers => has("users:manage"),
        Action::ManageIntegrations => has("integrations:manage"),
        Action::ReadAudit => has("audit:read"),
    }
}

/// Rule of a matched route; `None` = not in the table (admin-only fallback).
pub fn rule(method: &str, path: &str) -> Option<Rule> {
    // axum serves HEAD with the GET handler.
    let method = if method == "HEAD" { "GET" } else { method };
    ROUTES.iter().find(|(m, p, _)| *m == method && *p == path).map(|&(_, _, r)| r)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected grants, one row per role: (role, flag, actions allowed).
    fn expected(role: Role, flag: bool) -> Vec<Action> {
        match (role, flag) {
            (Role::Admin, _) => Action::ALL.to_vec(),
            (Role::Editor, false) => vec![Read, ReadEvidence, Create, Update, Delete],
            (Role::Editor, true) => vec![Read, ReadEvidence, Create, Update, Delete, ExecuteScan],
            (Role::Modifier, false) => vec![Read, ReadEvidence, Update],
            (Role::Modifier, true) => vec![Read, ReadEvidence, Update, ExecuteScan],
            (Role::Viewer, _) => vec![Read],
        }
    }

    #[test]
    fn full_matrix() {
        for role in [Role::Admin, Role::Editor, Role::Modifier, Role::Viewer] {
            for flag in [false, true] {
                let allowed = expected(role, flag);
                for action in Action::ALL {
                    assert_eq!(
                        role.can(action, flag),
                        allowed.contains(&action),
                        "{role:?} (can_execute_scans={flag}) {action:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn execute_flag_defaults() {
        assert!(Role::Admin.default_execute_flag() && Role::Editor.default_execute_flag());
        assert!(!Role::Modifier.default_execute_flag() && !Role::Viewer.default_execute_flag());
        assert!(!Role::Viewer.execute_flag(true), "viewers never execute scans");
        assert!(Role::Modifier.execute_flag(true));
    }

    #[test]
    fn route_table() {
        let public: Vec<_> = ROUTES.iter().filter(|r| r.2 == Public).map(|r| (r.0, r.1)).collect();
        assert_eq!(public, [("GET", "/api/health"), ("POST", "/api/auth/login"), ("POST", "/api/v1/auth/login")]);
        for (i, (m, p, _)) in ROUTES.iter().enumerate() {
            assert!(["GET", "POST", "PUT", "PATCH", "DELETE"].contains(m), "{m} {p}");
            assert!(p.starts_with("/api/"), "{p}");
            assert!(!ROUTES[..i].iter().any(|(m2, p2, _)| m2 == m && p2 == p), "duplicate {m} {p}");
        }
        assert_eq!(rule("HEAD", "/api/scans"), Some(Requires(Read)));
        assert_eq!(rule("POST", "/api/scans/{id}/run"), Some(Requires(ExecuteScan)));
        assert_eq!(rule("GET", "/api/runs/{id}/export"), None, "unknown routes are not guessed");
        assert_eq!(rule("DELETE", "/api/health"), None);
    }
    #[test]
    fn every_v1_route_has_a_contract_permission() {
        // Custom roles reach exactly the routes of the dashboard contract.
        for (m, p, r) in ROUTES {
            if p.starts_with("/api/v1/") && matches!(r, Rule::Requires(_)) {
                assert!(v1_perm(m, p).is_some(), "{m} {p} missing from V1_PERMS");
            }
        }
        for (m, p, perm) in V1_PERMS {
            assert!(rule(m, p).is_some(), "{m} {p} is not a route");
            assert!(PERMISSIONS.contains(perm), "{perm} is not a contract permission");
        }
    }

    #[test]
    fn custom_role_handler_checks() {
        let perms: Vec<String> = ["findings:read", "findings:update"].iter().map(|s| s.to_string()).collect();
        assert!(custom_can(&perms, Action::Update));
        assert!(!custom_can(&perms, Action::ExecuteScan));
        assert!(!custom_can(&perms, Action::ReadEvidence));
    }
}
