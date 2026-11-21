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
}
