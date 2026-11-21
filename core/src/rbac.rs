//! RBAC — the four roles required by the task (PROJECT.md §12).
//! Checks happen in the API layer, not only in the UI.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Create,
    Update,
    Delete,
    ManageUsers,
    ManageIntegrations,
}

impl Role {
    pub fn can(self, action: Action) -> bool {
        use Action::*;
        match self {
            Role::Admin => true,
            Role::Editor => matches!(action, Read | Create | Update | Delete),
            Role::Modifier => matches!(action, Read | Update),
            Role::Viewer => matches!(action, Read),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix() {
        assert!(Role::Admin.can(Action::ManageUsers));
        assert!(Role::Editor.can(Action::Delete));
        assert!(!Role::Editor.can(Action::ManageUsers));
        assert!(Role::Modifier.can(Action::Update));
        assert!(!Role::Modifier.can(Action::Create));
        assert!(!Role::Modifier.can(Action::Delete));
        assert!(Role::Viewer.can(Action::Read));
        assert!(!Role::Viewer.can(Action::Update));
    }
}
