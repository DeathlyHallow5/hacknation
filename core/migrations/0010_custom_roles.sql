-- Custom roles (requirement 12: "możliwość tworzenia własnych ról"). The four built-in roles
-- stay in code (rbac::Role); a custom role is a named set of dashboard permissions
-- (frontend/src/lib/api/types.ts PERMISSIONS), checked per /api/v1 route (rbac::V1_PERMS).
CREATE TABLE custom_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT[] NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (cardinality(permissions) > 0)
);
CREATE UNIQUE INDEX custom_roles_name_key ON custom_roles (lower(name));

-- A user with a custom role keeps role = 'viewer' as its base (legacy /api routes,
-- "last admin" checks) and never the scan.execute flag; the custom role decides the rest.
ALTER TABLE users
    ADD COLUMN custom_role_id UUID REFERENCES custom_roles (id) ON DELETE RESTRICT,
    ADD CONSTRAINT users_custom_role_is_viewer CHECK (custom_role_id IS NULL OR (role = 'viewer' AND NOT can_execute_scans));

