-- Authentication, sessions and an append-only audit trail (PROJECT.md §10, F-01, review §8.2/§8.5).

-- Users are disabled, never deleted: audit_log rows keep referencing them.
ALTER TABLE users
    ADD COLUMN disabled          BOOLEAN NOT NULL DEFAULT false,
    -- Starting scans is active network impact: a separate right (scan.execute), never for viewers.
    ADD COLUMN can_execute_scans BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN last_login_at     TIMESTAMPTZ,
    ADD CONSTRAINT users_viewer_cannot_execute CHECK (role <> 'viewer' OR NOT can_execute_scans);

-- Server-side sessions. Only the SHA-256 of the bearer token is stored, never the token.
CREATE TABLE sessions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id),
    token_hash   BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    ip           INET,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX sessions_user_active_idx ON sessions (user_id) WHERE revoked_at IS NULL;

-- Who did what, from where, with which result. Never passwords, tokens or request bodies.
ALTER TABLE audit_log
    ADD COLUMN ip      INET,
    ADD COLUMN method  TEXT,
    ADD COLUMN path    TEXT,          -- matched route template, e.g. /api/scans/{id}; never a query string
    ADD COLUMN status  SMALLINT,      -- HTTP status of the response
    ADD COLUMN outcome TEXT NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'failure', 'denied'));
CREATE INDEX audit_log_user_idx ON audit_log (user_id, id DESC);

-- Append-only: the application can only INSERT. (The table owner can still disable the
-- trigger; protecting against a compromised database account is out of scope.)
CREATE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is not allowed', TG_OP;
END
$$;
CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();
