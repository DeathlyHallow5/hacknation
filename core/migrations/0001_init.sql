-- Attack Surface Intelligence — initial schema (see PROJECT.md §8).
-- Sensitive columns are BYTEA encrypted with pgp_sym_encrypt (Encryption at Rest, §11.1);
-- the key comes from ASI_DATA_KEY and never lives in the database.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE user_role   AS ENUM ('admin', 'editor', 'modifier', 'viewer');      -- §12 RBAC
CREATE TYPE target_kind AS ENUM ('ip', 'cidr', 'domain');
CREATE TYPE scan_status AS ENUM ('queued', 'running', 'paused', 'done', 'failed', 'cancelled');
CREATE TYPE host_state  AS ENUM ('active', 'unstable', 'inactive');
CREATE TYPE change_type AS ENUM ('new', 'gone', 'changed');

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          user_role NOT NULL DEFAULT 'viewer',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Normalized input (§3.1). Manual edits are flagged so scans never overwrite them.
CREATE TABLE targets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind        target_kind NOT NULL,
    value       TEXT NOT NULL UNIQUE,          -- canonical form: 10.0.0.0/24, 10.0.0.5, example.com
    label       TEXT,
    notes       TEXT,
    manual_edit BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One scan run (§3.2): window, rate limit and resume checkpoint.
CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    status          scan_status NOT NULL DEFAULT 'queued',
    schedule_cron   TEXT,                       -- NULL = one-off run
    window_minutes  INTEGER,                    -- auto-stop after N minutes, resume next window
    rate_limit_pps  INTEGER NOT NULL DEFAULT 100,
    checkpoint      JSONB,                      -- where to resume (batch index etc.)
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    error           TEXT
);

CREATE TABLE scan_targets (
    scan_id   UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    PRIMARY KEY (scan_id, target_id)
);

-- Host observation per scan; miss_count drives the Inactive status (§7).
CREATE TABLE hosts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    address     INET NOT NULL,
    hostname    TEXT,
    state       host_state NOT NULL DEFAULT 'active',
    miss_count  INTEGER NOT NULL DEFAULT 0,
    seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, address)
);

CREATE TABLE services (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    service     TEXT,
    product     TEXT,
    version     TEXT,
    confidence  REAL NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 1),
    banner_enc  BYTEA,                          -- encrypted raw banner
    UNIQUE (host_id, port, protocol)
);

-- HTTP/HTTPS fingerprint (§6.2). Headers/cookies/TLS/raw evidence are encrypted.
CREATE TABLE http_findings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id   UUID NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    status_code  INTEGER,
    title        TEXT,
    redirects    TEXT[],
    technologies TEXT[],
    cms          TEXT,
    favicon_hash TEXT,
    is_admin     BOOLEAN NOT NULL DEFAULT false,
    is_staging   BOOLEAN NOT NULL DEFAULT false,
    headers_enc  BYTEA,
    cookies_enc  BYTEA,
    tls_enc      BYTEA,
    raw_enc      BYTEA
);

-- Custom safe-detection signatures (§6.3). Detection only — never exploitation.
CREATE TABLE signatures (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    kind        TEXT NOT NULL CHECK (kind IN ('header', 'cookie', 'body', 'path', 'favicon', 'nuclei')),
    rule        JSONB NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE signature_hits (
    signature_id UUID NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    service_id   UUID NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    evidence_enc BYTEA,
    PRIMARY KEY (signature_id, service_id)
);

-- Diff between two runs (§7).
CREATE TABLE diffs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_a      UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scan_b      UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    entity      TEXT NOT NULL,                  -- e.g. "10.0.0.5:443/tcp"
    change      change_type NOT NULL,
    field       TEXT,                           -- what changed (title, version, ...)
    old_value   TEXT,
    new_value   TEXT,
    confidence  REAL NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Analytics (§3.7).
CREATE TABLE tags (
    id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE
);
CREATE TABLE target_tags (
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    tag_id    UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (target_id, tag_id)
);

-- Who changed what and when — edits allowed at any time, even mid-scan.
CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    user_id    UUID REFERENCES users(id),
    action     TEXT NOT NULL,
    entity     TEXT NOT NULL,
    entity_id  TEXT,
    details    JSONB,
    at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX hosts_address_idx    ON hosts (address);
CREATE INDEX diffs_scans_idx      ON diffs (scan_a, scan_b);
CREATE INDEX audit_log_entity_idx ON audit_log (entity, entity_id);
