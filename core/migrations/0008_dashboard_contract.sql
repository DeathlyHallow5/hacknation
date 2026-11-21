-- Fields the dashboard contract (/api/v1, frontend/src/lib/api/types.ts) needs, and the
-- analyst state of derived findings (AGH requirement 14: edits survive rescans).

ALTER TABLE targets
    ADD COLUMN owner       TEXT,
    ADD COLUMN criticality TEXT NOT NULL DEFAULT 'medium'
        CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
    ADD COLUMN tags        TEXT[] NOT NULL DEFAULT '{}',
    -- Excluded targets are left out of new runs ("no-scan list").
    ADD COLUMN excluded    BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN source      TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'import')),
    ADD COLUMN updated_by  UUID REFERENCES users(id);   -- updated_at exists since 0001

-- Findings are derived from the latest run of each scan (admin panels, staging, risky
-- ports...). Their id is deterministic (UUIDv5 of scan, category and entity key), so the
-- analyst's status, notes and score survive every rescan.
CREATE TABLE finding_states (
    finding_id     UUID PRIMARY KEY,
    scan_id        UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    category       TEXT NOT NULL,
    entity_key     TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'in_review', 'confirmed', 'false_positive', 'accepted')),
    score_override SMALLINT CHECK (score_override BETWEEN 0 AND 100),
    assignee       TEXT,
    tags           TEXT[] NOT NULL DEFAULT '{}',
    notes_enc      BYTEA,                       -- pgp_sym_encrypt, like other analyst notes
    updated_by     UUID REFERENCES users(id),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
