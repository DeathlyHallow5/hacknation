-- Editable overlays that survive rescans (PROJECT.md §2.6, §5.2; F-15; AGH requirement 14).
-- Raw evidence stays immutable. Analysts annotate a stable entity key at SCAN level — the
-- keys the diff uses: host → IP, service → ip:port/proto, http → URL — so an annotation
-- applies to every past and future run of the scan, whatever the run status.

CREATE TABLE annotations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    entity_kind     TEXT NOT NULL CHECK (entity_kind IN ('host', 'service', 'http')),
    entity_key      TEXT NOT NULL CHECK (length(entity_key) BETWEEN 1 AND 2048),
    label           TEXT,
    owner           TEXT,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    priority        SMALLINT CHECK (priority BETWEEN 1 AND 3),
    false_positive  BOOLEAN NOT NULL DEFAULT false,
    suppressed      BOOLEAN NOT NULL DEFAULT false,
    suppress_reason TEXT,
    notes_enc       BYTEA,                      -- pgp_sym_encrypt, like scan evidence (§11)
    reason          TEXT,                       -- why this version was written
    version         INTEGER NOT NULL DEFAULT 1, -- optimistic locking
    created_by      UUID REFERENCES users(id),
    updated_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, entity_kind, entity_key)
);

-- Every replaced or deleted version, with its author, time and reason (review §4, §19.4).
CREATE TABLE annotation_history (
    id              BIGSERIAL PRIMARY KEY,
    annotation_id   UUID NOT NULL,              -- no FK: history outlives a deleted annotation
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    entity_kind     TEXT NOT NULL,
    entity_key      TEXT NOT NULL,
    version         INTEGER NOT NULL,
    label           TEXT,
    owner           TEXT,
    tags            TEXT[] NOT NULL,
    priority        SMALLINT,
    false_positive  BOOLEAN NOT NULL,
    suppressed      BOOLEAN NOT NULL,
    suppress_reason TEXT,
    notes_enc       BYTEA,
    reason          TEXT,
    author          UUID REFERENCES users(id),  -- who wrote this version, and when
    authored_at     TIMESTAMPTZ NOT NULL,
    change          TEXT NOT NULL CHECK (change IN ('update', 'delete')),  -- what ended it
    changed_by      UUID REFERENCES users(id),
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX annotation_history_annotation_idx ON annotation_history (annotation_id, version DESC);

-- Append-only; rows only go away together with their scan (the ON DELETE CASCADE runs
-- inside the foreign-key trigger, hence the trigger depth check).
CREATE FUNCTION annotation_history_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'annotation_history is append-only: % is not allowed', TG_OP;
END
$$;
CREATE TRIGGER annotation_history_no_change BEFORE UPDATE OR DELETE ON annotation_history
    FOR EACH ROW EXECUTE FUNCTION annotation_history_append_only();

-- Target notes are written encrypted (F-13). The plaintext column stays readable for rows
-- written before (or by importers that still use it); an edit moves the value to notes_enc.
ALTER TABLE targets ADD COLUMN notes_enc BYTEA;
