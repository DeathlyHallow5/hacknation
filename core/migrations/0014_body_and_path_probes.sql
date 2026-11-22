-- Signatures on page content (requirement: "charakterystyczny fragment HTML", "wersja w stopce")
-- and on safe GET probes ("ścieżka /login, /admin, /version, bez prób logowania").

-- First 32 KiB of the page body, encrypted like all evidence. Never shown in the dashboard:
-- only the signature engine reads it (matched evidence keeps a short snippet).
ALTER TABLE http_findings ADD COLUMN body_enc BYTEA;

-- One GET per (web service, path) asked for by an enabled "path" signature condition. Only on
-- web services the run already found, no redirects followed, no credentials, rate-limited.
CREATE TABLE http_probes (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id         UUID NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    service_id     UUID NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    path           TEXT NOT NULL,
    url            TEXT NOT NULL,
    status_code    INTEGER,
    title          TEXT,
    content_length BIGINT,
    body_enc       BYTEA,
    probed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (service_id, path)
);
CREATE INDEX http_probes_run ON http_probes (run_id);
