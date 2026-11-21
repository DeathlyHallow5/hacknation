-- Raw scanner output per batch, encrypted. DefectDojo has built-in parsers for these
-- native formats ("Nmap Scan", "Naabu Scan", "httpx Scan", "Nuclei Scan"), so export is
-- import-scan / reimport-scan of these files (PROJECT.md §11.2). Also serves as evidence.
CREATE TABLE run_artifacts (
    id          BIGSERIAL PRIMARY KEY,
    run_id      UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    batch       INTEGER NOT NULL,
    tool        TEXT NOT NULL CHECK (tool IN ('nmap', 'naabu', 'httpx', 'nuclei')),
    content_enc BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_id, batch, tool)
);
