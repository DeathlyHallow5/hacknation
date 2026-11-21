-- Diff Engine (PROJECT.md §7): host history across runs, change confidence and interest.

-- After how many consecutive missed runs a host is reported Inactive (task: "Po jakim
-- czasie braku odpowiedzi w sukcesywnych skanach raportować host jako nieaktywny?").
ALTER TABLE scans
    ADD COLUMN inactive_after_misses INTEGER NOT NULL DEFAULT 3
        CHECK (inactive_after_misses BETWEEN 1 AND 100);

-- Each run's host roster also carries hosts that were not seen (state unstable/inactive),
-- so history survives between runs. flaps = how often the host came back after a miss.
ALTER TABLE hosts
    ADD COLUMN flaps INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Old/new values may contain header values, cookie names, certificate data: encrypted.
ALTER TABLE diffs
    DROP COLUMN old_value,
    DROP COLUMN new_value,
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'service' CHECK (kind IN ('host', 'service', 'http')),
    ADD COLUMN interest SMALLINT NOT NULL DEFAULT 1 CHECK (interest BETWEEN 1 AND 3),
    ADD COLUMN old_enc BYTEA,
    ADD COLUMN new_enc BYTEA;
ALTER TABLE diffs ALTER COLUMN kind DROP DEFAULT;
CREATE INDEX diffs_run_b_idx ON diffs (run_b, interest DESC);

-- A re-check may fingerprint the same URL twice in one run: upsert instead of duplicating.
DELETE FROM http_findings a USING http_findings b
    WHERE a.service_id = b.service_id AND a.url = b.url AND a.id::text < b.id::text;
ALTER TABLE http_findings ADD CONSTRAINT http_findings_service_url_key UNIQUE (service_id, url);
