-- Dashboard contract, part 2: scan profiles, clock windows and schedules (F-20), safe
-- custom signatures (F-26), manual overrides of hosts/services, settings, DefectDojo log.

-- ---------- scan profiles ----------
CREATE TABLE scan_profiles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 120),
    description TEXT NOT NULL DEFAULT '',
    builtin     BOOLEAN NOT NULL DEFAULT false,
    config      JSONB NOT NULL,               -- ScanProfile fields of the contract (ports, rate, ...)
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO scan_profiles (name, description, builtin, config) VALUES
('Szybki', 'Top 100 portów, 100 zapytań/s — codzienny przegląd.', true,
 '{"ports":{"preset":"top100","custom":""},"rate_limit_rps":100,"max_concurrency":64,"nmap_timing":"T3",
   "host_timeout_s":60,"http_probe":true,"tls_probe":true,"follow_redirects":true,"max_redirects":3,
   "signatures":"all","signature_ids":[],"unstable_retries":1,"batch_strategy":"auto","batch_prefix":24}'),
('Standardowy', 'Top 1000 portów, 200 zapytań/s — pełniejszy obraz usług.', true,
 '{"ports":{"preset":"top1000","custom":""},"rate_limit_rps":200,"max_concurrency":128,"nmap_timing":"T3",
   "host_timeout_s":120,"http_probe":true,"tls_probe":true,"follow_redirects":true,"max_redirects":3,
   "signatures":"all","signature_ids":[],"unstable_retries":1,"batch_strategy":"auto","batch_prefix":24}'),
('Delikatny', 'Top 100 portów, 20 zapytań/s — sieci wrażliwe (drukarki, IoT, laboratoria).', true,
 '{"ports":{"preset":"top100","custom":""},"rate_limit_rps":20,"max_concurrency":16,"nmap_timing":"T2",
   "host_timeout_s":180,"http_probe":true,"tls_probe":true,"follow_redirects":false,"max_redirects":0,
   "signatures":"all","signature_ids":[],"unstable_retries":2,"batch_strategy":"auto","batch_prefix":26}');

-- ---------- scans: clock windows, schedules, run metadata ----------
ALTER TABLE scans
    ADD COLUMN profile_id          UUID REFERENCES scan_profiles(id) ON DELETE SET NULL,
    -- Clock window in local time (an end <= start means the window crosses midnight).
    ADD COLUMN window_start        TIME,
    ADD COLUMN window_end          TIME,
    ADD COLUMN timezone            TEXT NOT NULL DEFAULT 'Europe/Warsaw',
    -- ISO weekdays (1 = Monday) when the window opens; empty = every day.
    ADD COLUMN schedule_days       INTEGER[] NOT NULL DEFAULT '{}',
    -- A recurring schedule (Harmonogramy), as opposed to a one-off scan.
    ADD COLUMN is_schedule         BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN on_window_exceeded  TEXT NOT NULL DEFAULT 'pause_resume'
        CHECK (on_window_exceeded IN ('pause_resume', 'stop')),
    -- Demo: close the window after N seconds and reopen it N seconds later.
    ADD COLUMN test_window_seconds INTEGER CHECK (test_window_seconds BETWEEN 5 AND 3600),
    ADD COLUMN tags                TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN notes               TEXT,
    ADD CONSTRAINT scans_window_pair CHECK ((window_start IS NULL) = (window_end IS NULL)),
    ADD CONSTRAINT scans_days CHECK (schedule_days <@ ARRAY[1,2,3,4,5,6,7]);

ALTER TABLE scan_runs
    ADD COLUMN tags  TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN notes TEXT;

-- First opening of a clock window strictly after `after` (DST-aware: local time in `tz`).
CREATE FUNCTION asi_next_window_open(w_start TIME, tz TEXT, days INTEGER[], after TIMESTAMPTZ)
RETURNS TIMESTAMPTZ LANGUAGE sql STABLE AS $$
    SELECT min(o) FROM (
        SELECT (d::date + w_start) AT TIME ZONE tz AS o
        FROM generate_series((after AT TIME ZONE tz)::date - 1, (after AT TIME ZONE tz)::date + 8,
                             interval '1 day') AS d
        WHERE cardinality(days) = 0 OR extract(isodow FROM d)::int = ANY (days)
    ) x WHERE o > after
$$;

-- Close of the window that contains `at` (NULL when `at` is outside every window).
CREATE FUNCTION asi_window_close(w_start TIME, w_end TIME, tz TEXT, days INTEGER[], at TIMESTAMPTZ)
RETURNS TIMESTAMPTZ LANGUAGE sql STABLE AS $$
    SELECT min(c) FROM (
        SELECT o + CASE WHEN w_end > w_start THEN w_end - w_start ELSE w_end - w_start + interval '24 hours' END AS c,
               o
        FROM (SELECT (d::date + w_start) AT TIME ZONE tz AS o, d
              FROM generate_series((at AT TIME ZONE tz)::date - 1, (at AT TIME ZONE tz)::date, interval '1 day') AS d
              WHERE cardinality(days) = 0 OR extract(isodow FROM d)::int = ANY (days)) opens
    ) w WHERE o <= at AND c > at
$$;

-- ---------- signatures (contract shape; detection only, never exploitation) ----------
ALTER TABLE signatures
    DROP CONSTRAINT signatures_kind_check,
    ALTER COLUMN kind SET DEFAULT 'custom',
    ADD COLUMN category     TEXT NOT NULL DEFAULT 'technology',
    ADD COLUMN technology   TEXT,
    ADD COLUMN score_weight INTEGER NOT NULL DEFAULT 10 CHECK (score_weight BETWEEN 0 AND 50),
    ADD COLUMN tags         TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN version      INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN builtin      BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN updated_at   TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE signature_hits
    ADD COLUMN run_id            UUID REFERENCES scan_runs(id) ON DELETE CASCADE,
    ADD COLUMN url               TEXT,
    ADD COLUMN extracted_version TEXT,
    ADD COLUMN signature_version INTEGER,
    ADD COLUMN matched_at        TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE INDEX signature_hits_run_idx ON signature_hits (run_id);

-- ---------- manual overrides of hosts and services (requirement 14) ----------
-- Keyed by the stable entity key (host = IP, service = ip:port/proto), across scans and runs;
-- scanners never write here, so an override survives every rescan.
CREATE TABLE asset_overrides (
    entity_kind   TEXT NOT NULL CHECK (entity_kind IN ('host', 'service')),
    entity_key    TEXT NOT NULL,
    field         TEXT NOT NULL,
    value         JSONB NOT NULL,
    scanner_value JSONB,
    updated_by    UUID REFERENCES users(id),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_kind, entity_key, field)
);

-- ---------- users: what the dashboard shows ----------
ALTER TABLE users ADD COLUMN display_name TEXT, ADD COLUMN email TEXT;

-- ---------- settings and DefectDojo ----------
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    secret_enc BYTEA,                         -- e.g. the DefectDojo API token (pgp_sym_encrypt)
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE defectdojo_exports (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    by_user    UUID REFERENCES users(id),
    count      INTEGER NOT NULL,
    as_kind    TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('success', 'partial', 'failed')),
    message    TEXT NOT NULL,
    links      JSONB NOT NULL DEFAULT '[]'
);

ALTER TABLE finding_states ADD COLUMN defectdojo JSONB;

-- Runs created from an imported file (never scanned).
ALTER TABLE scan_runs ADD COLUMN source TEXT NOT NULL DEFAULT 'scanner' CHECK (source IN ('scanner', 'import'));
