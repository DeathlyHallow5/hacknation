-- Split scan definitions (scans) from executions (scan_runs) so the Diff Engine can
-- compare runs of the same scan (PROJECT.md §3.2, §7).

CREATE TABLE scan_runs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id           UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    status            scan_status NOT NULL DEFAULT 'running',
    -- Targets frozen at run start: edits made mid-run apply to the next run and never
    -- shift batch boundaries of the current one.
    target_snapshot   JSONB,
    checkpoint        INTEGER NOT NULL DEFAULT 0,      -- next batch index to scan
    total_batches     INTEGER,
    window_started_at TIMESTAMPTZ,
    resume_at         TIMESTAMPTZ,                     -- set while paused between windows
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at       TIMESTAMPTZ,
    error             TEXT,
    stats             JSONB NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX scan_runs_one_active ON scan_runs (scan_id)
    WHERE status IN ('queued', 'running', 'paused');
CREATE INDEX scan_runs_scan_idx ON scan_runs (scan_id, started_at DESC);

ALTER TABLE scans
    DROP COLUMN status,
    DROP COLUMN checkpoint,
    DROP COLUMN started_at,
    DROP COLUMN finished_at,
    DROP COLUMN error,
    DROP COLUMN schedule_cron,
    -- naabu top-ports preset ('100' | '1000' | 'full') or an explicit list like '22,80,8000-8100'
    ADD COLUMN ports                TEXT NOT NULL DEFAULT '100',
    ADD COLUMN batch_size           INTEGER NOT NULL DEFAULT 256 CHECK (batch_size BETWEEN 1 AND 65536),
    ADD COLUMN preflight            BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN repeat_every_minutes INTEGER CHECK (repeat_every_minutes > 0),
    ADD COLUMN enabled              BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN next_run_at          TIMESTAMPTZ DEFAULT now(),
    ADD CONSTRAINT scans_window_positive CHECK (window_minutes IS NULL OR window_minutes > 0),
    ADD CONSTRAINT scans_rate_range CHECK (rate_limit_pps BETWEEN 1 AND 10000);

-- Observations and diffs now belong to runs. Tables are empty at this point.
DELETE FROM hosts;
ALTER TABLE hosts DROP CONSTRAINT hosts_scan_id_fkey;
ALTER TABLE hosts DROP CONSTRAINT hosts_scan_id_address_key;
ALTER TABLE hosts RENAME COLUMN scan_id TO run_id;
ALTER TABLE hosts
    ADD CONSTRAINT hosts_run_id_fkey FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    ADD CONSTRAINT hosts_run_id_address_key UNIQUE (run_id, address);

DELETE FROM diffs;
ALTER TABLE diffs DROP CONSTRAINT diffs_scan_a_fkey;
ALTER TABLE diffs DROP CONSTRAINT diffs_scan_b_fkey;
ALTER TABLE diffs RENAME COLUMN scan_a TO run_a;
ALTER TABLE diffs RENAME COLUMN scan_b TO run_b;
ALTER TABLE diffs
    ADD CONSTRAINT diffs_run_a_fkey FOREIGN KEY (run_a) REFERENCES scan_runs(id) ON DELETE CASCADE,
    ADD CONSTRAINT diffs_run_b_fkey FOREIGN KEY (run_b) REFERENCES scan_runs(id) ON DELETE CASCADE;
