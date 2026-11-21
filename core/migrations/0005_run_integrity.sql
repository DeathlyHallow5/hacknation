-- Run integrity fixes (PROJECT.md §15: F-04, F-07, F-12).

-- A run whose batches partly failed (tool error after a retry) finishes as 'partial':
-- it is diffed only on what it covered and is never used as a baseline for later runs.
ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'partial';

ALTER TABLE scan_runs
    -- Offset into the run's target list; /8 or large IPv6 ranges overflow 32 bits.
    ALTER COLUMN checkpoint TYPE BIGINT,
    -- Scan settings frozen at run start (ports, rate, window, thresholds), so editing the
    -- scan mid-run applies to the next run and never changes a run between windows.
    ADD COLUMN config_snapshot JSONB;
