-- "Teraz" (start now) while the scan's clock window is closed: the operator asked for this
-- run explicitly, so it runs at once and is not paused by that window (the dashboard's
-- contract: only "W najbliższym oknie" waits). Inside an open window it still stops at close.
ALTER TABLE scan_runs ADD COLUMN ignore_window BOOLEAN NOT NULL DEFAULT false;
