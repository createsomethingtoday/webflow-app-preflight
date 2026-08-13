PRAGMA foreign_keys = ON;

-- NOTE: the ALTER TABLE ... ADD COLUMN statements below are NOT re-runnable
-- (SQLite has no ADD COLUMN IF NOT EXISTS). If this migration partially
-- applied, drop only the statements that already succeeded before re-running.

ALTER TABLE companion_pairings
  ADD COLUMN runtime_test_package_id TEXT REFERENCES runtime_test_packages(id);

ALTER TABLE companion_sessions
  ADD COLUMN runtime_test_package_id TEXT REFERENCES runtime_test_packages(id);

ALTER TABLE companion_runs
  ADD COLUMN runtime_test_package_id TEXT REFERENCES runtime_test_packages(id);

CREATE INDEX IF NOT EXISTS idx_companion_pairings_runtime_package
  ON companion_pairings(runtime_test_package_id);

CREATE INDEX IF NOT EXISTS idx_companion_sessions_runtime_package
  ON companion_sessions(runtime_test_package_id);

CREATE INDEX IF NOT EXISTS idx_companion_runs_runtime_package
  ON companion_runs(runtime_test_package_id);
