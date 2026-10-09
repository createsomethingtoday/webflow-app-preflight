PRAGMA foreign_keys = ON;

-- Install URL checks stamped on a review. Append-only: each run records the
-- inputs it used and the full result, and the newest row per review is the
-- current state. Developers record a check from the extension; reviewers
-- re-run it from the reviewer workspace, optionally supplying the scopes
-- configured for the app so the IU-8 comparison can run.
CREATE TABLE IF NOT EXISTS install_url_checks (
  id TEXT PRIMARY KEY,
  review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
  review_version_id TEXT NOT NULL REFERENCES review_versions(id) ON DELETE CASCADE,
  actor_user_id TEXT NOT NULL,
  actor_role TEXT NOT NULL CHECK(actor_role IN ('developer', 'reviewer')),
  install_url TEXT NOT NULL,
  client_id TEXT,
  capabilities_json TEXT NOT NULL,
  configured_scopes_json TEXT,
  verdict TEXT NOT NULL CHECK(verdict IN ('pass', 'warn', 'block')),
  probe_code TEXT,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_install_url_checks_review_created
  ON install_url_checks(review_id, created_at DESC);
