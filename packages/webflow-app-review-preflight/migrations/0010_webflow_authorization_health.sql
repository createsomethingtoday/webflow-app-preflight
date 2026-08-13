PRAGMA foreign_keys = ON;

-- The most recent scheduled authorization probe. This deliberately stores
-- only state and HTTP status—not the OAuth token, response body, or identity.
CREATE TABLE IF NOT EXISTS webflow_authorization_health (
  id TEXT PRIMARY KEY CHECK (id = 'active'),
  state TEXT NOT NULL CHECK (state IN ('ready', 'reconnect_required', 'unavailable')),
  status_code INTEGER,
  checked_at TEXT NOT NULL
);
