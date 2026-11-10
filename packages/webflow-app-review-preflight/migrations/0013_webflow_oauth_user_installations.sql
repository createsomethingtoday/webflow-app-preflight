PRAGMA foreign_keys = ON;

-- One OAuth token per Webflow user. Webflow resolves a Designer ID token only
-- when the bearer token's authorization covers the ID token's site, so one
-- shared token cannot serve developers in different Workspaces.
CREATE TABLE IF NOT EXISTS webflow_oauth_user_installations (
  user_id TEXT PRIMARY KEY,
  access_token_ciphertext TEXT NOT NULL,
  access_token_iv TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
