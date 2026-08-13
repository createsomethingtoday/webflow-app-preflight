-- Submission receipts: the reconciliation stamp between a preflight run and
-- the official Marketplace submission form. The developer copies the receipt
-- code from the extension into the form; the form's server traces it through
-- the public verify endpoint. Only the SHA-256 of the code is stored, so a
-- database read never yields a redeemable code.
CREATE TABLE IF NOT EXISTS submission_receipts (
  id TEXT PRIMARY KEY,
  code_sha256 TEXT NOT NULL UNIQUE,
  review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
  review_version_id TEXT NOT NULL REFERENCES review_versions(id) ON DELETE CASCADE,
  owner_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_submission_receipts_review
  ON submission_receipts(review_id, created_at DESC);

-- Private source-map artifact uploaded alongside the bundle (never published;
-- stored so a reviewer replay can confirm the same artifact by SHA-256).
-- NOTE: ALTER TABLE ... ADD COLUMN is not re-runnable (no IF NOT EXISTS).
ALTER TABLE review_versions ADD COLUMN source_map_sha256 TEXT;
ALTER TABLE review_versions ADD COLUMN source_map_key TEXT;
ALTER TABLE review_versions ADD COLUMN source_map_file_name TEXT;
