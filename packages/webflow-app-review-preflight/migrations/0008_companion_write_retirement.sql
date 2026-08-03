PRAGMA foreign_keys = ON;

-- The browser-companion write paths are retired. Historical rows remain
-- readable, but no NEW companion mission receipt may claim the Webflow-owned
-- 'webflow_observed' trust level: that trust is earned only by the
-- server-owned runtime observation pipeline. The original CHECK constraint
-- (migration 0003) still permits the value, so triggers enforce the
-- tightened rule for new and updated rows without rewriting applied schema.

DROP TRIGGER IF EXISTS trg_companion_mission_receipts_reject_webflow_observed_insert;
CREATE TRIGGER trg_companion_mission_receipts_reject_webflow_observed_insert
BEFORE INSERT ON companion_mission_receipts
WHEN NEW.evidence_trust = 'webflow_observed'
BEGIN
  SELECT RAISE(ABORT, 'companion mission receipts may no longer record webflow_observed evidence trust');
END;

DROP TRIGGER IF EXISTS trg_companion_mission_receipts_reject_webflow_observed_update;
CREATE TRIGGER trg_companion_mission_receipts_reject_webflow_observed_update
BEFORE UPDATE OF evidence_trust ON companion_mission_receipts
WHEN NEW.evidence_trust = 'webflow_observed' AND OLD.evidence_trust <> 'webflow_observed'
BEGIN
  SELECT RAISE(ABORT, 'companion mission receipts may no longer record webflow_observed evidence trust');
END;

-- Missing indexes for hot lookups:
--   * patterns.ts aggregates review_findings joined on review_version_id
--   * runtime-jobs.ts deduplicates on runtime_jobs(review_version_id)
CREATE INDEX IF NOT EXISTS idx_review_findings_review_version
  ON review_findings(review_version_id);

CREATE INDEX IF NOT EXISTS idx_runtime_jobs_review_version
  ON runtime_jobs(review_version_id, created_at DESC);
