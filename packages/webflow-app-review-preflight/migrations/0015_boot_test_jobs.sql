PRAGMA foreign_keys = ON;

-- Designer Extension boot tests. A boot test is advisory evidence about one
-- immutable review version: it never changes readiness, a finding, or a
-- runtime-observation security status.
CREATE TABLE IF NOT EXISTS boot_test_jobs (
  id TEXT PRIMARY KEY,
  review_version_id TEXT NOT NULL REFERENCES review_versions(id) ON DELETE CASCADE,
  requested_by_user_id TEXT NOT NULL,
  -- Who ran the job: the review owner from the Designer Extension, or a
  -- reviewer replaying the same version from the reviewer workspace.
  actor_role TEXT NOT NULL CHECK(actor_role IN ('developer', 'reviewer')),
  status TEXT NOT NULL CHECK(status IN ('approved', 'running', 'complete', 'failed', 'expired')),
  capability_sha256 TEXT NOT NULL UNIQUE,
  nonce TEXT NOT NULL UNIQUE,
  contract_json TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  completed_at TEXT,
  evidence_trust TEXT CHECK(evidence_trust IS NULL OR evidence_trust = 'webflow_observed'),
  result_status TEXT CHECK(result_status IS NULL OR result_status IN ('passed', 'failed', 'error')),
  result_json TEXT,
  sandbox_id TEXT,
  sandbox_started_at TEXT,
  sandbox_terminated_at TEXT,
  sandbox_termination_status TEXT
    CHECK(sandbox_termination_status IS NULL OR sandbox_termination_status IN ('pending', 'verified', 'failed')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_boot_test_jobs_version_created
  ON boot_test_jobs(review_version_id, created_at DESC);

-- One active boot test per review version and actor role, so a running
-- developer test never blocks a reviewer replay of the same version.
CREATE UNIQUE INDEX IF NOT EXISTS idx_boot_test_jobs_one_active_per_version_actor
  ON boot_test_jobs(review_version_id, actor_role)
  WHERE status IN ('approved', 'running');

CREATE INDEX IF NOT EXISTS idx_boot_test_jobs_active_expiry
  ON boot_test_jobs(status, expires_at)
  WHERE status IN ('approved', 'running');
