import {
  BOOT_TEST_FAILURES,
  BOOT_TEST_LIMITS,
  DESIGNER_EXTENSION_HOST_CSP,
  type BootTestCspViolation,
  type BootTestFailure,
  type BootTestJobContract,
  type BootTestReplayComparison,
  type BootTestResult,
  type BootTestSummary
} from '@create-something/webflow-app-review-preflight';
import { authenticate, authenticateCompanion, companionRoleForUser } from './auth';
import {
  E2BRuntimeLaunchError,
  launchRuntimeObservationInE2B,
  terminateRuntimeObservationInE2B,
  type E2BRuntimeLaunchStage
} from './e2b-runtime-launcher';
import { json } from './http';
import { checkSandboxLimits, sandboxLimitResponse, type SandboxLimitHit } from './sandbox-limits';
import type { AuthenticatedUser, Env } from './types';

/**
 * Designer Extension boot test: a second sandbox job kind beside the runtime
 * observation. The Worker issues a one-time, expiring capability bound to one
 * review version, the sandbox runner uses it to read the contract and that
 * version's bundle, and the Worker re-validates every field of the result
 * before it stores it as `webflow_observed` evidence.
 *
 * The result is advisory. Nothing here reads or writes readiness, findings,
 * or runtime-observation security status.
 */

const JOB_LIFETIME_MS = 15 * 60 * 1000;
const MAX_RESULT_BYTES = 64 * 1024;
const MAX_POLICY_LENGTH = 4_096;
const MAX_BUNDLE_BYTES = 10 * 1024 * 1024;
const RECONCILE_BATCH_LIMIT = 10;
const CONTROLS: BootTestJobContract['controls'] = {
  networkMode: 'local_static_server_only',
  viewport: { width: 320, height: 460 },
  navigationTimeoutMs: 15_000,
  settleMs: 3_000,
  totalTimeoutMs: 60_000,
  evidenceTrust: 'webflow_observed'
};
const SECRET_VALUE =
  /(?:Bearer\s+[A-Za-z0-9._~+/=-]{8,}|-----BEGIN [^-]*PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{12,})/i;
const ROUTES = {
  review: /^\/v1\/reviews\/([^/]+)\/boot-tests$/,
  job: /^\/v1\/boot-test-jobs\/([^/]+)$/,
  bundle: /^\/v1\/boot-test-jobs\/([^/]+)\/bundle$/,
  result: /^\/v1\/boot-test-jobs\/([^/]+)\/result$/,
  reviewerReplay: /^\/reviewer\/review-versions\/([^/]+)\/boot-test-replay$/
};

export class BootTestResultError extends Error {}
export class BootTestConfigurationError extends Error {}

type BootTestJobStatus = BootTestSummary['status'];
type BootTestActorRole = BootTestSummary['actorRole'];

interface BootTestJobRow {
  id: string;
  review_version_id: string;
  requested_by_user_id: string;
  actor_role: BootTestActorRole;
  status: BootTestJobStatus;
  capability_sha256: string;
  contract_json: string;
  approved_at: string;
  expires_at: string;
  completed_at: string | null;
  evidence_trust: 'webflow_observed' | null;
  result_status: BootTestResult['status'] | null;
  result_json: string | null;
}

export function bootTestsEnabled(env: Env): boolean {
  return env.BOOT_TEST_ENABLED?.trim() === 'true';
}

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes))
    .map((value) => value.toString(16).padStart(2, '0'))
    .join('');
}

async function sha256(value: string): Promise<string> {
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
}

function randomCapability(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function bearerToken(request: Request): string | null {
  const value = request.headers.get('authorization');
  if (!value?.startsWith('Bearer ')) return null;
  return value.slice('Bearer '.length).trim() || null;
}

function constantTimeEqual(left: string, right: string): boolean {
  let mismatch = left.length ^ right.length;
  for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
    mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return mismatch === 0;
}

/** The policy each new job carries: `BOOT_TEST_CSP` when set, else the captured default. */
export function bootTestPolicy(env: Env): string {
  const configured = env.BOOT_TEST_CSP?.trim();
  if (!configured) return DESIGNER_EXTENSION_HOST_CSP;
  if (configured.length > MAX_POLICY_LENGTH || !/^[\x20-\x7e]+$/.test(configured)) {
    throw new BootTestConfigurationError(
      'BOOT_TEST_CSP must be one printable ASCII header value of at most 4,096 characters.'
    );
  }
  return configured;
}

function summaryFromRow(row: BootTestJobRow): BootTestSummary {
  const expired =
    (row.status === 'approved' || row.status === 'running') &&
    Date.parse(row.expires_at) <= Date.now();
  return {
    id: row.id,
    reviewVersionId: row.review_version_id,
    actorRole: row.actor_role,
    status: expired ? 'expired' : row.status,
    trust: row.evidence_trust,
    advisory: true,
    approvedAt: row.approved_at,
    expiresAt: row.expires_at,
    completedAt: row.completed_at,
    bootTest: row.result_json ? (JSON.parse(row.result_json) as BootTestResult) : null
  };
}

async function recordEvent(
  env: Env,
  reviewVersionId: string,
  actor: string,
  eventType: string,
  payload: Record<string, unknown>,
  at = new Date().toISOString()
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO review_events
      (id, review_id, review_version_id, actor_user_id, event_type, payload_json, created_at)
     SELECT ?, review_id, id, ?, ?, ?, ?
       FROM review_versions
      WHERE id = ?`
  )
    .bind(crypto.randomUUID(), actor, eventType, JSON.stringify(payload), at, reviewVersionId)
    .run();
}

/**
 * Status of the most recent completed developer boot test for a review
 * version, for the submission receipt. Reviewer replays never change it: the
 * receipt reports what the developer saw when they submitted, and a later
 * replay must not rewrite that. A version with no developer result is
 * `not_run`.
 */
export async function bootTestSummaryForVersion(
  reviewVersionId: string,
  env: Env
): Promise<{ status: 'passed' | 'failed' | 'error' | 'not_run' }> {
  if (!bootTestsEnabled(env)) return { status: 'not_run' };
  const row = await env.DB.prepare(
    `SELECT result_status
       FROM boot_test_jobs
      WHERE review_version_id = ? AND actor_role = 'developer'
        AND status = 'complete' AND result_status IS NOT NULL
      ORDER BY completed_at DESC, created_at DESC
      LIMIT 1`
  )
    .bind(reviewVersionId)
    .first<{ result_status: 'passed' | 'failed' | 'error' }>();
  return { status: row?.result_status ?? 'not_run' };
}

export async function terminateBootTestSandbox(
  jobId: string,
  env: Env
): Promise<'verified' | 'failed' | 'not_started'> {
  const row = await env.DB.prepare(
    `SELECT sandbox_id, sandbox_termination_status, review_version_id
       FROM boot_test_jobs WHERE id = ?`
  )
    .bind(jobId)
    .first<{
      sandbox_id: string | null;
      sandbox_termination_status: string | null;
      review_version_id: string;
    }>();
  if (!row?.sandbox_id) return 'not_started';
  if (row.sandbox_termination_status === 'verified') return 'verified';
  const result = await terminateRuntimeObservationInE2B(row.sandbox_id, env);
  const now = new Date().toISOString();
  await env.DB.prepare(
    `UPDATE boot_test_jobs
        SET sandbox_termination_status = ?, sandbox_terminated_at = ?, updated_at = ?
      WHERE id = ? AND sandbox_id = ?`
  )
    .bind(result, result === 'verified' ? now : null, now, jobId, row.sandbox_id)
    .run();
  if (row.sandbox_termination_status !== result) {
    await recordEvent(env, row.review_version_id, 'webflow-runtime-coordinator', 'boot_test_sandbox_terminated', {
      bootTestJobId: jobId,
      termination: result
    });
  }
  return result;
}

/** Cron: expire overdue jobs and verify their sandboxes are gone. */
export async function reconcileBootTestJobs(env: Env): Promise<{ reconciled: number; failed: number }> {
  if (!bootTestsEnabled(env)) return { reconciled: 0, failed: 0 };
  const now = new Date().toISOString();
  await env.DB.prepare(
    `UPDATE boot_test_jobs
        SET status = 'expired', updated_at = ?
      WHERE status IN ('approved', 'running') AND expires_at <= ?`
  )
    .bind(now, now)
    .run();
  const rows = await env.DB.prepare(
    `SELECT id FROM boot_test_jobs
      WHERE sandbox_id IS NOT NULL
        AND COALESCE(sandbox_termination_status, 'pending') <> 'verified'
        AND status IN ('complete', 'failed', 'expired')
      ORDER BY updated_at ASC
      LIMIT ${RECONCILE_BATCH_LIMIT}`
  ).all<{ id: string }>();
  let reconciled = 0;
  let failed = 0;
  for (const row of rows.results) {
    try {
      const outcome = await terminateBootTestSandbox(row.id, env);
      if (outcome === 'failed') failed += 1;
      else reconciled += 1;
    } catch (error) {
      failed += 1;
      console.error('Boot test sandbox reconcile failed', error);
    }
  }
  return { reconciled, failed };
}

async function activeJob(
  reviewVersionId: string,
  actorRole: BootTestActorRole,
  env: Env
): Promise<BootTestJobRow | null> {
  return env.DB.prepare(
    `SELECT * FROM boot_test_jobs
      WHERE review_version_id = ? AND actor_role = ?
        AND status IN ('approved', 'running') AND expires_at > ?
      ORDER BY created_at DESC
      LIMIT 1`
  )
    .bind(reviewVersionId, actorRole, new Date().toISOString())
    .first<BootTestJobRow>();
}

function safeLaunchMessage(stage: E2BRuntimeLaunchStage): string {
  switch (stage) {
    case 'configuration':
      return 'The boot test runner is not configured. Ask a reviewer to configure the server-owned runner.';
    case 'sandbox_create':
      return 'The boot test runner could not create a secure sandbox.';
    case 'runner_start':
      return 'The boot test runner could not start inside the secure sandbox.';
  }
}

interface BootTestVersionRow {
  review_id: string;
  version_id: string;
  artifact_sha256: string;
  compressed_bytes: number;
  artifact_kind: string | null;
}

type IssueOutcome =
  | { kind: 'issued' | 'active'; job: BootTestSummary }
  | { kind: 'unavailable'; message: string }
  | { kind: 'limit_reached'; hit: SandboxLimitHit }
  | { kind: 'dispatch_failed'; message: string };

/**
 * Issues one job for an exact review version and starts its sandbox. The
 * caller has already authorized the actor; this function records the role.
 * One job may be active per version and actor role.
 */
async function issueBootTest(
  version: BootTestVersionRow,
  actorRole: BootTestActorRole,
  user: AuthenticatedUser,
  request: Request,
  env: Env
): Promise<IssueOutcome> {
  if (version.artifact_kind === 'runtime_manifest') {
    return { kind: 'unavailable', message: 'A boot test needs an uploaded Designer Extension bundle.' };
  }
  if (!(version.compressed_bytes > 0 && version.compressed_bytes <= MAX_BUNDLE_BYTES)) {
    return { kind: 'unavailable', message: 'The bundle size is out of range.' };
  }

  let policy: string;
  try {
    policy = bootTestPolicy(env);
  } catch (error) {
    return { kind: 'dispatch_failed', message: (error as Error).message };
  }

  const nowMs = Date.now();
  const now = new Date(nowMs).toISOString();
  await env.DB.prepare(
    `UPDATE boot_test_jobs SET status = 'expired', updated_at = ?
      WHERE review_version_id = ? AND status IN ('approved', 'running') AND expires_at <= ?`
  )
    .bind(now, version.version_id, now)
    .run();
  const existing = await activeJob(version.version_id, actorRole, env);
  if (existing) return { kind: 'active', job: summaryFromRow(existing) };

  const hit = await checkSandboxLimits(env, {
    userId: user.id,
    exemptFromUserLimit: actorRole === 'reviewer' || companionRoleForUser(user, env) === 'reviewer'
  });
  if (hit) return { kind: 'limit_reached', hit };

  const id = crypto.randomUUID();
  const capability = randomCapability();
  const nonce = crypto.randomUUID();
  const expiresAt = new Date(nowMs + JOB_LIFETIME_MS).toISOString();
  const contract: BootTestJobContract = {
    schemaVersion: 'designer_extension_boot_test_job.v1',
    purpose: 'designer_extension_boot_test',
    bootTestJobId: id,
    reviewId: version.review_id,
    reviewVersionId: version.version_id,
    bundleSha256: version.artifact_sha256,
    bundleBytes: version.compressed_bytes,
    nonce,
    contentSecurityPolicy: policy,
    controls: CONTROLS,
    limits: { ...BOOT_TEST_LIMITS },
    boundaries: {
      advisoryOnly: true,
      affectsReadiness: false,
      officialDecision: null,
      canWriteGovernance: false,
      acceptsAccountCredentials: false
    },
    expiresAt
  };
  try {
    await env.DB.prepare(
      `INSERT INTO boot_test_jobs
        (id, review_version_id, requested_by_user_id, actor_role, status, capability_sha256,
         nonce, contract_json, approved_at, expires_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        id,
        version.version_id,
        user.id,
        actorRole,
        await sha256(capability),
        nonce,
        JSON.stringify(contract),
        now,
        expiresAt,
        now,
        now
      )
      .run();
  } catch (error) {
    // The partial unique index allows one active job per version and role;
    // a concurrent request that won the race is returned instead.
    const raced = await activeJob(version.version_id, actorRole, env);
    if (raced) return { kind: 'active', job: summaryFromRow(raced) };
    throw error;
  }
  await recordEvent(
    env,
    version.version_id,
    user.id,
    actorRole === 'reviewer' ? 'boot_test_replay_requested' : 'boot_test_requested',
    { bootTestJobId: id, actorRole, nonce, expiresAt },
    now
  );

  let sandboxId: string | null = null;
  try {
    const launched = await launchRuntimeObservationInE2B(
      {
        observationJobId: id,
        apiBaseUrl: new URL(request.url).origin,
        capability,
        jobKind: 'boot_test'
      },
      env
    );
    sandboxId = launched.sandboxId;
    const startedAt = new Date().toISOString();
    await env.DB.prepare(
      `UPDATE boot_test_jobs
          SET sandbox_id = ?, sandbox_started_at = ?, sandbox_termination_status = 'pending',
              updated_at = ?
        WHERE id = ? AND sandbox_id IS NULL`
    )
      .bind(sandboxId, startedAt, startedAt, id)
      .run();
  } catch (error) {
    const stage: E2BRuntimeLaunchStage =
      error instanceof E2BRuntimeLaunchError ? error.stage : 'runner_start';
    const failedAt = new Date().toISOString();
    const partialSandbox = error instanceof E2BRuntimeLaunchError ? error.sandboxId : undefined;
    let termination = error instanceof E2BRuntimeLaunchError ? error.terminationStatus : undefined;
    const recordedSandbox = sandboxId ?? partialSandbox ?? null;
    if (sandboxId) termination = await terminateRuntimeObservationInE2B(sandboxId, env);
    await env.DB.prepare(
      `UPDATE boot_test_jobs
          SET status = 'failed', sandbox_id = COALESCE(sandbox_id, ?),
              sandbox_termination_status = ?, sandbox_terminated_at = ?, updated_at = ?
        WHERE id = ? AND status = 'approved'`
    )
      .bind(
        recordedSandbox,
        recordedSandbox ? (termination ?? 'failed') : null,
        termination === 'verified' ? failedAt : null,
        failedAt,
        id
      )
      .run();
    await recordEvent(env, version.version_id, user.id, 'boot_test_dispatch_failed', {
      bootTestJobId: id,
      actorRole,
      stage
    }, failedAt);
    return { kind: 'dispatch_failed', message: safeLaunchMessage(stage) };
  }

  const row = await env.DB.prepare('SELECT * FROM boot_test_jobs WHERE id = ?')
    .bind(id)
    .first<BootTestJobRow>();
  return { kind: 'issued', job: summaryFromRow(row!) };
}

const VERSION_COLUMNS = `r.id AS review_id, v.id AS version_id, v.artifact_sha256, v.compressed_bytes,
            json_extract(v.review_json, '$.artifact.kind') AS artifact_kind`;

async function requestBootTest(
  reviewId: string,
  request: Request,
  env: Env,
  user: AuthenticatedUser,
  origin: string | null
): Promise<Response> {
  // Only the review owner, on the site that owns the review, may start a test.
  const version = await env.DB.prepare(
    `SELECT ${VERSION_COLUMNS}
       FROM reviews r
       JOIN review_versions v ON v.id = r.latest_version_id
      WHERE r.id = ? AND r.owner_user_id = ? AND r.site_id IS ?`
  )
    .bind(reviewId, user.id, user.siteId)
    .first<BootTestVersionRow>();
  if (!version) return json({ error: 'review_not_found' }, 404, origin);
  const outcome = await issueBootTest(version, 'developer', user, request, env);
  switch (outcome.kind) {
    case 'unavailable':
      return json({ error: 'boot_test_unavailable', message: outcome.message }, 400, origin);
    case 'limit_reached':
      return sandboxLimitResponse(outcome.hit, origin);
    case 'dispatch_failed':
      return json({ error: 'boot_test_dispatch_unavailable', message: outcome.message }, 503, origin);
    case 'active':
      return json({ bootTest: outcome.job, deduplicated: true }, 200, origin);
    case 'issued':
      return json({ bootTest: outcome.job, deduplicated: false }, 201, origin);
  }
}

function reviewerRedirect(parameter: string, value: string): Response {
  return new Response(null, {
    status: 303,
    headers: {
      location: `/reviewer?${parameter}=${encodeURIComponent(value)}`,
      'cache-control': 'no-store'
    }
  });
}

/**
 * Reviewer replay of the exact version in the reviewer's workspace session.
 * It uses the same authorization as the runtime replay: an HttpOnly reviewer
 * session minted from a one-time handoff, bound to one review version. A
 * Designer identity, a developer session, or another version is refused.
 */
async function requestReviewerBootTestReplay(
  reviewVersionId: string,
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  const user = await authenticateCompanion(request, env);
  if (!user) return json({ error: 'unauthorized' }, 401, origin);
  if (
    user.companionSession?.actorRole !== 'reviewer' ||
    user.companionSession.reviewVersionId !== reviewVersionId
  ) {
    return json(
      {
        error: 'boot_test_replay_forbidden',
        message: 'Only an authenticated reviewer may replay the boot test for this exact review version.'
      },
      403,
      origin
    );
  }
  const version = await env.DB.prepare(
    `SELECT ${VERSION_COLUMNS}
       FROM review_versions v
       JOIN reviews r ON r.id = v.review_id
      WHERE v.id = ? AND r.id = ?`
  )
    .bind(reviewVersionId, user.companionSession.reviewId)
    .first<BootTestVersionRow>();
  if (!version) return json({ error: 'review_version_not_found' }, 404, origin);
  const outcome = await issueBootTest(version, 'reviewer', user, request, env);
  switch (outcome.kind) {
    case 'issued':
      return reviewerRedirect('bootTestStarted', outcome.job.id);
    case 'active':
      return reviewerRedirect(
        'bootTest',
        'A boot test replay is already running for this version. Refresh this page to see the result.'
      );
    case 'limit_reached':
      return reviewerRedirect('bootTest', outcome.hit.message);
    case 'unavailable':
    case 'dispatch_failed':
      return reviewerRedirect('bootTest', outcome.message);
  }
}

/**
 * Compares the reviewer's latest replay with the developer's latest run of
 * the same version. Only the status and the set of failures count.
 */
export function compareBootTestRuns(
  developer: BootTestResult | null,
  reviewer: BootTestResult | null
): BootTestReplayComparison {
  if (!developer || !reviewer) return 'not_compared';
  if (developer.status === 'error' || reviewer.status === 'error') return 'infrastructure_incomplete';
  const sameFailures =
    developer.failures.length === reviewer.failures.length &&
    developer.failures.every((failure) => reviewer.failures.includes(failure));
  if (developer.status !== reviewer.status || !sameFailures) return 'mixed_evidence';
  return developer.status === 'passed' ? 'reproduced_pass' : 'reproduced_failure';
}

export interface ReviewerBootTestView {
  /** The latest completed developer run, or the latest developer job when none completed. */
  developer: BootTestSummary | null;
  /** The latest completed reviewer replay, or the latest replay job when none completed. */
  reviewer: BootTestSummary | null;
  developerInProgress: boolean;
  reviewerInProgress: boolean;
  /** Compares the two latest completed results only. */
  comparison: BootTestReplayComparison;
}

/**
 * The developer's and the reviewer's latest results for one version, for the
 * reviewer workspace. Null when the feature is off.
 */
export async function reviewerBootTestView(
  reviewVersionId: string,
  env: Env
): Promise<ReviewerBootTestView | null> {
  if (!bootTestsEnabled(env)) return null;
  const latest = async (actorRole: BootTestActorRole) => {
    const query = (completedOnly: boolean) =>
      env.DB.prepare(
        `SELECT * FROM boot_test_jobs
          WHERE review_version_id = ? AND actor_role = ?
            ${completedOnly ? "AND status = 'complete'" : ''}
          ORDER BY created_at DESC
          LIMIT 1`
      )
        .bind(reviewVersionId, actorRole)
        .first<BootTestJobRow>();
    const [completed, newest] = await Promise.all([query(true), query(false)]);
    const newestSummary = newest ? summaryFromRow(newest) : null;
    return {
      shown: completed ? summaryFromRow(completed) : newestSummary,
      inProgress:
        newestSummary !== null &&
        (newestSummary.status === 'approved' || newestSummary.status === 'running')
    };
  };
  const [developer, reviewer] = await Promise.all([latest('developer'), latest('reviewer')]);
  return {
    developer: developer.shown,
    reviewer: reviewer.shown,
    developerInProgress: developer.inProgress,
    reviewerInProgress: reviewer.inProgress,
    comparison: compareBootTestRuns(
      developer.shown?.bootTest ?? null,
      reviewer.shown?.bootTest ?? null
    )
  };
}

async function listBootTests(
  reviewId: string,
  env: Env,
  user: AuthenticatedUser,
  origin: string | null
): Promise<Response> {
  const includeAll = companionRoleForUser(user, env) === 'reviewer';
  const review = await env.DB.prepare(
    `SELECT id FROM reviews WHERE id = ? AND (? = 1 OR (owner_user_id = ? AND site_id IS ?))`
  )
    .bind(reviewId, includeAll ? 1 : 0, user.id, user.siteId)
    .first<{ id: string }>();
  if (!review) return json({ error: 'review_not_found' }, 404, origin);
  const rows = await env.DB.prepare(
    `SELECT j.*
       FROM boot_test_jobs j
       JOIN review_versions v ON v.id = j.review_version_id
      WHERE v.review_id = ?
      ORDER BY j.created_at DESC
      LIMIT 20`
  )
    .bind(reviewId)
    .all<BootTestJobRow>();
  return json({ bootTests: rows.results.map(summaryFromRow) }, 200, origin);
}

type CapabilityLookup =
  | { row: BootTestJobRow; contract: BootTestJobContract }
  | { response: Response };

async function jobForCapability(
  jobId: string,
  request: Request,
  env: Env,
  origin: string | null,
  allowed: BootTestJobStatus[]
): Promise<CapabilityLookup> {
  const supplied = bearerToken(request);
  if (!supplied) return { response: json({ error: 'unauthorized' }, 401, origin) };
  const row = await env.DB.prepare('SELECT * FROM boot_test_jobs WHERE id = ?')
    .bind(jobId)
    .first<BootTestJobRow>();
  if (!row) return { response: json({ error: 'boot_test_job_not_found' }, 404, origin) };
  if (!constantTimeEqual(await sha256(supplied), row.capability_sha256)) {
    return { response: json({ error: 'unauthorized' }, 401, origin) };
  }
  if (!allowed.includes(row.status) || Date.parse(row.expires_at) <= Date.now()) {
    return { response: json({ error: 'boot_test_job_unavailable' }, 410, origin) };
  }
  return { row, contract: JSON.parse(row.contract_json) as BootTestJobContract };
}

async function getBootTestJob(
  jobId: string,
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  const lookup = await jobForCapability(jobId, request, env, origin, ['approved', 'running']);
  if ('response' in lookup) return lookup.response;
  if (lookup.row.status === 'approved') {
    const now = new Date().toISOString();
    await env.DB.prepare(
      `UPDATE boot_test_jobs SET status = 'running', updated_at = ? WHERE id = ? AND status = 'approved'`
    )
      .bind(now, jobId)
      .run();
    await recordEvent(env, lookup.row.review_version_id, 'webflow-runtime-runner', 'boot_test_started', {
      bootTestJobId: jobId,
      nonce: lookup.contract.nonce
    }, now);
  }
  return json({ bootTestJob: { id: jobId, status: 'running', contract: lookup.contract } }, 200, origin);
}

/**
 * The bundle download: only while the job runs, only with its capability,
 * and only the bytes of the review version the job is bound to.
 */
async function getBootTestBundle(
  jobId: string,
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  const lookup = await jobForCapability(jobId, request, env, origin, ['running']);
  if ('response' in lookup) return lookup.response;
  const version = await env.DB.prepare(
    'SELECT artifact_key, artifact_sha256 FROM review_versions WHERE id = ?'
  )
    .bind(lookup.row.review_version_id)
    .first<{ artifact_key: string; artifact_sha256: string }>();
  if (!version || version.artifact_sha256 !== lookup.contract.bundleSha256) {
    return json({ error: 'boot_test_bundle_unavailable' }, 410, origin);
  }
  const object = await env.ARTIFACTS.get(version.artifact_key);
  if (!object || object.size > lookup.contract.bundleBytes) {
    await object?.body.cancel();
    return json({ error: 'boot_test_bundle_unavailable' }, 410, origin);
  }
  return new Response(object.body, {
    status: 200,
    headers: {
      'content-type': 'application/zip',
      'content-length': String(object.size),
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff'
    }
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function boundedInteger(value: unknown, max: number): value is number {
  return Number.isInteger(value) && Number(value) >= 0 && Number(value) <= max;
}

// Labels are bundle-relative paths, hosts, or fixed tokens: printable ASCII,
// never a URL, never a query or fragment, never a parent-directory segment.
function safeLabel(value: unknown, maxLength: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxLength &&
    /^[\x20-\x7e]+$/.test(value) &&
    !value.includes('://') &&
    !/[?#]/.test(value) &&
    !value.split('/').includes('..') &&
    !SECRET_VALUE.test(value)
  );
}

const HOST = /^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:.]+\])(?::\d{1,5})?$/i;
const MAX_HOST_LENGTH = 260;
// Stands in for a bundle-influenced label that fails its format or length rule.
const UNREADABLE_LABEL = '[unreadable]';

function stringList(
  value: unknown,
  cap: number,
  accept: (item: unknown) => boolean
): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= cap &&
    value.every(accept) &&
    new Set(value).size === value.length
  );
}

/**
 * Bundle code controls these labels, so a bad one is replaced instead of
 * rejecting the result: the verdict must always land. Lists are cut to their
 * cap first and de-duplicated after, and `replaced` counts what was changed.
 */
function tolerantLabels(
  items: unknown[],
  cap: number,
  clean: (item: unknown) => string | null
): { labels: string[]; replaced: number } {
  const labels = new Set<string>();
  let replaced = Math.max(0, items.length - cap);
  for (const item of items.slice(0, cap)) {
    const label = clean(item);
    if (label === null) replaced += 1;
    labels.add(label ?? UNREADABLE_LABEL);
  }
  return { labels: [...labels], replaced };
}

function fail(message: string): never {
  throw new BootTestResultError(message);
}

/**
 * Re-validates everything the runner returned against the job contract.
 * The identity and verdict fields are strict: anything malformed or
 * internally inconsistent is rejected and nothing is stored. Free-text labels
 * the bundle can influence (hosts, paths, messages) are tolerant: a bad one
 * becomes `[unreadable]`, an over-long list is cut to its cap, and the count
 * of such changes is kept as `labelsReplaced`.
 */
export function validateBootTestEvidence(
  raw: unknown,
  jobId: string,
  contract: BootTestJobContract
): BootTestResult & { labelsReplaced?: number } {
  const limits = contract.limits;
  if (
    !isRecord(raw) ||
    !hasExactKeys(raw, [
      'schemaVersion',
      'bootTestJobId',
      'reviewVersionId',
      'bundleSha256',
      'nonce',
      'trust',
      'startedAt',
      'finishedAt',
      'bootTest'
    ]) ||
    raw.schemaVersion !== 'designer_extension_boot_test_evidence.v1' ||
    raw.bootTestJobId !== jobId ||
    raw.reviewVersionId !== contract.reviewVersionId ||
    raw.bundleSha256 !== contract.bundleSha256 ||
    raw.nonce !== contract.nonce ||
    raw.trust !== 'webflow_observed'
  ) {
    fail('The boot test result does not match the server-issued job contract.');
  }
  const evidence = raw as Record<string, unknown>;
  const startedAt = typeof evidence.startedAt === 'string' ? Date.parse(evidence.startedAt) : NaN;
  const finishedAt = typeof evidence.finishedAt === 'string' ? Date.parse(evidence.finishedAt) : NaN;
  if (
    !Number.isFinite(startedAt) ||
    !Number.isFinite(finishedAt) ||
    finishedAt < startedAt ||
    finishedAt - startedAt > contract.controls.totalTimeoutMs + 30_000 ||
    finishedAt > Date.now() + 60_000
  ) {
    fail('The boot test timestamps fall outside the job budget.');
  }

  const result = evidence.bootTest;
  if (
    !isRecord(result) ||
    !hasExactKeys(result, [
      'status',
      'failures',
      'cspViolations',
      'missingFiles',
      'uncaughtErrors',
      'externalHostsRequested',
      'renderedTextLength',
      'renderedElementCount'
    ]) ||
    !['passed', 'failed', 'error'].includes(String(result.status)) ||
    !stringList(result.failures, BOOT_TEST_FAILURES.length, (item) =>
      BOOT_TEST_FAILURES.includes(item as BootTestFailure)
    ) ||
    !Array.isArray(result.cspViolations) ||
    !Array.isArray(result.missingFiles) ||
    !Array.isArray(result.uncaughtErrors) ||
    !Array.isArray(result.externalHostsRequested) ||
    !boundedInteger(result.renderedTextLength, 10_000_000) ||
    !boundedInteger(result.renderedElementCount, 10_000_000)
  ) {
    fail('The boot test result is malformed or exceeds its caps.');
  }

  let labelsReplaced = 0;
  const label =
    (maxLength: number) =>
    (item: unknown): string | null =>
      safeLabel(item, maxLength) ? item : null;
  const cspViolations: BootTestCspViolation[] = [];
  const seenViolations = new Set<string>();
  const cspItems = result.cspViolations as unknown[];
  labelsReplaced += Math.max(0, cspItems.length - limits.cspViolations);
  for (const item of cspItems.slice(0, limits.cspViolations)) {
    // The object shape comes from the runner, not the bundle: keep it strict.
    if (!isRecord(item) || !hasExactKeys(item, ['directive', 'blocked', 'source'])) {
      fail('A CSP violation in the boot test result is malformed.');
    }
    const clean = label(limits.messageLength);
    const directive =
      typeof item.directive === 'string' && /^[a-z-]{1,40}$/.test(item.directive)
        ? item.directive
        : 'unknown';
    const blocked = clean(item.blocked);
    const source = clean(item.source);
    labelsReplaced += Number(directive !== item.directive) + Number(blocked === null) + Number(source === null);
    const violation = {
      directive,
      blocked: blocked ?? UNREADABLE_LABEL,
      source: source ?? UNREADABLE_LABEL
    };
    const key = `${violation.directive}\n${violation.blocked}\n${violation.source}`;
    if (seenViolations.has(key)) continue;
    seenViolations.add(key);
    cspViolations.push(violation);
  }
  const missing = tolerantLabels(
    result.missingFiles as unknown[],
    limits.missingFiles,
    label(limits.messageLength)
  );
  const hosts = tolerantLabels(
    result.externalHostsRequested as unknown[],
    limits.externalHosts,
    (item) =>
      typeof item === 'string' && item.length <= MAX_HOST_LENGTH && HOST.test(item) ? item : null
  );
  const errors = tolerantLabels(
    result.uncaughtErrors as unknown[],
    limits.uncaughtErrors,
    (item) => {
      if (typeof item !== 'string' || SECRET_VALUE.test(item)) return null;
      return item.slice(0, limits.messageLength);
    }
  );
  labelsReplaced += missing.replaced + hosts.replaced + errors.replaced;

  const typed = {
    ...(result as unknown as BootTestResult),
    missingFiles: missing.labels,
    externalHostsRequested: hosts.labels,
    uncaughtErrors: errors.labels
  };
  const failures = new Set(typed.failures);
  const blank = typed.renderedTextLength === 0 && typed.renderedElementCount === 0;
  const consistent =
    typed.status === 'error'
      ? failures.size === 0
      : (typed.status === 'failed') === failures.size > 0 &&
        failures.has('bundled_file_missing') === typed.missingFiles.length > 0 &&
        failures.has('blank_panel') === blank &&
        (!failures.has('bundled_script_blocked_by_csp') ||
          cspViolations.some(
            (violation) =>
              /^(?:script-src|worker-src)/.test(violation.directive) &&
              !['inline', 'eval', 'trusted-types'].includes(violation.blocked)
          ));
  if (!consistent) fail('The boot test result is internally inconsistent.');

  return {
    status: typed.status,
    failures: BOOT_TEST_FAILURES.filter((failure) => failures.has(failure)),
    cspViolations,
    missingFiles: typed.missingFiles,
    uncaughtErrors: typed.uncaughtErrors,
    externalHostsRequested: typed.externalHostsRequested,
    renderedTextLength: typed.renderedTextLength,
    renderedElementCount: typed.renderedElementCount,
    ...(labelsReplaced > 0 ? { labelsReplaced } : {})
  };
}

async function recordBootTestResult(
  jobId: string,
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response> {
  const lookup = await jobForCapability(jobId, request, env, origin, ['running']);
  if ('response' in lookup) return lookup.response;
  const declared = Number(request.headers.get('content-length') ?? 0);
  if (declared > MAX_RESULT_BYTES) {
    return json({ error: 'invalid_boot_test_result', message: 'The result is too large.' }, 400, origin);
  }
  const text = await request.text();
  let result: BootTestResult;
  try {
    if (new TextEncoder().encode(text).byteLength > MAX_RESULT_BYTES) {
      throw new BootTestResultError('The result is too large.');
    }
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch {
      throw new BootTestResultError('The result must be valid JSON.');
    }
    result = validateBootTestEvidence(raw, jobId, lookup.contract);
  } catch (error) {
    if (error instanceof BootTestResultError) {
      return json({ error: 'invalid_boot_test_result', message: error.message }, 400, origin);
    }
    throw error;
  }

  const completedAt = new Date().toISOString();
  const update = await env.DB.prepare(
    `UPDATE boot_test_jobs
        SET status = 'complete', completed_at = ?, evidence_trust = 'webflow_observed',
            result_status = ?, result_json = ?, updated_at = ?
      WHERE id = ? AND status = 'running' AND result_json IS NULL AND expires_at > ?`
  )
    .bind(completedAt, result.status, JSON.stringify(result), completedAt, jobId, completedAt)
    .run();
  if (update.meta.changes !== 1) {
    return json({ error: 'boot_test_job_unavailable' }, 410, origin);
  }
  await recordEvent(env, lookup.row.review_version_id, 'webflow-runtime-runner', 'boot_test_completed', {
    bootTestJobId: jobId,
    trust: 'webflow_observed',
    status: result.status,
    failures: result.failures
  }, completedAt);
  await terminateBootTestSandbox(jobId, env);
  return json(
    { bootTestJobId: jobId, status: 'complete', trust: 'webflow_observed', bootTest: { status: result.status } },
    200,
    origin
  );
}

function routeId(match: RegExpMatchArray): string {
  return decodeURIComponent(match[1]!);
}

/**
 * Handles every boot test route, or returns null for any other path. With
 * `BOOT_TEST_ENABLED` off, every boot test route answers 404.
 */
export async function handleBootTestRequest(
  request: Request,
  env: Env,
  origin: string | null
): Promise<Response | null> {
  const { pathname } = new URL(request.url);
  const review = pathname.match(ROUTES.review);
  const job = pathname.match(ROUTES.job);
  const bundle = pathname.match(ROUTES.bundle);
  const result = pathname.match(ROUTES.result);
  const reviewerReplay = pathname.match(ROUTES.reviewerReplay);
  if (!review && !job && !bundle && !result && !reviewerReplay) return null;
  if (!bootTestsEnabled(env)) return json({ error: 'not_found' }, 404, origin);

  if (reviewerReplay && request.method === 'POST') {
    return requestReviewerBootTestReplay(routeId(reviewerReplay), request, env, origin);
  }
  if (job && request.method === 'GET') return getBootTestJob(routeId(job), request, env, origin);
  if (bundle && request.method === 'GET') {
    return getBootTestBundle(routeId(bundle), request, env, origin);
  }
  if (result && request.method === 'POST') {
    return recordBootTestResult(routeId(result), request, env, origin);
  }
  if (review && (request.method === 'GET' || request.method === 'POST')) {
    const user = await authenticate(request, env);
    if (!user) return json({ error: 'unauthorized' }, 401, origin);
    return request.method === 'POST'
      ? requestBootTest(routeId(review), request, env, user, origin)
      : listBootTests(routeId(review), env, user, origin);
  }
  return json({ error: 'not_found' }, 404, origin);
}
