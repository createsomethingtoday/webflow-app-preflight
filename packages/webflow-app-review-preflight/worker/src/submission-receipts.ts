import type { BundleReview } from '@create-something/webflow-app-review-preflight';
import { bootTestSummaryForVersion } from './boot-tests';
import { installUrlCheckSummaryForVersion, type InstallUrlCheckSummary } from './install-url-checks';
import { runtimeAdvisoryForVersion, type RuntimeAdvisory } from './runtime-advisory';
import type { AuthenticatedUser, Env } from './types';

/**
 * Submission receipts stamp a preflight run so the official Marketplace
 * submission form can trace the submission back to the validated artifacts.
 *
 * Trust model: the receipt code is an unguessable 128-bit bearer reference.
 * Only its SHA-256 is stored, so a database read never yields a redeemable
 * code. Verification exposes reconciliation metadata only (hashes, statuses,
 * app name) — never findings, evidence, or artifact bytes. A receipt is a
 * reference, not an approval: `readiness` and runtime status describe what
 * preflight observed, and the reviewer replay remains the verification.
 */

export interface SubmissionReceipt {
  code: string;
  createdAt: string;
}

export interface SubmissionReceiptVerification {
  reviewId: string;
  appName: string | null;
  bundleSha256: string;
  sourceMapArtifactSha256: string | null;
  readiness: BundleReview['summary']['readiness'];
  sourceMapStatus: string;
  runtimeSecurityStatus: 'passed' | 'blocked' | 'none';
  /** How the review was created: the Designer extension or the creator CLI. */
  authVia: 'designer' | 'oauth';
  installUrl: InstallUrlCheckSummary | null;
  createdAt: string;
  /**
   * Source `.map` files ship inside the production bundle ZIP (not the private
   * review artifact). Guidance only: never changes `readiness`. Reviews stored
   * before the scanner recorded exposed maps read as `false`.
   */
  sourceMapsInBundle: boolean;
  /** A client ID is bound to this receipt after this call. */
  clientIdBound: boolean;
  /** The receipt is bound to a different client ID than the one in this request. */
  clientIdConflict: boolean;
  /**
   * Advisory summary of the published-site runtime checks for this version
   * (strict-CSP replay, static scan counts, mutable runtime URLs). Never a
   * gate. `null` when the summary could not be read.
   */
  runtimeAdvisory: RuntimeAdvisory | null;
  /**
   * Advisory status of the latest Designer Extension boot test for this
   * version. `not_run` when no test finished or the feature is off.
   */
  bootTest: 'passed' | 'failed' | 'error' | 'not_run';
}

export interface SubmissionReceiptVerifyOptions {
  /** Client ID from the request body; only a 64-character hex string is honoured. */
  clientId?: unknown;
  /** Bind `clientId` to the receipt when it has none yet. Only `true` binds. */
  bind?: unknown;
}

const RECEIPT_PREFIX = 'wfpre_';
const RECEIPT_PATTERN = /^wfpre_[a-f0-9]{32}$/;
const CLIENT_ID_PATTERN = /^[a-f0-9]{64}$/i;

function normalizeClientId(value: unknown): string | null {
  return typeof value === 'string' && CLIENT_ID_PATTERN.test(value) ? value.toLowerCase() : null;
}

function toHex(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return [...view].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(value: string): Promise<string> {
  return toHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
}

function generateReceiptCode(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `${RECEIPT_PREFIX}${toHex(bytes)}`;
}

/**
 * Issue a new receipt for a review version. Prior receipts stay redeemable:
 * a receipt names an immutable version, so an older code can never point at
 * newer, unvalidated bytes.
 */
export async function issueSubmissionReceipt(
  env: Env,
  input: {
    reviewId: string;
    reviewVersionId: string;
    ownerUserId: string;
    createdAt: string;
  }
): Promise<SubmissionReceipt> {
  const code = generateReceiptCode();
  await env.DB.prepare(
    `INSERT INTO submission_receipts
      (id, code_sha256, review_id, review_version_id, owner_user_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(
      crypto.randomUUID(),
      await sha256Hex(code),
      input.reviewId,
      input.reviewVersionId,
      input.ownerUserId,
      input.createdAt
    )
    .run();
  return { code, createdAt: input.createdAt };
}

/**
 * Issue a fresh receipt for the review's latest version, owner-scoped.
 * Returns null when the review does not exist or is not owned by the caller.
 */
export async function reissueSubmissionReceipt(
  reviewId: string,
  env: Env,
  user: AuthenticatedUser
): Promise<SubmissionReceipt | null> {
  const row = await env.DB.prepare(
    `SELECT latest_version_id FROM reviews WHERE id = ? AND owner_user_id = ? AND site_id IS ?`
  )
    .bind(reviewId, user.id, user.siteId)
    .first<{ latest_version_id: string }>();
  if (!row) return null;
  return issueSubmissionReceipt(env, {
    reviewId,
    reviewVersionId: row.latest_version_id,
    ownerUserId: user.id,
    createdAt: new Date().toISOString()
  });
}

/**
 * Resolve a receipt code to reconciliation metadata. Unauthenticated by
 * design — the code itself is the secret — and intentionally minimal in what
 * it returns. Unknown, malformed, or dangling codes all resolve to null so
 * the endpoint cannot be used to probe which reviews exist.
 */
export async function verifySubmissionReceipt(
  env: Env,
  code: unknown,
  options: SubmissionReceiptVerifyOptions = {}
): Promise<SubmissionReceiptVerification | null> {
  if (typeof code !== 'string') return null;
  const normalized = code.trim().toLowerCase();
  if (!RECEIPT_PATTERN.test(normalized)) return null;

  const row = await env.DB.prepare(
    `SELECT sr.id, sr.review_id, sr.review_version_id, sr.created_at, sr.bound_client_id,
            v.review_json, v.source_map_sha256, r.auth_via
       FROM submission_receipts sr
       JOIN review_versions v ON v.id = sr.review_version_id
       JOIN reviews r ON r.id = sr.review_id
      WHERE sr.code_sha256 = ?`
  )
    .bind(await sha256Hex(normalized))
    .first<{
      id: string;
      review_id: string;
      review_version_id: string;
      created_at: string;
      bound_client_id: string | null;
      review_json: string;
      source_map_sha256: string | null;
      auth_via: string | null;
    }>();
  if (!row) return null;

  const result = JSON.parse(row.review_json) as BundleReview;

  // Client ID binding. One conditional UPDATE decides a race (the loser
  // matches zero rows), then the row is re-read so the answer reflects the
  // winner. The bound value itself is never returned.
  const clientId = normalizeClientId(options.clientId);
  let boundClientId = row.bound_client_id;
  if (options.bind === true && clientId && boundClientId === null) {
    await env.DB.prepare(
      `UPDATE submission_receipts SET bound_client_id = ? WHERE id = ? AND bound_client_id IS NULL`
    )
      .bind(clientId, row.id)
      .run();
    const reread = await env.DB.prepare(
      `SELECT bound_client_id FROM submission_receipts WHERE id = ?`
    )
      .bind(row.id)
      .first<{ bound_client_id: string | null }>();
    boundClientId = reread?.bound_client_id ?? null;
  }

  // Latest server-owned runtime evidence for this exact version, if any.
  // The security evaluation was computed server-side when the evidence was
  // recorded; this read never trusts anything the runner sent unvalidated.
  const evidenceRow = await env.DB.prepare(
    `SELECT j.evidence_manifest_json
       FROM runtime_test_packages p
       JOIN runtime_observation_jobs j ON j.test_package_id = p.id
      WHERE p.review_version_id = ?
        AND j.status = 'complete'
        AND j.evidence_trust = 'webflow_observed'
      ORDER BY j.created_at DESC
      LIMIT 1`
  )
    .bind(row.review_version_id)
    .first<{ evidence_manifest_json: string | null }>();

  let runtimeSecurityStatus: SubmissionReceiptVerification['runtimeSecurityStatus'] = 'none';
  if (evidenceRow?.evidence_manifest_json) {
    try {
      const manifest = JSON.parse(evidenceRow.evidence_manifest_json) as {
        securityEvaluation?: { status?: unknown };
      };
      const status = manifest.securityEvaluation?.status;
      if (status === 'passed' || status === 'blocked') {
        runtimeSecurityStatus = status;
      }
    } catch {
      // Unreadable stored evidence never blocks receipt resolution.
    }
  }

  // Advisory summaries. A failure to read one must never fail receipt
  // verification, so each read degrades on its own.
  let runtimeAdvisory: RuntimeAdvisory | null = null;
  try {
    runtimeAdvisory = await runtimeAdvisoryForVersion(row.review_version_id, env);
  } catch {
    runtimeAdvisory = null;
  }
  let bootTest: SubmissionReceiptVerification['bootTest'] = 'not_run';
  try {
    bootTest = (await bootTestSummaryForVersion(row.review_version_id, env)).status;
  } catch {
    bootTest = 'not_run';
  }

  return {
    reviewId: row.review_id,
    appName: result.artifactScope.appName,
    bundleSha256: result.artifact.sha256,
    sourceMapArtifactSha256: row.source_map_sha256 ?? result.artifact.sourceMaps?.sha256 ?? null,
    readiness: result.summary.readiness,
    sourceMapStatus: result.sourceMapSummary?.status ?? 'not_applicable',
    runtimeSecurityStatus,
    // Rows from before the column existed are NULL and were all Designer reviews.
    authVia: row.auth_via === 'oauth' ? 'oauth' : 'designer',
    installUrl: await installUrlCheckSummaryForVersion(row.review_version_id, env),
    createdAt: row.created_at,
    sourceMapsInBundle: (result.sourceMapSummary?.exposedSourceMapFiles?.length ?? 0) > 0,
    clientIdBound: boundClientId !== null,
    clientIdConflict: boundClientId !== null && clientId !== null && boundClientId !== clientId,
    runtimeAdvisory,
    bootTest
  };
}
