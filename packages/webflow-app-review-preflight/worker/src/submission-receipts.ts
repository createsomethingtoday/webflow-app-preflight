import type { BundleReview } from '@create-something/webflow-app-review-preflight';
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
  createdAt: string;
}

const RECEIPT_PREFIX = 'wfpre_';
const RECEIPT_PATTERN = /^wfpre_[a-f0-9]{32}$/;

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
    `SELECT latest_version_id FROM reviews WHERE id = ? AND owner_user_id = ?`
  )
    .bind(reviewId, user.id)
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
  code: unknown
): Promise<SubmissionReceiptVerification | null> {
  if (typeof code !== 'string') return null;
  const normalized = code.trim().toLowerCase();
  if (!RECEIPT_PATTERN.test(normalized)) return null;

  const row = await env.DB.prepare(
    `SELECT sr.review_id, sr.review_version_id, sr.created_at,
            v.review_json, v.source_map_sha256
       FROM submission_receipts sr
       JOIN review_versions v ON v.id = sr.review_version_id
      WHERE sr.code_sha256 = ?`
  )
    .bind(await sha256Hex(normalized))
    .first<{
      review_id: string;
      review_version_id: string;
      created_at: string;
      review_json: string;
      source_map_sha256: string | null;
    }>();
  if (!row) return null;

  const result = JSON.parse(row.review_json) as BundleReview;

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

  return {
    reviewId: row.review_id,
    appName: result.artifactScope.appName,
    bundleSha256: result.artifact.sha256,
    sourceMapArtifactSha256: row.source_map_sha256 ?? result.artifact.sourceMaps?.sha256 ?? null,
    readiness: result.summary.readiness,
    sourceMapStatus: result.sourceMapSummary?.status ?? 'not_applicable',
    runtimeSecurityStatus,
    createdAt: row.created_at
  };
}
