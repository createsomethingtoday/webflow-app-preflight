import {
  createBundleReview,
  createHostedRuntimeReviewArtifact,
  HostedRuntimeReviewInputError,
  type BundleReview
} from '@create-something/webflow-app-review-preflight';
import type { AuthenticatedUser, Env, StoredReview } from './types';

const MAX_BUNDLE_BYTES = 10 * 1024 * 1024;

export class ReviewInputError extends Error {}
export class RuntimeReviewInputError extends Error {}
/** A concurrent revision won the uniqueness race; the caller should retry. */
export class ReviewConflictError extends Error {}

function safePathSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9_-]/g, '_');
}

function asName(value: FormDataEntryValue | null, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  const normalized = value.trim().slice(0, 120);
  return normalized || fallback;
}

async function analyzeBundle(bytes: ArrayBuffer, fileName: string): Promise<BundleReview> {
  try {
    return await createBundleReview({ bundle: bytes, fileName });
  } catch {
    throw new ReviewInputError('We could not read this zip. Re-export the bundle and try again.');
  }
}

function storedReview(
  name: string,
  versionId: string,
  result: BundleReview
): StoredReview {
  return {
    id: result.reviewId,
    name,
    createdAt: result.createdAt,
    updatedAt: result.createdAt,
    latestVersion: {
      id: versionId,
      sequence: 1,
      createdAt: result.createdAt,
      result
    }
  };
}

export async function createReview(
  request: Request,
  env: Env,
  user: AuthenticatedUser
): Promise<StoredReview> {
  const form = await request.formData();
  const bundle = form.get('bundle');

  if (!(bundle instanceof File)) {
    throw new ReviewInputError('Choose a .zip app bundle to start the review.');
  }
  if (!bundle.name.toLowerCase().endsWith('.zip')) {
    throw new ReviewInputError('The uploaded bundle must be a .zip file.');
  }
  if (bundle.size === 0 || bundle.size > MAX_BUNDLE_BYTES) {
    throw new ReviewInputError('The bundle must be between 1 byte and 10 MB.');
  }

  const bytes = await bundle.arrayBuffer();
  const result = await analyzeBundle(bytes, bundle.name);
  const versionId = crypto.randomUUID();
  const name = asName(form.get('name'), result.artifactScope.appName ?? bundle.name);
  const owner = safePathSegment(user.id);
  const artifactKey = `${owner}/artifacts/sha256/${result.artifact.sha256}.zip`;

  const existing = await env.ARTIFACTS.head(artifactKey);
  if (!existing) {
    await env.ARTIFACTS.put(artifactKey, bytes, {
      httpMetadata: { contentType: 'application/zip' },
      customMetadata: {
        sha256: result.artifact.sha256,
        policyRulesetVersion: result.policySnapshot.rulesetVersion
      }
    });
  }

  const statements = [
    env.DB.prepare(
      `INSERT INTO reviews
        (id, owner_user_id, site_id, name, created_at, updated_at, latest_version_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      result.reviewId,
      user.id,
      user.siteId,
      name,
      result.createdAt,
      result.createdAt,
      versionId
    ),
    env.DB.prepare(
      `INSERT INTO review_versions
        (id, review_id, sequence, artifact_sha256, artifact_key, file_name,
         compressed_bytes, policy_ruleset_version, policy_config_version,
         review_json, created_at)
       VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      versionId,
      result.reviewId,
      result.artifact.sha256,
      artifactKey,
      bundle.name,
      result.artifact.compressedBytes,
      result.policySnapshot.rulesetVersion,
      result.policySnapshot.configVersion,
      JSON.stringify(result),
      result.createdAt
    ),
    ...result.guidance.map((finding) =>
      env.DB.prepare(
        `INSERT INTO review_findings
          (id, review_version_id, rule_id, label, title, severity, confidence,
           finding_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        `${versionId}:${finding.id}`,
        versionId,
        finding.id,
        finding.label,
        finding.title,
        finding.severity,
        finding.confidence,
        JSON.stringify(finding),
        result.createdAt
      )
    ),
    env.DB.prepare(
      `INSERT INTO review_events
        (id, review_id, review_version_id, actor_user_id, event_type,
         payload_json, created_at)
       VALUES (?, ?, ?, ?, 'review_created', ?, ?)`
    ).bind(
      crypto.randomUUID(),
      result.reviewId,
      versionId,
      user.id,
      JSON.stringify({
        sequence: 1,
        artifactSha256: result.artifact.sha256,
        scope: result.artifactScope.primary
      }),
      result.createdAt
    )
  ];

  await env.DB.batch(statements);
  return storedReview(name, versionId, result);
}

export async function createRuntimeReview(
  request: Request,
  env: Env,
  user: AuthenticatedUser
): Promise<StoredReview> {
  let body: unknown;
  try {
    const text = await request.text();
    if (!text || text.length > 32 * 1024) throw new Error();
    body = JSON.parse(text);
  } catch {
    throw new RuntimeReviewInputError('Hosted runtime review input must be valid JSON.');
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new RuntimeReviewInputError('Hosted runtime review input must be an object.');
  }

  let artifact: Awaited<ReturnType<typeof createHostedRuntimeReviewArtifact>>;
  try {
    const value = body as Record<string, unknown>;
    artifact = await createHostedRuntimeReviewArtifact({
      appName: value.appName as string,
      runtimeUrls: value.runtimeUrls as string[]
    });
  } catch (error) {
    if (error instanceof HostedRuntimeReviewInputError) {
      throw new RuntimeReviewInputError(error.message);
    }
    throw error;
  }

  const result = artifact.review;
  const versionId = crypto.randomUUID();
  const name = `${result.artifactScope.appName} runtime review`;
  const owner = safePathSegment(user.id);
  const artifactKey = `${owner}/artifacts/sha256/${result.artifact.sha256}.json`;

  if (!(await env.ARTIFACTS.head(artifactKey))) {
    await env.ARTIFACTS.put(artifactKey, artifact.manifest, {
      httpMetadata: { contentType: 'application/json' },
      customMetadata: {
        sha256: result.artifact.sha256,
        artifactKind: 'runtime_manifest'
      }
    });
  }

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO reviews
        (id, owner_user_id, site_id, name, created_at, updated_at, latest_version_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      result.reviewId,
      user.id,
      user.siteId,
      name,
      result.createdAt,
      result.createdAt,
      versionId
    ),
    env.DB.prepare(
      `INSERT INTO review_versions
        (id, review_id, sequence, artifact_sha256, artifact_key, file_name,
         compressed_bytes, policy_ruleset_version, policy_config_version,
         review_json, created_at)
       VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      versionId,
      result.reviewId,
      result.artifact.sha256,
      artifactKey,
      result.artifact.fileName,
      result.artifact.compressedBytes,
      result.policySnapshot.rulesetVersion,
      result.policySnapshot.configVersion,
      JSON.stringify(result),
      result.createdAt
    ),
    env.DB.prepare(
      `INSERT INTO review_events
        (id, review_id, review_version_id, actor_user_id, event_type,
         payload_json, created_at)
       VALUES (?, ?, ?, ?, 'runtime_review_created', ?, ?)`
    ).bind(
      crypto.randomUUID(),
      result.reviewId,
      versionId,
      user.id,
      JSON.stringify({
        artifactSha256: result.artifact.sha256,
        appType: result.artifactScope.appType,
        runtimeArtifactCount: result.runtime.references.length
      }),
      result.createdAt
    )
  ]);

  return storedReview(name, versionId, result);
}

interface LatestReviewRow {
  name: string;
  created_at: string;
  updated_at: string;
  version_id: string;
  sequence: number;
  review_json: string;
}

export interface ReviewComparison {
  resolved: string[];
  remaining: string[];
  added: string[];
}

function compareResults(
  previous: BundleReview,
  current: BundleReview
): ReviewComparison {
  const previousIds = new Set(previous.guidance.map((item) => item.id));
  const currentIds = new Set(current.guidance.map((item) => item.id));

  return {
    resolved: [...previousIds].filter((id) => !currentIds.has(id)).sort(),
    remaining: [...previousIds].filter((id) => currentIds.has(id)).sort(),
    added: [...currentIds].filter((id) => !previousIds.has(id)).sort()
  };
}

export async function addRevision(
  reviewId: string,
  request: Request,
  env: Env,
  user: AuthenticatedUser
): Promise<{
  review: StoredReview;
  comparison: ReviewComparison;
  deduplicated: boolean;
} | null> {
  const currentRow = await env.DB.prepare(
    `SELECT r.name, r.created_at, r.updated_at, v.id AS version_id, v.sequence,
            v.review_json
       FROM reviews r
       JOIN review_versions v ON v.id = r.latest_version_id
      WHERE r.id = ? AND r.owner_user_id = ?`
  )
    .bind(reviewId, user.id)
    .first<LatestReviewRow>();

  if (!currentRow) return null;

  const form = await request.formData();
  const bundle = form.get('bundle');
  if (!(bundle instanceof File)) {
    throw new ReviewInputError('Choose a .zip app bundle to add a revision.');
  }
  if (!bundle.name.toLowerCase().endsWith('.zip')) {
    throw new ReviewInputError('The uploaded bundle must be a .zip file.');
  }
  if (bundle.size === 0 || bundle.size > MAX_BUNDLE_BYTES) {
    throw new ReviewInputError('The bundle must be between 1 byte and 10 MB.');
  }

  const bytes = await bundle.arrayBuffer();
  const result = await analyzeBundle(bytes, bundle.name);
  result.reviewId = reviewId;
  const previous = JSON.parse(currentRow.review_json) as BundleReview;

  const duplicate = await env.DB.prepare(
    `SELECT id, sequence, created_at, review_json
       FROM review_versions
      WHERE review_id = ? AND artifact_sha256 = ?`
  )
    .bind(reviewId, result.artifact.sha256)
    .first<{
      id: string;
      sequence: number;
      created_at: string;
      review_json: string;
    }>();

  if (duplicate) {
    const duplicateResult = JSON.parse(duplicate.review_json) as BundleReview;
    return {
      review: {
        id: reviewId,
        name: currentRow.name,
        createdAt: currentRow.created_at,
        updatedAt: duplicate.created_at,
        latestVersion: {
          id: duplicate.id,
          sequence: duplicate.sequence,
          createdAt: duplicate.created_at,
          result: duplicateResult
        }
      },
      comparison: compareResults(previous, duplicateResult),
      deduplicated: true
    };
  }

  const versionId = crypto.randomUUID();
  const eventId = crypto.randomUUID();
  const owner = safePathSegment(user.id);
  const artifactKey = `${owner}/artifacts/sha256/${result.artifact.sha256}.zip`;

  // The next sequence is computed INSIDE the transactional batch
  // (MAX(sequence) + 1) rather than from a value read earlier, so two
  // concurrent revisions cannot both claim the same sequence. A remaining
  // uniqueness race (e.g. the same artifact submitted twice concurrently)
  // is reported as a retryable conflict instead of a 500, and the artifact
  // bytes are written to R2 only after the batch commits, so a failed batch
  // leaves no orphan R2 object.
  let batchResults: D1Result[];
  try {
    batchResults = await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO review_versions
          (id, review_id, sequence, artifact_sha256, artifact_key, file_name,
           compressed_bytes, policy_ruleset_version, policy_config_version,
           review_json, created_at)
         VALUES (?, ?,
                 (SELECT COALESCE(MAX(sequence), 0) + 1
                    FROM review_versions WHERE review_id = ?),
                 ?, ?, ?, ?, ?, ?, ?, ?)
         RETURNING sequence`
      ).bind(
        versionId,
        reviewId,
        reviewId,
        result.artifact.sha256,
        artifactKey,
        bundle.name,
        result.artifact.compressedBytes,
        result.policySnapshot.rulesetVersion,
        result.policySnapshot.configVersion,
        JSON.stringify(result),
        result.createdAt
      ),
      ...result.guidance.map((finding) =>
        env.DB.prepare(
          `INSERT INTO review_findings
            (id, review_version_id, rule_id, label, title, severity, confidence,
             finding_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          `${versionId}:${finding.id}`,
          versionId,
          finding.id,
          finding.label,
          finding.title,
          finding.severity,
          finding.confidence,
          JSON.stringify(finding),
          result.createdAt
        )
      ),
      env.DB.prepare(
        `UPDATE reviews
            SET latest_version_id = ?, updated_at = ?
          WHERE id = ? AND owner_user_id = ?`
      ).bind(versionId, result.createdAt, reviewId, user.id),
      env.DB.prepare(
        `INSERT INTO review_events
          (id, review_id, review_version_id, actor_user_id, event_type,
           payload_json, created_at)
         VALUES (?, ?, ?, ?, 'revision_added',
                 json_set(?, '$.sequence',
                          (SELECT sequence FROM review_versions WHERE id = ?)),
                 ?)`
      ).bind(
        eventId,
        reviewId,
        versionId,
        user.id,
        JSON.stringify({
          artifactSha256: result.artifact.sha256,
          comparison: compareResults(previous, result)
        }),
        versionId,
        result.createdAt
      )
    ]);
  } catch (error) {
    if (error instanceof Error && /UNIQUE constraint/i.test(error.message)) {
      throw new ReviewConflictError(
        'Another revision for this review landed at the same time. Retry the upload.'
      );
    }
    throw error;
  }

  const nextSequence = Number(
    (batchResults[0]?.results?.[0] as { sequence?: number } | undefined)?.sequence ??
      currentRow.sequence + 1
  );

  try {
    const existing = await env.ARTIFACTS.head(artifactKey);
    if (!existing) {
      await env.ARTIFACTS.put(artifactKey, bytes, {
        httpMetadata: { contentType: 'application/zip' },
        customMetadata: {
          sha256: result.artifact.sha256,
          policyRulesetVersion: result.policySnapshot.rulesetVersion
        }
      });
    }
  } catch (error) {
    // Never leave a committed version row pointing at missing bytes: roll
    // the revision back (findings cascade from the version delete).
    await env.DB.batch([
      env.DB.prepare('DELETE FROM review_events WHERE id = ?').bind(eventId),
      env.DB.prepare(
        `UPDATE reviews SET latest_version_id = ?, updated_at = ?
          WHERE id = ? AND owner_user_id = ?`
      ).bind(currentRow.version_id, currentRow.updated_at, reviewId, user.id),
      env.DB.prepare('DELETE FROM review_versions WHERE id = ?').bind(versionId)
    ]);
    throw error;
  }

  return {
    review: {
      id: reviewId,
      name: currentRow.name,
      createdAt: currentRow.created_at,
      updatedAt: result.createdAt,
      latestVersion: {
        id: versionId,
        sequence: nextSequence,
        createdAt: result.createdAt,
        result
      }
    },
    comparison: compareResults(previous, result),
    deduplicated: false
  };
}

interface StoredReviewRow {
  id: string;
  name: string;
  created_at: string;
  updated_at: string;
  version_id: string;
  sequence: number;
  version_created_at: string;
  review_json: string;
}

export interface ReviewSummary {
  id: string;
  name: string;
  updatedAt: string;
  latestSequence: number;
  readiness: BundleReview['summary']['readiness'];
  appName: string | null;
  reviewType: 'bundle' | 'runtime_manifest';
  coverage: BundleReview['coverage'];
}

export async function listReviews(
  env: Env,
  user: AuthenticatedUser,
  options: { includeAll?: boolean } = {}
): Promise<ReviewSummary[]> {
  const rows = await env.DB.prepare(
    `SELECT r.id, r.name, r.updated_at, v.sequence, v.review_json
       FROM reviews r
       JOIN review_versions v ON v.id = r.latest_version_id
      WHERE (? = 1 OR r.owner_user_id = ?)
      ORDER BY r.updated_at DESC
      LIMIT 50`
  )
    .bind(options.includeAll ? 1 : 0, user.id)
    .all<{
      id: string;
      name: string;
      updated_at: string;
      sequence: number;
      review_json: string;
    }>();

  return rows.results.map((row) => {
    const result = JSON.parse(row.review_json) as BundleReview;
    return {
      id: row.id,
      name: row.name,
      updatedAt: row.updated_at,
      latestSequence: row.sequence,
      readiness: result.summary.readiness,
      appName: result.artifactScope.appName,
      reviewType: result.artifact.kind === 'runtime_manifest' ? 'runtime_manifest' : 'bundle',
      coverage: result.coverage
    };
  });
}

export async function getReview(
  reviewId: string,
  env: Env,
  user: AuthenticatedUser,
  options: { includeAll?: boolean } = {}
): Promise<StoredReview | null> {
  const row = await env.DB.prepare(
    `SELECT r.id, r.name, r.created_at, r.updated_at,
            v.id AS version_id, v.sequence, v.created_at AS version_created_at,
            v.review_json
       FROM reviews r
       JOIN review_versions v ON v.id = r.latest_version_id
      WHERE r.id = ? AND (? = 1 OR r.owner_user_id = ?)`
  )
    .bind(reviewId, options.includeAll ? 1 : 0, user.id)
    .first<StoredReviewRow>();

  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    latestVersion: {
      id: row.version_id,
      sequence: row.sequence,
      createdAt: row.version_created_at,
      result: JSON.parse(row.review_json) as BundleReview
    }
  };
}
