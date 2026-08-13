import {
  createBundleReview,
  createHostedRuntimeReviewArtifact,
  HostedRuntimeReviewInputError,
  SourceMapArtifactError,
  type BundleReview
} from '@create-something/webflow-app-review-preflight';
import {
  issueSubmissionReceipt,
  type SubmissionReceipt
} from './submission-receipts';
import type { AuthenticatedUser, Env, StoredReview } from './types';

const MAX_BUNDLE_BYTES = 10 * 1024 * 1024;
const MAX_SOURCE_MAP_BYTES = 10 * 1024 * 1024;

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

interface SourceMapUpload {
  fileName: string;
  bytes: ArrayBuffer;
  sha256: string;
  extension: 'map' | 'zip';
}

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Parse the optional private source-map artifact from the multipart form.
 * The artifact is the same one the developer attaches to the official
 * submission form, so validation mirrors it: one .map file or one .zip.
 */
async function parseSourceMapUpload(
  form: FormData
): Promise<SourceMapUpload | null> {
  const entry = form.get('sourceMaps');
  if (entry === null) return null;
  if (!(entry instanceof File)) {
    throw new ReviewInputError('Source maps must be uploaded as a file.');
  }
  const lowerName = entry.name.toLowerCase();
  const extension = lowerName.endsWith('.map')
    ? 'map'
    : lowerName.endsWith('.zip')
      ? 'zip'
      : null;
  if (!extension) {
    throw new ReviewInputError(
      'Upload source maps as a single .map file or a .zip archive of .map files.'
    );
  }
  if (entry.size === 0 || entry.size > MAX_SOURCE_MAP_BYTES) {
    throw new ReviewInputError('The source-map upload must be between 1 byte and 10 MB.');
  }
  const bytes = await entry.arrayBuffer();
  return {
    fileName: entry.name,
    bytes,
    sha256: toHex(await crypto.subtle.digest('SHA-256', bytes)),
    extension
  };
}

async function storeSourceMapArtifact(
  env: Env,
  owner: string,
  upload: SourceMapUpload
): Promise<string> {
  const key = `${owner}/artifacts/source-maps/${upload.sha256}.${upload.extension}`;
  if (!(await env.ARTIFACTS.head(key))) {
    await env.ARTIFACTS.put(key, upload.bytes, {
      httpMetadata: {
        contentType: upload.extension === 'zip' ? 'application/zip' : 'application/json'
      },
      customMetadata: {
        sha256: upload.sha256,
        artifactKind: 'source_maps'
      }
    });
  }
  return key;
}

async function analyzeBundle(
  bytes: ArrayBuffer,
  fileName: string,
  sourceMapUpload: SourceMapUpload | null
): Promise<BundleReview> {
  try {
    return await createBundleReview({
      bundle: bytes,
      fileName,
      ...(sourceMapUpload
        ? {
            sourceMapArtifact: {
              fileName: sourceMapUpload.fileName,
              bytes: sourceMapUpload.bytes
            }
          }
        : {})
    });
  } catch (error) {
    if (error instanceof SourceMapArtifactError) {
      throw new ReviewInputError(error.message);
    }
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
): Promise<{ review: StoredReview; submissionReceipt: SubmissionReceipt }> {
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

  const sourceMapUpload = await parseSourceMapUpload(form);
  const bytes = await bundle.arrayBuffer();
  const result = await analyzeBundle(bytes, bundle.name, sourceMapUpload);
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
  const sourceMapKey = sourceMapUpload
    ? await storeSourceMapArtifact(env, owner, sourceMapUpload)
    : null;

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
         review_json, created_at,
         source_map_sha256, source_map_key, source_map_file_name)
       VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
      result.createdAt,
      sourceMapUpload?.sha256 ?? null,
      sourceMapKey,
      sourceMapUpload?.fileName ?? null
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
  const submissionReceipt = await issueSubmissionReceipt(env, {
    reviewId: result.reviewId,
    reviewVersionId: versionId,
    ownerUserId: user.id,
    createdAt: result.createdAt
  });
  return { review: storedReview(name, versionId, result), submissionReceipt };
}

export async function createRuntimeReview(
  request: Request,
  env: Env,
  user: AuthenticatedUser
): Promise<{ review: StoredReview; submissionReceipt: SubmissionReceipt }> {
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

  const submissionReceipt = await issueSubmissionReceipt(env, {
    reviewId: result.reviewId,
    reviewVersionId: versionId,
    ownerUserId: user.id,
    createdAt: result.createdAt
  });
  return { review: storedReview(name, versionId, result), submissionReceipt };
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
  submissionReceipt: SubmissionReceipt;
} | null> {
  const currentRow = await env.DB.prepare(
    `SELECT r.name, r.created_at, r.updated_at, v.id AS version_id, v.sequence,
            v.review_json
       FROM reviews r
       JOIN review_versions v ON v.id = r.latest_version_id
      WHERE r.id = ? AND r.owner_user_id = ? AND r.site_id IS ?`
  )
    .bind(reviewId, user.id, user.siteId)
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

  const sourceMapUpload = await parseSourceMapUpload(form);
  const bytes = await bundle.arrayBuffer();
  const result = await analyzeBundle(bytes, bundle.name, sourceMapUpload);
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
    // A deduplicated upload still gets a fresh receipt: the developer needs
    // a code to paste into the submission form even when the bytes matched
    // an earlier revision.
    const submissionReceipt = await issueSubmissionReceipt(env, {
      reviewId,
      reviewVersionId: duplicate.id,
      ownerUserId: user.id,
      createdAt: new Date().toISOString()
    });
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
      deduplicated: true,
      submissionReceipt
    };
  }

  const versionId = crypto.randomUUID();
  const eventId = crypto.randomUUID();
  const owner = safePathSegment(user.id);
  const artifactKey = `${owner}/artifacts/sha256/${result.artifact.sha256}.zip`;
  const sourceMapKey = sourceMapUpload
    ? `${owner}/artifacts/source-maps/${sourceMapUpload.sha256}.${sourceMapUpload.extension}`
    : null;

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
           review_json, created_at,
           source_map_sha256, source_map_key, source_map_file_name)
         VALUES (?, ?,
                 (SELECT COALESCE(MAX(sequence), 0) + 1
                    FROM review_versions WHERE review_id = ?),
                 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        result.createdAt,
        sourceMapUpload?.sha256 ?? null,
        sourceMapKey,
        sourceMapUpload?.fileName ?? null
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
          WHERE id = ? AND owner_user_id = ? AND site_id IS ?`
      ).bind(versionId, result.createdAt, reviewId, user.id, user.siteId),
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
    if (sourceMapUpload) {
      await storeSourceMapArtifact(env, owner, sourceMapUpload);
    }
  } catch (error) {
    // Never leave a committed version row pointing at missing bytes: roll
    // the revision back (findings cascade from the version delete).
    await env.DB.batch([
      env.DB.prepare('DELETE FROM review_events WHERE id = ?').bind(eventId),
      env.DB.prepare(
        `UPDATE reviews SET latest_version_id = ?, updated_at = ?
          WHERE id = ? AND owner_user_id = ? AND site_id IS ?`
      ).bind(currentRow.version_id, currentRow.updated_at, reviewId, user.id, user.siteId),
      env.DB.prepare('DELETE FROM review_versions WHERE id = ?').bind(versionId)
    ]);
    throw error;
  }

  const submissionReceipt = await issueSubmissionReceipt(env, {
    reviewId,
    reviewVersionId: versionId,
    ownerUserId: user.id,
    createdAt: result.createdAt
  });

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
    deduplicated: false,
    submissionReceipt
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
      WHERE (? = 1 OR (r.owner_user_id = ? AND r.site_id IS ?))
      ORDER BY r.updated_at DESC
      LIMIT 50`
  )
    .bind(options.includeAll ? 1 : 0, user.id, user.siteId)
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
      WHERE r.id = ? AND (? = 1 OR (r.owner_user_id = ? AND r.site_id IS ?))`
  )
    .bind(reviewId, options.includeAll ? 1 : 0, user.id, user.siteId)
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
