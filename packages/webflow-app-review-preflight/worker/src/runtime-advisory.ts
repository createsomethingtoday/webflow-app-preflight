import {
  mutableRuntimeUrls,
  type BundleReview,
  type RuntimeCspReplay,
  type RuntimeStaticScan
} from '@create-something/webflow-app-review-preflight';
import type { Env } from './types';

/**
 * Advisory runtime signals: the strict-CSP replay and mutable runtime URLs.
 * Nothing here feeds `securityStatus`, the security predicates, blockers or
 * readiness. The runner's replay result is untrusted input until it passes
 * `sanitizeCspReplay`.
 */

const MAX_CSP_REPLAY_VIOLATIONS = 50;
const FORBIDDEN_VALUE =
  /(?:Bearer\s+[A-Za-z0-9._~+/=-]{8,}|-----BEGIN [^-]*PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{12,})/i;
const HOST = '[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::\\d{1,5})?';
const DIRECTIVE = /^[a-z-]{1,60}$/;
const BLOCKED = new RegExp(`^(?:inline|eval|[a-z-]{1,24}|${HOST})$`, 'i');
// "host/path": printable ASCII with no whitespace, query or fragment.
const SOURCE = new RegExp(`^(?:document|${HOST}/[\\x21-\\x7e]{0,300})$`, 'i');

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

/**
 * Accepts `cspReplay` only in its exact shape, with size caps, and returns a
 * freshly built copy. Anything else (extra keys, wrong types, over-long
 * lists, an inconsistent status, secret-looking text, `?`/`#` in a source)
 * returns null so the caller drops it and treats the replay as `not_run`.
 */
export function sanitizeCspReplay(raw: unknown): RuntimeCspReplay | null {
  if (!isRecord(raw) || !hasExactKeys(raw, ['status', 'runtimeReadyObserved', 'violations'])) {
    return null;
  }
  const { status, runtimeReadyObserved, violations } = raw;
  if (
    (status !== 'clean' && status !== 'violations' && status !== 'not_run') ||
    typeof runtimeReadyObserved !== 'boolean' ||
    !Array.isArray(violations) ||
    violations.length > MAX_CSP_REPLAY_VIOLATIONS
  ) {
    return null;
  }
  const clean: RuntimeCspReplay['violations'] = [];
  for (const item of violations) {
    if (
      !isRecord(item) ||
      !hasExactKeys(item, ['directive', 'blocked', 'source', 'fromRuntime']) ||
      typeof item.directive !== 'string' ||
      !DIRECTIVE.test(item.directive) ||
      typeof item.blocked !== 'string' ||
      !BLOCKED.test(item.blocked) ||
      typeof item.source !== 'string' ||
      !SOURCE.test(item.source) ||
      FORBIDDEN_VALUE.test(item.source) ||
      /[?#]/.test(item.source) ||
      typeof item.fromRuntime !== 'boolean'
    ) {
      return null;
    }
    clean.push({
      directive: item.directive,
      blocked: item.blocked,
      source: item.source,
      fromRuntime: item.fromRuntime
    });
  }
  // The status must follow from the entries: `violations` only when at least
  // one is the runtime's own, and `not_run` carries nothing.
  const runtimeOwned = clean.some((violation) => violation.fromRuntime);
  if (
    (status === 'violations' && !runtimeOwned) ||
    (status === 'clean' && runtimeOwned) ||
    (status === 'not_run' && (clean.length > 0 || runtimeReadyObserved))
  ) {
    return null;
  }
  return { status, runtimeReadyObserved, violations: clean };
}

const MAX_STATIC_SCAN_FILES = 8;
const MAX_STATIC_SCAN_FINDINGS = 60;

/**
 * Accepts `runtimeStaticScan` only as rule-level counts in its exact shape.
 * Returns a fresh copy, or null for anything else (extra keys, free text
 * where an identifier belongs, over-long lists, an inconsistent status).
 */
export function sanitizeRuntimeStaticScan(raw: unknown): RuntimeStaticScan | null {
  if (!isRecord(raw) || !hasExactKeys(raw, ['status', 'filesScanned', 'findings'])) return null;
  const { status, filesScanned, findings } = raw;
  if (
    (status !== 'scanned' && status !== 'not_run') ||
    !Number.isInteger(filesScanned) ||
    Number(filesScanned) < 0 ||
    Number(filesScanned) > MAX_STATIC_SCAN_FILES ||
    !Array.isArray(findings) ||
    findings.length > MAX_STATIC_SCAN_FINDINGS
  ) {
    return null;
  }
  const clean: RuntimeStaticScan['findings'] = [];
  for (const item of findings) {
    if (
      !isRecord(item) ||
      !hasExactKeys(item, ['ruleId', 'name', 'severity', 'count']) ||
      typeof item.ruleId !== 'string' ||
      !/^[A-Z0-9][A-Z0-9-]{0,59}$/.test(item.ruleId) ||
      typeof item.name !== 'string' ||
      !/^[A-Za-z0-9 ()/.,'-]{1,80}$/.test(item.name) ||
      typeof item.severity !== 'string' ||
      !/^[A-Z]{3,10}$/.test(item.severity) ||
      !Number.isInteger(item.count) ||
      Number(item.count) < 1 ||
      Number(item.count) > 100_000
    ) {
      return null;
    }
    clean.push({
      ruleId: item.ruleId,
      name: item.name,
      severity: item.severity,
      count: Number(item.count)
    });
  }
  if (
    (status === 'not_run' && (Number(filesScanned) !== 0 || clean.length > 0)) ||
    (status === 'scanned' && Number(filesScanned) === 0)
  ) {
    return null;
  }
  return { status, filesScanned: Number(filesScanned), findings: clean };
}

export const NOT_RUN_STATIC_SCAN: RuntimeStaticScan = {
  status: 'not_run',
  filesScanned: 0,
  findings: []
};

export const NOT_RUN_CSP_REPLAY: RuntimeCspReplay = {
  status: 'not_run',
  runtimeReadyObserved: false,
  violations: []
};

export interface RuntimeAdvisory {
  /** A completed, Webflow-observed runtime run exists for this version. */
  observationRan: boolean;
  cspReplay: RuntimeCspReplay['status'];
  /** Total advisory static-scan matches over the served runtime files; 0 when not run. */
  staticFindingCount: number;
  /** Declared runtime URLs with neither a version nor a content hash. */
  mutableRuntimeUrlCount: number;
}

function runtimeUrlsOfPackage(packageJson: string): string[] {
  try {
    const parsed = JSON.parse(packageJson) as { runtimeArtifacts?: unknown };
    return Array.isArray(parsed.runtimeArtifacts)
      ? parsed.runtimeArtifacts
          .map((artifact) => (isRecord(artifact) ? artifact.url : null))
          .filter((url): url is string => typeof url === 'string')
      : [];
  } catch {
    return [];
  }
}

/**
 * Summarizes the advisory runtime signals for one review version, for the
 * submission receipt. Read-only; unreadable stored data degrades to
 * "not run" / 0 instead of failing the caller.
 */
export async function runtimeAdvisoryForVersion(
  reviewVersionId: string,
  env: Env
): Promise<RuntimeAdvisory> {
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
    .bind(reviewVersionId)
    .first<{ evidence_manifest_json: string | null }>();

  let cspReplay: RuntimeAdvisory['cspReplay'] = 'not_run';
  let staticFindingCount = 0;
  if (evidenceRow?.evidence_manifest_json) {
    try {
      const manifest = JSON.parse(evidenceRow.evidence_manifest_json) as {
        cspReplay?: unknown;
        runtimeStaticScan?: unknown;
      };
      cspReplay = sanitizeCspReplay(manifest.cspReplay)?.status ?? 'not_run';
      const scan = sanitizeRuntimeStaticScan(manifest.runtimeStaticScan);
      staticFindingCount =
        scan?.status === 'scanned'
          ? scan.findings.reduce((total, finding) => total + finding.count, 0)
          : 0;
    } catch {
      // Unreadable stored evidence reads as "not run".
    }
  }

  // Declared URLs: the latest runtime test package of this version, else the
  // hosted review's own declared list.
  let mutableRuntimeUrlCount = 0;
  const packageRow = await env.DB.prepare(
    `SELECT package_json
       FROM runtime_test_packages
      WHERE review_version_id = ?
      ORDER BY created_at DESC
      LIMIT 1`
  )
    .bind(reviewVersionId)
    .first<{ package_json: string }>();
  if (packageRow) {
    mutableRuntimeUrlCount = mutableRuntimeUrls(runtimeUrlsOfPackage(packageRow.package_json)).length;
  } else {
    const versionRow = await env.DB.prepare('SELECT review_json FROM review_versions WHERE id = ?')
      .bind(reviewVersionId)
      .first<{ review_json: string }>();
    if (versionRow) {
      try {
        const review = JSON.parse(versionRow.review_json) as BundleReview;
        if (review.artifact?.kind === 'runtime_manifest') {
          mutableRuntimeUrlCount = (
            review.runtime.mutableRuntimeUrls ?? mutableRuntimeUrls(review.runtime.references)
          ).length;
        }
      } catch {
        // Unreadable review JSON counts as zero.
      }
    }
  }

  return {
    observationRan: Boolean(evidenceRow),
    cspReplay,
    staticFindingCount,
    mutableRuntimeUrlCount
  };
}
