import { env, exports } from 'cloudflare:workers';
import type { RuntimeObservationJobContract } from '@create-something/webflow-app-review-preflight';
import { describe, expect, test } from 'vitest';
import {
  runtimeAdvisoryForVersion,
  sanitizeCspReplay,
  sanitizeRuntimeStaticScan
} from '../src/runtime-advisory';
import { evaluateRuntimeSecurity, validateManifest } from '../src/runtime-observations';
import type { Env } from '../src/types';

const TARGET = 'https://site.example.test/page';
const RUNTIME = 'https://cdn.example.test/runtime/v1.2.3/run.js';
const SHA = 'a'.repeat(64);
const INTEGRITY = `sha256-${btoa(String.fromCharCode(...new Uint8Array(32).fill(0xaa)))}`;

const violation = (overrides: Record<string, unknown> = {}) => ({
  directive: 'script-src-elem',
  blocked: 'inline',
  source: 'cdn.example.test/runtime/v1.2.3/run.js',
  fromRuntime: true,
  ...overrides
});
const replay = (overrides: Record<string, unknown> = {}) => ({
  status: 'violations',
  runtimeReadyObserved: true,
  violations: [violation()],
  ...overrides
});

const finding = (overrides: Record<string, unknown> = {}) => ({
  ruleId: 'SEC-NO-DCE',
  name: 'Dynamic Code Execution',
  severity: 'BLOCKER',
  count: 2,
  ...overrides
});
const scan = (overrides: Record<string, unknown> = {}) => ({
  status: 'scanned',
  filesScanned: 1,
  findings: [finding()],
  ...overrides
});

describe('sanitizeRuntimeStaticScan', () => {
  test('accepts rule-level counts, a clean scan and not_run', () => {
    expect(sanitizeRuntimeStaticScan(scan())).toEqual(scan());
    expect(sanitizeRuntimeStaticScan(scan({ findings: [] }))).not.toBeNull();
    expect(
      sanitizeRuntimeStaticScan({ status: 'not_run', filesScanned: 0, findings: [] })
    ).not.toBeNull();
  });

  test.each<[string, unknown]>([
    ['a non-object', 'scanned'],
    ['an extra key', { ...scan(), source: 'eval(x)' }],
    ['an extra finding key', scan({ findings: [{ ...finding(), snippet: 'eval(x)' }] })],
    ['a code-looking name', scan({ findings: [finding({ name: 'eval("x"); <b>' })] })],
    ['a lowercase rule id', scan({ findings: [finding({ ruleId: 'sec no dce' })] })],
    ['a zero count', scan({ findings: [finding({ count: 0 })] })],
    ['a fractional count', scan({ findings: [finding({ count: 1.5 })] })],
    ['too many files', scan({ filesScanned: 9 })],
    ['too many findings', scan({ findings: Array.from({ length: 61 }, () => finding()) })],
    ['scanned with no files', scan({ filesScanned: 0 })],
    ['not_run with findings', { status: 'not_run', filesScanned: 0, findings: [finding()] }]
  ])('rejects %s', (_label, raw) => {
    expect(sanitizeRuntimeStaticScan(raw)).toBeNull();
  });
});

describe('sanitizeCspReplay', () => {
  test('accepts the exact shape and returns a fresh copy', () => {
    const raw = replay();
    const clean = sanitizeCspReplay(raw);
    expect(clean).toEqual(raw);
    expect(clean).not.toBe(raw);
    expect(
      sanitizeCspReplay({
        status: 'clean',
        runtimeReadyObserved: false,
        violations: [violation({ fromRuntime: false, source: 'document', blocked: 'cdn.other.test' })]
      })
    ).not.toBeNull();
    expect(
      sanitizeCspReplay({ status: 'not_run', runtimeReadyObserved: false, violations: [] })
    ).not.toBeNull();
  });

  test.each<[string, unknown]>([
    ['a non-object', 'violations'],
    ['an array', []],
    ['an extra top-level key', { ...replay(), pageText: 'x' }],
    ['a missing key', { status: 'clean', violations: [] }],
    ['an unknown status', replay({ status: 'failed' })],
    ['a non-boolean ready flag', replay({ runtimeReadyObserved: 'yes' })],
    ['violations that are not a list', replay({ violations: {} })],
    ['more than 50 violations', replay({ violations: Array.from({ length: 51 }, () => violation()) })],
    ['an extra violation key', replay({ violations: [{ ...violation(), sample: 'alert(1)' }] })],
    ['a violation without fromRuntime', replay({ violations: [{ directive: 'a', blocked: 'inline', source: 'document' }] })],
    ['a non-boolean fromRuntime', replay({ violations: [violation({ fromRuntime: 1 })] })],
    ['a directive with odd characters', replay({ violations: [violation({ directive: 'script src' })] })],
    ['a blocked value that is a full URL', replay({ violations: [violation({ blocked: 'https://a.test/x.js' })] })],
    ['a source with a query string', replay({ violations: [violation({ source: 'cdn.example.test/run.js?token=1' })] })],
    ['a source with whitespace', replay({ violations: [violation({ source: 'cdn.example.test/a b.js' })] })],
    ['a source with a secret-looking token', replay({ violations: [violation({ source: 'cdn.example.test/sk-abcdefghijklmnop' })] })],
    ['an over-long source', replay({ violations: [violation({ source: `cdn.example.test/${'a'.repeat(400)}` })] })],
    ['violations status without a runtime entry', replay({ violations: [violation({ fromRuntime: false })] })],
    ['clean status with a runtime entry', replay({ status: 'clean' })],
    ['not_run with entries', { status: 'not_run', runtimeReadyObserved: false, violations: [violation()] }]
  ])('rejects %s', (_label, raw) => {
    expect(sanitizeCspReplay(raw)).toBeNull();
  });
});

function contract(): RuntimeObservationJobContract {
  return {
    schemaVersion: 'runtime_observation_job.v1',
    purpose: 'webflow_observation',
    testPackageId: 'package-1',
    reviewId: 'review-1',
    reviewVersionId: 'version-1',
    bundleSha256: 'b'.repeat(64),
    nonce: 'nonce-1',
    target: { url: TARGET, host: 'site.example.test' },
    sandboxInstallationId: 'sandbox-1',
    runtimeArtifacts: [{ url: RUNTIME, sha256: SHA, integrity: INTEGRITY }],
    negativeProxyProbe: { method: 'GET', url: 'https://cdn.example.test/proxy' },
    lifecycle: { readySelector: '[data-runtime-ready]' },
    controls: {
      allowedHosts: ['site.example.test', 'cdn.example.test'],
      maxRequests: 100,
      requestTimeoutMs: 10_000,
      totalTimeoutMs: 90_000,
      networkMode: 'exact_host_allowlist',
      evidenceTrust: 'webflow_observed',
      executionEvidence: 'chromium_cdp_v1',
      negativeProxyCanaryUrl: 'https://cdn.example.test/canary'
    },
    boundaries: {
      partnerCanSubmitEvidence: false,
      officialDecision: null,
      canWriteGovernance: false,
      acceptsAccountCredentials: false
    },
    expiresAt: new Date(Date.now() + 60_000).toISOString()
  };
}

function manifest(extra: Record<string, unknown> = {}): Record<string, unknown> {
  const now = new Date().toISOString();
  return {
    schemaVersion: 'runtime_observation_evidence.v1',
    observationJobId: 'job-1',
    testPackageId: 'package-1',
    reviewVersionId: 'version-1',
    bundleSha256: 'b'.repeat(64),
    nonce: 'nonce-1',
    targetUrl: TARGET,
    trust: 'webflow_observed',
    executionEvidence: 'chromium_cdp_v1',
    startedAt: now,
    finishedAt: now,
    redaction: { applied: true, headersRemoved: true, cookiesRemoved: true, formValuesMasked: true },
    runtimeReadyObserved: true,
    runtimeArtifacts: [
      {
        url: RUNTIME,
        expectedSha256: SHA,
        observedSha256: SHA,
        integrity: INTEGRITY,
        domIntegrity: INTEGRITY,
        domCrossOrigin: 'anonymous',
        loadedByPage: true,
        trustedRuntimeInitiator: false,
        sourceMap: { available: false }
      }
    ],
    runtimeCreatedScripts: [],
    unreviewedRuntimeScripts: [],
    cleanup: { status: 'not_tested', residue: [] },
    negativeProxyCanary: {
      url: 'https://cdn.example.test/canary',
      outcome: 'blocked',
      statusCode: 403
    },
    artifacts: [
      {
        field: 'network_log',
        kind: 'network_log',
        fileName: 'network-log.json',
        contentType: 'application/json',
        bytes: 10,
        sha256: 'c'.repeat(64)
      }
    ],
    ...extra
  };
}

describe('runtime manifest validation of the CSP replay', () => {
  test('keeps a valid replay and leaves older evidence without one', () => {
    const withReplay = validateManifest(manifest({ cspReplay: replay() }), 'job-1', contract());
    expect(withReplay.cspReplay).toEqual(replay());
    const without = validateManifest(manifest(), 'job-1', contract());
    expect('cspReplay' in without).toBe(false);
  });

  test.each<[string, unknown]>([
    ['extra keys', { ...replay(), pageText: '<html>secret page</html>' }],
    ['a wrong type', 'violations'],
    ['an unbounded list', replay({ violations: Array.from({ length: 5_000 }, () => violation()) })],
    ['a secret-looking path', replay({ violations: [violation({ source: 'cdn.example.test/sk-abcdefghijklmnop' })] })]
  ])('drops a malformed replay (%s) and stores not_run, never the raw value', (_label, raw) => {
    const validated = validateManifest(manifest({ cspReplay: raw }), 'job-1', contract());
    expect(validated.cspReplay).toEqual({
      status: 'not_run',
      runtimeReadyObserved: false,
      violations: []
    });
    expect(JSON.stringify(validated)).not.toContain('pageText');
    expect(JSON.stringify(validated)).not.toContain('secret page');
  });

  test('keeps a valid static scan, drops a malformed one, and never changes the evaluation', () => {
    const baseline = evaluateRuntimeSecurity(
      validateManifest(manifest(), 'job-1', contract()),
      contract()
    );
    const kept = validateManifest(manifest({ runtimeStaticScan: scan() }), 'job-1', contract());
    expect(kept.runtimeStaticScan).toEqual(scan());
    const dropped = validateManifest(
      manifest({ runtimeStaticScan: { ...scan(), source: 'eval(secret)' } }),
      'job-1',
      contract()
    );
    expect(dropped.runtimeStaticScan).toEqual({ status: 'not_run', filesScanned: 0, findings: [] });
    expect(JSON.stringify(dropped)).not.toContain('eval(secret)');
    for (const value of [
      scan(),
      scan({ findings: [] }),
      { status: 'not_run', filesScanned: 0, findings: [] },
      { garbage: true }
    ]) {
      const validated = validateManifest(manifest({ runtimeStaticScan: value }), 'job-1', contract());
      expect(evaluateRuntimeSecurity(validated, contract())).toEqual(baseline);
    }
    expect('runtimeStaticScan' in validateManifest(manifest(), 'job-1', contract())).toBe(false);
  });

  test('never changes the security evaluation', () => {
    const baseline = evaluateRuntimeSecurity(
      validateManifest(manifest(), 'job-1', contract()),
      contract()
    );
    for (const cspReplay of [
      replay(),
      { status: 'not_run', runtimeReadyObserved: false, violations: [] },
      { garbage: true }
    ]) {
      const validated = validateManifest(manifest({ cspReplay }), 'job-1', contract());
      expect(evaluateRuntimeSecurity(validated, contract())).toEqual(baseline);
    }
  });
});

const DEVELOPER = { authorization: 'Bearer test-token', origin: 'http://localhost:1337' };

async function createHostedReview(runtimeUrls: string[]): Promise<string> {
  const response = await exports.default.fetch(
    new Request('https://preflight.test/v1/runtime-reviews', {
      method: 'POST',
      headers: { ...DEVELOPER, 'content-type': 'application/json' },
      body: JSON.stringify({ appName: 'Example Sync', runtimeUrls })
    })
  );
  expect(response.status).toBe(201);
  const created = await response.json<{ review: { latestVersion: { id: string } } }>();
  return created.review.latestVersion.id;
}

async function seedPackage(versionId: string, runtimeUrls: string[]): Promise<string> {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO runtime_test_packages
      (id, review_version_id, owner_user_id, status, trust, target_url, target_host,
       sandbox_installation_id, license_mode, license_expires_at, package_json,
       created_at, updated_at)
     VALUES (?, ?, 'local-user', 'ready', 'partner_supplied', ?, 'site.example.test',
             'sandbox-1', 'installation_allowlist', ?, ?, ?, ?)`
  )
    .bind(
      id,
      versionId,
      TARGET,
      new Date(Date.now() + 60_000).toISOString(),
      JSON.stringify({
        runtimeArtifacts: runtimeUrls.map((url) => ({ url, sha256: SHA, integrity: INTEGRITY }))
      }),
      now,
      now
    )
    .run();
  return id;
}

async function seedJob(
  packageId: string,
  manifestJson: string | null,
  status = 'complete'
): Promise<void> {
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO runtime_observation_jobs
      (id, test_package_id, status, capability_sha256, nonce, contract_json,
       approved_by_actor, approved_at, expires_at, consumed_at, evidence_trust,
       evidence_manifest_json, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, '{}', 'webflow-runtime-coordinator', ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      crypto.randomUUID(),
      packageId,
      status,
      crypto.randomUUID().replace(/-/g, '').padEnd(64, '0'),
      crypto.randomUUID(),
      now,
      new Date(Date.now() + 60_000).toISOString(),
      status === 'complete' ? now : null,
      status === 'complete' ? 'webflow_observed' : null,
      manifestJson,
      now,
      now
    )
    .run();
}

describe('runtimeAdvisoryForVersion', () => {
  const advisory = (versionId: string) => runtimeAdvisoryForVersion(versionId, env as unknown as Env);

  test('reports no observation for a version without one', async () => {
    const versionId = await createHostedReview(['https://cdn.example.test/run.js']);
    expect(await advisory(versionId)).toEqual({
      observationRan: false,
      cspReplay: 'not_run',
      staticFindingCount: 0,
      mutableRuntimeUrlCount: 1
    });
    expect(await advisory('missing-version')).toEqual({
      observationRan: false,
      cspReplay: 'not_run',
      staticFindingCount: 0,
      mutableRuntimeUrlCount: 0
    });
  });

  test('reports a clean replay and counts only mutable declared URLs', async () => {
    const versionId = await createHostedReview(['https://cdn.example.test/v1.2.3/run.js']);
    const packageId = await seedPackage(versionId, [
      'https://cdn.example.test/v1.2.3/run.js',
      'https://cdn.example.test/run.js',
      'https://cdn.example.test/other.js?v=2'
    ]);
    await seedJob(
      packageId,
      JSON.stringify({
        runtimeStaticScan: scan({ findings: [finding(), finding({ ruleId: 'SEC-UNSAFE-HTML', count: 3 })] }),
        cspReplay: {
          status: 'clean',
          runtimeReadyObserved: true,
          violations: [violation({ fromRuntime: false, source: 'document' })]
        }
      })
    );
    expect(await advisory(versionId)).toEqual({
      observationRan: true,
      cspReplay: 'clean',
      staticFindingCount: 5,
      mutableRuntimeUrlCount: 2
    });
  });

  test('reports runtime violations from the latest completed observation', async () => {
    const versionId = await createHostedReview(['https://cdn.example.test/run.js']);
    const packageId = await seedPackage(versionId, ['https://cdn.example.test/v1.2.3/run.js']);
    await seedJob(
      packageId,
      JSON.stringify({ cspReplay: replay(), runtimeStaticScan: scan({ findings: [] }) })
    );
    expect(await advisory(versionId)).toEqual({
      observationRan: true,
      cspReplay: 'violations',
      staticFindingCount: 0,
      mutableRuntimeUrlCount: 0
    });
  });

  test('treats a missing, malformed or unreadable replay as not run', async () => {
    for (const stored of [
      JSON.stringify({}),
      JSON.stringify({ cspReplay: { status: 'violations', violations: [] } }),
      '{not json'
    ]) {
      const versionId = await createHostedReview(['https://cdn.example.test/v1.2.3/run.js']);
      const packageId = await seedPackage(versionId, ['https://cdn.example.test/v1.2.3/run.js']);
      await seedJob(packageId, stored);
      expect(await advisory(versionId)).toMatchObject({ observationRan: true, cspReplay: 'not_run' });
    }
  });

  test('ignores jobs that did not complete', async () => {
    const versionId = await createHostedReview(['https://cdn.example.test/v1.2.3/run.js']);
    const packageId = await seedPackage(versionId, ['https://cdn.example.test/v1.2.3/run.js']);
    await seedJob(packageId, JSON.stringify({ cspReplay: replay() }), 'failed');
    expect(await advisory(versionId)).toMatchObject({ observationRan: false, cspReplay: 'not_run' });
  });
});
