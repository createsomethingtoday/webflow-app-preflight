import { env } from 'cloudflare:workers';
import JSZip from 'jszip';
import {
  DESIGNER_EXTENSION_HOST_CSP,
  type BootTestEvidence,
  type BootTestJobContract
} from '@create-something/webflow-app-review-preflight';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { bootTestSummaryForVersion, validateBootTestEvidence } from '../src/boot-tests';
import worker from '../src/index';
import type { Env } from '../src/types';

const ORIGIN = 'http://localhost:1337';

afterEach(() => {
  vi.unstubAllGlobals();
});

function enabledEnv(overrides: Partial<Env> = {}): Env {
  return { ...(env as unknown as Env), BOOT_TEST_ENABLED: 'true', ...overrides };
}

async function call(
  path: string,
  init: RequestInit & { token?: string } = {},
  workerEnv: Env = enabledEnv()
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set('origin', ORIGIN);
  if (init.token) headers.set('authorization', `Bearer ${init.token}`);
  return worker.fetch(new Request(`https://preflight.test${path}`, { ...init, headers }), workerEnv);
}

async function createReview(seed: string): Promise<{ reviewId: string; versionId: string; bundle: Uint8Array }> {
  const zip = new JSZip();
  zip.file('index.html', `<!doctype html><title>Fixture</title><p>${seed}</p>`);
  zip.file('webflow.json', JSON.stringify({ name: 'Fixture extension', apiVersion: '2', publicDir: 'dist' }));
  const bundle = await zip.generateAsync({ type: 'uint8array' });
  const form = new FormData();
  form.set('bundle', new File([bundle], 'fixture.zip', { type: 'application/zip' }));
  const response = await call('/v1/reviews', { method: 'POST', body: form, token: 'test-token' });
  expect(response.status).toBe(201);
  const body = await response.json<{ review: { id: string; latestVersion: { id: string } } }>();
  return { reviewId: body.review.id, versionId: body.review.latestVersion.id, bundle };
}

interface E2BStub {
  runBodies: Array<Record<string, unknown>>;
  createBodies: Array<Record<string, unknown>>;
}

// Plays E2B's control plane and the template's /run route.
function stubE2B(): E2BStub {
  const stub: E2BStub = { runBodies: [], createBodies: [] };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.url === 'https://api.e2b.app/sandboxes' && request.method === 'POST') {
        stub.createBodies.push(await request.json());
        return Response.json(
          {
            templateID: 'template-boot-test',
            sandboxID: 'sandbox-boot-123',
            trafficAccessToken: 'traffic-access-token'
          },
          { status: 201 }
        );
      }
      if (request.url === 'https://api.e2b.app/sandboxes/sandbox-boot-123') {
        return request.method === 'DELETE'
          ? new Response(null, { status: 204 })
          : Response.json({ error: 'not_found' }, { status: 404 });
      }
      if (request.url === 'https://3000-sandbox-boot-123.e2b.app/run') {
        stub.runBodies.push(await request.json());
        return Response.json({ accepted: true }, { status: 202 });
      }
      return new Response('unexpected', { status: 500 });
    })
  );
  return stub;
}

async function startJob(
  reviewId: string,
  workerEnv: Env = enabledEnv()
): Promise<{ jobId: string; capability: string; stub: E2BStub }> {
  const stub = stubE2B();
  const response = await call(`/v1/reviews/${reviewId}/boot-tests`, { method: 'POST', token: 'test-token' }, workerEnv);
  expect(response.status).toBe(201);
  const body = await response.json<{ bootTest: { id: string; status: string } }>();
  expect(body.bootTest.status).toBe('approved');
  expect(JSON.stringify(body)).not.toMatch(/capability/i);
  const capability = String(stub.runBodies[0]?.capability ?? '');
  return { jobId: body.bootTest.id, capability, stub };
}

async function fetchContract(jobId: string, capability: string): Promise<BootTestJobContract> {
  const response = await call(`/v1/boot-test-jobs/${jobId}`, { token: capability });
  expect(response.status).toBe(200);
  const body = await response.json<{ bootTestJob: { contract: BootTestJobContract } }>();
  return body.bootTestJob.contract;
}

function evidence(contract: BootTestJobContract, overrides: Partial<BootTestEvidence['bootTest']> = {}): BootTestEvidence {
  const startedAt = new Date(Date.now() - 5_000).toISOString();
  return {
    schemaVersion: 'designer_extension_boot_test_evidence.v1',
    bootTestJobId: contract.bootTestJobId,
    reviewVersionId: contract.reviewVersionId,
    bundleSha256: contract.bundleSha256,
    nonce: contract.nonce,
    trust: 'webflow_observed',
    startedAt,
    finishedAt: new Date().toISOString(),
    bootTest: {
      status: 'passed',
      failures: [],
      cspViolations: [],
      missingFiles: [],
      uncaughtErrors: [],
      externalHostsRequested: ['api.example.test'],
      renderedTextLength: 12,
      renderedElementCount: 3,
      ...overrides
    }
  };
}

async function postResult(jobId: string, capability: string, body: unknown): Promise<Response> {
  return call(`/v1/boot-test-jobs/${jobId}/result`, {
    method: 'POST',
    token: capability,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
}

describe('Designer Extension boot test API', () => {
  test('answers 404 on every boot test route while BOOT_TEST_ENABLED is off', async () => {
    const { reviewId } = await createReview('switch-off');
    const off = { ...(env as unknown as Env) };
    delete off.BOOT_TEST_ENABLED;
    for (const workerEnv of [off, enabledEnv({ BOOT_TEST_ENABLED: 'false' })]) {
      const fetchSpy = vi.fn();
      vi.stubGlobal('fetch', fetchSpy);
      const responses = await Promise.all([
        call(`/v1/reviews/${reviewId}/boot-tests`, { method: 'POST', token: 'test-token' }, workerEnv),
        call(`/v1/reviews/${reviewId}/boot-tests`, { token: 'test-token' }, workerEnv),
        call('/v1/boot-test-jobs/some-job', { token: 'x'.repeat(43) }, workerEnv),
        call('/v1/boot-test-jobs/some-job/bundle', { token: 'x'.repeat(43) }, workerEnv),
        call('/v1/boot-test-jobs/some-job/result', { method: 'POST', body: '{}' }, workerEnv)
      ]);
      expect(responses.map((response) => response.status)).toEqual([404, 404, 404, 404, 404]);
      expect(fetchSpy).not.toHaveBeenCalled();
      vi.unstubAllGlobals();
    }
    const rows = await env.DB.prepare('SELECT COUNT(*) AS count FROM boot_test_jobs').first<{ count: number }>();
    expect(rows?.count).toBe(0);
    await expect(bootTestSummaryForVersion('any-version', off)).resolves.toEqual({ status: 'not_run' });
  });

  test('lets only the review owner start a boot test, and keeps the capability server-side', async () => {
    const { reviewId, versionId } = await createReview('owner-only');
    stubE2B();
    expect((await call(`/v1/reviews/${reviewId}/boot-tests`, { method: 'POST' })).status).toBe(401);
    expect(
      (await call(`/v1/reviews/${reviewId}/boot-tests`, { method: 'POST', token: 'reviewer-test-token' })).status
    ).toBe(404);
    const count = await env.DB.prepare('SELECT COUNT(*) AS count FROM boot_test_jobs WHERE review_version_id = ?')
      .bind(versionId)
      .first<{ count: number }>();
    expect(count?.count).toBe(0);

    const { jobId, capability, stub } = await startJob(reviewId);
    expect(stub.createBodies[0]).toMatchObject({
      secure: true,
      network: { allowPublicTraffic: false },
      metadata: { lane: 'app_review_boot_test', observation_job_id: jobId }
    });
    expect(stub.runBodies[0]).toEqual({
      observationJobId: jobId,
      apiBaseUrl: 'https://preflight.test',
      capability: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      jobKind: 'boot_test'
    });
    const stored = await env.DB.prepare('SELECT capability_sha256, status, sandbox_id FROM boot_test_jobs WHERE id = ?')
      .bind(jobId)
      .first<{ capability_sha256: string; status: string; sandbox_id: string }>();
    expect(stored).toMatchObject({ status: 'approved', sandbox_id: 'sandbox-boot-123' });
    expect(stored?.capability_sha256).not.toContain(capability);

    // One active job per review version: a second request returns the same job.
    const again = await call(`/v1/reviews/${reviewId}/boot-tests`, { method: 'POST', token: 'test-token' });
    expect(again.status).toBe(200);
    expect(await again.json()).toMatchObject({ deduplicated: true, bootTest: { id: jobId } });

    // A reviewer may read the result list; the owner sees it too.
    const listed = await call(`/v1/reviews/${reviewId}/boot-tests`, { token: 'reviewer-test-token' });
    expect(listed.status).toBe(200);
    expect(await listed.json()).toMatchObject({ bootTests: [{ id: jobId, advisory: true, bootTest: null }] });
  });

  test('issues a bounded contract and serves only that version bundle to the job capability', async () => {
    const { reviewId, versionId, bundle } = await createReview('contract');
    const { jobId, capability } = await startJob(reviewId);

    expect((await call(`/v1/boot-test-jobs/${jobId}`, { token: 'w'.repeat(43) })).status).toBe(401);
    expect((await call(`/v1/boot-test-jobs/${jobId}/bundle`, { token: capability })).status).toBe(410);

    const contract = await fetchContract(jobId, capability);
    const version = await env.DB.prepare('SELECT artifact_sha256, compressed_bytes FROM review_versions WHERE id = ?')
      .bind(versionId)
      .first<{ artifact_sha256: string; compressed_bytes: number }>();
    expect(contract).toMatchObject({
      schemaVersion: 'designer_extension_boot_test_job.v1',
      purpose: 'designer_extension_boot_test',
      bootTestJobId: jobId,
      reviewId,
      reviewVersionId: versionId,
      bundleSha256: version!.artifact_sha256,
      bundleBytes: version!.compressed_bytes,
      contentSecurityPolicy: DESIGNER_EXTENSION_HOST_CSP,
      controls: {
        networkMode: 'local_static_server_only',
        settleMs: 3_000,
        totalTimeoutMs: 60_000,
        evidenceTrust: 'webflow_observed'
      },
      boundaries: {
        advisoryOnly: true,
        affectsReadiness: false,
        officialDecision: null,
        canWriteGovernance: false,
        acceptsAccountCredentials: false
      }
    });
    expect(contract.nonce).toMatch(/^[0-9a-f-]{36}$/);
    expect(Date.parse(contract.expiresAt) - Date.now()).toBeLessThanOrEqual(15 * 60 * 1000);

    const download = await call(`/v1/boot-test-jobs/${jobId}/bundle`, { token: capability });
    expect(download.status).toBe(200);
    expect(download.headers.get('content-type')).toBe('application/zip');
    expect(new Uint8Array(await download.arrayBuffer())).toEqual(bundle);
    expect((await call(`/v1/boot-test-jobs/${jobId}/bundle`, { token: 'w'.repeat(43) })).status).toBe(401);
  });

  test('takes the policy from BOOT_TEST_CSP when an operator sets it', async () => {
    const { reviewId } = await createReview('policy-override');
    const policy = "default-src 'self'; frame-ancestors https://*.design.webflow.com";
    const workerEnv = enabledEnv({ BOOT_TEST_CSP: policy });
    const { jobId, capability } = await startJob(reviewId, workerEnv);
    const response = await call(`/v1/boot-test-jobs/${jobId}`, { token: capability }, workerEnv);
    const body = await response.json<{ bootTestJob: { contract: BootTestJobContract } }>();
    expect(body.bootTestJob.contract.contentSecurityPolicy).toBe(policy);

    const { reviewId: other } = await createReview('policy-invalid');
    stubE2B();
    const rejected = await call(
      `/v1/reviews/${other}/boot-tests`,
      { method: 'POST', token: 'test-token' },
      enabledEnv({ BOOT_TEST_CSP: "script-src 'self'\nx-injected: 1" })
    );
    expect(rejected.status).toBe(503);
  });

  test('rejects malformed runner results, then stores one valid advisory result', async () => {
    const { reviewId, versionId } = await createReview('results');
    const before = await call(`/v1/reviews/${reviewId}`, { token: 'test-token' });
    const readinessBefore = (await before.json<{ review: { latestVersion: { result: { summary: unknown } } } }>())
      .review.latestVersion.result.summary;
    const { jobId, capability } = await startJob(reviewId);
    const contract = await fetchContract(jobId, capability);
    const good = evidence(contract);

    const malformed: Array<[string, unknown]> = [
      ['a wrong nonce', { ...good, nonce: 'other-nonce' }],
      ['another review version', { ...good, reviewVersionId: 'other-version' }],
      ['an extra field', { ...good, officialDecision: 'approve' }],
      ['an unknown failure code', evidence(contract, { status: 'failed', failures: ['slow_panel' as never] })],
      ['passed with a failure', evidence(contract, { status: 'passed', failures: ['blank_panel'], renderedTextLength: 0, renderedElementCount: 0 })],
      ['failed without a failure', evidence(contract, { status: 'failed' })],
      ['a blank panel the counts contradict', evidence(contract, { status: 'failed', failures: ['blank_panel'] })],
      ['missing files without the failure', evidence(contract, { missingFiles: ['assets/app.js'] })],
      [
        'a CSP failure without a script violation',
        evidence(contract, {
          status: 'failed',
          failures: ['bundled_script_blocked_by_csp'],
          cspViolations: [{ directive: 'img-src', blocked: 'images.example.test', source: 'document' }]
        })
      ],
      [
        'a full URL in a violation',
        evidence(contract, {
          cspViolations: [{ directive: 'img-src', blocked: 'https://images.example.test/a.png?id=1', source: 'document' }]
        })
      ],
      [
        'a parent-directory path',
        evidence(contract, { status: 'failed', failures: ['bundled_file_missing'], missingFiles: ['../secrets.json'] })
      ],
      ['too many hosts', evidence(contract, { externalHostsRequested: Array.from({ length: 21 }, (_, i) => `h${i}.example.test`) })],
      ['an over-long message', evidence(contract, { uncaughtErrors: ['x'.repeat(301)] })],
      ['a secret-shaped message', evidence(contract, { uncaughtErrors: ['Bearer abcdefghijklmnop failed'] })],
      ['a negative count', evidence(contract, { renderedElementCount: -1 })],
      ['an error result with failures', evidence(contract, { status: 'error', failures: ['blank_panel'], renderedTextLength: 0, renderedElementCount: 0 })],
      ['timestamps beyond the budget', { ...good, startedAt: new Date(Date.now() - 10 * 60 * 1000).toISOString() }]
    ];
    for (const [label, body] of malformed) {
      const response = await postResult(jobId, capability, body);
      expect(response.status, label).toBe(400);
    }
    expect((await call(`/v1/boot-test-jobs/${jobId}/result`, { method: 'POST', body: 'not json', token: capability })).status).toBe(400);
    expect((await postResult(jobId, 'w'.repeat(43), good)).status).toBe(401);
    const stillRunning = await env.DB.prepare('SELECT status, result_json FROM boot_test_jobs WHERE id = ?')
      .bind(jobId)
      .first<{ status: string; result_json: string | null }>();
    expect(stillRunning).toEqual({ status: 'running', result_json: null });
    await expect(bootTestSummaryForVersion(versionId, enabledEnv())).resolves.toEqual({ status: 'not_run' });

    const accepted = await postResult(jobId, capability, good);
    expect(accepted.status).toBe(200);
    expect(await accepted.json()).toMatchObject({ status: 'complete', trust: 'webflow_observed', bootTest: { status: 'passed' } });
    expect((await postResult(jobId, capability, good)).status).toBe(410);
    expect((await call(`/v1/boot-test-jobs/${jobId}/bundle`, { token: capability })).status).toBe(410);

    const stored = await env.DB.prepare(
      'SELECT status, evidence_trust, result_status, sandbox_termination_status FROM boot_test_jobs WHERE id = ?'
    )
      .bind(jobId)
      .first();
    expect(stored).toEqual({
      status: 'complete',
      evidence_trust: 'webflow_observed',
      result_status: 'passed',
      sandbox_termination_status: 'verified'
    });

    // Advisory only: the static review summary is unchanged.
    const after = await call(`/v1/reviews/${reviewId}`, { token: 'test-token' });
    expect((await after.json<{ review: { latestVersion: { result: { summary: unknown } } } }>()).review.latestVersion.result.summary).toEqual(readinessBefore);
  });

  test('summarizes the latest boot test per version as not_run, passed, or failed', async () => {
    const passing = await createReview('summary-passed');
    const failing = await createReview('summary-failed');
    const workerEnv = enabledEnv();
    await expect(bootTestSummaryForVersion(passing.versionId, workerEnv)).resolves.toEqual({ status: 'not_run' });

    const first = await startJob(passing.reviewId);
    const firstContract = await fetchContract(first.jobId, first.capability);
    expect((await postResult(first.jobId, first.capability, evidence(firstContract))).status).toBe(200);
    await expect(bootTestSummaryForVersion(passing.versionId, workerEnv)).resolves.toEqual({ status: 'passed' });

    const second = await startJob(failing.reviewId);
    const secondContract = await fetchContract(second.jobId, second.capability);
    const failed = evidence(secondContract, {
      status: 'failed',
      failures: ['blank_panel', 'bundled_script_blocked_by_csp'],
      cspViolations: [{ directive: 'script-src-elem', blocked: 'assets/app.js', source: 'document' }],
      renderedTextLength: 0,
      renderedElementCount: 0
    });
    expect((await postResult(second.jobId, second.capability, failed)).status).toBe(200);
    await expect(bootTestSummaryForVersion(failing.versionId, workerEnv)).resolves.toEqual({ status: 'failed' });
    await expect(bootTestSummaryForVersion(passing.versionId, workerEnv)).resolves.toEqual({ status: 'passed' });
  });

  test('reports a dispatch failure without leaving an active job', async () => {
    const { reviewId, versionId } = await createReview('dispatch-failure');
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ error: 'unavailable' }, { status: 503 })));
    const response = await call(`/v1/reviews/${reviewId}/boot-tests`, { method: 'POST', token: 'test-token' });
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({
      error: 'boot_test_dispatch_unavailable',
      message: 'The boot test runner could not create a secure sandbox.'
    });
    const row = await env.DB.prepare('SELECT status FROM boot_test_jobs WHERE review_version_id = ?')
      .bind(versionId)
      .first<{ status: string }>();
    expect(row?.status).toBe('failed');
    await expect(bootTestSummaryForVersion(versionId, enabledEnv())).resolves.toEqual({ status: 'not_run' });
  });

  test('normalizes failure order in an accepted result', () => {
    const contract = {
      bootTestJobId: 'job-1',
      reviewVersionId: 'version-1',
      bundleSha256: 'a'.repeat(64),
      nonce: 'nonce-1',
      controls: { totalTimeoutMs: 60_000 },
      limits: { cspViolations: 20, missingFiles: 20, uncaughtErrors: 10, externalHosts: 20, messageLength: 300 }
    } as BootTestJobContract;
    const result = validateBootTestEvidence(
      evidence(contract, {
        status: 'failed',
        failures: ['bundled_file_missing', 'blank_panel'],
        missingFiles: ['index.html'],
        renderedTextLength: 0,
        renderedElementCount: 0
      }),
      'job-1',
      contract
    );
    expect(result.failures).toEqual(['blank_panel', 'bundled_file_missing']);
  });
});
