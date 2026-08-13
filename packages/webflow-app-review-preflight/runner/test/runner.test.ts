import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { RuntimeObservationJobContract } from '@create-something/webflow-app-review-preflight';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import {
  redactText,
  runRuntimeObservation,
  sanitizeUrl,
  validateObservationContract
} from '../src/index.js';

// The adversarial fixtures allowlist loopback (127.0.0.1); loopback/private
// hosts are a deliberate test opt-in (see RUNTIME_ALLOW_PRIVATE_HOSTS, FIX 1).
beforeEach(() => {
  process.env.RUNTIME_ALLOW_PRIVATE_HOSTS = '1';
});
afterEach(() => {
  delete process.env.RUNTIME_ALLOW_PRIVATE_HOSTS;
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
    target: { url: 'http://127.0.0.1:4173/runtime-fixture', host: '127.0.0.1' },
    sandboxInstallationId: 'sandbox-1',
    runtimeArtifacts: [
      {
        url: 'http://127.0.0.1:4173/runtime-v1.js',
        sha256: 'a'.repeat(64),
        integrity: 'sha256-fixture'
      }
    ],
    negativeProxyProbe: {
      method: 'GET',
      url: 'http://127.0.0.1:4173/proxy?url=http%3A%2F%2F127.0.0.1%3A4174%2Fcanary'
    },
    lifecycle: {
      readySelector: '[data-runtime-ready]'
    },
    controls: {
      allowedHosts: ['127.0.0.1'],
      maxRequests: 100,
      requestTimeoutMs: 10_000,
      totalTimeoutMs: 90_000,
      networkMode: 'exact_host_allowlist',
      evidenceTrust: 'webflow_observed',
      executionEvidence: 'chromium_cdp_v1',
      negativeProxyCanaryUrl: 'http://127.0.0.1:4174/canary'
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

interface AdversarialFixtureOptions {
  markup(integrity: string): string;
  proxyStatus: number;
  runtimeSource?: string | ((secondaryIntegrity: string) => string);
  secondaryRuntimeSource?: string;
}

async function runAdversarialFixture({
  markup,
  proxyStatus,
  runtimeSource = 'document.body.setAttribute("data-runtime-ready", "");',
  secondaryRuntimeSource
}: AdversarialFixtureOptions): Promise<{
  result: Awaited<ReturnType<typeof runRuntimeObservation>>;
  manifest: Record<string, unknown>;
  networkLog: unknown;
  consoleLog: unknown;
}> {
  const secondaryDigest = secondaryRuntimeSource
    ? createHash('sha256').update(secondaryRuntimeSource).digest()
    : null;
  const secondaryIntegrity = secondaryDigest
    ? `sha256-${secondaryDigest.toString('base64')}`
    : '';
  const resolvedRuntimeSource = typeof runtimeSource === 'function'
    ? runtimeSource(secondaryIntegrity)
    : runtimeSource;
  const digest = createHash('sha256').update(resolvedRuntimeSource).digest();
  const integrity = `sha256-${digest.toString('base64')}`;
  const outputDir = await mkdtemp(join(tmpdir(), 'runtime-runner-adversarial-'));
  let jobContract!: RuntimeObservationJobContract;
  const server = createServer((request, response) => {
    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;
    const url = new URL(request.url ?? '/', origin);
    if (url.pathname === '/v1/runtime-observation-jobs/job-1') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ observationJob: { contract: jobContract } }));
      return;
    }
    if (url.pathname === '/v1/runtime-observation-jobs/job-1/evidence') {
      request.resume();
      request.on('end', () => {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ status: 'complete' }));
      });
      return;
    }
    if (url.pathname === '/runtime-fixture') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><body>${markup(integrity)}</body>`);
      return;
    }
    if (url.pathname === '/runtime-v1.js') {
      response.writeHead(200, {
        'content-type': 'application/javascript; charset=utf-8',
        'access-control-allow-origin': '*'
      });
      response.end(resolvedRuntimeSource);
      return;
    }
    if (url.pathname === '/runtime-v2.js' && secondaryRuntimeSource) {
      response.writeHead(200, {
        'content-type': 'application/javascript; charset=utf-8',
        'access-control-allow-origin': '*'
      });
      response.end(secondaryRuntimeSource);
      return;
    }
    if (url.pathname === '/extra-module.js' || url.pathname === '/worker.js') {
      response.writeHead(200, {
        'content-type': 'application/javascript; charset=utf-8',
        'access-control-allow-origin': '*'
      });
      response.end('globalThis.__unreviewedRuntimeCode = true;');
      return;
    }
    if (url.pathname === '/proxy') {
      response.writeHead(proxyStatus, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: 'fixture_proxy_result' }));
      return;
    }
    response.writeHead(404);
    response.end('not found');
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  const origin = `http://127.0.0.1:${address.port}`;
  jobContract = {
    ...contract(),
    target: { url: `${origin}/runtime-fixture`, host: '127.0.0.1' },
    runtimeArtifacts: [
      {
        url: `${origin}/runtime-v1.js`,
        sha256: digest.toString('hex'),
        integrity
      },
      ...(secondaryDigest
        ? [{
            url: `${origin}/runtime-v2.js`,
            sha256: secondaryDigest.toString('hex'),
            integrity: secondaryIntegrity,
            loadMode: 'runtime_child' as const
          }]
        : [])
    ],
    negativeProxyProbe: { method: 'GET', url: `${origin}/proxy` },
    controls: {
      ...contract().controls,
      allowedHosts: ['127.0.0.1', 'localhost'],
      negativeProxyCanaryUrl: `${origin}/canary`
    }
  };

  try {
    const result = await runRuntimeObservation({
      apiBaseUrl: origin,
      observationJobId: 'job-1',
      capability: 'c'.repeat(64),
      outputDir
    });
    const manifest = JSON.parse(await readFile(join(outputDir, 'manifest.json'), 'utf8')) as Record<
      string,
      unknown
    >;
    const networkLog = JSON.parse(
      await readFile(join(outputDir, 'network-log.json'), 'utf8')
    ) as unknown;
    const consoleLog = JSON.parse(
      await readFile(join(outputDir, 'console-log.json'), 'utf8')
    ) as unknown;
    return { result, manifest, networkLog, consoleLog };
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(outputDir, { recursive: true, force: true });
  }
}

interface ServerFixtureOptions {
  // Static route table: pathname -> { body, contentType, status }.
  routes(origin: string): Map<string, { body: string; contentType: string; status?: number }>;
  buildContract(origin: string): RuntimeObservationJobContract;
  allowPrivateHosts?: boolean;
}

// Lower-level harness: full control over routes and the observation contract.
// Returns the on-disk manifest and script_inventory (written before any upload),
// plus any rejection surfaced by runRuntimeObservation.
async function runServerFixture(options: ServerFixtureOptions): Promise<{
  manifest?: Record<string, unknown>;
  scriptInventory?: Array<Record<string, unknown>>;
  rejection?: string;
  result?: Awaited<ReturnType<typeof runRuntimeObservation>>;
}> {
  const outputDir = await mkdtemp(join(tmpdir(), 'runtime-runner-server-'));
  let jobContract!: RuntimeObservationJobContract;
  let routeTable = new Map<string, { body: string; contentType: string; status?: number }>();
  const server = createServer((request, response) => {
    const address = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${address.port}`;
    const url = new URL(request.url ?? '/', origin);
    if (url.pathname === '/v1/runtime-observation-jobs/job-1') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ observationJob: { contract: jobContract } }));
      return;
    }
    if (url.pathname === '/v1/runtime-observation-jobs/job-1/evidence') {
      request.resume();
      request.on('end', () => {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ status: 'complete' }));
      });
      return;
    }
    const route = routeTable.get(url.pathname);
    if (route) {
      response.writeHead(route.status ?? 200, {
        'content-type': route.contentType,
        'access-control-allow-origin': '*',
        'cache-control': 'no-store'
      });
      response.end(route.body);
      return;
    }
    response.writeHead(404);
    response.end('not found');
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  const origin = `http://127.0.0.1:${address.port}`;
  routeTable = options.routes(origin);
  jobContract = options.buildContract(origin);

  const previous = process.env.RUNTIME_ALLOW_PRIVATE_HOSTS;
  if (options.allowPrivateHosts === false) {
    delete process.env.RUNTIME_ALLOW_PRIVATE_HOSTS;
  } else {
    process.env.RUNTIME_ALLOW_PRIVATE_HOSTS = '1';
  }

  try {
    let result: Awaited<ReturnType<typeof runRuntimeObservation>> | undefined;
    let rejection: string | undefined;
    try {
      result = await runRuntimeObservation({
        apiBaseUrl: origin,
        observationJobId: 'job-1',
        capability: 'c'.repeat(64),
        outputDir
      });
    } catch (error) {
      rejection = error instanceof Error ? error.message : String(error);
    }
    const manifest = await readFile(join(outputDir, 'manifest.json'), 'utf8')
      .then((raw) => JSON.parse(raw) as Record<string, unknown>)
      .catch(() => undefined);
    const scriptInventory = await readFile(join(outputDir, 'script-inventory.json'), 'utf8')
      .then((raw) => JSON.parse(raw) as Array<Record<string, unknown>>)
      .catch(() => undefined);
    return { manifest, scriptInventory, rejection, result };
  } finally {
    if (previous === undefined) delete process.env.RUNTIME_ALLOW_PRIVATE_HOSTS;
    else process.env.RUNTIME_ALLOW_PRIVATE_HOSTS = previous;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(outputDir, { recursive: true, force: true });
  }
}

function loopbackContract(
  origin: string,
  runtimeArtifacts: RuntimeObservationJobContract['runtimeArtifacts'],
  overrides: Partial<RuntimeObservationJobContract['controls']> = {}
): RuntimeObservationJobContract {
  const base = contract();
  return {
    ...base,
    target: { url: `${origin}/runtime-fixture`, host: '127.0.0.1' },
    runtimeArtifacts,
    negativeProxyProbe: { method: 'GET', url: `${origin}/proxy` },
    controls: {
      ...base.controls,
      allowedHosts: ['127.0.0.1', 'localhost'],
      negativeProxyCanaryUrl: `${origin}/canary`,
      ...overrides
    }
  };
}

describe('runtime observation runner boundaries', () => {
  test('redacts secrets and query values from evidence text', () => {
    expect(redactText('Bearer abcdefghijkl user@example.com')).toBe(
      '[redacted-secret] [redacted-email]'
    );
    expect(sanitizeUrl('https://example.com/path?token=secret&email=user@example.com')).toBe(
      'https://example.com/path?token=%5Bredacted%5D&email=%5Bredacted%5D'
    );
  });

  test('rejects a contract that broadens the server host allowlist', () => {
    const safe = contract();
    expect(() => validateObservationContract('job-1', safe)).not.toThrow();
    expect(() =>
      validateObservationContract('job-1', {
        ...safe,
        target: { url: 'https://attacker.example', host: 'attacker.example' }
      })
    ).toThrow('attempts to broaden its host boundary');
  });

  test('accepts an explicit no-proxy policy only with a null canary URL', () => {
    const safe = contract();
    const noProxy = {
      ...safe,
      negativeProxyProbe: {
        mode: 'none_declared' as const,
        declaration: 'no_proxy_surface' as const
      },
      controls: {
        ...safe.controls,
        negativeProxyCanaryUrl: null
      }
    };

    expect(() => validateObservationContract('job-1', noProxy)).not.toThrow();
    expect(() =>
      validateObservationContract('job-1', {
        ...noProxy,
        controls: {
          ...noProxy.controls,
          negativeProxyCanaryUrl: 'http://127.0.0.1:4174/canary'
        }
      })
    ).toThrow('unsafe contract');
  });

  test('does not let reviewed page code forge a blocked proxy canary', async () => {
    const { result, manifest } = await runAdversarialFixture({
      proxyStatus: 503,
      markup: (integrity) => `
        <script>window.fetch = async () => ({ status: 403 });</script>
        <script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`
    });
    expect(result.negativeProxyOutcome).toBe('error');
    expect(manifest.negativeProxyCanary).toMatchObject({ outcome: 'error', statusCode: 503 });
  }, 30_000);

  test('uses a production-like Chrome identity for automation-sensitive runtimes', async () => {
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      runtimeSource: `
        const looksLikeChrome = navigator.userAgent.includes('Chrome/');
        if (looksLikeChrome && navigator.webdriver === false) {
          document.body.setAttribute('data-runtime-ready', '');
        }`,
      markup: (integrity) =>
        `<script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`
    });

    expect(manifest.runtimeReadyObserved).toBe(true);
  }, 30_000);

  test('does not treat a fetched but unexecuted pinned script as loaded', async () => {
    const { manifest, networkLog } = await runAdversarialFixture({
      proxyStatus: 403,
      runtimeSource: 'globalThis.__reviewedRuntimeExecuted = true;',
      markup: (integrity) => `
        <link rel="preload" as="script" href="/runtime-v1.js" crossorigin="anonymous">
        <script type="application/json" src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>
        <div data-runtime-ready></div>`
    });
    const observations = manifest.runtimeArtifacts as Array<{ loadedByPage: boolean }>;
    expect(observations[0]?.loadedByPage).toBe(false);
  }, 30_000);

  test('reports anonymous code execution initiated by the pinned runtime', async () => {
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      runtimeSource: `
        eval('globalThis.__runtimeEvalExecuted = true');
        document.body.setAttribute('data-runtime-ready', '');`,
      markup: (integrity) =>
        `<script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`
    });
    expect(manifest.runtimeCreatedScripts).toEqual([
      expect.stringMatching(/^\[inline-or-eval:[a-f0-9]{12}\]$/)
    ]);
  }, 30_000);

  test('does not let the page forge the pinned script integrity attribute', async () => {
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      markup: (integrity) => `
        <script src="/runtime-v1.js" crossorigin="anonymous"></script>
        <script>
          Object.defineProperty(document, 'scripts', {
            configurable: true,
            value: [{
              src: new URL('/runtime-v1.js', location.href).toString(),
              getAttribute(name) {
                return name === 'integrity' ? '${integrity}' : name === 'crossorigin' ? 'anonymous' : null;
              }
            }]
          });
        </script>`
    });
    const observations = manifest.runtimeArtifacts as Array<{ domIntegrity: string | null }>;
    expect(observations[0]?.domIntegrity).toBeNull();
  }, 30_000);

  test('does not accept an integrity attribute added after the script loaded', async () => {
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      markup: (integrity) => `
        <script
          src="/runtime-v1.js"
          crossorigin="anonymous"
          onload="this.integrity='${integrity}'"
        ></script>`
    });
    const observations = manifest.runtimeArtifacts as Array<{ domIntegrity: string | null }>;
    expect(observations[0]?.domIntegrity).toBeNull();
  }, 30_000);

  test('reports module and Worker code initiated by the pinned runtime', async () => {
    const { manifest, networkLog } = await runAdversarialFixture({
      proxyStatus: 403,
      runtimeSource: `
        void import('/extra-module.js');
        new Worker('/worker.js');
        document.body.setAttribute('data-runtime-ready', '');`,
      markup: (integrity) =>
        `<script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`
    });
    expect(manifest.runtimeCreatedScripts, JSON.stringify(networkLog)).toEqual(
      expect.arrayContaining([
        expect.stringContaining('/extra-module.js'),
        expect.stringContaining('/worker.js')
      ])
    );
  }, 30_000);

  test('accepts a dynamically inserted script when that exact file is declared and pinned', async () => {
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      secondaryRuntimeSource: 'globalThis.__reviewedDependencyExecuted = true;',
      runtimeSource: (secondaryIntegrity) => `
        const dependency = document.createElement('script');
        dependency.src = '/runtime-v2.js';
        dependency.integrity = '${secondaryIntegrity}';
        dependency.crossOrigin = 'anonymous';
        dependency.addEventListener('load', () => {
          document.body.setAttribute('data-runtime-ready', '');
        });
        document.head.append(dependency);`,
      markup: (integrity) =>
        `<script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`
    });

    expect(manifest.runtimeArtifacts).toEqual([
      expect.objectContaining({ loadedByPage: true, trustedRuntimeInitiator: false }),
      expect.objectContaining({ loadedByPage: true, trustedRuntimeInitiator: true })
    ]);
    expect(manifest.runtimeCreatedScripts).toEqual([]);
    expect(manifest.unreviewedRuntimeScripts).toEqual([]);
  }, 30_000);

  test('reports a cross-host module request initiated by the pinned runtime', async () => {
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      runtimeSource: `
        void import('http://localhost:' + location.port + '/extra-module.js');
        document.body.setAttribute('data-runtime-ready', '');`,
      markup: (integrity) =>
        `<script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`
    });
    expect(manifest.runtimeCreatedScripts).toEqual(
      expect.arrayContaining([
        expect.stringContaining('localhost:'),
        expect.stringContaining('/extra-module.js')
      ])
    );
  }, 30_000);

  test('bounds hostile console output at the evidence source', async () => {
    const { consoleLog } = await runAdversarialFixture({
      proxyStatus: 403,
      markup: (integrity) => `
        <script>for (let index = 0; index < 250; index += 1) console.log('flood-' + index);</script>
        <script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`
    });
    expect(consoleLog).toMatchObject({
      messages: expect.any(Array),
      droppedMessages: 150
    });
    expect((consoleLog as { messages: unknown[] }).messages).toHaveLength(100);
  }, 30_000);

  test('reports a Blob Worker created by the pinned runtime', async () => {
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      runtimeSource: `
        const workerUrl = URL.createObjectURL(new Blob([
          'globalThis.__blobWorkerExecuted = true;'
        ], { type: 'application/javascript' }));
        new Worker(workerUrl);
        document.body.setAttribute('data-runtime-ready', '');`,
      markup: (integrity) =>
        `<script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`
    });
    expect(manifest.runtimeCreatedScripts).toEqual(
      expect.arrayContaining([expect.stringMatching(/^blob:/)])
    );
  }, 30_000);

  test('reports iframe code execution initiated by the pinned runtime', async () => {
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      runtimeSource: `
        const frame = document.createElement('iframe');
        frame.srcdoc = '<script>globalThis.__iframeRuntimeExecuted = true<\\/script>';
        document.body.append(frame);
        document.body.setAttribute('data-runtime-ready', '');`,
      markup: (integrity) =>
        `<script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`
    });
    expect(manifest.runtimeCreatedScripts).toEqual(
      expect.arrayContaining([expect.stringMatching(/^\[inline-or-eval:[a-f0-9]{12}\]$/)])
    );
  }, 30_000);

  test('FIX1: rejects a loopback host allowlist unless explicitly opted in', async () => {
    const source = 'document.body.setAttribute("data-runtime-ready", "");';
    const digest = createHash('sha256').update(source).digest();
    const integrity = `sha256-${digest.toString('base64')}`;
    const { rejection, manifest } = await runServerFixture({
      allowPrivateHosts: false,
      routes: () =>
        new Map([
          [
            '/runtime-fixture',
            {
              contentType: 'text/html',
              body: `<!doctype html><body><script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script></body>`
            }
          ],
          ['/runtime-v1.js', { contentType: 'application/javascript', body: source }]
        ]),
      buildContract: (origin) =>
        loopbackContract(origin, [
          { url: `${origin}/runtime-v1.js`, sha256: digest.toString('hex'), integrity }
        ])
    });
    expect(rejection).toMatch(/loopback or private-network address/);
    // Rejected before any evidence is produced.
    expect(manifest).toBeUndefined();
  }, 30_000);

  test('FIX2: a stale cleanup selector downgrades cleanup to not_tested', async () => {
    const source = 'document.body.setAttribute("data-runtime-ready", "");';
    const digest = createHash('sha256').update(source).digest();
    const integrity = `sha256-${digest.toString('base64')}`;
    const { result, manifest, rejection } = await runServerFixture({
      routes: () =>
        new Map([
          [
            '/runtime-fixture',
            {
              contentType: 'text/html',
              body: `<!doctype html><body><script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script></body>`
            }
          ],
          ['/runtime-v1.js', { contentType: 'application/javascript', body: source }],
          ['/proxy', { contentType: 'application/json', status: 403, body: '{}' }]
        ]),
      buildContract: (origin) => {
        const base = loopbackContract(origin, [
          { url: `${origin}/runtime-v1.js`, sha256: digest.toString('hex'), integrity }
        ]);
        return {
          ...base,
          lifecycle: {
            readySelector: '[data-runtime-ready]',
            cleanupTrigger: { type: 'click', selector: '#nonexistent-cleanup' }
          }
        };
      }
    });
    expect(rejection).toBeUndefined();
    expect(result?.status).toBe('complete');
    expect(result?.cleanupStatus).toBe('not_tested');
    expect((manifest?.cleanup as { status: string }).status).toBe('not_tested');
  }, 30_000);

  test('FIX2: a navigation failure uploads a partial failed manifest and reports failure', async () => {
    const { manifest, rejection } = await runServerFixture({
      routes: () => new Map(),
      buildContract: (origin) => {
        const base = loopbackContract(origin, [
          { url: `${origin}/runtime-v1.js`, sha256: 'a'.repeat(64), integrity: 'sha256-fixture' }
        ]);
        // Unreachable port forces page.goto to throw mid-run.
        return { ...base, target: { url: 'http://127.0.0.1:1/runtime-fixture', host: '127.0.0.1' } };
      }
    });
    expect(rejection).toMatch(/partial evidence/);
    expect(manifest?.status).toBe('failed');
    expect(typeof manifest?.failureReason).toBe('string');
    const artifacts = manifest?.artifacts as Array<{ field: string }>;
    expect(artifacts.map((artifact) => artifact.field)).toEqual(
      expect.arrayContaining(['network_log', 'console_log'])
    );
  }, 30_000);

  test('FIX3: query-distinct runtime pins do not alias DOM integrity', async () => {
    const source = 'document.body.setAttribute("data-runtime-ready", "");';
    const digest = createHash('sha256').update(source).digest();
    const sha = digest.toString('hex');
    const integrity = `sha256-${digest.toString('base64')}`;
    const { manifest, rejection } = await runServerFixture({
      routes: () =>
        new Map([
          [
            '/runtime-fixture',
            {
              contentType: 'text/html',
              body: `<!doctype html><body><script src="/runtime.js?v=1" integrity="${integrity}" crossorigin="anonymous"></script></body>`
            }
          ],
          ['/runtime.js', { contentType: 'application/javascript', body: source }],
          ['/proxy', { contentType: 'application/json', status: 403, body: '{}' }]
        ]),
      buildContract: (origin) =>
        loopbackContract(origin, [
          { url: `${origin}/runtime.js?v=1`, sha256: sha, integrity },
          { url: `${origin}/runtime.js?v=2`, sha256: sha, integrity, loadMode: 'runtime_child' as const }
        ])
    });
    expect(rejection).toBeUndefined();
    const artifacts = manifest?.runtimeArtifacts as Array<{ url: string; domIntegrity: string | null }>;
    const v1 = artifacts.find((artifact) => artifact.url.endsWith('v=1'));
    const v2 = artifacts.find((artifact) => artifact.url.endsWith('v=2'));
    // Only the pin actually present in the DOM carries the integrity attribute.
    expect(v1?.domIntegrity).toBe(integrity);
    expect(v2?.domIntegrity).toBeNull();
  }, 30_000);

  test('FIX4: off-allowlist requests do not consume the request budget', async () => {
    const source = 'document.body.setAttribute("data-runtime-ready", "");';
    const digest = createHash('sha256').update(source).digest();
    const integrity = `sha256-${digest.toString('base64')}`;
    const noise = Array.from(
      { length: 30 },
      (_, index) => `<img src="http://blocked.invalid/noise-${index}.png">`
    ).join('');
    const { manifest, rejection } = await runServerFixture({
      routes: () =>
        new Map([
          [
            '/runtime-fixture',
            {
              contentType: 'text/html',
              body: `<!doctype html><body>${noise}<script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script></body>`
            }
          ],
          ['/runtime-v1.js', { contentType: 'application/javascript', body: source }],
          ['/proxy', { contentType: 'application/json', status: 403, body: '{}' }]
        ]),
      buildContract: (origin) =>
        loopbackContract(
          origin,
          [{ url: `${origin}/runtime-v1.js`, sha256: digest.toString('hex'), integrity }],
          { maxRequests: 3 as 100 }
        )
    });
    expect(rejection).toBeUndefined();
    expect(manifest?.runtimeReadyObserved).toBe(true);
    const artifacts = manifest?.runtimeArtifacts as Array<{ loadedByPage: boolean }>;
    expect(artifacts[0]?.loadedByPage).toBe(true);
  }, 30_000);

  test('FIX5: a non-http sourceMappingURL is not fetched', async () => {
    const source =
      'document.body.setAttribute("data-runtime-ready", "");\n//# sourceMappingURL=data:application/json;base64,e30=';
    const digest = createHash('sha256').update(source).digest();
    const integrity = `sha256-${digest.toString('base64')}`;
    const { manifest, rejection } = await runServerFixture({
      routes: () =>
        new Map([
          [
            '/runtime-fixture',
            {
              contentType: 'text/html',
              body: `<!doctype html><body><script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script></body>`
            }
          ],
          ['/runtime-v1.js', { contentType: 'application/javascript', body: source }],
          ['/proxy', { contentType: 'application/json', status: 403, body: '{}' }]
        ]),
      buildContract: (origin) =>
        loopbackContract(origin, [
          { url: `${origin}/runtime-v1.js`, sha256: digest.toString('hex'), integrity }
        ])
    });
    expect(rejection).toBeUndefined();
    const artifacts = manifest?.runtimeArtifacts as Array<{
      sourceMap: { available: boolean; url?: string };
    }>;
    expect(artifacts[0]?.sourceMap.available).toBe(false);
    expect(artifacts[0]?.sourceMap.url).toBeUndefined();
  }, 30_000);

  test('FIX5: an allowlisted http sourceMappingURL is fetched under the size cap', async () => {
    const source =
      'document.body.setAttribute("data-runtime-ready", "");\n//# sourceMappingURL=/runtime-v1.js.map';
    const digest = createHash('sha256').update(source).digest();
    const integrity = `sha256-${digest.toString('base64')}`;
    const { manifest, rejection } = await runServerFixture({
      routes: () =>
        new Map([
          [
            '/runtime-fixture',
            {
              contentType: 'text/html',
              body: `<!doctype html><body><script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script></body>`
            }
          ],
          ['/runtime-v1.js', { contentType: 'application/javascript', body: source }],
          [
            '/runtime-v1.js.map',
            {
              contentType: 'application/json',
              body: JSON.stringify({ version: 3, sources: [], names: [], mappings: '' })
            }
          ],
          ['/proxy', { contentType: 'application/json', status: 403, body: '{}' }]
        ]),
      buildContract: (origin) =>
        loopbackContract(origin, [
          { url: `${origin}/runtime-v1.js`, sha256: digest.toString('hex'), integrity }
        ])
    });
    expect(rejection).toBeUndefined();
    const artifacts = manifest?.runtimeArtifacts as Array<{
      sourceMap: { available: boolean; url?: string };
    }>;
    expect(artifacts[0]?.sourceMap.available).toBe(true);
    expect(artifacts[0]?.sourceMap.url).toContain('/runtime-v1.js.map');
  }, 30_000);
});
