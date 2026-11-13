import { defaultRuleset } from '@create-something/bundle-scanner-core';
import { createHash } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  WEBFLOW_PLATFORM_ASSET_HOSTS,
  type RuntimeObservationJobContract
} from '@create-something/webflow-app-review-preflight';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import {
  PLATFORM_ASSET_HOSTS,
  buildReplayCsp,
  normalizeCspIssue,
  redactText,
  runRuntimeObservation,
  scanRuntimeSources,
  STATIC_SCAN_EXCLUDED_RULES,
  runtimeScopeKey,
  sanitizeUrl,
  validateObservationContract
} from '../src/index.js';

// Names resolve without the network so the suite runs offline. A test sets an
// answer here. Any other name resolves to a multicast address: a TCP
// connection to one fails at once on every platform, so a platform asset
// request fails fast and never waits for a time-out.
const dnsAnswers = vi.hoisted(
  () =>
    new Map<string, Array<{ address: string; family: number }>>([
      ['localhost', [{ address: '127.0.0.1', family: 4 }]]
    ])
);
vi.mock('node:dns/promises', () => ({
  lookup: async (host: string) => dnsAnswers.get(host) ?? [{ address: '224.0.0.1', family: 4 }]
}));

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
  controls?: Partial<RuntimeObservationJobContract['controls']>;
  /** Make every document request after the first one hang (replay time-out). */
  hangRepeatDocumentRequests?: boolean;
  cspReplayTimeoutMs?: number;
}

async function runAdversarialFixture({
  markup,
  proxyStatus,
  runtimeSource = 'document.body.setAttribute("data-runtime-ready", "");',
  secondaryRuntimeSource,
  controls = {},
  hangRepeatDocumentRequests = false,
  cspReplayTimeoutMs
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
  let documentRequests = 0;
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
      documentRequests += 1;
      if (hangRepeatDocumentRequests && documentRequests > 1) return;
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
    if (url.pathname === '/redirect-off') {
      response.writeHead(302, { location: 'http://127.0.0.2:9/off' });
      response.end();
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
      negativeProxyCanaryUrl: `${origin}/canary`,
      ...controls
    }
  };

  try {
    const result = await runRuntimeObservation({
      apiBaseUrl: origin,
      observationJobId: 'job-1',
      capability: 'c'.repeat(64),
      outputDir,
      ...(cspReplayTimeoutMs ? { cspReplayTimeoutMs } : {})
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
    server.closeAllConnections();
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
  networkLog?: { entries: Array<Record<string, unknown>> };
  // The path of each WebSocket handshake that reached the fixture server.
  upgradeRequests: string[];
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
  const upgradeRequests: string[] = [];
  server.on('upgrade', (request, socket) => {
    upgradeRequests.push(request.url ?? '');
    socket.destroy();
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
    const networkLog = await readFile(join(outputDir, 'network-log.json'), 'utf8')
      .then((raw) => JSON.parse(raw) as { entries: Array<Record<string, unknown>> })
      .catch(() => undefined);
    return { manifest, scriptInventory, networkLog, upgradeRequests, rejection, result };
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

  test('accepts only Webflow-owned platform asset hosts on the contract', () => {
    const safe = contract();
    // The runner's copy must match the list the worker puts on contracts.
    expect(new Set(WEBFLOW_PLATFORM_ASSET_HOSTS)).toEqual(PLATFORM_ASSET_HOSTS);
    expect(() =>
      validateObservationContract('job-1', {
        ...safe,
        controls: { ...safe.controls, platformAssetHosts: [...WEBFLOW_PLATFORM_ASSET_HOSTS] }
      })
    ).not.toThrow();
    expect(() =>
      validateObservationContract('job-1', {
        ...safe,
        controls: { ...safe.controls, platformAssetHosts: [] }
      })
    ).not.toThrow();
    for (const platformAssetHosts of [
      ['cdn.prod.website-files.com', 'evil.example'],
      ['127.0.0.1'],
      [42]
    ]) {
      expect(() =>
        validateObservationContract('job-1', {
          ...safe,
          controls: { ...safe.controls, platformAssetHosts: platformAssetHosts as string[] }
        })
      ).toThrow('unsafe contract');
    }
  });

  test('lets the page reach a platform asset host only when the contract names it', async () => {
    const asset = 'https://cdn.prod.website-files.com/preflight-fixture/none.css';
    const markup = (integrity: string) => `
      <link rel="stylesheet" href="${asset}">
      <img src="/redirect-off" alt="">
      <script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`;
    type Entry = { phase: string; url: string; method?: string; blocked: boolean | null };
    const requestFor = (log: unknown, prefix: string) =>
      (log as { entries: Entry[] }).entries.find(
        (entry) => entry.phase === 'request' && entry.url.startsWith(prefix)
      );

    const allowed = await runAdversarialFixture({
      proxyStatus: 403,
      markup,
      controls: { platformAssetHosts: ['cdn.prod.website-files.com'] }
    });
    expect(requestFor(allowed.networkLog, asset)).toMatchObject({ blocked: false });
    expect(allowed.manifest.runtimeReadyObserved).toBe(true);
    // A redirect off the allowlist is still blocked at the hop.
    expect(requestFor(allowed.networkLog, 'http://127.0.0.2:9/off')).toMatchObject({
      blocked: true
    });

    const confined = await runAdversarialFixture({ proxyStatus: 403, markup });
    expect(requestFor(confined.networkLog, asset)).toMatchObject({ blocked: true });
  }, 60_000);

  test('does not let platform asset requests consume the request budget', async () => {
    const prefix = 'https://cdn.prod.website-files.com/preflight-fixture/i';
    const images = Array.from(
      { length: 120 },
      (_, index) => `<img src="${prefix}${index}.png" alt="">`
    ).join('');
    const { manifest, networkLog } = await runAdversarialFixture({
      proxyStatus: 403,
      markup: (integrity) =>
        `${images}<script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`,
      controls: { platformAssetHosts: ['cdn.prod.website-files.com'] }
    });
    const entries = (networkLog as { entries: Array<{ phase: string; url: string; blocked: boolean | null }> })
      .entries;
    const assetRequests = entries.filter(
      (entry) => entry.phase === 'request' && entry.url.startsWith(prefix)
    );
    // More asset requests than the whole budget, none of them blocked, and the
    // pinned runtime still loaded after them.
    expect(assetRequests.length).toBeGreaterThan(100);
    expect(assetRequests.every((entry) => entry.blocked === false)).toBe(true);
    expect(manifest.runtimeReadyObserved).toBe(true);
    const observations = manifest.runtimeArtifacts as Array<{ loadedByPage: boolean }>;
    expect(observations[0]?.loadedByPage).toBe(true);
  }, 90_000);

  test('scopes the runtime-sibling rule to the asset directory on platform hosts', () => {
    const platform = new Set(['cdn.prod.website-files.com']);
    expect(runtimeScopeKey(new URL('https://api.partner.com/v2/runtime.js'), platform)).toBe(
      'api.partner.com'
    );
    expect(
      runtimeScopeKey(new URL('https://cdn.prod.website-files.com/site-a/runtime.js'), platform)
    ).toBe('cdn.prod.website-files.com/site-a');
    expect(
      runtimeScopeKey(new URL('https://cdn.prod.website-files.com/site-b/js/webflow.js'), platform)
    ).toBe('cdn.prod.website-files.com/site-b');
    expect(runtimeScopeKey(new URL('https://cdn.prod.website-files.com/'), platform)).toBe(
      'cdn.prod.website-files.com/'
    );
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

  test('reports every SRI form of the executed bytes so a page may publish sha384 or sha512', async () => {
    const runtimeSource = 'document.body.setAttribute("data-runtime-ready", "sha384");';
    const sha384 = `sha384-${createHash('sha384').update(runtimeSource).digest('base64')}`;
    const sha512 = `sha512-${createHash('sha512').update(runtimeSource).digest('base64')}`;
    let pinnedSha256 = '';
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      runtimeSource,
      markup: (integrity) => {
        pinnedSha256 = integrity;
        return `<script src="/runtime-v1.js" integrity="${sha384}" crossorigin="anonymous"></script>`;
      }
    });

    const observations = manifest.runtimeArtifacts as Array<{
      loadedByPage: boolean;
      domIntegrity: string | null;
      observedIntegrity: string[];
    }>;
    expect(observations[0]?.loadedByPage).toBe(true);
    expect(observations[0]?.domIntegrity).toBe(sha384);
    expect(observations[0]?.observedIntegrity).toEqual([pinnedSha256, sha384, sha512]);
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

describe('strict-CSP replay', () => {
  type Replay = {
    status: string;
    runtimeReadyObserved: boolean;
    violations: Array<{ directive: string; blocked: string; source: string; fromRuntime: boolean }>;
  };
  const scriptTag = (integrity: string) =>
    `<script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`;

  test('builds a policy with no unsafe-inline or unsafe-eval', () => {
    const policy = buildReplayCsp(
      ['https://runtime.partner.test/app/v1.2.3/run.js'],
      new Set(['cdn.prod.website-files.com'])
    );
    expect(policy).toContain("default-src 'self' https://runtime.partner.test https://cdn.prod.website-files.com");
    expect(policy).not.toMatch(/unsafe-inline|unsafe-eval/);
  });

  test('keeps only directive, blocked kind or host, and source location', () => {
    const context = {
      documentUrl: 'https://site.test/page',
      runtimeUrls: new Set(['https://runtime.test/run.js']),
      runtimeScopes: new Set(['runtime.test']),
      platformHosts: new Set<string>()
    };
    // The shape Chromium sends in Audits.issueAdded for a blocked request.
    expect(
      normalizeCspIssue(
        {
          violatedDirective: 'script-src-elem',
          contentSecurityPolicyViolationType: 'kURLViolation',
          blockedURL: 'https://other.test/x.js?token=abc',
          isReportOnly: false,
          sourceCodeLocation: { url: 'https://runtime.test/run.js', lineNumber: 3, columnNumber: 9 }
        },
        context
      )
    ).toEqual({
      directive: 'script-src-elem',
      blocked: 'other.test',
      source: 'runtime.test/run.js',
      fromRuntime: true
    });
    expect(
      normalizeCspIssue(
        {
          violatedDirective: 'script-src-elem',
          contentSecurityPolicyViolationType: 'kInlineViolation',
          isReportOnly: false,
          sourceCodeLocation: { url: 'https://site.test/page', lineNumber: 1, columnNumber: 1 }
        },
        context
      )
    ).toEqual({
      directive: 'script-src-elem',
      blocked: 'inline',
      source: 'document',
      fromRuntime: false
    });
    expect(
      normalizeCspIssue(
        { violatedDirective: 'script-src', contentSecurityPolicyViolationType: 'kEvalViolation' },
        context
      )
    ).toEqual({ directive: 'script-src', blocked: 'eval', source: 'document', fromRuntime: false });
    // A report-only issue is not a violation of the enforced replay policy.
    expect(
      normalizeCspIssue(
        {
          violatedDirective: 'script-src-elem',
          contentSecurityPolicyViolationType: 'kInlineViolation',
          isReportOnly: true
        },
        context
      )
    ).toBeNull();
    expect(normalizeCspIssue('nope', context)).toBeNull();
  });

  test('records an inline script created by the runtime as a runtime violation', async () => {
    const { manifest, result } = await runAdversarialFixture({
      proxyStatus: 403,
      runtimeSource: `
        const inline = document.createElement('script');
        inline.textContent = 'window.__inlineRan = true';
        document.head.appendChild(inline);
        document.body.setAttribute('data-runtime-ready', '');`,
      markup: scriptTag
    });
    expect(result.status).toBe('complete');
    const replay = manifest.cspReplay as Replay;
    expect(replay.status).toBe('violations');
    expect(replay.runtimeReadyObserved).toBe(true);
    expect(replay.violations).toContainEqual(
      expect.objectContaining({
        blocked: 'inline',
        source: expect.stringMatching(/\/runtime-v1\.js$/),
        fromRuntime: true
      })
    );
    expect(JSON.stringify(replay)).not.toContain('__inlineRan');
  }, 60_000);

  test('records eval called by the runtime as a runtime violation', async () => {
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      runtimeSource: `
        try { eval('1 + 1'); } catch {}
        document.body.setAttribute('data-runtime-ready', '');`,
      markup: scriptTag
    });
    const replay = manifest.cspReplay as Replay;
    expect(replay.status).toBe('violations');
    expect(replay.violations).toContainEqual(
      expect.objectContaining({ blocked: 'eval', fromRuntime: true })
    );
  }, 60_000);

  test('a violation from the customer page alone leaves the replay clean', async () => {
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      markup: (integrity) =>
        `<script>window.__customerInline = true;</script>
         <style>body { margin: 0; }</style>
         ${scriptTag(integrity)}`
    });
    const replay = manifest.cspReplay as Replay;
    expect(replay.status).toBe('clean');
    expect(replay.runtimeReadyObserved).toBe(true);
    expect(replay.violations.length).toBeGreaterThan(0);
    expect(replay.violations.every((violation) => violation.fromRuntime === false)).toBe(true);
  }, 60_000);

  test('runtime code cannot hide its own violation from the replay', async () => {
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      // The runtime first attacks every page-side reporting path it could
      // reach, then injects an inline script.
      runtimeSource: `
        for (const target of [window, document]) {
          target.addEventListener('securitypolicyviolation', (event) => {
            event.stopImmediatePropagation();
            event.preventDefault();
          }, true);
        }
        for (const name of Object.getOwnPropertyNames(window)) {
          if (/csp|replay|report/i.test(name)) {
            try { delete window[name]; } catch {}
            try { window[name] = () => {}; } catch {}
          }
        }
        const realCreate = Document.prototype.createElement;
        Document.prototype.createElement = function (...args) {
          return Reflect.apply(realCreate, this, args);
        };
        const inline = document.createElement('script');
        inline.textContent = 'window.__hiddenInline = true';
        document.head.appendChild(inline);
        document.body.setAttribute('data-runtime-ready', '');`,
      markup: scriptTag
    });
    const replay = manifest.cspReplay as Replay;
    expect(replay.status).toBe('violations');
    expect(replay.violations).toContainEqual(
      expect.objectContaining({
        blocked: 'inline',
        source: expect.stringMatching(/\/runtime-v1\.js$/),
        fromRuntime: true
      })
    );
  }, 60_000);

  test('page code cannot invent a violation', async () => {
    const { manifest } = await runAdversarialFixture({
      proxyStatus: 403,
      // No real violation happens. The runtime only dispatches a synthetic
      // event and calls every reporting name a page-side probe might expose.
      runtimeSource: `
        const fake = {
          documentURI: location.href,
          violatedDirective: 'script-src-elem',
          effectiveDirective: 'script-src-elem',
          originalPolicy: "default-src 'self'",
          disposition: 'enforce',
          blockedURI: 'inline',
          sourceFile: location.origin + '/runtime-v1.js',
          statusCode: 200
        };
        document.dispatchEvent(new SecurityPolicyViolationEvent('securitypolicyviolation', fake));
        for (const name of ['__wfCspReplayReport', '__cspReplayReport', 'reportCspViolation']) {
          try { window[name]?.({ directive: 'script-src-elem', blockedURI: 'inline', sourceFile: fake.sourceFile, createdByRuntime: true }); } catch {}
        }
        document.body.setAttribute('data-runtime-ready', '');`,
      markup: scriptTag
    });
    const replay = manifest.cspReplay as Replay;
    expect(replay.status).toBe('clean');
    expect(replay.runtimeReadyObserved).toBe(true);
    expect(replay.violations).toEqual([]);
  }, 60_000);

  test('a replay time-out reports not_run and leaves the observation unchanged', async () => {
    const baseline = await runAdversarialFixture({ proxyStatus: 403, markup: scriptTag });
    const timedOut = await runAdversarialFixture({
      proxyStatus: 403,
      markup: scriptTag,
      hangRepeatDocumentRequests: true,
      cspReplayTimeoutMs: 1_500
    });
    expect(timedOut.result.status).toBe('complete');
    expect(timedOut.manifest.cspReplay).toEqual({
      status: 'not_run',
      runtimeReadyObserved: false,
      violations: []
    });
    // Everything the Worker's security evaluation reads is identical.
    const { cspReplay: _replay, startedAt: _s, finishedAt: _f, artifacts: _a, ...rest } =
      timedOut.manifest;
    const { cspReplay: _r2, startedAt: _s2, finishedAt: _f2, artifacts: _a2, ...baselineRest } =
      baseline.manifest;
    const portless = (value: unknown) =>
      JSON.parse(JSON.stringify(value).replace(/127\.0\.0\.1:\d+/g, '127.0.0.1:PORT'));
    expect(portless(rest)).toEqual(portless(baselineRest));
  }, 90_000);
});

describe('advisory static scan of served runtime bytes', () => {
  type Scan = {
    status: string;
    filesScanned: number;
    findings: Array<{ ruleId: string; name: string; severity: string; count: number }>;
  };
  const dirty =
    'const run = (code) => eval(code);\nrun("1");\ndocument.body.innerHTML = "<b>" + location.hash + "</b>";\ndocument.body.setAttribute("data-runtime-ready", "");';
  const scriptTag = (integrity: string) =>
    `<script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script>`;

  test('excluded rules are real ruleset rules', () => {
    const known = new Set(defaultRuleset.rules.map((rule) => rule.ruleId));
    for (const ruleId of Object.keys(STATIC_SCAN_EXCLUDED_RULES)) expect(known.has(ruleId)).toBe(true);
  });

  test('reports rule-level counts for eval and an innerHTML write, and nothing else', () => {
    const scan = scanRuntimeSources(new Map([['https://runtime.test/run.js', dirty]]));
    expect(scan.status).toBe('scanned');
    expect(scan.filesScanned).toBe(1);
    expect(scan.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ ruleId: 'SEC-NO-DCE', count: 1 }),
        expect.objectContaining({ ruleId: 'SEC-UNSAFE-HTML', count: 1 })
      ])
    );
    const text = JSON.stringify(scan);
    expect(text).not.toContain('eval(');
    expect(text).not.toContain('innerHTML');
    expect(text).not.toContain('location.hash');
    expect(text).not.toContain('runtime.test');
    for (const finding of scan.findings) {
      expect(Object.keys(finding).sort()).toEqual(['count', 'name', 'ruleId', 'severity']);
    }
  });

  test('skips Designer-only rules and comment matches', () => {
    const scan = scanRuntimeSources(
      new Map([
        [
          'a',
          'window.open("/x");\ndocument.addEventListener("keydown", (e) => { if (e.metaKey && e.key === "k") {} });\n// eval("1")\n'
        ]
      ])
    );
    expect(scan).toEqual({ status: 'scanned', filesScanned: 1, findings: [] });
  });

  test('a clean file scans with no findings; no bytes means not_run', () => {
    expect(scanRuntimeSources(new Map([['a', 'document.body.dataset.ready = "1";']]))).toEqual({
      status: 'scanned',
      filesScanned: 1,
      findings: []
    });
    expect(scanRuntimeSources(new Map())).toEqual({ status: 'not_run', filesScanned: 0, findings: [] });
    expect(scanRuntimeSources(new Map([['a', '']])).status).toBe('not_run');
  });

  test('the observation records the scan of the bytes it served', async () => {
    const { manifest, result } = await runAdversarialFixture({
      proxyStatus: 403,
      runtimeSource: dirty,
      markup: scriptTag
    });
    expect(result.status).toBe('complete');
    const scan = manifest.runtimeStaticScan as Scan;
    expect(scan.status).toBe('scanned');
    expect(scan.findings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining(['SEC-NO-DCE', 'SEC-UNSAFE-HTML'])
    );
    const clean = await runAdversarialFixture({ proxyStatus: 403, markup: scriptTag });
    expect(clean.manifest.runtimeStaticScan).toEqual({
      status: 'scanned',
      filesScanned: 1,
      findings: []
    });
  }, 90_000);
});

describe('pinned host addresses', () => {
  const source =
    'document.body.setAttribute("data-runtime-ready", "");\n//# sourceMappingURL=/runtime-v1.js.map';
  const digest = createHash('sha256').update(source).digest();
  const integrity = `sha256-${digest.toString('base64')}`;
  const pageRoutes = (headMarkup = '') =>
    new Map([
      [
        '/runtime-fixture',
        {
          contentType: 'text/html',
          body: `<!doctype html><body>${headMarkup}<script src="/runtime-v1.js" integrity="${integrity}" crossorigin="anonymous"></script></body>`
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
    ]);

  test('every connection goes to the address that was checked, not to a new DNS answer', async () => {
    // The name exists only in the one answer that the runner checked. A second
    // resolution, by the browser or by a request client, finds nothing.
    dnsAnswers.set('pinned-fixture.test', [{ address: '127.0.0.1', family: 4 }]);
    try {
      const { manifest, rejection } = await runServerFixture({
        routes: () => pageRoutes(),
        buildContract: (origin) => {
          const named = origin.replace('127.0.0.1', 'pinned-fixture.test');
          const base = loopbackContract(
            named,
            [{ url: `${named}/runtime-v1.js`, sha256: digest.toString('hex'), integrity }],
            { allowedHosts: ['pinned-fixture.test'] }
          );
          return { ...base, target: { url: base.target.url, host: 'pinned-fixture.test' } };
        }
      });
      expect(rejection).toBeUndefined();
      expect(manifest?.runtimeReadyObserved).toBe(true);
      const artifacts = manifest?.runtimeArtifacts as Array<{
        loadedByPage: boolean;
        sourceMap: { available: boolean };
      }>;
      // The page and the runtime file loaded through the pinned proxy.
      expect(artifacts[0]?.loadedByPage).toBe(true);
      // The source map check is the runner's own request. It used the pin too.
      expect(artifacts[0]?.sourceMap.available).toBe(true);
    } finally {
      dnsAnswers.delete('pinned-fixture.test');
    }
  }, 30_000);

  test('a host with one private address in its answer fails the job before any request', async () => {
    dnsAnswers.set('rebind-fixture.test', [
      { address: '203.0.113.10', family: 4 },
      { address: '127.0.0.1', family: 4 }
    ]);
    try {
      const { manifest, rejection } = await runServerFixture({
        allowPrivateHosts: false,
        routes: () => pageRoutes(),
        buildContract: (origin) => {
          const named = origin.replace('127.0.0.1', 'rebind-fixture.test');
          const base = loopbackContract(
            named,
            [{ url: `${named}/runtime-v1.js`, sha256: digest.toString('hex'), integrity }],
            { allowedHosts: ['rebind-fixture.test'] }
          );
          return { ...base, target: { url: base.target.url, host: 'rebind-fixture.test' } };
        }
      });
      expect(rejection).toMatch(/did not resolve to a public network address/);
      expect(manifest).toBeUndefined();
    } finally {
      dnsAnswers.delete('rebind-fixture.test');
    }
  }, 30_000);

  test('the page cannot send UDP to an address', async () => {
    const udp = createSocket('udp4');
    let datagrams = 0;
    udp.on('message', () => {
      datagrams += 1;
    });
    await new Promise<void>((resolve) => udp.bind(0, '127.0.0.1', resolve));
    try {
      // A WebRTC connection sends a STUN request over UDP to its ICE server.
      // No route handler and no HTTP proxy sees that datagram.
      const { manifest, rejection } = await runServerFixture({
        routes: () =>
          pageRoutes(
            `<script>(async () => {
              const peer = new RTCPeerConnection({ iceServers: [{ urls: "stun:127.0.0.1:${udp.address().port}" }] });
              peer.createDataChannel("probe");
              await peer.setLocalDescription(await peer.createOffer());
            })();</script>`
          ),
        buildContract: (origin) =>
          loopbackContract(origin, [
            { url: `${origin}/runtime-v1.js`, sha256: digest.toString('hex'), integrity }
          ])
      });
      expect(rejection).toBeUndefined();
      expect(manifest?.runtimeReadyObserved).toBe(true);
      expect(datagrams).toBe(0);
    } finally {
      udp.close();
    }
  }, 30_000);

  test('a WebSocket reaches an allowed host only; any other host is refused and recorded', async () => {
    let port = '';
    const { manifest, networkLog, upgradeRequests, rejection } = await runServerFixture({
      routes: (origin) => {
        port = new URL(origin).port;
        return pageRoutes(
          `<script>new WebSocket("ws://127.0.0.1:${port}/allowed-socket");new WebSocket("ws://localhost:${port}/other-socket");</script>`
        );
      },
      buildContract: (origin) =>
        loopbackContract(
          origin,
          [{ url: `${origin}/runtime-v1.js`, sha256: digest.toString('hex'), integrity }],
          // `localhost` is not on the allowlist here, although it is this machine.
          { allowedHosts: ['127.0.0.1'] }
        )
    });
    expect(rejection).toBeUndefined();
    expect(manifest?.runtimeReadyObserved).toBe(true);
    // Only the handshake for the allowed host reached the server.
    expect(upgradeRequests).toEqual(['/allowed-socket']);
    expect(networkLog?.entries).toContainEqual({
      phase: 'request',
      url: `connect://localhost:${port}`,
      method: 'CONNECT',
      resourceType: 'tunnel',
      blocked: true
    });
  }, 30_000);
});
