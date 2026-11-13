import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { crc32, deflateRawSync } from 'node:zlib';
import {
  BOOT_TEST_LIMITS,
  type BootTestEvidence,
  type BootTestJobContract
} from '@create-something/webflow-app-review-preflight';
import { describe, expect, test } from 'vitest';
import { clampBootTestLabels, runBootTest, validateBootTestContract } from '../src/boot-test.js';
import { extensionSiteRoot, readBundleZip } from '../src/boot-test-zip.js';

const BROWSER_TEST_TIMEOUT_MS = 30_000;
const CAPABILITY = 'c'.repeat(64);

// A minimal ZIP writer for fixtures: stored entries by default, deflated on request.
function zip(entries: Record<string, string | Uint8Array>, options: { deflate?: boolean } = {}): Uint8Array {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const [name, value] of Object.entries(entries)) {
    const content = Buffer.from(typeof value === 'string' ? Buffer.from(value) : value);
    const data = options.deflate ? deflateRawSync(content) : content;
    const nameBytes = Buffer.from(name);
    const crc = crc32(content);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(options.deflate ? 8 : 0, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(options.deflate ? 8 : 0, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(content.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, data);
    centrals.push(central, nameBytes);
    offset += local.length + nameBytes.length + data.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(entries).length, 8);
  end.writeUInt16LE(Object.keys(entries).length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return new Uint8Array(Buffer.concat([...locals, directory, end]));
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function contract(bundle: Uint8Array, overrides: Partial<BootTestJobContract> = {}): BootTestJobContract {
  return {
    schemaVersion: 'designer_extension_boot_test_job.v1',
    purpose: 'designer_extension_boot_test',
    bootTestJobId: 'job-1',
    reviewId: 'review-1',
    reviewVersionId: 'version-1',
    bundleSha256: sha256(bundle),
    bundleBytes: bundle.byteLength,
    nonce: 'nonce-0000-0001',
    contentSecurityPolicy: 'frame-ancestors https://*.design.webflow.com https://webflow.com',
    controls: {
      networkMode: 'local_static_server_only',
      viewport: { width: 320, height: 460 },
      navigationTimeoutMs: 10_000,
      settleMs: 300,
      totalTimeoutMs: 25_000,
      evidenceTrust: 'webflow_observed'
    },
    limits: {
      cspViolations: 20,
      missingFiles: 20,
      uncaughtErrors: 10,
      externalHosts: 20,
      messageLength: 300
    },
    boundaries: {
      advisoryOnly: true,
      affectsReadiness: false,
      officialDecision: null,
      canWriteGovernance: false,
      acceptsAccountCredentials: false
    },
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    ...overrides
  };
}

// Plays the Worker: serves the contract and bundle for the capability, and
// records the uploaded result and every other request the sandbox made.
async function runFixture(
  bundleOrFactory: Uint8Array | ((apiOrigin: string) => Uint8Array),
  overrides: Partial<BootTestJobContract> = {},
  servedOverride?: Uint8Array
): Promise<{ evidence: BootTestEvidence; strayRequests: string[] }> {
  let jobContract!: BootTestJobContract;
  let served!: Uint8Array;
  const strayRequests: string[] = [];
  let uploaded: BootTestEvidence | undefined;
  const server = createServer((request, response) => {
    const authorized = request.headers.authorization === `Bearer ${CAPABILITY}`;
    if (request.url === '/v1/boot-test-jobs/job-1' && authorized) {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ bootTestJob: { contract: jobContract } }));
      return;
    }
    if (request.url === '/v1/boot-test-jobs/job-1/bundle' && authorized) {
      response.writeHead(200, { 'content-type': 'application/zip' });
      response.end(Buffer.from(served));
      return;
    }
    if (request.url === '/v1/boot-test-jobs/job-1/result' && authorized) {
      const chunks: Buffer[] = [];
      request.on('data', (chunk: Buffer) => chunks.push(chunk));
      request.on('end', () => {
        uploaded = JSON.parse(Buffer.concat(chunks).toString('utf8')) as BootTestEvidence;
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end('{"status":"complete"}');
      });
      return;
    }
    strayRequests.push(request.url ?? '');
    response.writeHead(404);
    response.end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  const bundle =
    typeof bundleOrFactory === 'function'
      ? bundleOrFactory(`http://127.0.0.1:${port}`)
      : bundleOrFactory;
  jobContract = contract(bundle, overrides);
  served = servedOverride ?? bundle;
  try {
    const result = await runBootTest({
      apiBaseUrl: `http://127.0.0.1:${port}`,
      bootTestJobId: 'job-1',
      capability: CAPABILITY
    });
    expect(uploaded).toEqual(result.evidence);
    return { evidence: result.evidence, strayRequests };
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

const RENDERING_APP = `
  const root = document.getElementById('root');
  root.textContent = 'Extension ready';
  window.webflow.getSelectedElement().then((element) => {
    root.dataset.selected = String(element);
  });
`;

function indexHtml(body: string, head = ''): string {
  return `<!doctype html><html><head><meta charset="utf-8">${head}</head><body>${body}</body></html>`;
}

describe('Designer Extension boot test', () => {
  test(
    'passes a bundle that renders under the host policy with the Designer API stub',
    async () => {
      const bundle = zip({
        'index.html': indexHtml('<div id="root"></div><script type="module" src="./assets/app.js"></script>'),
        'assets/app.js': RENDERING_APP,
        'webflow.json': '{"name":"Fixture","apiVersion":"2","publicDir":"dist"}'
      });
      const { evidence } = await runFixture(bundle);

      expect(evidence).toMatchObject({
        schemaVersion: 'designer_extension_boot_test_evidence.v1',
        bootTestJobId: 'job-1',
        reviewVersionId: 'version-1',
        bundleSha256: sha256(bundle),
        nonce: 'nonce-0000-0001',
        trust: 'webflow_observed'
      });
      expect(evidence.bootTest).toMatchObject({
        status: 'passed',
        failures: [],
        cspViolations: [],
        missingFiles: [],
        uncaughtErrors: [],
        externalHostsRequested: []
      });
      expect(evidence.bootTest.renderedTextLength).toBe('Extension ready'.length);
      expect(evidence.bootTest.renderedElementCount).toBeGreaterThan(0);
    },
    BROWSER_TEST_TIMEOUT_MS
  );

  test(
    'fails when the job policy blocks a bundled script',
    async () => {
      const bundle = zip({
        'index.html': indexHtml('<div id="root"></div><script src="assets/app.js"></script>'),
        'assets/app.js': RENDERING_APP
      });
      const { evidence } = await runFixture(bundle, {
        contentSecurityPolicy: "script-src https://cdn.example.test"
      });

      expect(evidence.bootTest.status).toBe('failed');
      expect(evidence.bootTest.failures).toEqual(['blank_panel', 'bundled_script_blocked_by_csp']);
      expect(evidence.bootTest.cspViolations).toContainEqual({
        directive: 'script-src-elem',
        blocked: 'assets/app.js',
        source: 'document'
      });
      expect(evidence.bootTest.missingFiles).toEqual([]);
    },
    BROWSER_TEST_TIMEOUT_MS
  );

  test(
    "fails when the bundle's own meta policy blocks its script, and records inline and eval",
    async () => {
      const bundle = zip({
        'index.html': indexHtml(
          '<p>Static shell</p><script>window.inline = 1</script><script src="assets/app.js"></script>',
          `<meta http-equiv="Content-Security-Policy" content="script-src 'self'">`
        ),
        'assets/app.js': 'try { eval("1"); } catch (error) {}'
      });
      const passing = await runFixture(bundle);
      expect(passing.evidence.bootTest.status).toBe('passed');
      expect(passing.evidence.bootTest.cspViolations).toEqual(
        expect.arrayContaining([
          { directive: 'script-src-elem', blocked: 'inline', source: 'document' },
          { directive: 'script-src', blocked: 'eval', source: 'assets/app.js' }
        ])
      );

      const blocked = zip({
        'index.html': indexHtml(
          '<p>Static shell</p><script src="assets/app.js"></script>',
          `<meta http-equiv="Content-Security-Policy" content="script-src https://cdn.example.test">`
        ),
        'assets/app.js': RENDERING_APP
      });
      const failing = await runFixture(blocked);
      expect(failing.evidence.bootTest.failures).toEqual(['bundled_script_blocked_by_csp']);
    },
    BROWSER_TEST_TIMEOUT_MS
  );

  test(
    'fails when index.html references a file that is not in the ZIP',
    async () => {
      const bundle = zip({
        'index.html': indexHtml(
          '<div id="root"></div><link rel="stylesheet" href="assets/missing.css"><script src="assets/missing.js"></script><script src="assets/app.js"></script>'
        ),
        'assets/app.js': RENDERING_APP
      });
      const { evidence } = await runFixture(bundle);

      expect(evidence.bootTest.status).toBe('failed');
      expect(evidence.bootTest.failures).toEqual(['bundled_file_missing']);
      expect(evidence.bootTest.missingFiles).toEqual(['assets/missing.css', 'assets/missing.js']);
      expect(evidence.bootTest.renderedTextLength).toBeGreaterThan(0);
    },
    BROWSER_TEST_TIMEOUT_MS
  );

  test(
    'fails an empty page as a blank panel',
    async () => {
      const bundle = zip({
        'index.html': indexHtml('<div id="root"></div><script src="app.js"></script>'),
        'app.js': 'window.started = true;'
      });
      const { evidence } = await runFixture(bundle);

      expect(evidence.bootTest).toMatchObject({
        status: 'failed',
        failures: ['blank_panel'],
        renderedTextLength: 0,
        renderedElementCount: 0
      });
    },
    BROWSER_TEST_TIMEOUT_MS
  );

  test(
    'passes an app whose only problem is a blocked external request, and lists the hosts',
    async () => {
      const bundle = zip({
        'index.html': indexHtml(
          '<div id="root"></div><img alt="" src="https://images.example.test/logo.png"><script src="app.js"></script>'
        ),
        'app.js': `${RENDERING_APP}
          fetch('https://api.example.test/v1/settings?key=value').then((response) => response.json());
          new WebSocket('wss://socket.example.test/live');`
      });
      const { evidence } = await runFixture(bundle);

      expect(evidence.bootTest.status).toBe('passed');
      expect(evidence.bootTest.failures).toEqual([]);
      expect(evidence.bootTest.externalHostsRequested).toEqual([
        'api.example.test',
        'images.example.test',
        'socket.example.test'
      ]);
      expect(evidence.bootTest.uncaughtErrors.length).toBeLessThanOrEqual(10);
      expect(JSON.stringify(evidence)).not.toContain('key=value');
    },
    BROWSER_TEST_TIMEOUT_MS
  );

  test(
    'lets the page reach only the local static server, not other loopback services',
    async () => {
      // The fixture Worker listens on another loopback port. The page tries to
      // read the bundle route and the sandbox launch port; neither may connect.
      let apiHost = '';
      const { evidence, strayRequests } = await runFixture((apiOrigin) => {
        apiHost = new URL(apiOrigin).host;
        return zip({
          'index.html': indexHtml(
            `<div id="root"></div><img alt="" src="${apiOrigin}/pixel.png"><script src="app.js"></script>`
          ),
          'app.js': `${RENDERING_APP}
            fetch('${apiOrigin}/v1/boot-test-jobs/job-1/bundle').catch(() => {});
            new Worker(URL.createObjectURL(new Blob(["fetch('${apiOrigin}/from-worker').catch(() => {})"])));
            new WebSocket('${apiOrigin.replace('http', 'ws')}/socket');
            fetch('http://127.0.0.1:3000/run', { method: 'POST' }).catch(() => {});`
        });
      });

      expect(strayRequests).toEqual([]);
      expect(evidence.bootTest.status).toBe('passed');
      expect(evidence.bootTest.externalHostsRequested).toEqual(
        expect.arrayContaining(['127.0.0.1:3000', apiHost])
      );
    },
    BROWSER_TEST_TIMEOUT_MS
  );

  test(
    'caps every list and truncates messages',
    async () => {
      const missingScripts = Array.from(
        { length: 30 },
        (_, index) => `<script src="missing/file-${index}.js"></script>`
      ).join('');
      const externalImages = Array.from(
        { length: 30 },
        (_, index) => `<img alt="" src="https://host-${index}.example.test/a.png">`
      ).join('');
      const errors = Array.from(
        { length: 15 },
        (_, index) =>
          `<script>throw new Error('failure ${index} ' + 'x'.repeat(1000))</script>`
      ).join('');
      const bundle = zip({
        'index.html': indexHtml(`<p>Shell</p>${missingScripts}${externalImages}${errors}`)
      });
      const { evidence } = await runFixture(bundle);

      expect(evidence.bootTest.failures).toEqual(['bundled_file_missing']);
      expect(evidence.bootTest.missingFiles).toHaveLength(20);
      expect(evidence.bootTest.externalHostsRequested).toHaveLength(20);
      expect(evidence.bootTest.uncaughtErrors).toHaveLength(10);
      for (const message of evidence.bootTest.uncaughtErrors) {
        expect(message.length).toBeLessThanOrEqual(300);
      }
    },
    BROWSER_TEST_TIMEOUT_MS
  );

  test(
    'reports error, not a bundle failure, when the downloaded bytes do not match',
    async () => {
      const bundle = zip({ 'index.html': indexHtml('<p>Hello</p>') });
      const other = zip({ 'index.html': indexHtml('<p>Changed</p>') });
      const { evidence } = await runFixture(bundle, {}, other);

      expect(evidence.bootTest).toEqual({
        status: 'error',
        failures: [],
        cspViolations: [],
        missingFiles: [],
        uncaughtErrors: [],
        externalHostsRequested: [],
        renderedTextLength: 0,
        renderedElementCount: 0
      });
    },
    BROWSER_TEST_TIMEOUT_MS
  );

  test('fails a bundle without index.html without starting a browser', async () => {
    const bundle = zip({ 'assets/app.js': RENDERING_APP });
    const { evidence } = await runFixture(bundle);
    expect(evidence.bootTest).toMatchObject({
      status: 'failed',
      failures: ['blank_panel', 'bundled_file_missing'],
      missingFiles: ['index.html']
    });
  });
});

describe('boot test contract and archive boundaries', () => {
  const bundle = zip({ 'index.html': indexHtml('<p>Hello</p>') });

  test('accepts the issued contract shape and the Worker caps', () => {
    expect(() => validateBootTestContract('job-1', contract(bundle))).not.toThrow();
    // The runner keeps its own ceilings; the Worker's caps must fit inside them.
    expect(() =>
      validateBootTestContract('job-1', contract(bundle, { limits: { ...BOOT_TEST_LIMITS } }))
    ).not.toThrow();
  });

  test.each([
    ['a header-splitting policy', { contentSecurityPolicy: "script-src 'self'\r\nx-injected: 1" }],
    ['an empty policy', { contentSecurityPolicy: '' }],
    ['another job id', { bootTestJobId: 'job-2' }],
    ['an expired contract', { expiresAt: new Date(Date.now() - 1).toISOString() }],
    ['a raised cap', { limits: { ...contract(bundle).limits, missingFiles: 500 } }],
    [
      'a different network mode',
      { controls: { ...contract(bundle).controls, networkMode: 'open' } }
    ],
    ['a longer settle time', { controls: { ...contract(bundle).controls, settleMs: 30_000 } }],
    [
      'a decision-bearing boundary',
      { boundaries: { ...contract(bundle).boundaries, affectsReadiness: true } }
    ],
    ['an oversized bundle', { bundleBytes: 11 * 1024 * 1024 }]
  ])('rejects %s', (_label, override) => {
    expect(() =>
      validateBootTestContract(
        'job-1',
        contract(bundle, override as unknown as Partial<BootTestJobContract>)
      )
    ).toThrow(/unsafe contract/);
  });

  test('reads stored and deflated entries and skips traversal paths', () => {
    const stored = readBundleZip(zip({ 'a.txt': 'one', '../escape.js': 'x', '__MACOSX/a': 'y' }));
    expect([...stored.keys()]).toEqual(['a.txt']);
    const deflated = readBundleZip(zip({ 'b.txt': 'two'.repeat(100) }, { deflate: true }));
    expect(new TextDecoder().decode(deflated.get('b.txt'))).toBe('two'.repeat(100));
  });

  test('rejects an archive over the uncompressed budget', () => {
    expect(() =>
      readBundleZip(zip({ 'big.txt': 'x'.repeat(2_000) }, { deflate: true }), {
        maxFiles: 10,
        maxTotalBytes: 1_000
      })
    ).toThrow(/size limit/);
    expect(() => readBundleZip(new Uint8Array([1, 2, 3]))).toThrow(/not a ZIP/);
  });

  test('serves the directory that holds the shallowest index.html', () => {
    const files = readBundleZip(
      zip({
        'dist/index.html': '<p>root</p>',
        'dist/assets/app.js': '1',
        'dist/nested/index.html': '<p>nested</p>',
        'webflow.json': '{}'
      })
    );
    const site = extensionSiteRoot(files);
    expect(site?.root).toBe('dist/');
    expect([...site!.files.keys()].sort()).toEqual([
      'assets/app.js',
      'index.html',
      'nested/index.html'
    ]);
  });
});

describe('boot test label clamp', () => {
  test('replaces labels the Worker would refuse and keeps the verdict fields', () => {
    const clamped = clampBootTestLabels(
      {
        status: 'failed',
        failures: ['bundled_file_missing'],
        cspViolations: [
          { directive: 'script-src-elem', blocked: 'a?b', source: 'document' },
          { directive: 'script-src-elem', blocked: 'c?d', source: 'document' }
        ],
        missingFiles: ['dir/a?b.js', 'ok.js', 'x/\u00e9.js'],
        uncaughtErrors: ['x'.repeat(500), 'Bearer abcdefghijkl'],
        externalHostsRequested: [`${'a'.repeat(300)}.com`, 'my_host.com', 'api.example.test'],
        renderedTextLength: 3,
        renderedElementCount: 1
      },
      { ...BOOT_TEST_LIMITS }
    );
    expect(clamped).toMatchObject({
      status: 'failed',
      failures: ['bundled_file_missing'],
      cspViolations: [{ directive: 'script-src-elem', blocked: '[unreadable]', source: 'document' }],
      missingFiles: ['[unreadable]', 'ok.js'],
      externalHostsRequested: ['[unreadable]', 'api.example.test'],
      renderedTextLength: 3
    });
    expect(clamped.uncaughtErrors).toEqual(['x'.repeat(300), '[unreadable]']);
  });
});
