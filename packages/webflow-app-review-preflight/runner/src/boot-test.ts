import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { createServer as createTcpServer, type AddressInfo } from 'node:net';
import type {
  BootTestCspViolation,
  BootTestEvidence,
  BootTestFailure,
  BootTestJobContract,
  BootTestResult
} from '@create-something/webflow-app-review-preflight';
import { chromium, type Browser, type CDPSession } from 'playwright';
import { BUNDLE_ZIP_LIMITS, extensionSiteRoot, readBundleZip } from './boot-test-zip.js';
import { readCapped, redactText } from './index.js';

/**
 * Designer Extension boot test.
 *
 * The runner downloads the review version's bundle from the Worker with the
 * job capability, serves it from a static server bound to 127.0.0.1 inside
 * the sandbox, and opens `index.html` in a fresh headless Chromium. Every
 * response carries the job's Content-Security-Policy. The browser can reach
 * only that server: a route handler aborts every other origin, WebSockets
 * are closed before they connect, and the browser's proxy points at a local
 * socket that accepts and drops every connection, so traffic that escapes
 * the route handler still cannot leave the sandbox.
 *
 * The result is advisory. It never changes readiness, a finding, or a
 * runtime-observation security status.
 */

// The runner's own ceilings. A contract may ask for less, never for more.
const MAX_BUNDLE_BYTES = 10 * 1024 * 1024;
const MAX_POLICY_LENGTH = 4_096;
const LIMIT_CEILINGS = {
  cspViolations: 20,
  missingFiles: 20,
  uncaughtErrors: 10,
  externalHosts: 20,
  messageLength: 300
} as const;
const JOB_FETCH_TIMEOUT_MS = 10_000;
const BUNDLE_FETCH_TIMEOUT_MS = 20_000;
const RESULT_UPLOAD_TIMEOUT_MS = 15_000;
const FAILURE_ORDER: readonly BootTestFailure[] = [
  'blank_panel',
  'bundled_script_blocked_by_csp',
  'bundled_file_missing'
];
// Requests the browser makes on its own; a missing one never breaks a panel.
const IGNORED_MISSING_PATHS = new Set(['favicon.ico']);

const CONTENT_TYPES: Record<string, string> = {
  html: 'text/html; charset=utf-8',
  htm: 'text/html; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8',
  cjs: 'text/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8',
  json: 'application/json; charset=utf-8',
  map: 'application/json; charset=utf-8',
  txt: 'text/plain; charset=utf-8',
  svg: 'image/svg+xml',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  avif: 'image/avif',
  ico: 'image/x-icon',
  woff: 'font/woff',
  woff2: 'font/woff2',
  ttf: 'font/ttf',
  otf: 'font/otf',
  wasm: 'application/wasm'
};

export interface BootTestRunnerInput {
  apiBaseUrl: string;
  bootTestJobId: string;
  capability: string;
}

export interface BootTestRunnerOutput {
  bootTestJobId: string;
  evidence: BootTestEvidence;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function inRange(value: unknown, min: number, max: number): boolean {
  return Number.isInteger(value) && Number(value) >= min && Number(value) <= max;
}

function exactKeys(value: object, keys: string[]): boolean {
  return Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

export function validateBootTestContract(jobId: string, contract: BootTestJobContract): void {
  const limits = contract.limits as Record<string, unknown> | undefined;
  const unsafe =
    contract.schemaVersion !== 'designer_extension_boot_test_job.v1' ||
    contract.purpose !== 'designer_extension_boot_test' ||
    contract.bootTestJobId !== jobId ||
    typeof contract.nonce !== 'string' ||
    contract.nonce.length < 8 ||
    !/^[a-f0-9]{64}$/.test(contract.bundleSha256) ||
    !Number.isInteger(contract.bundleBytes) ||
    contract.bundleBytes <= 0 ||
    contract.bundleBytes > MAX_BUNDLE_BYTES ||
    !(Date.parse(contract.expiresAt) > Date.now()) ||
    typeof contract.contentSecurityPolicy !== 'string' ||
    contract.contentSecurityPolicy.length === 0 ||
    contract.contentSecurityPolicy.length > MAX_POLICY_LENGTH ||
    // A header value: printable ASCII only, so it can never split the header.
    !/^[\x20-\x7e]+$/.test(contract.contentSecurityPolicy) ||
    contract.controls?.networkMode !== 'local_static_server_only' ||
    contract.controls.evidenceTrust !== 'webflow_observed' ||
    !inRange(contract.controls.navigationTimeoutMs, 1_000, 15_000) ||
    !inRange(contract.controls.settleMs, 100, 3_000) ||
    !inRange(contract.controls.totalTimeoutMs, 5_000, 60_000) ||
    !Number.isInteger(contract.controls.viewport?.width) ||
    !Number.isInteger(contract.controls.viewport?.height) ||
    contract.controls.viewport.width < 200 ||
    contract.controls.viewport.width > 1_600 ||
    contract.controls.viewport.height < 200 ||
    contract.controls.viewport.height > 1_200 ||
    !limits ||
    !exactKeys(limits, Object.keys(LIMIT_CEILINGS)) ||
    Object.entries(LIMIT_CEILINGS).some(
      ([key, ceiling]) =>
        !Number.isInteger(limits[key]) || Number(limits[key]) < 1 || Number(limits[key]) > ceiling
    ) ||
    contract.boundaries?.advisoryOnly !== true ||
    contract.boundaries.affectsReadiness !== false ||
    contract.boundaries.officialDecision !== null ||
    contract.boundaries.canWriteGovernance !== false ||
    contract.boundaries.acceptsAccountCredentials !== false;
  if (unsafe) throw new Error(`Boot test job ${jobId} has an unsafe contract.`);
}

function contentTypeFor(path: string): string {
  const extension = path.slice(path.lastIndexOf('.') + 1).toLowerCase();
  return CONTENT_TYPES[extension] ?? 'application/octet-stream';
}

/** Bundle-relative path for a same-origin URL path; `index.html` for a directory. */
function bundlePathFor(pathname: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  let path = decoded.replace(/^\/+/, '');
  if (path === '' || path.endsWith('/')) path += 'index.html';
  if (path.split('/').includes('..') || path.includes('\0')) return null;
  return path;
}

function safePathLabel(path: string, maxLength: number): string {
  return redactText(path).replace(/[^\x20-\x7e]/g, '?').slice(0, maxLength);
}

interface StaticSite {
  origin: string;
  server: Server;
  missing: Set<string>;
}

async function serveBundle(
  files: Map<string, Uint8Array>,
  policy: string
): Promise<StaticSite> {
  const missing = new Set<string>();
  const server = createServer((request, response) => {
    const headers: Record<string, string> = {
      'content-security-policy': policy,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff'
    };
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      response.writeHead(405, headers).end();
      return;
    }
    let path: string | null = null;
    try {
      path = bundlePathFor(new URL(request.url ?? '/', 'http://127.0.0.1').pathname);
    } catch {
      path = null;
    }
    const file = path === null ? undefined : files.get(path);
    if (!file) {
      if (path !== null && !IGNORED_MISSING_PATHS.has(path)) missing.add(path);
      response.writeHead(404, { ...headers, 'content-type': 'text/plain; charset=utf-8' });
      response.end(request.method === 'HEAD' ? undefined : 'Not in the bundle.');
      return;
    }
    response.writeHead(200, {
      ...headers,
      'content-type': contentTypeFor(path!),
      'content-length': String(file.byteLength)
    });
    response.end(request.method === 'HEAD' ? undefined : Buffer.from(file));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return { origin: `http://127.0.0.1:${port}`, server, missing };
}

/** A local socket that drops every connection: the browser's dead-end proxy. */
async function blackholeProxy(): Promise<{ url: string; close(): Promise<void> }> {
  const server = createTcpServer((socket) => socket.destroy());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve()))
  };
}

// Runs in the page before any bundle code. The Designer API is unavailable
// in the test, so every call resolves to null instead of throwing on a
// missing global; `subscribe` returns an unsubscribe function.
function installDesignerApiStub(): void {
  const unsubscribe = () => undefined;
  const api = new Proxy(
    {},
    {
      get(_target, property) {
        if (typeof property !== 'string' || property === 'then') return undefined;
        if (property === 'subscribe') return () => unsubscribe;
        return async () => null;
      }
    }
  );
  Object.defineProperty(window, 'webflow', { value: api, configurable: true, writable: true });
}

interface CspIssueDetails {
  violatedDirective?: string;
  isReportOnly?: boolean;
  contentSecurityPolicyViolationType?: string;
  blockedURL?: string;
  sourceCodeLocation?: { url?: string };
}

interface RenderedContent {
  textLength: number;
  elementCount: number;
}

// Measured from Chromium's layout tree, not from page JavaScript, so page
// code cannot fake a rendered panel by overriding DOM APIs.
async function measureRenderedContent(cdp: CDPSession): Promise<RenderedContent> {
  const snapshot = await cdp.send('DOMSnapshot.captureSnapshot', {
    computedStyles: ['visibility']
  });
  const strings = snapshot.strings;
  let textLength = 0;
  let elementCount = 0;
  for (const document of snapshot.documents) {
    const nodeTypes = document.nodes.nodeType ?? [];
    const nodeNames = document.nodes.nodeName ?? [];
    const { nodeIndex, bounds, styles, text } = document.layout;
    for (let index = 0; index < nodeIndex.length; index += 1) {
      const node = nodeIndex[index]!;
      const box = bounds[index] ?? [];
      if (!((box[2] ?? 0) > 0 && (box[3] ?? 0) > 0)) continue;
      const visibility = strings[styles[index]?.[0] ?? -1];
      if (visibility === 'hidden' || visibility === 'collapse') continue;
      if (nodeTypes[node] === 3) {
        const value = strings[text[index] ?? -1] ?? '';
        textLength += value.trim().length;
      } else if (nodeTypes[node] === 1) {
        const name = (strings[nodeNames[node] ?? -1] ?? '').toUpperCase();
        if (!['HTML', 'HEAD', 'BODY'].includes(name)) elementCount += 1;
      }
    }
  }
  return { textLength, elementCount };
}

// The Worker's rules for bundle-influenced labels, applied before upload so
// one odd host or path cannot make the Worker refuse the whole verdict.
const UNREADABLE_LABEL = '[unreadable]';
const MAX_HOST_LENGTH = 260;
const HOST = /^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:.]+\])(?::\d{1,5})?$/i;
const SECRET_VALUE =
  /(?:Bearer\s+[A-Za-z0-9._~+/=-]{8,}|-----BEGIN [^-]*PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{12,})/i;

function isSafeLabel(value: string, maxLength: number): boolean {
  return (
    value.length > 0 &&
    value.length <= maxLength &&
    /^[\x20-\x7e]+$/.test(value) &&
    !value.includes('://') &&
    !/[?#]/.test(value) &&
    !value.split('/').includes('..') &&
    !SECRET_VALUE.test(value)
  );
}

/** Replaces labels the Worker would reject with `[unreadable]`; lists stay unique and within caps. */
export function clampBootTestLabels(
  result: BootTestResult,
  limits: BootTestJobContract['limits']
): BootTestResult {
  const list = (items: string[], cap: number, keep: (item: string) => boolean) => [
    ...new Set(items.slice(0, cap).map((item) => (keep(item) ? item : UNREADABLE_LABEL)))
  ];
  const label = (value: string) => (isSafeLabel(value, limits.messageLength) ? value : UNREADABLE_LABEL);
  const seen = new Set<string>();
  const cspViolations = result.cspViolations
    .slice(0, limits.cspViolations)
    .map((item) => ({ ...item, blocked: label(item.blocked), source: label(item.source) }))
    .filter((item) => {
      const key = `${item.directive}\n${item.blocked}\n${item.source}`;
      return seen.has(key) ? false : Boolean(seen.add(key));
    });
  return {
    ...result,
    cspViolations,
    missingFiles: list(result.missingFiles, limits.missingFiles, (item) =>
      isSafeLabel(item, limits.messageLength)
    ),
    uncaughtErrors: result.uncaughtErrors
      .slice(0, limits.uncaughtErrors)
      .map((item) => (SECRET_VALUE.test(item) ? UNREADABLE_LABEL : item.slice(0, limits.messageLength))),
    externalHostsRequested: list(
      result.externalHostsRequested,
      limits.externalHosts,
      (item) => item.length <= MAX_HOST_LENGTH && HOST.test(item)
    )
  };
}

function emptyResult(status: BootTestResult['status']): BootTestResult {
  return {
    status,
    failures: [],
    cspViolations: [],
    missingFiles: [],
    uncaughtErrors: [],
    externalHostsRequested: [],
    renderedTextLength: 0,
    renderedElementCount: 0
  };
}

function finalize(result: Omit<BootTestResult, 'status'>): BootTestResult {
  const failures = FAILURE_ORDER.filter((failure) => result.failures.includes(failure));
  return { ...result, failures, status: failures.length > 0 ? 'failed' : 'passed' };
}

/** Boots the extension in Chromium and classifies what it sees. */
export async function bootExtension(
  bundle: Uint8Array,
  contract: BootTestJobContract
): Promise<BootTestResult> {
  const limits = contract.limits;
  const site = extensionSiteRoot(readBundleZip(bundle, BUNDLE_ZIP_LIMITS));
  if (!site) {
    return finalize({
      ...emptyResult('failed'),
      failures: ['blank_panel', 'bundled_file_missing'],
      missingFiles: ['index.html']
    });
  }

  const files = site.files;
  const cspViolations = new Map<string, BootTestCspViolation>();
  const blockedBundleScripts = new Set<string>();
  const cspMissing = new Set<string>();
  const externalHosts = new Set<string>();
  const uncaughtErrors: string[] = [];
  const recordExternal = (value: string) => {
    try {
      const host = new URL(value).host.toLowerCase();
      if (host) externalHosts.add(host);
    } catch {
      // Unparseable URLs carry no host to report.
    }
  };

  const served = await serveBundle(files, contract.contentSecurityPolicy);
  const proxy = await blackholeProxy();
  let browser: Browser | null = null;
  try {
    const origin = served.origin;
    const sameOriginPath = (value: string | undefined): string | null => {
      if (!value) return null;
      try {
        const url = new URL(value);
        return url.origin === origin ? bundlePathFor(url.pathname) : null;
      } catch {
        return null;
      }
    };

    browser = await chromium.launch({
      headless: true,
      // Loopback bypasses the dead-end proxy; the route handler below admits
      // only the static server's exact origin.
      proxy: { server: proxy.url, bypass: '127.0.0.1' },
      args: ['--disable-blink-features=AutomationControlled']
    });
    const context = await browser.newContext({
      viewport: contract.controls.viewport,
      serviceWorkers: 'block',
      acceptDownloads: false
    });
    await context.addInitScript(installDesignerApiStub);
    await context.routeWebSocket(/.*/, (socket) => {
      recordExternal(socket.url());
      void socket.close();
    });
    await context.route('**/*', async (route) => {
      const value = route.request().url();
      let requestOrigin: string | null = null;
      try {
        requestOrigin = new URL(value).origin;
      } catch {
        requestOrigin = null;
      }
      if (requestOrigin === origin) {
        await route.continue();
        return;
      }
      recordExternal(value);
      await route.abort('blockedbyclient');
    });

    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    cdp.on('Audits.issueAdded', (event) => {
      if (event.issue.code !== 'ContentSecurityPolicyIssue') return;
      const details = event.issue.details.contentSecurityPolicyIssueDetails as
        | CspIssueDetails
        | undefined;
      if (!details || details.isReportOnly) return;
      const directive = (details.violatedDirective ?? 'unknown')
        .toLowerCase()
        .replace(/[^a-z-]/g, '')
        .slice(0, 40) || 'unknown';
      const type = details.contentSecurityPolicyViolationType ?? '';
      let blocked: string;
      if (type === 'kInlineViolation') {
        blocked = 'inline';
      } else if (type === 'kEvalViolation' || type === 'kWasmEvalViolation') {
        blocked = 'eval';
      } else if (type.startsWith('kTrustedTypes')) {
        blocked = 'trusted-types';
      } else {
        const path = sameOriginPath(details.blockedURL);
        if (path !== null) {
          blocked = safePathLabel(path, limits.messageLength);
          if (!files.has(path)) {
            if (!IGNORED_MISSING_PATHS.has(path)) cspMissing.add(path);
          } else if (/^(?:script-src|worker-src)/.test(directive)) {
            blockedBundleScripts.add(path);
          }
        } else {
          let host = 'unknown';
          try {
            host = new URL(details.blockedURL ?? '').host.toLowerCase() || 'unknown';
          } catch {
            host = 'unknown';
          }
          if (host !== 'unknown') externalHosts.add(host);
          blocked = host;
        }
      }
      const sourceUrl = details.sourceCodeLocation?.url;
      const sourcePath = sameOriginPath(sourceUrl);
      const source =
        sourcePath === null || sourceUrl === `${origin}/` || sourcePath === 'index.html'
          ? 'document'
          : safePathLabel(sourcePath, limits.messageLength);
      const key = `${directive}\n${blocked}\n${source}`;
      if (!cspViolations.has(key)) cspViolations.set(key, { directive, blocked, source });
    });
    await cdp.send('Audits.enable');
    page.on('pageerror', (error) => {
      if (uncaughtErrors.length < limits.uncaughtErrors) {
        uncaughtErrors.push(redactText(error.message).slice(0, limits.messageLength));
      }
    });

    await page.goto(`${origin}/`, {
      waitUntil: 'load',
      timeout: contract.controls.navigationTimeoutMs
    });
    await page.waitForTimeout(contract.controls.settleMs);
    const rendered = await measureRenderedContent(cdp);

    const missingFiles = [...new Set([...served.missing, ...cspMissing])]
      .filter((path) => !files.has(path))
      .map((path) => safePathLabel(path, limits.messageLength));
    const failures: BootTestFailure[] = [];
    if (rendered.textLength === 0 && rendered.elementCount === 0) failures.push('blank_panel');
    if (blockedBundleScripts.size > 0) failures.push('bundled_script_blocked_by_csp');
    if (missingFiles.length > 0) failures.push('bundled_file_missing');

    const result = finalize({
      failures,
      cspViolations: [...cspViolations.values()].slice(0, limits.cspViolations),
      missingFiles: [...new Set(missingFiles)].sort().slice(0, limits.missingFiles),
      uncaughtErrors,
      externalHostsRequested: [...externalHosts].sort().slice(0, limits.externalHosts),
      renderedTextLength: rendered.textLength,
      renderedElementCount: rendered.elementCount
    });
    return clampBootTestLabels(result, limits);
  } finally {
    await browser?.close().catch(() => undefined);
    await proxy.close();
    await new Promise<void>((resolve) => {
      served.server.closeAllConnections();
      served.server.close(() => resolve());
    });
  }
}

function jobUrl(apiBaseUrl: string, jobId: string, suffix = ''): URL {
  return new URL(`/v1/boot-test-jobs/${encodeURIComponent(jobId)}${suffix}`, apiBaseUrl);
}

async function fetchBootTestJob(input: BootTestRunnerInput): Promise<BootTestJobContract> {
  const response = await fetch(jobUrl(input.apiBaseUrl, input.bootTestJobId), {
    headers: { authorization: `Bearer ${input.capability}` },
    redirect: 'manual',
    signal: AbortSignal.timeout(JOB_FETCH_TIMEOUT_MS)
  });
  if (!response.ok) throw new Error(`Boot test job fetch failed with HTTP ${response.status}.`);
  const body = (await response.json()) as { bootTestJob?: { contract?: BootTestJobContract } };
  const contract = body.bootTestJob?.contract;
  if (!contract) throw new Error('Boot test job contract is missing.');
  validateBootTestContract(input.bootTestJobId, contract);
  return contract;
}

async function downloadBundle(
  input: BootTestRunnerInput,
  contract: BootTestJobContract
): Promise<Uint8Array> {
  const response = await fetch(jobUrl(input.apiBaseUrl, input.bootTestJobId, '/bundle'), {
    headers: { authorization: `Bearer ${input.capability}` },
    redirect: 'manual',
    signal: AbortSignal.timeout(BUNDLE_FETCH_TIMEOUT_MS)
  });
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error(`Bundle download failed with HTTP ${response.status}.`);
  }
  const bytes = await readCapped(response, contract.bundleBytes);
  if (sha256Hex(bytes) !== contract.bundleSha256) {
    throw new Error('The downloaded bundle does not match the review version.');
  }
  return bytes;
}

async function uploadResult(
  input: BootTestRunnerInput,
  evidence: BootTestEvidence
): Promise<void> {
  const response = await fetch(jobUrl(input.apiBaseUrl, input.bootTestJobId, '/result'), {
    method: 'POST',
    headers: {
      authorization: `Bearer ${input.capability}`,
      'content-type': 'application/json'
    },
    body: JSON.stringify(evidence),
    redirect: 'manual',
    signal: AbortSignal.timeout(RESULT_UPLOAD_TIMEOUT_MS)
  });
  if (!response.ok) {
    const detail = redactText(await response.text()).slice(0, 300);
    throw new Error(`Boot test result upload failed with HTTP ${response.status}: ${detail}`);
  }
}

export async function runBootTest(input: BootTestRunnerInput): Promise<BootTestRunnerOutput> {
  const apiBase = new URL(input.apiBaseUrl);
  if (apiBase.username || apiBase.password || !['http:', 'https:'].includes(apiBase.protocol)) {
    throw new Error('API base URL is invalid.');
  }
  if (!input.capability || input.capability.length < 32) {
    throw new Error('A job-scoped boot test capability is required.');
  }

  const contract = await fetchBootTestJob(input);
  const startedAt = new Date();
  let bootTest: BootTestResult;
  let budgetTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    bootTest = await Promise.race([
      downloadBundle(input, contract).then((bundle) => bootExtension(bundle, contract)),
      new Promise<never>((_, reject) => {
        budgetTimer = setTimeout(
          () => reject(new Error('The boot test exceeded its time budget.')),
          contract.controls.totalTimeoutMs
        );
      })
    ]);
  } catch {
    // The test itself could not run. That says nothing about the bundle.
    bootTest = emptyResult('error');
  } finally {
    if (budgetTimer) clearTimeout(budgetTimer);
  }

  const evidence: BootTestEvidence = {
    schemaVersion: 'designer_extension_boot_test_evidence.v1',
    bootTestJobId: input.bootTestJobId,
    reviewVersionId: contract.reviewVersionId,
    bundleSha256: contract.bundleSha256,
    nonce: contract.nonce,
    trust: 'webflow_observed',
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    bootTest
  };
  await uploadResult(input, evidence);
  return { bootTestJobId: input.bootTestJobId, evidence };
}
