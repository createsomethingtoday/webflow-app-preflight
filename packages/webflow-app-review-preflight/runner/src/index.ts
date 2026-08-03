import { createHash } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { mkdir, writeFile } from 'node:fs/promises';
import type { RuntimeObservationJobContract } from '@create-something/webflow-app-review-preflight';
import {
  chromium,
  type Browser,
  type CDPSession,
  type Page,
  type Response as PlaywrightResponse
} from 'playwright';

const SECRET_TEXT =
  /(?:Bearer\s+[A-Za-z0-9._~+/=-]{8,}|-----BEGIN [^-]*PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{12,})/gi;
const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const JOB_FETCH_TIMEOUT_MS = 10_000;
const EVIDENCE_UPLOAD_TIMEOUT_MS = 30_000;
// Caps for reading attacker-controlled bytes into runner memory.
const MAX_RUNTIME_ARTIFACT_BYTES = 16 * 1024 * 1024;
const MAX_SOURCE_MAP_BYTES = 16 * 1024 * 1024;

export interface RuntimeRunnerInput {
  apiBaseUrl: string;
  observationJobId: string;
  capability: string;
  browser?: Browser;
  outputDir?: string;
}

export interface RuntimeRunnerResult {
  observationJobId: string;
  status: 'complete';
  trust: 'webflow_observed';
  cleanupStatus: 'clean' | 'residue_detected' | 'not_tested';
  negativeProxyOutcome: 'blocked' | 'exposed' | 'error' | 'not_applicable';
  artifactCount: number;
}

interface EvidenceArtifact {
  field: string;
  kind: string;
  fileName: string;
  contentType: 'image/png' | 'application/json';
  bytes: Uint8Array;
  sha256: string;
}

interface RuntimeArtifactObservation {
  url: string;
  expectedSha256: string;
  observedSha256: string;
  integrity: string;
  domIntegrity: string | null;
  domCrossOrigin: string | null;
  loadedByPage: boolean;
  trustedRuntimeInitiator: boolean;
  sourceMap: { available: boolean; url?: string };
}

interface BrowserState {
  scripts: Array<{
    src: string;
    integrity: string | null;
    crossOrigin: string | null;
    runtimeCreated: boolean;
  }>;
  storage: {
    local: Array<{ key: string; bytes: number }>;
    session: Array<{ key: string; bytes: number }>;
  };
  dom: {
    elementCount: number;
    iframeCount: number;
    dialogCount: number;
    fixedElementCount: number;
  };
}

interface ParsedScript {
  scriptId: string;
  url: string;
  stackTrace?: unknown;
  frameInitiatorStack?: unknown;
}

interface TrustedScriptRequest {
  url: string;
  resourceType: string;
  initiator?: unknown;
}

interface TrustedExecutionEvidence {
  executedDigestsByUrl: Map<string, Set<string>>;
  trustedRuntimeInitiatedUrls: Set<string>;
  runtimeCreatedScripts: string[];
  unreviewedRuntimeScripts: string[];
}

function sha256(bytes: Uint8Array | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function isPrivateNetworkAddress(address: string): boolean {
  const normalized = address.toLowerCase().split('%')[0] ?? '';
  if (
    normalized === '::1' ||
    normalized.startsWith('fc') ||
    normalized.startsWith('fd') ||
    normalized.startsWith('fe8') ||
    normalized.startsWith('fe9') ||
    normalized.startsWith('fea') ||
    normalized.startsWith('feb')
  ) {
    return true;
  }
  const ipv4 = normalized.startsWith('::ffff:') ? normalized.slice('::ffff:'.length) : normalized;
  const parts = ipv4.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) return false;
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b! >= 16 && b! <= 31) ||
    (a === 192 && b === 168)
  );
}

function privateHostsAllowed(): boolean {
  return process.env.RUNTIME_ALLOW_PRIVATE_HOSTS === '1';
}

async function assertResolvedHostBoundary(hosts: Set<string>): Promise<void> {
  const allowPrivate = privateHostsAllowed();
  for (const host of hosts) {
    if (host === 'localhost' || isPrivateNetworkAddress(host)) {
      // Loopback / RFC1918 hosts are exactly what this boundary exists to block:
      // reaching them lets the sandboxed browser hit the template's own launch
      // endpoint (http://127.0.0.1:3000/run) or cloud metadata surfaces. They are
      // permitted ONLY as an explicit test/integration opt-in.
      if (allowPrivate) continue;
      throw new Error(
        `Allowed host ${host} is a loopback or private-network address; ` +
          'set RUNTIME_ALLOW_PRIVATE_HOSTS=1 only in trusted local fixtures to permit it.'
      );
    }
    const addresses = await lookup(host, { all: true, verbatim: true });
    if (
      addresses.length === 0 ||
      addresses.some(({ address }) => isPrivateNetworkAddress(address))
    ) {
      throw new Error(`Allowed host ${host} did not resolve to a public network address.`);
    }
    // TOCTOU: we resolve here, but the browser resolves the host again when it
    // actually connects. A DNS-rebinding server can return a public address now
    // and a private one at navigation time. The CDP Network.responseReceived
    // private-IP detection (privateNetworkResponses) is the defense-in-depth
    // backstop for that window.
  }
}

export function redactText(value: string): string {
  return value
    .replace(SECRET_TEXT, '[redacted-secret]')
    .replace(EMAIL, '[redacted-email]')
    .slice(0, 1000);
}

export function sanitizeUrl(value: string): string {
  try {
    const url = new URL(value);
    for (const key of [...url.searchParams.keys()]) {
      url.searchParams.set(key, '[redacted]');
    }
    url.username = '';
    url.password = '';
    url.hash = '';
    return url.toString();
  } catch {
    return '[invalid-url]';
  }
}

function safeIdentifier(value: string): string {
  return /^[a-zA-Z0-9_.:-]{1,80}$/.test(value) ? value : `[redacted:${sha256(value).slice(0, 12)}]`;
}

// Collects RAW initiator URLs. These are used only for equality comparison
// against the raw pinned-runtime URLs; they are never serialized, so they are
// not sanitized here (keeping them raw prevents query-string aliasing).
function stackUrls(value: unknown, result = new Set<string>()): Set<string> {
  if (!value || typeof value !== 'object') return result;
  const record = value as Record<string, unknown>;
  if (typeof record.url === 'string' && record.url) {
    result.add(record.url);
  }
  if (Array.isArray(record.callFrames)) {
    for (const frame of record.callFrames) {
      if (!frame || typeof frame !== 'object') continue;
      const url = (frame as Record<string, unknown>).url;
      if (typeof url === 'string' && url) result.add(url);
    }
  }
  if (record.stack) stackUrls(record.stack, result);
  if (record.parent) stackUrls(record.parent, result);
  return result;
}

async function collectTrustedExecutionEvidence(
  cdp: CDPSession,
  parsedScripts: ParsedScript[],
  scriptRequests: TrustedScriptRequest[],
  workerUrls: string[],
  pins: RuntimeObservationJobContract['runtimeArtifacts']
): Promise<TrustedExecutionEvidence> {
  // Evidence maps are keyed on the RAW url so that distinct query strings
  // (runtime.js?v=1 vs runtime.js?v=2) never collapse to one key. URLs are
  // sanitized only when they become serialized labels below.
  const pinnedUrls = new Set(pins.map((pin) => pin.url));
  const runtimeHosts = new Set(pins.map((pin) => new URL(pin.url).hostname.toLowerCase()));
  const executedDigestsByUrl = new Map<string, Set<string>>();
  const trustedRuntimeInitiatedUrls = new Set<string>();
  const runtimeCreatedScripts = new Set<string>();
  const unreviewedRuntimeScripts = new Set<string>();

  for (const parsed of parsedScripts.slice(0, 1_000)) {
    const rawUrl = parsed.url;
    const isValidUrl = rawUrl !== '' && URL.canParse(rawUrl);
    const initiatorUrls = stackUrls(parsed.stackTrace);
    stackUrls(parsed.frameInitiatorStack, initiatorUrls);
    const initiatedByPinnedRuntime = [...initiatorUrls].some((url) => pinnedUrls.has(url));
    let isRuntimeHostScript = false;
    if (isValidUrl) {
      isRuntimeHostScript = runtimeHosts.has(new URL(rawUrl).hostname.toLowerCase());
    }
    if (!pinnedUrls.has(rawUrl) && !initiatedByPinnedRuntime && !isRuntimeHostScript) continue;

    let source = '';
    try {
      const result = await cdp.send('Debugger.getScriptSource', { scriptId: parsed.scriptId });
      source = typeof result.scriptSource === 'string' ? result.scriptSource : '';
    } catch {
      source = '';
    }
    const digest = sha256(source);
    if (pinnedUrls.has(rawUrl)) {
      const digests = executedDigestsByUrl.get(rawUrl) ?? new Set<string>();
      digests.add(digest);
      executedDigestsByUrl.set(rawUrl, digests);
      if (initiatedByPinnedRuntime) trustedRuntimeInitiatedUrls.add(rawUrl);
      continue;
    }

    const label = isValidUrl ? sanitizeUrl(rawUrl) : `[inline-or-eval:${digest.slice(0, 12)}]`;
    if (initiatedByPinnedRuntime) runtimeCreatedScripts.add(label);
    if (initiatedByPinnedRuntime || isRuntimeHostScript) unreviewedRuntimeScripts.add(label);
  }

  for (const request of scriptRequests.slice(0, 1_000)) {
    const rawUrl = request.url;
    const isValidUrl = URL.canParse(rawUrl);
    const initiatorUrls = stackUrls(request.initiator);
    const initiatedByPinnedRuntime = [...initiatorUrls].some((url) => pinnedUrls.has(url));
    if (pinnedUrls.has(rawUrl)) {
      if (initiatedByPinnedRuntime) trustedRuntimeInitiatedUrls.add(rawUrl);
      continue;
    }
    let isRuntimeHostScript = false;
    if (isValidUrl) {
      isRuntimeHostScript = runtimeHosts.has(new URL(rawUrl).hostname.toLowerCase());
    }
    if (!initiatedByPinnedRuntime && !isRuntimeHostScript) continue;
    const label = isValidUrl
      ? sanitizeUrl(rawUrl)
      : `[${request.resourceType.toLowerCase()}-request]`;
    if (initiatedByPinnedRuntime || isRuntimeHostScript) runtimeCreatedScripts.add(label);
    unreviewedRuntimeScripts.add(label);
  }

  for (const workerUrl of workerUrls.slice(0, 100)) {
    if (pinnedUrls.has(workerUrl)) continue;
    const label = sanitizeUrl(workerUrl);
    runtimeCreatedScripts.add(label);
    unreviewedRuntimeScripts.add(label);
  }

  if (parsedScripts.length > 1_000 || scriptRequests.length > 1_000 || workerUrls.length > 100) {
    runtimeCreatedScripts.add('[execution-observation-truncated]');
    unreviewedRuntimeScripts.add('[execution-observation-truncated]');
  }
  return {
    executedDigestsByUrl,
    trustedRuntimeInitiatedUrls,
    runtimeCreatedScripts: [...runtimeCreatedScripts].slice(0, 100),
    unreviewedRuntimeScripts: [...unreviewedRuntimeScripts].slice(0, 100)
  };
}

export function validateObservationContract(
  jobId: string,
  contract: RuntimeObservationJobContract
): void {
  if (
    contract.schemaVersion !== 'runtime_observation_job.v1' ||
    contract.purpose !== 'webflow_observation' ||
    !contract.nonce ||
    Date.parse(contract.expiresAt) <= Date.now() ||
    contract.boundaries.partnerCanSubmitEvidence !== false ||
    contract.boundaries.officialDecision !== null ||
    contract.boundaries.canWriteGovernance !== false ||
    contract.boundaries.acceptsAccountCredentials !== false ||
    contract.controls.networkMode !== 'exact_host_allowlist' ||
    contract.controls.evidenceTrust !== 'webflow_observed' ||
    contract.controls.executionEvidence !== 'chromium_cdp_v1' ||
    (contract.negativeProxyProbe.mode === 'none_declared'
      ? contract.controls.negativeProxyCanaryUrl !== null
      : typeof contract.controls.negativeProxyCanaryUrl !== 'string') ||
    contract.controls.allowedHosts.length === 0 ||
    contract.controls.allowedHosts.length > 12
  ) {
    throw new Error(`Observation job ${jobId} has an unsafe contract.`);
  }

  const allowed = new Set(contract.controls.allowedHosts);
  const urls = [
    contract.target.url,
    ...(contract.negativeProxyProbe.mode === 'none_declared'
      ? []
      : [contract.negativeProxyProbe.url]),
    ...contract.runtimeArtifacts.map((artifact) => artifact.url)
  ];
  for (const value of urls) {
    const url = new URL(value);
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.username ||
      url.password ||
      !allowed.has(url.hostname.toLowerCase())
    ) {
      throw new Error(`Observation job ${jobId} attempts to broaden its host boundary.`);
    }
  }
  if (
    contract.runtimeArtifacts.some(
      (artifact) =>
        !/^[a-f0-9]{64}$/.test(artifact.sha256) ||
        !artifact.integrity.startsWith('sha256-') ||
        !['document', 'runtime_child'].includes(artifact.loadMode ?? 'document')
    )
  ) {
    throw new Error(`Observation job ${jobId} contains an unpinned runtime artifact.`);
  }
}

function jsonArtifact(field: string, value: unknown): EvidenceArtifact {
  const bytes = new TextEncoder().encode(`${JSON.stringify(value, null, 2)}\n`);
  return {
    field,
    kind: field,
    fileName: `${field.replace(/_/g, '-')}.json`,
    contentType: 'application/json',
    bytes,
    sha256: sha256(bytes)
  };
}

function pngArtifact(field: string, bytes: Uint8Array): EvidenceArtifact {
  return {
    field,
    kind: field,
    fileName: `${field.replace(/_/g, '-')}.png`,
    contentType: 'image/png',
    bytes,
    sha256: sha256(bytes)
  };
}

async function captureState(page: Page): Promise<BrowserState> {
  const value = await page.evaluate(() => {
    const storage = (target: Storage) =>
      Array.from({ length: target.length }, (_, index) => {
        const key = target.key(index) ?? '';
        return { key, bytes: new TextEncoder().encode(target.getItem(key) ?? '').byteLength };
      });
    const elements = [...document.querySelectorAll<HTMLElement>('*')];
    return {
      scripts: [...document.scripts].map((script) => ({
        src: script.src,
        integrity: script.getAttribute('integrity'),
        crossOrigin: script.getAttribute('crossorigin'),
        runtimeCreated: Boolean(Reflect.get(script, Symbol.for('webflow.runtime-created-script')))
      })),
      storage: {
        local: storage(localStorage),
        session: storage(sessionStorage)
      },
      dom: {
        elementCount: elements.length,
        iframeCount: document.querySelectorAll('iframe').length,
        dialogCount: document.querySelectorAll('[role="dialog"], dialog').length,
        fixedElementCount: elements.filter(
          (element) => getComputedStyle(element).position === 'fixed'
        ).length
      }
    };
  });
  return {
    ...value,
    // src is kept RAW; sanitize only at serialization (see serializeScripts).
    storage: {
      local: value.storage.local.map((item) => ({ ...item, key: safeIdentifier(item.key) })),
      session: value.storage.session.map((item) => ({ ...item, key: safeIdentifier(item.key) }))
    }
  };
}

// Sanitizes script src values for evidence artifacts. Internal comparisons use
// the raw src; only serialized output passes through here.
function serializeScripts(scripts: BrowserState['scripts']): BrowserState['scripts'] {
  return scripts.map((script) => ({
    ...script,
    src: script.src === '[invalid-url]' ? script.src : sanitizeUrl(script.src)
  }));
}

function attributesRecord(attributes: string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (let index = 0; index < attributes.length; index += 2) {
    const name = attributes[index];
    const value = attributes[index + 1];
    if (name && value !== undefined) result[name.toLowerCase()] = value;
  }
  return result;
}

async function captureTrustedScripts(
  cdp: CDPSession,
  documentUrl: string
): Promise<BrowserState['scripts']> {
  await cdp.send('DOM.enable');
  const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
  const { nodeIds } = await cdp.send('DOM.querySelectorAll', {
    nodeId: root.nodeId,
    selector: 'script[src]'
  });
  const scripts: BrowserState['scripts'] = [];
  for (const nodeId of nodeIds.slice(0, 200)) {
    const { attributes } = await cdp.send('DOM.getAttributes', { nodeId });
    const values = attributesRecord(attributes);
    if (!values.src) continue;
    // Keep src RAW; sanitize only at serialization (see serializeScripts).
    let src = '[invalid-url]';
    try {
      src = new URL(values.src, documentUrl).toString();
    } catch {
      src = '[invalid-url]';
    }
    scripts.push({
      src,
      integrity: values.integrity ?? null,
      crossOrigin: values.crossorigin ?? null,
      runtimeCreated: false
    });
  }
  return scripts;
}

async function screenshot(page: Page): Promise<Uint8Array> {
  return new Uint8Array(
    await page.screenshot({
      fullPage: false,
      animations: 'disabled',
      mask: [page.locator('input, textarea, [contenteditable="true"]')],
      maskColor: '#000000'
    })
  );
}

// Reads a response body while enforcing a byte cap, so a hostile server cannot
// exhaust runner memory with an unbounded (or Content-Length-lying) body.
async function readCapped(response: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = Number(response.headers.get('content-length') ?? '');
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new Error('Response exceeds the byte cap.');
  }
  if (!response.body) {
    const buffer = new Uint8Array(await response.arrayBuffer());
    if (buffer.byteLength > maxBytes) throw new Error('Response exceeds the byte cap.');
    return buffer;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) throw new Error('Response exceeds the byte cap.');
        chunks.push(value);
      }
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

async function readCappedBody(url: string, maxBytes: number): Promise<Uint8Array> {
  const response = await fetch(url, {
    redirect: 'manual',
    signal: AbortSignal.timeout(5_000)
  });
  return readCapped(response, maxBytes);
}

async function sourceMapReachable(url: URL, maxBytes: number): Promise<boolean> {
  const response = await fetch(url, {
    method: 'GET',
    redirect: 'manual',
    signal: AbortSignal.timeout(5_000)
  });
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    return false;
  }
  // Drain within the cap so a hostile map cannot blow up runner memory.
  await readCapped(response, maxBytes);
  return true;
}

async function observeRuntimeArtifact(
  pin: RuntimeObservationJobContract['runtimeArtifacts'][number],
  response: PlaywrightResponse | null,
  allowedHosts: Set<string>,
  scripts: BrowserState['scripts'],
  executedDigestsByUrl: Map<string, Set<string>>,
  trustedRuntimeInitiatedUrls: Set<string>
): Promise<RuntimeArtifactObservation> {
  const bytes = response
    ? new Uint8Array(await response.body())
    : await readCappedBody(pin.url, MAX_RUNTIME_ARTIFACT_BYTES);
  const source = new TextDecoder().decode(bytes);
  const match = source.match(/[#@]\s*sourceMappingURL=([^\s*]+)/);
  let sourceMap: RuntimeArtifactObservation['sourceMap'] = { available: false };
  if (match?.[1]) {
    const sourceMapUrl = new URL(match[1], pin.url);
    // The sourceMappingURL is attacker-controlled runtime bytes. Restrict to an
    // explicit http(s) protocol allowlist (not just an incidental empty-hostname
    // filter) and to the host allowlist, and cap the response body.
    if (
      ['http:', 'https:'].includes(sourceMapUrl.protocol) &&
      allowedHosts.has(sourceMapUrl.hostname.toLowerCase())
    ) {
      try {
        const available = await sourceMapReachable(sourceMapUrl, MAX_SOURCE_MAP_BYTES);
        sourceMap = { available, url: sanitizeUrl(sourceMapUrl.toString()) };
      } catch {
        sourceMap = { available: false, url: sanitizeUrl(sourceMapUrl.toString()) };
      }
    }
  }
  const observedSha256 = sha256(bytes);
  // scripts (request-boundary DOM captures) and the evidence maps are all keyed
  // on the RAW pin url, so each pin resolves to exactly its own file even when
  // two pins share a sanitized query string.
  return {
    url: pin.url,
    expectedSha256: pin.sha256,
    observedSha256,
    integrity: pin.integrity,
    domIntegrity: scripts.find((script) => script.src === pin.url)?.integrity ?? null,
    domCrossOrigin: scripts.find((script) => script.src === pin.url)?.crossOrigin ?? null,
    loadedByPage:
      response !== null &&
      (executedDigestsByUrl.get(pin.url)?.has(observedSha256) ?? false),
    trustedRuntimeInitiator: trustedRuntimeInitiatedUrls.has(pin.url),
    sourceMap
  };
}

interface CaptureResult {
  status: 'complete' | 'failed';
  manifest: Record<string, unknown>;
  artifacts: EvidenceArtifact[];
  cleanupStatus: 'clean' | 'residue_detected' | 'not_tested';
  negativeProxyOutcome: 'blocked' | 'exposed' | 'error' | 'not_applicable';
  failureReason?: string;
}

async function capture(
  contract: RuntimeObservationJobContract,
  browser: Browser
): Promise<CaptureResult> {
  const startedAt = new Date();
  const allowedHosts = new Set(contract.controls.allowedHosts);
  await assertResolvedHostBoundary(allowedHosts);
  const network: Array<Record<string, unknown>> = [];
  const consoleMessages: Array<{ type: string; text: string }> = [];
  const pageErrors: string[] = [];
  let droppedNetworkEntries = 0;
  let droppedConsoleMessages = 0;
  let droppedPageErrors = 0;
  const recordNetwork = (entry: Record<string, unknown>) => {
    if (network.length < 250) network.push(entry);
    else droppedNetworkEntries += 1;
  };
  const recordPageError = (message: string) => {
    if (pageErrors.length < 100) pageErrors.push(message);
    else droppedPageErrors += 1;
  };
  const artifactResponses = new Map<string, PlaywrightResponse>();
  const context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    serviceWorkers: 'block',
    acceptDownloads: false,
    userAgent: `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browser.version()} Safari/537.36`
  });
  await context.addInitScript(() => {
    const marker = Symbol.for('webflow.runtime-created-script');
    const originalCreateElement = Document.prototype.createElement;
    Document.prototype.createElement = function (
      this: Document,
      localName: string,
      options?: ElementCreationOptions
    ): HTMLElement {
      const element = Reflect.apply(originalCreateElement, this, [
        localName,
        options
      ]) as HTMLElement;
      if (localName.toLowerCase() === 'script') {
        Object.defineProperty(element, marker, { value: true });
      }
      return element;
    } as typeof Document.prototype.createElement;
  });
  let cdp: CDPSession | null = null;
  const requestBoundaryScripts = new Map<string, BrowserState['scripts'][number]>();
  const observedRuntimeArtifactRequests = new Set<string>();
  let requestCount = 0;
  await context.route('**/*', async (route) => {
    const request = route.request();
    let url: URL;
    try {
      url = new URL(request.url());
    } catch {
      await route.abort('blockedbyclient');
      return;
    }
    if (!['http:', 'https:'].includes(url.protocol)) {
      await route.continue();
      return;
    }
    const rawUrl = url.toString();
    if (
      cdp &&
      request.resourceType() === 'script' &&
      contract.runtimeArtifacts.some((artifact) => artifact.url === rawUrl) &&
      !observedRuntimeArtifactRequests.has(rawUrl)
    ) {
      observedRuntimeArtifactRequests.add(rawUrl);
      try {
        const scripts = await captureTrustedScripts(cdp, contract.target.url);
        // captureTrustedScripts now returns RAW src; match on the raw url.
        const script = scripts.find((candidate) => candidate.src === rawUrl);
        if (script) requestBoundaryScripts.set(rawUrl, script);
      } catch {
        // Missing request-boundary attributes fail closed in the final predicate.
      }
    }
    // Off-allowlist requests must not consume the request budget, otherwise
    // adversarial noise can exhaust maxRequests and starve the pinned runtime
    // request (surfaced as a false "Declared runtime did not load" blocker).
    if (!allowedHosts.has(url.hostname.toLowerCase())) {
      recordNetwork({
        phase: 'request',
        url: sanitizeUrl(url.toString()),
        method: request.method(),
        resourceType: request.resourceType(),
        blocked: true
      });
      await route.abort('blockedbyclient');
      return;
    }
    requestCount += 1;
    if (requestCount > contract.controls.maxRequests) {
      recordNetwork({
        phase: 'request',
        url: sanitizeUrl(url.toString()),
        method: request.method(),
        resourceType: request.resourceType(),
        blocked: true
      });
      await route.abort('blockedbyclient');
      return;
    }
    recordNetwork({
      phase: 'request',
      url: sanitizeUrl(url.toString()),
      method: request.method(),
      resourceType: request.resourceType(),
      blocked: false
    });
    await route.continue();
  });

  const page = await context.newPage();
  cdp = await context.newCDPSession(page);
  const parsedScripts: ParsedScript[] = [];
  const scriptRequests: TrustedScriptRequest[] = [];
  const workerUrls: string[] = [];
  const privateNetworkResponses = new Set<string>();
  const frameInitiatorStacks = new Map<string, unknown>();
  const executionContextFrames = new Map<number, string>();
  cdp.on('Page.frameAttached', (event) => {
    if (event.stack) frameInitiatorStacks.set(event.frameId, event.stack);
  });
  cdp.on('Runtime.executionContextCreated', (event) => {
    const frameId = event.context.auxData?.frameId;
    if (typeof frameId === 'string') {
      executionContextFrames.set(event.context.id, frameId);
    }
  });
  cdp.on('Debugger.scriptParsed', (event) => {
    if (parsedScripts.length <= 1_000) {
      const frameId = executionContextFrames.get(event.executionContextId);
      parsedScripts.push({
        scriptId: String(event.scriptId),
        url: typeof event.url === 'string' ? event.url : '',
        stackTrace: event.stackTrace,
        frameInitiatorStack: frameId ? frameInitiatorStacks.get(frameId) : undefined
      });
    }
  });
  cdp.on('Network.requestWillBeSent', (event) => {
    if (
      scriptRequests.length <= 1_000 &&
      ['Script', 'Worker', 'SharedWorker', 'ServiceWorker', 'Wasm'].includes(event.type ?? '')
    ) {
      scriptRequests.push({
        url: event.request.url,
        resourceType: event.type ?? 'Script',
        initiator: event.initiator
      });
    }
  });
  cdp.on('Network.responseReceived', (event) => {
    const remoteAddress = event.response.remoteIPAddress;
    if (!remoteAddress || !isPrivateNetworkAddress(remoteAddress)) return;
    try {
      const responseHost = new URL(event.response.url).hostname.toLowerCase();
      if (responseHost !== 'localhost' && !isPrivateNetworkAddress(responseHost)) {
        privateNetworkResponses.add(sanitizeUrl(event.response.url));
      }
    } catch {
      privateNetworkResponses.add('[invalid-private-network-response]');
    }
  });
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Debugger.enable');
  await cdp.send('Network.enable');
  await cdp.send('Runtime.setAsyncCallStackDepth', { maxDepth: 32 });
  page.on('console', (message) => {
    if (consoleMessages.length < 100) {
    consoleMessages.push({ type: message.type(), text: redactText(message.text()) });
    } else {
      droppedConsoleMessages += 1;
    }
  });
  page.on('worker', (worker) => {
    if (workerUrls.length <= 100) workerUrls.push(worker.url());
  });
  page.on('pageerror', (error) => recordPageError(redactText(error.message)));
  page.on('response', (response) => {
    const value = response.url();
    recordNetwork({
      phase: 'response',
      url: sanitizeUrl(value),
      status: response.status(),
      resourceType: response.request().resourceType()
    });
    if (contract.runtimeArtifacts.some((artifact) => artifact.url === value)) {
      artifactResponses.set(value, response);
    }
  });

  // Artifacts are accumulated as they are produced so that a mid-run failure or
  // budget timeout can still upload partial evidence (FIX 2).
  const partialArtifacts: EvidenceArtifact[] = [];
  const collectLogArtifacts = (): EvidenceArtifact[] => [
    jsonArtifact('network_log', { entries: network, droppedEntries: droppedNetworkEntries }),
    jsonArtifact('console_log', {
      messages: consoleMessages,
      pageErrors,
      droppedMessages: droppedConsoleMessages,
      droppedPageErrors
    })
  ];

  const runObservation = async (): Promise<CaptureResult> => {
    await page.goto(contract.target.url, {
      waitUntil: 'domcontentloaded',
      timeout: contract.controls.requestTimeoutMs
    });
    const before = await screenshot(page);
    partialArtifacts.push(pngArtifact('screenshot_before', before));
    let runtimeReadyObserved = false;
    try {
      await page.waitForSelector(contract.lifecycle.readySelector, {
        state: 'attached',
        timeout: contract.controls.requestTimeoutMs
      });
      runtimeReadyObserved = true;
      await page.waitForTimeout(Math.min(500, contract.controls.requestTimeoutMs));
    } catch {
      recordPageError('Runtime-ready selector was not observed.');
    }
    const installedState = await captureState(page);
    installedState.scripts = await captureTrustedScripts(cdp, page.url());
    const afterInstall = await screenshot(page);
    partialArtifacts.push(pngArtifact('screenshot_after_install', afterInstall));

    let negativeProxyOutcome: 'blocked' | 'exposed' | 'error' | 'not_applicable' =
      contract.negativeProxyProbe.mode === 'none_declared' ? 'not_applicable' : 'error';
    let negativeProxyStatusCode: number | null = null;
    if (contract.negativeProxyProbe.mode !== 'none_declared') {
      try {
        const probe = await context.request.get(contract.negativeProxyProbe.url, {
          failOnStatusCode: false,
          maxRedirects: 0,
          timeout: contract.controls.requestTimeoutMs
        });
        negativeProxyStatusCode = probe.status();
        negativeProxyOutcome =
          negativeProxyStatusCode >= 200 && negativeProxyStatusCode < 300
            ? 'exposed'
            : negativeProxyStatusCode === 401 || negativeProxyStatusCode === 403
              ? 'blocked'
              : 'error';
      } catch {
        negativeProxyOutcome = 'error';
      }
    }

    // A stale or unclickable cleanup selector must not abort the whole run; it
    // downgrades cleanup to 'not_tested' instead (FIX 2).
    let cleanupTested = Boolean(contract.lifecycle.cleanupTrigger);
    if (contract.lifecycle.cleanupTrigger) {
      try {
        await page.locator(contract.lifecycle.cleanupTrigger.selector).click({
          timeout: contract.controls.requestTimeoutMs
        });
        await page.waitForTimeout(250);
      } catch {
        cleanupTested = false;
        recordPageError('Cleanup trigger could not be exercised; cleanup not tested.');
      }
    }
    const observedState = await captureState(page);
    observedState.scripts = await captureTrustedScripts(cdp, page.url());
    const afterObservation = await screenshot(page);
    partialArtifacts.push(pngArtifact('screenshot_after_observation', afterObservation));

    // Keyed on the RAW artifact url; sanitize only when emitting labels.
    const pinnedUrls = new Set(contract.runtimeArtifacts.map((artifact) => artifact.url));
    const observedResidue = [
      ...observedState.scripts
        .filter((script) => pinnedUrls.has(script.src))
        .map((script) => `script:${sanitizeUrl(script.src)}`),
      ...observedState.storage.local.map((item) => `localStorage:${item.key}`),
      ...observedState.storage.session.map((item) => `sessionStorage:${item.key}`)
    ].slice(0, 100);
    const cleanupExercised = Boolean(contract.lifecycle.cleanupTrigger) && cleanupTested;
    const residue = cleanupExercised ? observedResidue : [];
    const cleanupStatus: 'clean' | 'residue_detected' | 'not_tested' = cleanupExercised
      ? residue.length === 0
        ? 'clean'
        : 'residue_detected'
      : 'not_tested';
    const trustedExecution = await collectTrustedExecutionEvidence(
      cdp,
      parsedScripts,
      scriptRequests,
      workerUrls,
      contract.runtimeArtifacts
    );
    const runtimeArtifacts = await Promise.all(
      contract.runtimeArtifacts.map((pin) =>
        observeRuntimeArtifact(
          pin,
          artifactResponses.get(pin.url) ?? null,
          allowedHosts,
          [...requestBoundaryScripts.values()],
          trustedExecution.executedDigestsByUrl,
          trustedExecution.trustedRuntimeInitiatedUrls
        )
      )
    );
    const runtimeHosts = new Set(
      contract.runtimeArtifacts.map((artifact) => new URL(artifact.url).hostname.toLowerCase())
    );
    const pageWorldUnreviewedRuntimeScripts = installedState.scripts
      .filter((script) => {
        if (!script.src || script.src === '[invalid-url]' || pinnedUrls.has(script.src))
          return false;
        try {
          return runtimeHosts.has(new URL(script.src).hostname.toLowerCase());
        } catch {
          return false;
        }
      })
      .map((script) => sanitizeUrl(script.src))
      .slice(0, 100);
    const pageWorldRuntimeCreatedScripts = installedState.scripts
      .filter(
        (script) =>
          script.runtimeCreated &&
          script.src &&
          script.src !== '[invalid-url]' &&
          !pinnedUrls.has(script.src)
      )
      .map((script) => sanitizeUrl(script.src))
      .slice(0, 100);
    const unreviewedRuntimeScripts = [
      ...new Set([
        ...pageWorldUnreviewedRuntimeScripts,
        ...trustedExecution.unreviewedRuntimeScripts
      ])
    ].slice(0, 100);
    const runtimeCreatedScripts = [
      ...new Set([
        ...pageWorldRuntimeCreatedScripts,
        ...trustedExecution.runtimeCreatedScripts,
        ...[...privateNetworkResponses].map((url) => `[private-network-response:${url}]`)
      ])
    ].slice(0, 100);

    const artifacts = [
      pngArtifact('screenshot_before', before),
      pngArtifact('screenshot_after_install', afterInstall),
      pngArtifact('screenshot_after_observation', afterObservation),
      jsonArtifact('network_log', { entries: network, droppedEntries: droppedNetworkEntries }),
      jsonArtifact('console_log', {
        messages: consoleMessages,
        pageErrors,
        droppedMessages: droppedConsoleMessages,
        droppedPageErrors
      }),
      jsonArtifact('dom_snapshot', {
        installed: installedState.dom,
        afterObservation: observedState.dom,
        scriptsAfterObservation: serializeScripts(observedState.scripts)
      }),
      jsonArtifact('storage_snapshot', {
        beforeNavigation: { local: [], session: [] },
        installed: installedState.storage,
        afterObservation: observedState.storage
      }),
      jsonArtifact('script_inventory', runtimeArtifacts)
    ];
    const finishedAt = new Date();
    const manifest = {
      schemaVersion: 'runtime_observation_evidence.v1',
      status: 'complete',
      observationJobId: '',
      testPackageId: contract.testPackageId,
      reviewVersionId: contract.reviewVersionId,
      bundleSha256: contract.bundleSha256,
      nonce: contract.nonce,
      targetUrl: contract.target.url,
      trust: 'webflow_observed',
      executionEvidence: contract.controls.executionEvidence,
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      redaction: {
        applied: true,
        headersRemoved: true,
        cookiesRemoved: true,
        formValuesMasked: true
      },
      runtimeReadyObserved,
      runtimeArtifacts,
      runtimeCreatedScripts,
      unreviewedRuntimeScripts,
      cleanup: { status: cleanupStatus, residue },
      negativeProxyCanary: {
        url: contract.controls.negativeProxyCanaryUrl,
        outcome: negativeProxyOutcome,
        statusCode: negativeProxyStatusCode
      },
      artifacts: artifacts.map((artifact) => ({
        field: artifact.field,
        kind: artifact.kind,
        fileName: artifact.fileName,
        contentType: artifact.contentType,
        bytes: artifact.bytes.byteLength,
        sha256: artifact.sha256
      }))
    };
    return { status: 'complete', manifest, artifacts, cleanupStatus, negativeProxyOutcome };
  };

  let budgetTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race<CaptureResult>([
      runObservation(),
      new Promise<never>((_, reject) => {
        budgetTimer = setTimeout(
          () => reject(new Error('Observation exceeded the total runtime budget.')),
          contract.controls.totalTimeoutMs
        );
      })
    ]);
  } catch (error) {
    // Any mid-run exception or budget timeout still produces a redacted,
    // partial-evidence 'failed' manifest so the developer's panel reports a
    // failure instead of hanging in 'running' until expiry (FIX 2).
    const failureReason = redactText(
      error instanceof Error ? error.message : 'Runtime observation failed.'
    );
    const failedArtifacts = [...partialArtifacts, ...collectLogArtifacts()];
    const manifest: Record<string, unknown> = {
      schemaVersion: 'runtime_observation_evidence.v1',
      status: 'failed',
      observationJobId: '',
      testPackageId: contract.testPackageId,
      reviewVersionId: contract.reviewVersionId,
      bundleSha256: contract.bundleSha256,
      nonce: contract.nonce,
      targetUrl: contract.target.url,
      trust: null,
      executionEvidence: contract.controls.executionEvidence,
      startedAt: startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
      failureReason,
      redaction: {
        applied: true,
        headersRemoved: true,
        cookiesRemoved: true,
        formValuesMasked: true
      },
      artifacts: failedArtifacts.map((artifact) => ({
        field: artifact.field,
        kind: artifact.kind,
        fileName: artifact.fileName,
        contentType: artifact.contentType,
        bytes: artifact.bytes.byteLength,
        sha256: artifact.sha256
      }))
    };
    return {
      status: 'failed',
      manifest,
      artifacts: failedArtifacts,
      cleanupStatus: 'not_tested',
      negativeProxyOutcome:
        contract.negativeProxyProbe.mode === 'none_declared' ? 'not_applicable' : 'error',
      failureReason
    };
  } finally {
    if (budgetTimer) clearTimeout(budgetTimer);
    await context.close();
  }
}

async function fetchJob(
  apiBaseUrl: string,
  observationJobId: string,
  capability: string
): Promise<RuntimeObservationJobContract> {
  const response = await fetch(
    new URL(`/v1/runtime-observation-jobs/${encodeURIComponent(observationJobId)}`, apiBaseUrl),
    {
      headers: { authorization: `Bearer ${capability}` },
      signal: AbortSignal.timeout(JOB_FETCH_TIMEOUT_MS)
    }
  );
  if (!response.ok) throw new Error(`Observation job fetch failed with HTTP ${response.status}.`);
  const body = (await response.json()) as {
    observationJob?: { contract?: RuntimeObservationJobContract };
  };
  if (!body.observationJob?.contract) throw new Error('Observation job contract is missing.');
  validateObservationContract(observationJobId, body.observationJob.contract);
  return body.observationJob.contract;
}

async function uploadEvidence(
  apiBaseUrl: string,
  observationJobId: string,
  capability: string,
  manifest: Record<string, unknown>,
  artifacts: EvidenceArtifact[]
): Promise<void> {
  manifest.observationJobId = observationJobId;
  const form = new FormData();
  form.set('manifest', JSON.stringify(manifest));
  for (const artifact of artifacts) {
    form.set(
      artifact.field,
      new Blob([Buffer.from(artifact.bytes)], { type: artifact.contentType }),
      artifact.fileName
    );
  }
  const response = await fetch(
    new URL(
      `/v1/runtime-observation-jobs/${encodeURIComponent(observationJobId)}/evidence`,
      apiBaseUrl
    ),
    {
      method: 'POST',
      headers: { authorization: `Bearer ${capability}` },
      body: form,
      signal: AbortSignal.timeout(EVIDENCE_UPLOAD_TIMEOUT_MS)
    }
  );
  if (!response.ok) {
    const detail = redactText(await response.text());
    throw new Error(`Observation evidence upload failed with HTTP ${response.status}: ${detail}`);
  }
}

export async function runRuntimeObservation(
  input: RuntimeRunnerInput
): Promise<RuntimeRunnerResult> {
  const apiBase = new URL(input.apiBaseUrl);
  if (apiBase.username || apiBase.password || !['http:', 'https:'].includes(apiBase.protocol)) {
    throw new Error('API base URL is invalid.');
  }
  if (!input.capability || input.capability.length < 32) {
    throw new Error('A job-scoped runtime observation capability is required.');
  }

  const contract = await fetchJob(apiBase.toString(), input.observationJobId, input.capability);
  const ownsBrowser = !input.browser;
  const browser = input.browser ?? (await chromium.launch({
    headless: true,
    args: ['--disable-blink-features=AutomationControlled']
  }));
  try {
    // capture() owns the total-runtime budget internally so that a timeout still
    // yields a partial-evidence 'failed' result rather than an orphaned run.
    const result = await capture(contract, browser);
    if (input.outputDir) {
      await mkdir(input.outputDir, { recursive: true });
      result.manifest.observationJobId = input.observationJobId;
      await Promise.all([
        writeFile(
          `${input.outputDir}/manifest.json`,
          `${JSON.stringify(result.manifest, null, 2)}\n`
        ),
        ...result.artifacts.map((artifact) =>
          writeFile(`${input.outputDir}/${artifact.fileName}`, artifact.bytes)
        )
      ]);
    }
    // Always upload — including on failure — through the one-time capability so
    // the Worker marks the job failed instead of leaving it 'running'.
    await uploadEvidence(
      apiBase.toString(),
      input.observationJobId,
      input.capability,
      result.manifest,
      result.artifacts
    );
    if (result.status === 'failed') {
      throw new Error(
        `Runtime observation failed and reported partial evidence: ${result.failureReason ?? 'unknown reason'}`
      );
    }
    return {
      observationJobId: input.observationJobId,
      status: 'complete',
      trust: 'webflow_observed',
      cleanupStatus: result.cleanupStatus,
      negativeProxyOutcome: result.negativeProxyOutcome,
      artifactCount: result.artifacts.length
    };
  } finally {
    if (ownsBrowser) await browser.close();
  }
}
