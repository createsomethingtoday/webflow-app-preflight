/**
 * Install URL validation for Data Client and Hybrid submissions.
 *
 * Tier 1 (`checkInstallUrlString`) runs deterministic rules over the string
 * the developer submitted. Tier 2 (`probeInstallUrl`) follows the URL once,
 * unauthenticated, and reads where the redirect chain ends. Rule IDs (IU-1 to
 * IU-9) match the install URL validation spec so the submission form, the
 * extension, and the reviewer workspace report the same codes.
 *
 * The probe fetches developer-supplied URLs from Webflow infrastructure, so
 * every hop is checked before it is requested: https only, no private or
 * local hosts, no tunnels. The response body is never returned to the caller;
 * only status, final host, and a verdict.
 */
import { isPrivateOrLocalHostname } from './net';

export type InstallUrlSeverity = 'block' | 'warn' | 'info';

export interface InstallUrlFinding {
  rule: string;
  severity: InstallUrlSeverity;
  message: string;
}

export interface AuthorizeHandoff {
  clientId: string | null;
  scopes: string[];
  hasState: boolean;
  hasWorkspace: boolean;
  hasRedirectUri: boolean;
}

export interface InstallUrlStringCheck {
  installUrl: string | null;
  requiresInstallUrl: boolean;
  verdict: 'pass' | 'warn' | 'block';
  findings: InstallUrlFinding[];
  authorize: AuthorizeHandoff | null;
}

export interface InstallUrlCheckInput {
  installUrl?: unknown;
  clientId?: unknown;
  capabilities?: unknown;
  configuredScopes?: unknown;
}

const TUNNEL_HOSTS = [
  'ngrok',
  'loca.lt',
  'trycloudflare.com',
  'localtunnel',
  'serveo',
  'tunnelmole',
  'lhr.life',
  'pinggy'
];

const HOSTING_PROVIDER_SUFFIXES = [
  '.railway.app',
  '.vercel.app',
  '.netlify.app',
  '.herokuapp.com',
  '.onrender.com',
  '.supabase.co',
  '.fly.dev',
  '.pages.dev',
  '.workers.dev',
  '.replit.app',
  '.repl.co',
  '.glitch.me',
  '.github.io',
  '.web.app',
  '.firebaseapp.com',
  '.azurewebsites.net',
  '.webflow.io'
];

const PLACEHOLDER_TOKENS = [
  'yourclientid',
  'your_',
  'yourworkspace',
  'yourdomain',
  'your-domain',
  'example.com',
  'placeholder',
  '<',
  '>',
  '{',
  '}'
];

const WEBFLOW_HOSTS = new Set(['webflow.com', 'www.webflow.com']);

function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string');
  if (typeof value === 'string') return [value];
  return [];
}

export function requiresInstallUrl(capabilities: unknown): boolean {
  return asStringList(capabilities).some((value) =>
    /data[\s_-]?client|hybrid/i.test(value)
  );
}

function isWebflowHost(host: string): boolean {
  return WEBFLOW_HOSTS.has(host) || host.endsWith('.webflow.com');
}

export function isTunnelHost(host: string): boolean {
  return TUNNEL_HOSTS.some((token) => host.includes(token));
}

export function isHostingProviderHost(host: string): boolean {
  return HOSTING_PROVIDER_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

function parseScopes(value: string | null): string[] {
  if (!value) return [];
  return value
    .split(/[\s+,]+/)
    .map((scope) => scope.trim())
    .filter((scope) => scope.length > 0);
}

export function parseAuthorizeHandoff(url: URL): AuthorizeHandoff | null {
  const host = url.hostname.toLowerCase();
  const path = url.pathname.replace(/\/+$/, '');
  if (!isWebflowHost(host) || path !== '/oauth/authorize') return null;
  const params = url.searchParams;
  return {
    clientId: params.get('client_id'),
    scopes: parseScopes(params.get('scope')),
    hasState: params.has('state') && (params.get('state') ?? '').length > 0,
    hasWorkspace: params.has('workspace'),
    hasRedirectUri: params.has('redirect_uri')
  };
}

/**
 * IU-8: requested scopes against the scopes configured for the app. Extra
 * scopes block (Webflow's own install already fails on them); missing ones
 * warn. Runs on a bare authorize URL at Tier 1 and on the probe's hand-off.
 */
export function compareScopes(requestedScopes: string[], configuredScopes: string[]): InstallUrlFinding[] {
  if (configuredScopes.length === 0) return [];
  const configured = new Set(configuredScopes);
  const requested = new Set(requestedScopes);
  const findings: InstallUrlFinding[] = [];
  const extra = requestedScopes.filter((scope) => !configured.has(scope));
  const missing = configuredScopes.filter((scope) => !requested.has(scope));
  if (extra.length > 0) {
    findings.push({
      rule: 'IU-8',
      severity: 'block',
      message: `Install URL requests scopes the app is not configured for: ${extra.join(', ')}.`
    });
  }
  if (missing.length > 0) {
    findings.push({
      rule: 'IU-8',
      severity: 'warn',
      message: `Install URL omits configured scopes: ${missing.join(', ')}.`
    });
  }
  return findings;
}

function worst(findings: InstallUrlFinding[]): 'pass' | 'warn' | 'block' {
  if (findings.some((finding) => finding.severity === 'block')) return 'block';
  if (findings.some((finding) => finding.severity === 'warn')) return 'warn';
  return 'pass';
}

/**
 * Tier 1: rules over the submitted string. No network.
 */
export function checkInstallUrlString(input: InstallUrlCheckInput): InstallUrlStringCheck {
  const findings: InstallUrlFinding[] = [];
  const raw = asString(input.installUrl) ?? '';
  const trimmed = raw.trim();
  const required = requiresInstallUrl(input.capabilities);
  const expectedClientId = asString(input.clientId)?.trim() || null;
  const configuredScopes = asStringList(input.configuredScopes).map((scope) => scope.trim());

  if (!trimmed) {
    if (required) {
      findings.push({
        rule: 'IU-1',
        severity: 'block',
        message:
          'An install URL is required for Data Client and Hybrid apps. It is the link a user clicks on your listing to start installation.'
      });
    }
    return { installUrl: null, requiresInstallUrl: required, verdict: worst(findings), findings, authorize: null };
  }

  if (!required) {
    findings.push({
      rule: 'IU-1',
      severity: 'info',
      message: 'Designer Extension apps do not use an install URL; this value is ignored.'
    });
  }

  if (trimmed.length > 2048) {
    findings.push({ rule: 'IU-9', severity: 'block', message: 'Install URL is longer than 2,048 characters.' });
  }
  if (/[^\x21-\x7e]/.test(trimmed)) {
    findings.push({
      rule: 'IU-2',
      severity: 'block',
      message: 'Install URL contains whitespace or a non-ASCII character. Paste the URL as plain text.'
    });
  }

  const lower = trimmed.toLowerCase();
  const placeholders = PLACEHOLDER_TOKENS.filter((token) => lower.includes(token));
  if (placeholders.length > 0) {
    findings.push({
      rule: 'IU-4',
      severity: 'block',
      message: `Install URL still contains placeholder text (${placeholders.join(', ')}).`
    });
  }

  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    findings.push({
      rule: 'IU-2',
      severity: 'block',
      message: 'Install URL has no scheme. It must start with https://.'
    });
    return { installUrl: trimmed, requiresInstallUrl: required, verdict: worst(findings), findings, authorize: null };
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    findings.push({ rule: 'IU-2', severity: 'block', message: 'Install URL does not parse as a URL.' });
    return { installUrl: trimmed, requiresInstallUrl: required, verdict: worst(findings), findings, authorize: null };
  }

  const host = url.hostname.toLowerCase();
  const path = url.pathname.toLowerCase();

  if (url.protocol !== 'https:') {
    findings.push({
      rule: 'IU-2',
      severity: 'block',
      message: `Install URL must use https (found ${url.protocol.replace(':', '')}).`
    });
  }
  if (url.port && url.port !== '443') {
    findings.push({ rule: 'IU-2', severity: 'block', message: 'Install URL must not use a non-standard port.' });
  }
  if (!host.includes('.') || isPrivateOrLocalHostname(host)) {
    findings.push({
      rule: 'IU-2',
      severity: 'block',
      message: 'Install URL host must be a public domain name, not localhost or an IP address.'
    });
  }

  if (/callback|redirect|oauth2redirect/.test(path) || url.searchParams.has('code') || url.searchParams.has('error')) {
    findings.push({
      rule: 'IU-3',
      severity: 'warn',
      message:
        'This looks like your OAuth callback. The install URL is the link a user clicks to start installation, not the redirect URI. If this endpoint starts the flow when no code is present, it is fine.'
    });
  }

  if (isTunnelHost(host)) {
    findings.push({
      rule: 'IU-5',
      severity: 'block',
      message: `${host} is a tunnel or local host. Use a production domain you control.`
    });
  } else if (host.endsWith('.webflow-ext.com')) {
    findings.push({
      rule: 'IU-5',
      severity: 'block',
      message: 'This is a Designer Extension bundle host. The install URL must start the Data Client OAuth flow.'
    });
  } else if (isHostingProviderHost(host)) {
    findings.push({
      rule: 'IU-5',
      severity: 'warn',
      message: `${host} is a hosting-provider subdomain. Reviewers may ask for a production domain you control.`
    });
  }

  if (host.includes('webflow') && !isWebflowHost(host) && !host.endsWith('.webflow-ext.com')) {
    findings.push({
      rule: 'IU-6',
      severity: 'block',
      message: `Hostname ${host} contains "webflow". Brand guidelines do not allow Webflow's name in your domain.`
    });
  } else if (!isWebflowHost(host) && /(^|\/)webflow(\/|$)/.test(path)) {
    findings.push({
      rule: 'IU-6',
      severity: 'info',
      message: 'Path contains "webflow". Allowed, but keep the brand out of the hostname.'
    });
  }

  const authorize = parseAuthorizeHandoff(url);
  if (isWebflowHost(host)) {
    if (!authorize) {
      findings.push({
        rule: 'IU-7',
        severity: 'block',
        message: `webflow.com${url.pathname} is not an install URL. Use your own endpoint or https://webflow.com/oauth/authorize?response_type=code&client_id=…`
      });
    } else {
      if (url.searchParams.get('response_type') !== 'code') {
        findings.push({ rule: 'IU-7', severity: 'block', message: 'Authorize URL must include response_type=code.' });
      }
      if (!authorize.clientId) {
        findings.push({ rule: 'IU-7', severity: 'block', message: 'Authorize URL is missing client_id.' });
      } else if (!/^[0-9a-f]{15,64}$/i.test(authorize.clientId)) {
        findings.push({
          rule: 'IU-7',
          severity: 'block',
          message: 'client_id is not a Webflow client ID. Copy it from your app settings.'
        });
      } else if (expectedClientId && authorize.clientId !== expectedClientId) {
        findings.push({
          rule: 'IU-7',
          severity: 'block',
          message: 'client_id in the install URL does not match the Client ID on this submission.'
        });
      }
      if (authorize.hasWorkspace) {
        findings.push({
          rule: 'IU-7',
          severity: 'warn',
          message: 'Remove the workspace parameter. It pins installation to one workspace.'
        });
      }
      if (authorize.hasRedirectUri) {
        findings.push({
          rule: 'IU-7',
          severity: 'warn',
          message: 'redirect_uri is pinned in the install URL. It must match the redirect URI registered for the app.'
        });
      }
      findings.push(...compareScopes(authorize.scopes, configuredScopes));
    }
  }

  return { installUrl: trimmed, requiresInstallUrl: required, verdict: worst(findings), findings, authorize };
}

export interface ProbeHop {
  url: string;
  status: number | null;
  error?: string;
}

export type ProbeCode =
  | 'reaches_authorize'
  | 'links_to_authorize'
  | 'no_oauth_handoff'
  | 'empty_page'
  | 'bot_challenge'
  | 'login_conflict'
  | 'not_found'
  | 'client_error'
  | 'server_error'
  | 'unreachable'
  | 'insecure_hop'
  | 'private_host'
  | 'tunnel_host'
  | 'redirect_loop'
  | 'too_many_redirects'
  | 'client_id_mismatch'
  | 'invalid_url';

export interface ProbeResult {
  verdict: 'pass' | 'warn' | 'block';
  code: ProbeCode;
  reason: string;
  hops: ProbeHop[];
  finalUrl: string | null;
  finalStatus: number | null;
  authorize: AuthorizeHandoff | null;
  durationMs: number;
}

export interface ProbeOptions {
  fetch?: typeof fetch;
  clientId?: string | null;
  maxRedirects?: number;
  totalTimeoutMs?: number;
  hopTimeoutMs?: number;
  retryDelayMs?: number;
}

const PROBE_USER_AGENT =
  'Mozilla/5.0 (compatible; WebflowMarketplacePreflight/1.0; +https://developers.webflow.com/apps/docs/marketplace/submitting-your-app)';

function finish(
  partial: Omit<ProbeResult, 'durationMs' | 'hops' | 'authorize'> & { authorize?: AuthorizeHandoff | null },
  hops: ProbeHop[],
  startedAt: number
): ProbeResult {
  return { authorize: null, ...partial, hops, durationMs: Date.now() - startedAt };
}

function hopGuard(url: URL): { code: ProbeCode; reason: string } | null {
  const host = url.hostname.toLowerCase();
  if (url.protocol !== 'https:') {
    return { code: 'insecure_hop', reason: `redirect chain moved to ${url.protocol.replace(':', '')}` };
  }
  if (!host.includes('.') || isPrivateOrLocalHostname(host)) {
    return { code: 'private_host', reason: `redirect chain reached a private or local host (${host})` };
  }
  if (isTunnelHost(host)) {
    return { code: 'tunnel_host', reason: `redirect chain reached a tunnel host (${host})` };
  }
  return null;
}

function redirectTarget(body: string, base: URL): URL | null {
  const meta = body.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=([^"'>\s]+)/i);
  const script = body.match(/(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/);
  const candidate = meta?.[1] ?? script?.[1];
  if (!candidate) return null;
  try {
    return new URL(candidate, base);
  } catch {
    return null;
  }
}

/**
 * Tier 2: follow the install URL once, unauthenticated, and classify where it
 * ends. Stops at webflow.com/oauth/authorize without requesting it; Webflow
 * would only bounce an anonymous request to login.
 */
export async function probeInstallUrl(installUrl: string, options: ProbeOptions = {}): Promise<ProbeResult> {
  const fetchImpl = options.fetch ?? fetch;
  const maxRedirects = options.maxRedirects ?? 8;
  const totalTimeoutMs = options.totalTimeoutMs ?? 10_000;
  const hopTimeoutMs = options.hopTimeoutMs ?? 8_000;
  const retryDelayMs = options.retryDelayMs ?? 500;
  const startedAt = Date.now();
  const hops: ProbeHop[] = [];
  const seen = new Set<string>();

  let current: URL;
  try {
    current = new URL(installUrl.trim());
  } catch {
    return finish(
      { verdict: 'block', code: 'invalid_url', reason: 'install URL does not parse', finalUrl: null, finalStatus: null },
      hops,
      startedAt
    );
  }

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const authorize = parseAuthorizeHandoff(current);
    if (authorize) {
      hops.push({ url: current.toString(), status: null });
      if (options.clientId && authorize.clientId && authorize.clientId !== options.clientId) {
        return finish(
          {
            verdict: 'block',
            code: 'client_id_mismatch',
            reason: 'authorize hand-off uses a different client_id than this submission',
            finalUrl: current.toString(),
            finalStatus: null,
            authorize
          },
          hops,
          startedAt
        );
      }
      return finish(
        {
          verdict: 'pass',
          code: 'reaches_authorize',
          reason: authorize.hasState
            ? 'reaches webflow.com/oauth/authorize with state'
            : 'reaches webflow.com/oauth/authorize without state',
          finalUrl: current.toString(),
          finalStatus: null,
          authorize
        },
        hops,
        startedAt
      );
    }

    const guard = hopGuard(current);
    if (guard) {
      hops.push({ url: current.toString(), status: null, error: guard.code });
      return finish(
        { verdict: 'block', code: guard.code, reason: guard.reason, finalUrl: current.toString(), finalStatus: null },
        hops,
        startedAt
      );
    }

    const key = current.toString();
    if (seen.has(key)) {
      hops.push({ url: key, status: null, error: 'redirect_loop' });
      return finish(
        { verdict: 'block', code: 'redirect_loop', reason: 'redirect chain loops', finalUrl: key, finalStatus: null },
        hops,
        startedAt
      );
    }
    seen.add(key);

    const remaining = totalTimeoutMs - (Date.now() - startedAt);
    if (remaining <= 0) {
      hops.push({ url: key, status: null, error: 'timeout' });
      return finish(
        { verdict: 'block', code: 'unreachable', reason: 'probe exceeded its time budget', finalUrl: key, finalStatus: null },
        hops,
        startedAt
      );
    }

    let response: Response | null = null;
    let lastError = 'network error';
    for (let attempt = 0; attempt < 2 && !response; attempt += 1) {
      // AbortController with an explicit clearTimeout: a timer left armed
      // after the fetch settles surfaces as an uncaught abort in workerd.
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), Math.min(hopTimeoutMs, remaining));
      try {
        response = await fetchImpl(key, {
          method: 'GET',
          redirect: 'manual',
          headers: { 'user-agent': PROBE_USER_AGENT, accept: 'text/html,*/*;q=0.8' },
          signal: controller.signal
        });
      } catch (error) {
        lastError = error instanceof Error ? `${error.name}: ${error.message}`.slice(0, 160) : 'network error';
        if (attempt === 0 && retryDelayMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
        }
      } finally {
        clearTimeout(timer);
      }
    }
    if (!response) {
      hops.push({ url: key, status: null, error: lastError });
      return finish(
        { verdict: 'block', code: 'unreachable', reason: `install URL could not be fetched (${lastError})`, finalUrl: key, finalStatus: null },
        hops,
        startedAt
      );
    }

    const status = response.status;
    hops.push({ url: key, status });

    if (status >= 300 && status < 400) {
      const location = response.headers.get('location');
      if (location) {
        try {
          current = new URL(location, current);
          continue;
        } catch {
          return finish(
            { verdict: 'block', code: 'client_error', reason: 'redirect target is not a valid URL', finalUrl: key, finalStatus: status },
            hops,
            startedAt
          );
        }
      }
    }

    const contentType = response.headers.get('content-type') ?? '';
    let body = '';
    if (status < 300 || status === 401 || status === 403 || status === 409) {
      if (/text\/html|application\/xhtml|text\/plain/.test(contentType) || contentType === '') {
        body = (await response.text()).slice(0, 65_536);
      }
    }
    const lowerBody = body.toLowerCase();

    if (status >= 500) {
      return finish(
        { verdict: 'block', code: 'server_error', reason: `install URL returned ${status}`, finalUrl: key, finalStatus: status },
        hops,
        startedAt
      );
    }
    if (status === 404 || status === 410) {
      return finish(
        { verdict: 'block', code: 'not_found', reason: `install URL returned ${status}`, finalUrl: key, finalStatus: status },
        hops,
        startedAt
      );
    }
    if (status === 401 || status === 403) {
      const challenge = /cloudflare|just a moment|captcha|access denied|attention required/.test(lowerBody);
      return finish(
        {
          verdict: challenge ? 'warn' : 'block',
          code: challenge ? 'bot_challenge' : 'client_error',
          reason: challenge
            ? `install URL answered ${status} with a bot challenge; reviewer confirms in a browser`
            : `install URL returned ${status}`,
          finalUrl: key,
          finalStatus: status
        },
        hops,
        startedAt
      );
    }
    if (status === 409 && /login|sign.?in/.test(key.toLowerCase() + lowerBody)) {
      return finish(
        { verdict: 'warn', code: 'login_conflict', reason: 'login flow answered 409; reviewer confirms in a browser', finalUrl: key, finalStatus: status },
        hops,
        startedAt
      );
    }
    if (status >= 400) {
      return finish(
        { verdict: 'block', code: 'client_error', reason: `install URL returned ${status}`, finalUrl: key, finalStatus: status },
        hops,
        startedAt
      );
    }

    const next = redirectTarget(body, current);
    if (next && next.toString() !== key) {
      current = next;
      continue;
    }
    if (lowerBody.includes('webflow.com/oauth/authorize')) {
      return finish(
        {
          verdict: 'pass',
          code: 'links_to_authorize',
          reason: 'page links to webflow.com/oauth/authorize (login-first or button flow)',
          finalUrl: key,
          finalStatus: status
        },
        hops,
        startedAt
      );
    }
    if (body.trim().length < 200) {
      return finish(
        { verdict: 'warn', code: 'empty_page', reason: 'install URL returned a near-empty page', finalUrl: key, finalStatus: status },
        hops,
        startedAt
      );
    }
    return finish(
      {
        verdict: 'warn',
        code: 'no_oauth_handoff',
        reason: 'install URL ends on a page with no Webflow OAuth hand-off; reviewer confirms it leads there',
        finalUrl: key,
        finalStatus: status
      },
      hops,
      startedAt
    );
  }

  return finish(
    {
      verdict: 'block',
      code: 'too_many_redirects',
      reason: `redirect chain exceeded ${maxRedirects} hops`,
      finalUrl: current.toString(),
      finalStatus: null
    },
    hops,
    startedAt
  );
}

export interface InstallUrlCheck extends InstallUrlStringCheck {
  probe: ProbeResult | null;
}

/**
 * Tier 1 followed by Tier 2. The probe is skipped when Tier 1 already blocks
 * on the string or when the caller opts out (form on-blur checks).
 */
export async function checkInstallUrl(
  input: InstallUrlCheckInput,
  options: { probe?: boolean } & ProbeOptions = {}
): Promise<InstallUrlCheck> {
  const stringCheck = checkInstallUrlString(input);
  const shouldProbe =
    options.probe !== false &&
    stringCheck.installUrl !== null &&
    stringCheck.requiresInstallUrl &&
    stringCheck.verdict !== 'block';
  if (!shouldProbe) return { ...stringCheck, probe: null };

  const probe = await probeInstallUrl(stringCheck.installUrl!, {
    ...options,
    clientId: asString(input.clientId)?.trim() || null
  });
  const findings = [...stringCheck.findings];
  if (probe.authorize && !stringCheck.authorize) {
    // The developer endpoint handed off to authorize: compare those scopes.
    findings.push(
      ...compareScopes(
        probe.authorize.scopes,
        asStringList(input.configuredScopes).map((scope) => scope.trim()).filter(Boolean)
      )
    );
  }
  if (probe.authorize && !probe.authorize.hasState) {
    findings.push({
      rule: 'IU-7',
      severity: 'info',
      message: 'OAuth hand-off carries no state parameter. Pending the state ruling, this is recorded, not enforced.'
    });
  }
  const verdict = worst([...findings, { rule: 'probe', severity: probe.verdict === 'pass' ? 'info' : probe.verdict, message: '' }]);
  return { ...stringCheck, findings, verdict, probe };
}
