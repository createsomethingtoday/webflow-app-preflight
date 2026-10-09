import { exports } from 'cloudflare:workers';
import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  checkInstallUrl,
  checkInstallUrlString,
  probeInstallUrl
} from '../src/install-url';

afterEach(() => {
  vi.unstubAllGlobals();
});

const DATA_CLIENT = { capabilities: ['Data Client v2'] };
const CLIENT_ID = 'd0a488aa5884654d34106a6d64d00019138b3be57a4364e7b6f19ed34c7b9ede';
const BARE = `https://webflow.com/oauth/authorize?response_type=code&client_id=${CLIENT_ID}&scope=sites%3Aread+cms%3Aread`;

function rules(result: { findings: { rule: string; severity: string }[] }, severity?: string): string[] {
  return result.findings
    .filter((finding) => !severity || finding.severity === severity)
    .map((finding) => finding.rule);
}

describe('Tier 1: install URL string rules', () => {
  test('requires an install URL for Data Client and Hybrid, not for Designer Extension', () => {
    expect(rules(checkInstallUrlString({ installUrl: '', ...DATA_CLIENT }), 'block')).toEqual(['IU-1']);
    expect(rules(checkInstallUrlString({ installUrl: '', capabilities: 'Hybrid' }), 'block')).toEqual(['IU-1']);
    const extension = checkInstallUrlString({ installUrl: '', capabilities: ['Designer Extension'] });
    expect(extension.verdict).toBe('pass');
    expect(extension.requiresInstallUrl).toBe(false);
    const ignored = checkInstallUrlString({ installUrl: 'https://app.example-ext.dev', capabilities: 'Designer Extension' });
    expect(ignored.findings).toEqual([expect.objectContaining({ rule: 'IU-1', severity: 'info' })]);
  });

  test('blocks malformed strings seen on live listings', () => {
    expect(rules(checkInstallUrlString({ installUrl: 'httsp://api.simplelocalize.io/install', ...DATA_CLIENT }), 'block')).toEqual(['IU-2']);
    expect(rules(checkInstallUrlString({ installUrl: 'http://app.trypixie.io/', ...DATA_CLIENT }), 'block')).toEqual(['IU-2']);
    expect(rules(checkInstallUrlString({ installUrl: 'app.pressmaster.ai', ...DATA_CLIENT }), 'block')).toEqual(['IU-2']);
    expect(rules(checkInstallUrlString({ installUrl: 'https://app.schemaflow.app/login⁩', ...DATA_CLIENT }), 'block')).toEqual(['IU-2']);
    expect(rules(checkInstallUrlString({ installUrl: 'https://app.example.dev:8443/start', ...DATA_CLIENT }), 'block')).toEqual(['IU-2']);
    expect(rules(checkInstallUrlString({ installUrl: 'https://127.0.0.1/start', ...DATA_CLIENT }), 'block')).toEqual(['IU-2']);
    expect(rules(checkInstallUrlString({ installUrl: `https://${'a'.repeat(2100)}.com/`, ...DATA_CLIENT }), 'block')).toContain('IU-9');
  });

  test('warns, not blocks, on callback-shaped paths', () => {
    const result = checkInstallUrlString({ installUrl: 'https://app.whalesync.com/oauth-callback/connector/webflow', ...DATA_CLIENT });
    expect(result.verdict).toBe('warn');
    expect(rules(result, 'warn')).toEqual(['IU-3']);
    expect(rules(checkInstallUrlString({ installUrl: 'https://app.gapflow.io/start?code=abc', ...DATA_CLIENT }), 'warn')).toEqual(['IU-3']);
  });

  test('blocks placeholder text, including YOUR_ tokens and non-hex client ids', () => {
    const result = checkInstallUrlString({
      installUrl: 'https://webflow.com/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID',
      ...DATA_CLIENT
    });
    expect(rules(result, 'block')).toEqual(['IU-4', 'IU-7']);
    expect(rules(checkInstallUrlString({ installUrl: 'https://example.com/install', ...DATA_CLIENT }), 'block')).toEqual(['IU-4']);
    expect(rules(checkInstallUrlString({ installUrl: 'https://app.acme.dev/{workspace}/install', ...DATA_CLIENT }), 'block')).toEqual(['IU-4']);
  });

  test('blocks tunnels and extension bundle hosts, warns on hosting providers', () => {
    expect(rules(checkInstallUrlString({ installUrl: 'https://a1b2.ngrok-free.app/auth', ...DATA_CLIENT }), 'block')).toEqual(['IU-5']);
    expect(rules(checkInstallUrlString({ installUrl: 'https://quiet-fox.loca.lt/auth', ...DATA_CLIENT }), 'block')).toEqual(['IU-5']);
    expect(rules(checkInstallUrlString({ installUrl: 'https://65791a622c7815e2cdb5bf43.webflow-ext.com', capabilities: 'Hybrid' }), 'block')).toEqual(['IU-5']);
    const hosted = checkInstallUrlString({ installUrl: 'https://bynder-app.railway.app/api/auth', ...DATA_CLIENT });
    expect(hosted.verdict).toBe('warn');
    expect(rules(hosted, 'warn')).toEqual(['IU-5']);
  });

  test('blocks webflow in the hostname, allows it in the path', () => {
    expect(rules(checkInstallUrlString({ installUrl: 'https://webflow.accessibe.com/', ...DATA_CLIENT }), 'block')).toEqual(['IU-6']);
    expect(rules(checkInstallUrlString({ installUrl: 'https://googleadsforwebflow.com/app', ...DATA_CLIENT }), 'block')).toEqual(['IU-6']);
    const path = checkInstallUrlString({ installUrl: 'https://api.answermage.com/auth/webflow', ...DATA_CLIENT });
    expect(path.verdict).toBe('pass');
    expect(rules(path, 'info')).toEqual(['IU-6']);
  });

  test('validates bare authorize URLs against the submission', () => {
    const ok = checkInstallUrlString({ installUrl: BARE, clientId: CLIENT_ID, ...DATA_CLIENT });
    expect(ok.verdict).toBe('pass');
    expect(ok.authorize).toEqual({
      clientId: CLIENT_ID,
      scopes: ['sites:read', 'cms:read'],
      hasState: false,
      hasWorkspace: false,
      hasRedirectUri: false
    });

    const mismatch = checkInstallUrlString({ installUrl: BARE, clientId: 'f'.repeat(64), ...DATA_CLIENT });
    expect(rules(mismatch, 'block')).toEqual(['IU-7']);

    const noType = checkInstallUrlString({ installUrl: `https://webflow.com/oauth/authorize?client_id=${CLIENT_ID}`, ...DATA_CLIENT });
    expect(rules(noType, 'block')).toEqual(['IU-7']);

    const workspace = checkInstallUrlString({ installUrl: `${BARE}&workspace=acme`, ...DATA_CLIENT });
    expect(rules(workspace, 'warn')).toEqual(['IU-7']);

    const login = checkInstallUrlString({
      installUrl: 'https://webflow.com/dashboard/login?r=https%3A%2F%2Fwebflow.com%2Foauth%2Fauthorize',
      ...DATA_CLIENT
    });
    expect(rules(login, 'block')).toEqual(['IU-7']);
  });

  test('compares requested scopes with configured scopes when the caller supplies them', () => {
    const extra = checkInstallUrlString({ installUrl: BARE, configuredScopes: ['sites:read'], ...DATA_CLIENT });
    expect(extra.findings).toContainEqual(expect.objectContaining({ rule: 'IU-8', severity: 'block' }));
    const missing = checkInstallUrlString({
      installUrl: BARE,
      configuredScopes: ['sites:read', 'cms:read', 'forms:read'],
      ...DATA_CLIENT
    });
    expect(rules(missing, 'warn')).toEqual(['IU-8']);
    expect(rules(missing, 'block')).toEqual([]);
  });
});

type Route = (url: string, init?: RequestInit) => Response | Promise<Response>;

function fakeFetch(routes: Record<string, Route>): typeof fetch & { calls: string[] } {
  const calls: string[] = [];
  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    calls.push(url);
    const route = routes[url] ?? routes[new URL(url).pathname];
    if (!route) return new Response('not routed', { status: 599 });
    return route(url, init);
  }) as unknown as typeof fetch & { calls: string[] };
  impl.calls = calls;
  return impl;
}

const redirect = (location: string) => () => new Response(null, { status: 302, headers: { location } });
const html = (body: string, status = 200) => () =>
  new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8' } });

describe('Tier 2: unauthenticated probe', () => {
  test('passes when the chain reaches webflow.com/oauth/authorize and does not request it', async () => {
    const fetchImpl = fakeFetch({
      'https://api.feedspace.io/v3/integration/oauth/authorize': redirect(
        `https://webflow.com/oauth/authorize?response_type=code&client_id=${CLIENT_ID}&state=abc&scope=sites%3Aread`
      )
    });
    const result = await probeInstallUrl('https://api.feedspace.io/v3/integration/oauth/authorize', {
      fetch: fetchImpl,
      clientId: CLIENT_ID,
      retryDelayMs: 0
    });
    expect(result.verdict).toBe('pass');
    expect(result.code).toBe('reaches_authorize');
    expect(result.authorize?.hasState).toBe(true);
    expect(result.hops).toHaveLength(2);
    expect(fetchImpl.calls).toEqual(['https://api.feedspace.io/v3/integration/oauth/authorize']);
  });

  test('encodes a Location header with raw spaces the way a browser would', async () => {
    const fetchImpl = fakeFetch({
      'https://sso.flowstar.co/install-webflow/faq/webflow': redirect(
        `https://webflow.com/oauth/authorize?client_id=${CLIENT_ID}&response_type=code&scope=assets:read authorized_user:read`
      )
    });
    const result = await probeInstallUrl('https://sso.flowstar.co/install-webflow/faq/webflow', { fetch: fetchImpl, retryDelayMs: 0 });
    expect(result.code).toBe('reaches_authorize');
    expect(result.authorize?.scopes).toEqual(['assets:read', 'authorized_user:read']);
  });

  test('blocks when the authorize hand-off uses a different client id', async () => {
    const fetchImpl = fakeFetch({
      '/start': redirect(`https://webflow.com/oauth/authorize?response_type=code&client_id=${'1'.repeat(64)}`)
    });
    const result = await probeInstallUrl('https://app.acme.dev/start', { fetch: fetchImpl, clientId: CLIENT_ID, retryDelayMs: 0 });
    expect(result.verdict).toBe('block');
    expect(result.code).toBe('client_id_mismatch');
  });

  test('blocks 404 and 5xx, retries a network failure once', async () => {
    expect((await probeInstallUrl('https://salviewer.app/', { fetch: fakeFetch({ '/': html('gone', 404) }), retryDelayMs: 0 })).code).toBe('not_found');
    expect((await probeInstallUrl('https://upbuilder.ai/install/webflow', { fetch: fakeFetch({ '/install/webflow': html('', 503) }), retryDelayMs: 0 })).code).toBe('server_error');

    let attempts = 0;
    const failing = (async () => {
      attempts += 1;
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    const result = await probeInstallUrl('https://app.fullsendhq.com/', { fetch: failing, retryDelayMs: 0 });
    expect(result.code).toBe('unreachable');
    expect(result.verdict).toBe('block');
    expect(attempts).toBe(2);
  });

  test('never follows a redirect onto a private host, plain http, or a tunnel', async () => {
    const privateHop = await probeInstallUrl('https://app.acme.dev/start', {
      fetch: fakeFetch({ '/start': redirect('https://169.254.169.254/latest/meta-data/') }),
      retryDelayMs: 0
    });
    expect(privateHop.code).toBe('private_host');
    expect(privateHop.hops.at(-1)?.status).toBeNull();

    const insecureHop = await probeInstallUrl('https://app.acme.dev/start', {
      fetch: fakeFetch({ '/start': redirect('http://app.acme.dev/login') }),
      retryDelayMs: 0
    });
    expect(insecureHop.code).toBe('insecure_hop');

    const tunnelHop = await probeInstallUrl('https://app.acme.dev/start', {
      fetch: fakeFetch({ '/start': redirect('https://a1b2.ngrok-free.app/auth') }),
      retryDelayMs: 0
    });
    expect(tunnelHop.code).toBe('tunnel_host');
  });

  test('detects loops and caps redirects', async () => {
    const loop = await probeInstallUrl('https://app.acme.dev/a', {
      fetch: fakeFetch({ '/a': redirect('https://app.acme.dev/b'), '/b': redirect('https://app.acme.dev/a') }),
      retryDelayMs: 0
    });
    expect(loop.code).toBe('redirect_loop');

    const routes: Record<string, Route> = {};
    for (let index = 0; index < 12; index += 1) {
      routes[`/hop${index}`] = redirect(`https://app.acme.dev/hop${index + 1}`);
    }
    const capped = await probeInstallUrl('https://app.acme.dev/hop0', { fetch: fakeFetch(routes), maxRedirects: 4, retryDelayMs: 0 });
    expect(capped.code).toBe('too_many_redirects');
  });

  test('classifies 2xx landings: authorize link passes, login page warns, bot challenge warns', async () => {
    const linked = await probeInstallUrl('https://app.acme.dev/connect', {
      fetch: fakeFetch({ '/connect': html(`<html><body><a href="https://webflow.com/oauth/authorize?client_id=${CLIENT_ID}">Connect</a></body></html>`) }),
      retryDelayMs: 0
    });
    expect(linked.code).toBe('links_to_authorize');
    expect(linked.verdict).toBe('pass');

    const login = await probeInstallUrl('https://app.acme.dev/login', {
      fetch: fakeFetch({ '/login': html(`<html><body>${'<p>Sign in to continue</p>'.repeat(20)}</body></html>`) }),
      retryDelayMs: 0
    });
    expect(login.code).toBe('no_oauth_handoff');
    expect(login.verdict).toBe('warn');

    const challenge = await probeInstallUrl('https://www.make.com/en/login', {
      fetch: fakeFetch({ '/en/login': html('<title>Just a moment...</title>', 403) }),
      retryDelayMs: 0
    });
    expect(challenge.code).toBe('bot_challenge');
    expect(challenge.verdict).toBe('warn');

    const meta = await probeInstallUrl('https://app.acme.dev/go', {
      fetch: fakeFetch({
        '/go': html(`<meta http-equiv="refresh" content="0; url=https://webflow.com/oauth/authorize?response_type=code&client_id=${CLIENT_ID}">`)
      }),
      retryDelayMs: 0
    });
    expect(meta.code).toBe('reaches_authorize');
  });
});

describe('checkInstallUrl', () => {
  test('skips the probe when Tier 1 blocks or the app is a Designer Extension', async () => {
    const fetchImpl = fakeFetch({});
    const blocked = await checkInstallUrl({ installUrl: 'http://app.acme.dev/', ...DATA_CLIENT }, { fetch: fetchImpl });
    expect(blocked.probe).toBeNull();
    const extension = await checkInstallUrl({ installUrl: 'https://app.acme.dev/', capabilities: 'Designer Extension' }, { fetch: fetchImpl });
    expect(extension.probe).toBeNull();
    expect(fetchImpl.calls).toEqual([]);
  });

  test('combines Tier 1 warnings with the probe verdict and records a missing state parameter', async () => {
    const fetchImpl = fakeFetch({
      '/webflow/callback': redirect(`https://webflow.com/oauth/authorize?response_type=code&client_id=${CLIENT_ID}`)
    });
    const result = await checkInstallUrl(
      { installUrl: 'https://app.hipaatizer.com/webflow/callback', clientId: CLIENT_ID, ...DATA_CLIENT },
      { fetch: fetchImpl, retryDelayMs: 0 }
    );
    expect(result.verdict).toBe('warn');
    expect(result.probe?.code).toBe('reaches_authorize');
    expect(result.findings).toContainEqual(expect.objectContaining({ rule: 'IU-3', severity: 'warn' }));
    expect(result.findings).toContainEqual(expect.objectContaining({ rule: 'IU-7', severity: 'info' }));
  });
});

describe('POST /v1/install-url/check', () => {
  const endpoint = 'https://preflight.test/v1/install-url/check';

  test('rejects anonymous callers', async () => {
    const response = await exports.default.fetch(
      new Request(endpoint, { method: 'POST', body: JSON.stringify({ installUrl: 'https://app.acme.dev' }) })
    );
    expect(response.status).toBe(401);
  });

  test('accepts the service token and returns Tier 1 findings without probing when asked', async () => {
    const stub = vi.fn(async () => new Response('unexpected', { status: 599 }));
    vi.stubGlobal('fetch', stub);
    const response = await exports.default.fetch(
      new Request(endpoint, {
        method: 'POST',
        headers: { authorization: 'Bearer install-url-check-test-token', 'content-type': 'application/json' },
        body: JSON.stringify({ installUrl: 'https://webflow.accessibe.com/', capabilities: ['Data Client v2'], probe: false })
      })
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { verdict: string; findings: { rule: string }[]; probe: unknown };
    expect(body.verdict).toBe('block');
    expect(body.findings.map((finding) => finding.rule)).toEqual(['IU-6']);
    expect(body.probe).toBeNull();
    expect(stub).not.toHaveBeenCalled();
  });

  test('accepts a signed-in developer and runs the probe', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
        if (url === 'https://app.acme.dev/install') {
          return new Response(null, {
            status: 302,
            headers: { location: `https://webflow.com/oauth/authorize?response_type=code&client_id=${CLIENT_ID}&state=x` }
          });
        }
        return new Response('unexpected', { status: 599 });
      })
    );
    const response = await exports.default.fetch(
      new Request(endpoint, {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337', 'content-type': 'application/json' },
        body: JSON.stringify({ installUrl: 'https://app.acme.dev/install', clientId: CLIENT_ID, capabilities: 'Hybrid' })
      })
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { verdict: string; probe: { code: string } };
    expect(body.verdict).toBe('pass');
    expect(body.probe.code).toBe('reaches_authorize');
  });

  test('rejects malformed bodies', async () => {
    const response = await exports.default.fetch(
      new Request(endpoint, {
        method: 'POST',
        headers: { authorization: 'Bearer install-url-check-test-token' },
        body: 'not json'
      })
    );
    expect(response.status).toBe(400);
  });
});
