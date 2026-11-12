import { env } from 'cloudflare:workers';
import { afterEach, describe, expect, test, vi } from 'vitest';
import worker from '../src/index';
import type { Env } from '../src/types';

const fetchWorker = (request: Request) => worker.fetch(request, env);

describe('Webflow OAuth installation', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test('exchanges a state-bound callback without exposing the app token', async () => {
    const start = await fetchWorker(
      new Request('https://preflight.test/v1/oauth/webflow/start')
    );

    expect(start.status).toBe(302);
    const authorization = new URL(start.headers.get('location')!);
    expect(`${authorization.origin}${authorization.pathname}`).toBe(
      'https://webflow.com/oauth/authorize'
    );
    expect(authorization.searchParams.get('response_type')).toBe('code');
    expect(authorization.searchParams.get('client_id')).toBe('webflow-client-id');
    expect(authorization.searchParams.get('scope')).toBe('authorized_user:read');
    expect(authorization.searchParams.get('redirect_uri')).toBe(
      'https://preflight.test/v1/oauth/webflow/callback'
    );
    const state = authorization.searchParams.get('state');
    expect(state).toMatch(/^[a-f0-9]{64}$/);
    const cookie = start.headers.get('set-cookie');
    expect(cookie).toContain(`webflow_oauth_state=${state}`);
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=Lax');

    const outboundFetch = vi.fn(async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(input);
      if (request.url === 'https://api.webflow.com/oauth/access_token') {
        return Response.json({ access_token: 'server-only-app-token' });
      }
      if (request.url === 'https://api.webflow.com/beta/token/resolve') {
        return Response.json({ id: 'webflow-user-id', siteId: 'webflow-site-id' });
      }
      return Response.json({ error: 'unexpected_outbound_request' }, { status: 500 });
    });
    vi.stubGlobal('fetch', outboundFetch);

    const callback = await fetchWorker(
      new Request(
        `https://preflight.test/v1/oauth/webflow/callback?code=single-use-code&state=${state}`,
        { headers: { cookie: cookie!.split(';', 1)[0]! } }
      )
    );

    expect(callback.status).toBe(303);
    expect(callback.headers.get('location')).toBe(
      'https://preflight.test/v1/oauth/webflow/complete'
    );
    expect(await callback.text()).not.toContain('server-only-app-token');

    const identity = await fetchWorker(
      new Request('https://preflight.test/v1/me', {
        headers: { authorization: 'Bearer designer-id-token' }
      })
    );
    expect(identity.status).toBe(200);
    expect(await identity.json()).toMatchObject({
      user: { id: 'webflow-user-id', siteId: 'webflow-site-id' }
    });
  });

  const USER_A = 'aaaaaaaaaaaaaaaaaaaaaaaa';
  const USER_B = 'bbbbbbbbbbbbbbbbbbbbbbbb';
  const idTokenFor = (sub: string) =>
    `header.${btoa(JSON.stringify({ sub })).replace(/=+$/, '')}.signature`;

  // Mirrors Webflow: a token resolves only the ID tokens of its own grantor.
  const webflowStub = (codes: Record<string, string>) =>
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const bearer = request.headers.get('authorization')?.slice('Bearer '.length);
      if (request.url === 'https://api.webflow.com/oauth/access_token') {
        const { code } = (await request.json()) as { code: string };
        return codes[code]
          ? Response.json({ access_token: `token-${codes[code]}` })
          : Response.json({ error: 'invalid_grant' }, { status: 400 });
      }
      if (request.url === 'https://api.webflow.com/beta/token/authorized_by') {
        return Response.json({ id: bearer?.slice('token-'.length) });
      }
      if (request.url === 'https://api.webflow.com/beta/token/resolve') {
        const { idToken } = (await request.json()) as { idToken: string };
        return idToken === idTokenFor(bearer?.slice('token-'.length) ?? '')
          ? Response.json({ id: bearer!.slice('token-'.length), siteId: 'site' })
          : Response.json({ message: 'ID token could not be resolved' }, { status: 400 });
      }
      return Response.json({ error: 'unexpected_outbound_request' }, { status: 500 });
    });

  const connect = async (code: string) => {
    const start = await fetchWorker(
      new Request('https://preflight.test/v1/oauth/webflow/start')
    );
    const state = new URL(start.headers.get('location')!).searchParams.get('state');
    return fetchWorker(
      new Request(
        `https://preflight.test/v1/oauth/webflow/callback?code=${code}&state=${state}`,
        { headers: { cookie: start.headers.get('set-cookie')!.split(';', 1)[0]! } }
      )
    );
  };
  const me = (sub: string) =>
    fetchWorker(
      new Request('https://preflight.test/v1/me', {
        headers: { authorization: `Bearer ${idTokenFor(sub)}` }
      })
    );

  test('keeps an earlier developer signed in after another developer connects', async () => {
    vi.stubGlobal('fetch', webflowStub({ 'code-a': USER_A, 'code-b': USER_B }));

    expect((await connect('code-a')).status).toBe(303);
    expect((await connect('code-b')).status).toBe(303);

    const first = await me(USER_A);
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ user: { id: USER_A } });
    const second = await me(USER_B);
    expect(second.status).toBe(200);
    expect(await second.json()).toMatchObject({ user: { id: USER_B } });
  });

  test('stores a direct Webflow install under its own user only', async () => {
    vi.stubGlobal('fetch', webflowStub({ 'code-a': USER_A, 'code-b': USER_B }));
    expect((await connect('code-a')).status).toBe(303);

    const install = await fetchWorker(
      new Request('https://preflight.test/v1/oauth/webflow/callback?code=code-b', {
        headers: { accept: 'text/html' }
      })
    );
    expect(install.status).toBe(303);
    expect(install.headers.get('location')).toBe(
      'https://preflight.test/v1/oauth/webflow/complete'
    );

    expect((await me(USER_B)).status).toBe(200);
    expect((await me(USER_A)).status).toBe(200);
    // The shared row still holds the state-bound connection, not the install.
    await env.DB.prepare('DELETE FROM webflow_oauth_user_installations').run();
    expect((await me(USER_A)).status).toBe(200);
    expect((await me(USER_B)).status).toBe(401);
  });

  test('uses a completed OAuth installation before the managed fallback token', async () => {
    const start = await fetchWorker(
      new Request('https://preflight.test/v1/oauth/webflow/start')
    );
    const authorization = new URL(start.headers.get('location')!);
    const state = authorization.searchParams.get('state')!;
    const cookie = start.headers.get('set-cookie')!;

    const outboundFetch = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const request =
          input instanceof Request ? input : new Request(input, init);
        if (request.url === 'https://api.webflow.com/oauth/access_token') {
          return Response.json({ access_token: 'fresh-oauth-token' });
        }
        if (request.url === 'https://api.webflow.com/beta/token/resolve') {
          return request.headers.get('authorization') ===
            'Bearer fresh-oauth-token'
            ? Response.json({
                id: 'webflow-user-id',
                siteId: 'webflow-site-id'
              })
            : Response.json({ error: 'unauthorized' }, { status: 401 });
        }
        return Response.json(
          { error: 'unexpected_outbound_request' },
          { status: 500 }
        );
      }
    );
    vi.stubGlobal('fetch', outboundFetch);

    const productionEnv = {
      ...env,
      WEBFLOW_APP_ACCESS_TOKEN: 'managed-fallback-token'
    } as Env;
    const callback = await worker.fetch(
      new Request(
        `https://preflight.test/v1/oauth/webflow/callback?code=single-use-code&state=${state}`,
        { headers: { cookie: cookie.split(';', 1)[0]! } }
      ),
      productionEnv
    );
    expect(callback.status).toBe(303);

    const identity = await worker.fetch(
      new Request('https://preflight.test/v1/me', {
        headers: { authorization: 'Bearer designer-id-token' }
      }),
      productionEnv
    );

    expect(identity.status).toBe(200);
    expect(await identity.json()).toMatchObject({
      user: { id: 'webflow-user-id', siteId: 'webflow-site-id' }
    });
    expect(outboundFetch).toHaveBeenLastCalledWith(
      'https://api.webflow.com/beta/token/resolve',
      expect.objectContaining({
        headers: expect.objectContaining({
          authorization: 'Bearer fresh-oauth-token'
        })
      })
    );
  });

  test('rejects a callback whose browser state does not match', async () => {
    const start = await fetchWorker(
      new Request('https://preflight.test/v1/oauth/webflow/start')
    );
    const authorization = new URL(start.headers.get('location')!);
    const state = authorization.searchParams.get('state')!;

    const callback = await fetchWorker(
      new Request(
        `https://preflight.test/v1/oauth/webflow/callback?code=single-use-code&state=${state}`,
        { headers: { cookie: 'webflow_oauth_state=another-state' } }
      )
    );

    expect(callback.status).toBe(400);
    expect(await callback.json()).toEqual({
      error: 'invalid_webflow_oauth_callback',
      reason: 'state_mismatch'
    });
  });

  test('restarts the secure flow for a browser callback without reusable state', async () => {
    await env.DB.prepare(
      "DELETE FROM webflow_oauth_installations WHERE id = 'active'"
    ).run();
    vi.stubGlobal('fetch', webflowStub({}));

    const callback = await fetchWorker(
      new Request(
        'https://preflight.test/v1/oauth/webflow/callback?code=unused-direct-install-code',
        { headers: { accept: 'text/html' } }
      )
    );

    expect(callback.status).toBe(303);
    expect(callback.headers.get('location')).toBe(
      'https://preflight.test/v1/oauth/webflow/start'
    );
    expect(await callback.text()).not.toContain('unused-direct-install-code');
  });

  test('does not report a connection when the browser state does not match', async () => {
    vi.stubGlobal('fetch', webflowStub({ 'code-a': USER_A, 'code-b': USER_B }));
    // Another developer is connected, so a shared token exists.
    expect((await connect('code-a')).status).toBe(303);

    const start = await fetchWorker(
      new Request('https://preflight.test/v1/oauth/webflow/start')
    );
    const state = new URL(start.headers.get('location')!).searchParams.get('state');
    const attempts = [
      // The state cookie expired or was never sent.
      { accept: 'text/html' },
      // A newer connection request replaced the cookie.
      { accept: 'text/html', cookie: 'webflow_oauth_state=another-state' }
    ];
    for (const headers of attempts) {
      const callback = await fetchWorker(
        new Request(
          `https://preflight.test/v1/oauth/webflow/callback?code=code-b&state=${state}`,
          { headers }
        )
      );
      const html = await callback.text();

      expect(callback.status).toBe(400);
      expect(callback.headers.get('location')).toBeNull();
      expect(html).toContain('Connection not completed');
      expect(html).not.toContain('Connection complete');
      expect(html).toContain('href="/v1/oauth/webflow/start"');
      expect(html).not.toContain('code-b');
    }

    // The failed attempts stored nothing for the second developer.
    await env.DB.prepare(
      "DELETE FROM webflow_oauth_installations WHERE id = 'active'"
    ).run();
    expect((await me(USER_A)).status).toBe(200);
    expect((await me(USER_B)).status).toBe(401);
  });

  test('does not report a connection when the state has already been used', async () => {
    vi.stubGlobal('fetch', webflowStub({ 'code-a': USER_A }));
    const start = await fetchWorker(
      new Request('https://preflight.test/v1/oauth/webflow/start')
    );
    const state = new URL(start.headers.get('location')!).searchParams.get('state');
    const replay = () =>
      fetchWorker(
        new Request(
          `https://preflight.test/v1/oauth/webflow/callback?code=code-a&state=${state}`,
          {
            headers: {
              accept: 'text/html',
              cookie: start.headers.get('set-cookie')!.split(';', 1)[0]!
            }
          }
        )
      );
    expect((await replay()).status).toBe(303);

    const second = await replay();
    expect(second.status).toBe(400);
    expect(await second.text()).toContain('Connection not completed');
  });

  test('renders a self-contained Webflow-style completion page', async () => {
    const response = await fetchWorker(
      new Request('https://preflight.test/v1/oauth/webflow/complete')
    );
    const html = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get('content-security-policy')).toContain(
      "default-src 'none'"
    );
    expect(response.headers.get('content-security-policy')).toContain(
      "style-src 'unsafe-inline'"
    );
    expect(html).toContain('App Review Preflight');
    expect(html).toContain('Connection complete');
    expect(html).toContain('#146ef5');
    expect(html).toContain('https://webflow.com/dashboard');
    expect(html).not.toContain('<script');
  });
});
