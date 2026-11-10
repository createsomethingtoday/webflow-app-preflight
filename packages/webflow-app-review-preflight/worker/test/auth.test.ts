import { env } from 'cloudflare:workers';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { authenticate } from '../src/auth';
import type { Env } from '../src/types';

const request = (token: string) =>
  new Request('https://preflight.test/v1/me', {
    headers: { authorization: `Bearer ${token}` }
  });

function stubWebflow(options: { resolveOk: boolean; applicationId?: string }) {
  const calls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      calls.push(url);
      if (url === 'https://api.webflow.com/oauth/access_token') {
        return Response.json({ access_token: 'app-token' });
      }
      if (url === 'https://api.webflow.com/beta/token/resolve') {
        return options.resolveOk
          ? Response.json({ id: 'designer-user', siteId: 'designer-site' })
          : Response.json({ error: 'invalid' }, { status: 401 });
      }
      if (url === 'https://api.webflow.com/v2/token/authorized_by') {
        return Response.json({ id: 'oauth-user', email: 'dev@example.com' });
      }
      if (url === 'https://api.webflow.com/v2/token/introspect') {
        return Response.json({
          application: { id: options.applicationId },
          authorization: { authorizedTo: { workspaceIds: ['ws-1'], siteIds: [] } }
        });
      }
      return Response.json({}, { status: 500 });
    })
  );
  return calls;
}

const withOAuth = (overrides: Partial<Env>): Env => ({
  ...(env as Env),
  WEBFLOW_APP_ACCESS_TOKEN: 'app-token',
  ...overrides
});

describe('authenticate', () => {
  afterEach(() => vi.unstubAllGlobals());

  test('Designer token resolve path is unchanged', async () => {
    stubWebflow({ resolveOk: true });
    const user = await authenticate(request('designer-id-token'), withOAuth({}));
    expect(user).toEqual({ id: 'designer-user', siteId: 'designer-site', authVia: 'designer' });
  });

  test('flag off rejects an OAuth bearer without calling the OAuth endpoints', async () => {
    const calls = stubWebflow({ resolveOk: false, applicationId: 'cli-app' });
    const user = await authenticate(
      request('oauth-token'),
      withOAuth({ PREFLIGHT_OAUTH_CLIENT_IDS: 'cli-app' })
    );
    expect(user).toBeNull();
    expect(calls.some((url) => url.includes('/v2/token/'))).toBe(false);
  });

  test('flag on rejects an application that is not allowlisted', async () => {
    stubWebflow({ resolveOk: false, applicationId: 'other-app' });
    const user = await authenticate(
      request('oauth-token'),
      withOAuth({ PREFLIGHT_OAUTH_BEARER_ENABLED: 'true', PREFLIGHT_OAUTH_CLIENT_IDS: 'cli-app' })
    );
    expect(user).toBeNull();
  });

  test('flag on with an empty allowlist rejects', async () => {
    stubWebflow({ resolveOk: false, applicationId: 'cli-app' });
    const user = await authenticate(
      request('oauth-token'),
      withOAuth({ PREFLIGHT_OAUTH_BEARER_ENABLED: 'true', PREFLIGHT_OAUTH_CLIENT_IDS: '' })
    );
    expect(user).toBeNull();
  });

  test('flag on rejects when introspection omits the application id', async () => {
    stubWebflow({ resolveOk: false });
    const user = await authenticate(
      request('oauth-token'),
      withOAuth({ PREFLIGHT_OAUTH_BEARER_ENABLED: 'true', PREFLIGHT_OAUTH_CLIENT_IDS: 'cli-app' })
    );
    expect(user).toBeNull();
  });

  test('flag on with an allowlisted application returns a siteId-null OAuth user', async () => {
    stubWebflow({ resolveOk: false, applicationId: 'cli-app' });
    const user = await authenticate(
      request('oauth-token'),
      withOAuth({
        PREFLIGHT_OAUTH_BEARER_ENABLED: 'true',
        PREFLIGHT_OAUTH_CLIENT_IDS: 'other, cli-app'
      })
    );
    expect(user).toEqual({
      id: 'oauth-user',
      siteId: null,
      authVia: 'oauth',
      workspaceIds: ['ws-1']
    });
  });

  test('a transport failure on token resolve is a refusal, not a thrown error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('network down');
      })
    );
    await expect(
      authenticate(
        request('any-token'),
        withOAuth({ PREFLIGHT_OAUTH_BEARER_ENABLED: 'true', PREFLIGHT_OAUTH_CLIENT_IDS: 'cli-app' })
      )
    ).resolves.toBeNull();
  });
});
