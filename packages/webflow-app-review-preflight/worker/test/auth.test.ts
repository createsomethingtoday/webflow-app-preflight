import { env } from 'cloudflare:workers';
import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  authenticate,
  companionRoleForUser,
  oauthTokenAgeAccepted,
  oauthUserAllowed
} from '../src/auth';
import type { Env } from '../src/types';

const request = (token: string) =>
  new Request('https://preflight.test/v1/me', {
    headers: { authorization: `Bearer ${token}` }
  });

const hoursAgo = (hours: number) => new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();

// `createdOn` is the issue time that Webflow reports for the token. The
// default is one hour ago; `null` leaves it out.
function stubWebflow(options: {
  resolveOk: boolean;
  applicationId?: string;
  createdOn?: string | null;
}) {
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
          authorization: {
            ...(options.createdOn === null ? {} : { createdOn: options.createdOn ?? hoursAgo(1) }),
            authorizedTo: { workspaceIds: ['ws-1'], siteIds: [] }
          }
        });
      }
      return Response.json({}, { status: 500 });
    })
  );
  return calls;
}

// The stub Webflow user (`oauth-user`) is on the CLI allowlist unless a test
// says otherwise.
const withOAuth = (overrides: Partial<Env>): Env => ({
  ...(env as Env),
  WEBFLOW_APP_ACCESS_TOKEN: 'app-token',
  PREFLIGHT_OAUTH_ALLOWED_USER_IDS: 'oauth-user',
  ...overrides
});

const cliOn: Partial<Env> = {
  PREFLIGHT_OAUTH_BEARER_ENABLED: 'true',
  PREFLIGHT_OAUTH_CLIENT_IDS: 'cli-app'
};

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

  test('a CLI token works for 24 hours after Webflow issued it', async () => {
    for (const [createdOn, accepted] of [
      [hoursAgo(23.9), true],
      [hoursAgo(24.1), false],
      [hoursAgo(24 * 400), false]
    ] as const) {
      stubWebflow({ resolveOk: false, applicationId: 'cli-app', createdOn });
      const user = await authenticate(request('oauth-token'), withOAuth(cliOn));
      expect(user?.authVia, createdOn).toBe(accepted ? 'oauth' : undefined);
    }
  });

  test('a CLI token with no usable issue time is refused', async () => {
    for (const createdOn of [null, '', 'not a date', hoursAgo(-1)]) {
      stubWebflow({ resolveOk: false, applicationId: 'cli-app', createdOn });
      expect(await authenticate(request('oauth-token'), withOAuth(cliOn)), String(createdOn)).toBeNull();
    }
  });

  test('a configured limit replaces 24 hours, and a bad value keeps it', async () => {
    stubWebflow({ resolveOk: false, applicationId: 'cli-app', createdOn: hoursAgo(1) });
    expect(
      await authenticate(
        request('oauth-token'),
        withOAuth({ ...cliOn, PREFLIGHT_OAUTH_TOKEN_MAX_AGE_SECONDS: '1800' })
      )
    ).toBeNull();
    const now = Date.parse('2026-11-13T12:00:00.000Z');
    for (const bad of ['0', '-10', 'never', '']) {
      const settings = { PREFLIGHT_OAUTH_TOKEN_MAX_AGE_SECONDS: bad };
      expect(oauthTokenAgeAccepted('2026-11-12T12:00:01.000Z', settings, now), bad).toBe(true);
      expect(oauthTokenAgeAccepted('2026-11-12T12:00:00.000Z', settings, now), bad).toBe(false);
    }
    // A small difference between the two clocks is not a wrong record.
    expect(oauthTokenAgeAccepted('2026-11-13T12:02:00.000Z', {}, now)).toBe(true);
    expect(oauthTokenAgeAccepted('2026-11-13T12:06:00.000Z', {}, now)).toBe(false);
  });

  test('the CLI path is closed to every user until a user list is set', async () => {
    for (const allowedUsers of [undefined, '', ' , ', 'another-user', '*, another-user']) {
      stubWebflow({ resolveOk: false, applicationId: 'cli-app' });
      const user = await authenticate(
        request('oauth-token'),
        withOAuth({ ...cliOn, PREFLIGHT_OAUTH_ALLOWED_USER_IDS: allowedUsers })
      );
      expect(user, String(allowedUsers)).toBeNull();
    }
    stubWebflow({ resolveOk: false, applicationId: 'cli-app' });
    expect(
      (
        await authenticate(
          request('oauth-token'),
          withOAuth({ ...cliOn, PREFLIGHT_OAUTH_ALLOWED_USER_IDS: 'another-user, oauth-user' })
        )
      )?.id
    ).toBe('oauth-user');
  });

  test('only the single value * opens the CLI path to every user', async () => {
    stubWebflow({ resolveOk: false, applicationId: 'cli-app' });
    expect(
      (
        await authenticate(
          request('oauth-token'),
          withOAuth({ ...cliOn, PREFLIGHT_OAUTH_ALLOWED_USER_IDS: '*' })
        )
      )?.id
    ).toBe('oauth-user');
    expect(oauthUserAllowed('anyone', { PREFLIGHT_OAUTH_ALLOWED_USER_IDS: '*' })).toBe(true);
    expect(oauthUserAllowed('*', { PREFLIGHT_OAUTH_ALLOWED_USER_IDS: '*, user-1' })).toBe(false);
    expect(oauthUserAllowed('anyone', { PREFLIGHT_OAUTH_ALLOWED_USER_IDS: '*, user-1' })).toBe(false);
    expect(oauthUserAllowed('', { PREFLIGHT_OAUTH_ALLOWED_USER_IDS: 'user-1' })).toBe(false);
  });

  test('flag on sends a bearer that is not a JWT straight to the OAuth path', async () => {
    const calls = stubWebflow({ resolveOk: false, applicationId: 'cli-app' });
    const user = await authenticate(
      request('0123456789abcdef'),
      withOAuth({ PREFLIGHT_OAUTH_BEARER_ENABLED: 'true', PREFLIGHT_OAUTH_CLIENT_IDS: 'cli-app' })
    );
    expect(user?.authVia).toBe('oauth');
    // The shared installation token is not spent on a resolve that cannot pass.
    expect(calls.some((url) => url.endsWith('/beta/token/resolve'))).toBe(false);
  });

  test('flag on still resolves a JWT-shaped bearer as a Designer ID token first', async () => {
    const calls = stubWebflow({ resolveOk: true });
    const user = await authenticate(
      request('aaa.bbb.ccc'),
      withOAuth({ PREFLIGHT_OAUTH_BEARER_ENABLED: 'true', PREFLIGHT_OAUTH_CLIENT_IDS: 'cli-app' })
    );
    expect(user).toEqual({ id: 'designer-user', siteId: 'designer-site', authVia: 'designer' });
    expect(calls.some((url) => url.includes('/v2/token/'))).toBe(false);
  });

  test('a creator CLI identity is never a reviewer, even when its user id is listed', () => {
    const listed = withOAuth({ REVIEWER_USER_IDS: 'oauth-user, designer-user' });
    expect(companionRoleForUser({ id: 'oauth-user', siteId: null, authVia: 'oauth' }, listed)).toBe('developer');
    expect(companionRoleForUser({ id: 'designer-user', siteId: 'site', authVia: 'designer' }, listed)).toBe('reviewer');
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
