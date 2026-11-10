import type { AuthenticatedUser, Env } from './types';
import {
  storedWebflowAccessTokenForUser,
  webflowAccessToken
} from './webflow-oauth';

interface ResolvedWebflowUser {
  id?: unknown;
  siteId?: unknown;
}

function bearerToken(request: Request): string | null {
  const value = request.headers.get('authorization');
  if (!value?.startsWith('Bearer ')) return null;
  const token = value.slice('Bearer '.length).trim();
  return token || null;
}

function cookieToken(request: Request, name: string): string | null {
  const cookie = request.headers.get('cookie');
  if (!cookie) return null;
  for (const item of cookie.split(';')) {
    const [key, ...parts] = item.trim().split('=');
    if (key === name) {
      const value = parts.join('=').trim();
      return value || null;
    }
  }
  return null;
}

export async function authenticate(
  request: Request,
  env: Env
): Promise<AuthenticatedUser | null> {
  const token = bearerToken(request);
  if (!token) return null;

  // Fail closed: dev-token identities are honored ONLY when the Worker is
  // explicitly configured as a development environment. A missing, empty, or
  // unrecognized ENVIRONMENT value behaves like production.
  if (
    env.ENVIRONMENT === 'development' &&
    env.PREFLIGHT_DEV_TOKEN &&
    token === env.PREFLIGHT_DEV_TOKEN
  ) {
    return { id: 'local-webflow-user', siteId: 'local-webflow-site' };
  }

  if (
    env.ENVIRONMENT === 'development' &&
    env.PREFLIGHT_REVIEWER_DEV_TOKEN &&
    token === env.PREFLIGHT_REVIEWER_DEV_TOKEN
  ) {
    return { id: 'local-webflow-reviewer', siteId: 'local-webflow-review-site' };
  }

  // Webflow resolves an ID token only when the bearer token's authorization
  // covers the ID token's site. Try the token this user granted first, then
  // the shared installation for users who connected before per-user storage.
  const subject = unverifiedIdTokenSubject(token);
  const userToken = subject
    ? await storedWebflowAccessTokenForUser(env, subject)
    : null;
  const sharedToken = await webflowAccessToken(env);
  const candidates = [userToken, sharedToken].filter(
    (value, index, all): value is string =>
      Boolean(value) && all.indexOf(value) === index
  );

  for (const appAccessToken of candidates) {
    const response = await fetch('https://api.webflow.com/beta/token/resolve', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${appAccessToken}`,
        'content-type': 'application/json'
      },
      body: JSON.stringify({ idToken: token })
    });

    if (!response.ok) {
      console.warn(
        JSON.stringify({
          event: 'webflow_id_token_resolve_failed',
          status: response.status,
          tokenSource: appAccessToken === userToken ? 'user' : 'shared'
        })
      );
      continue;
    }
    const resolved = (await response.json()) as ResolvedWebflowUser;
    if (typeof resolved.id !== 'string' || !resolved.id) continue;

    return {
      id: resolved.id,
      siteId: typeof resolved.siteId === 'string' ? resolved.siteId : null
    };
  }
  return null;
}

/**
 * Reads the `sub` claim without verifying the signature. The value only picks
 * which stored token to present; Webflow verifies the ID token itself and the
 * identity always comes from Webflow's response.
 */
function unverifiedIdTokenSubject(idToken: string): string | null {
  const payload = idToken.split('.')[1];
  if (!payload) return null;
  try {
    const padded = payload.replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(atob(padded)) as { sub?: unknown };
    return typeof claims.sub === 'string' ? claims.sub : null;
  } catch {
    return null;
  }
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export async function authenticateCompanion(
  request: Request,
  env: Env
): Promise<AuthenticatedUser | null> {
  const webflowUser = await authenticate(request, env);
  if (webflowUser) return webflowUser;

  // Companion sessions are established exclusively through the HttpOnly
  // reviewer session cookie. Session tokens are never issued as readable
  // bearers, so a bearer value is never accepted as a session token.
  const token = cookieToken(request, 'app_review_reviewer_session');
  if (!token) return null;
  const now = new Date().toISOString();
  const session = await env.DB.prepare(
    `SELECT actor_user_id, actor_site_id, actor_role, review_id, review_version_id,
            runtime_test_package_id
       FROM companion_sessions
      WHERE token_sha256 = ? AND revoked_at IS NULL AND expires_at > ?
        AND runtime_test_package_id IS NOT NULL`
  )
    .bind(await sha256(token), now)
    .first<{
      actor_user_id: string;
      actor_site_id: string | null;
      actor_role: 'developer' | 'reviewer';
      review_id: string;
      review_version_id: string;
      runtime_test_package_id: string;
    }>();
  if (!session) return null;
  return {
    id: session.actor_user_id,
    siteId: session.actor_site_id,
    companionSession: {
      reviewId: session.review_id,
      reviewVersionId: session.review_version_id,
      runtimeTestPackageId: session.runtime_test_package_id,
      actorRole: session.actor_role
    }
  };
}

export function companionRoleForUser(
  user: AuthenticatedUser,
  env: Env
): 'developer' | 'reviewer' {
  if (user.companionSession) return user.companionSession.actorRole;
  return new Set(
    (env.REVIEWER_USER_IDS ?? '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean)
  ).has(user.id)
    ? 'reviewer'
    : 'developer';
}
