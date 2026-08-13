import type { Env } from './types';
import { storedWebflowAccessToken } from './webflow-oauth';

export type WebflowAuthorizationState =
  | 'ready'
  | 'reconnect_required'
  | 'unavailable';

export interface WebflowAuthorizationReadiness {
  state: WebflowAuthorizationState;
  statusCode: number | null;
}

async function appAccessToken(env: Env): Promise<string | null> {
  return env.WEBFLOW_APP_ACCESS_TOKEN ?? storedWebflowAccessToken(env);
}

/**
 * Proves that the server-side token can perform the exact authorized-user
 * operation needed to resolve fresh Designer ID tokens. No token or response
 * body leaves this boundary.
 */
export async function checkWebflowAuthorization(
  env: Env
): Promise<WebflowAuthorizationReadiness> {
  const token = await appAccessToken(env);
  if (!token) return { state: 'reconnect_required', statusCode: null };

  try {
    const response = await fetch('https://api.webflow.com/beta/token/authorized_by', {
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(10_000)
    });
    if (response.ok) return { state: 'ready', statusCode: response.status };
    return {
      state:
        response.status === 401 || response.status === 403
          ? 'reconnect_required'
          : 'unavailable',
      statusCode: response.status
    };
  } catch {
    return { state: 'unavailable', statusCode: null };
  }
}

export async function recordWebflowAuthorizationReadiness(
  env: Env
): Promise<WebflowAuthorizationReadiness> {
  const readiness = await checkWebflowAuthorization(env);
  const checkedAt = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO webflow_authorization_health
       (id, state, status_code, checked_at)
     VALUES ('active', ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       state = excluded.state,
       status_code = excluded.status_code,
       checked_at = excluded.checked_at`
  )
    .bind(readiness.state, readiness.statusCode, checkedAt)
    .run();
  return readiness;
}

export async function latestWebflowAuthorizationReadiness(env: Env): Promise<{
  state: WebflowAuthorizationState | 'unknown';
  statusCode: number | null;
  checkedAt: string | null;
}> {
  const row = await env.DB.prepare(
    `SELECT state, status_code, checked_at
       FROM webflow_authorization_health
      WHERE id = 'active'`
  ).first<{ state: WebflowAuthorizationState; status_code: number | null; checked_at: string }>();

  return row
    ? { state: row.state, statusCode: row.status_code, checkedAt: row.checked_at }
    : { state: 'unknown', statusCode: null, checkedAt: null };
}
