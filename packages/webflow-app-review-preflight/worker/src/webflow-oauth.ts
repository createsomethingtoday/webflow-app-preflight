import type { Env } from './types';

const STATE_COOKIE = 'webflow_oauth_state';
const OAUTH_TTL_SECONDS = 15 * 60;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(value)
  );
  return bytesToHex(new Uint8Array(digest));
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function encryptionKey(env: Env): Promise<CryptoKey | null> {
  if (!env.WEBFLOW_TOKEN_ENCRYPTION_KEY) return null;
  try {
    const key = base64ToBytes(env.WEBFLOW_TOKEN_ENCRYPTION_KEY);
    if (key.byteLength !== 32) return null;
    return await crypto.subtle.importKey('raw', key, 'AES-GCM', false, [
      'encrypt',
      'decrypt'
    ]);
  } catch {
    return null;
  }
}

async function encryptAccessToken(
  token: string,
  env: Env
): Promise<{ ciphertext: string; iv: string } | null> {
  const key = await encryptionKey(env);
  if (!key) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(token)
  );
  return {
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    iv: bytesToBase64(iv)
  };
}

async function decryptAccessToken(
  ciphertext: string,
  iv: string,
  env: Env
): Promise<string | null> {
  const key = await encryptionKey(env);
  if (!key) return null;
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(iv) },
      key,
      base64ToBytes(ciphertext)
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    return null;
  }
}

function cookieValue(request: Request, name: string): string | null {
  for (const part of (request.headers.get('cookie') ?? '').split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return value.join('=') || null;
  }
  return null;
}

function stateCookie(state: string, maxAge = OAUTH_TTL_SECONDS): string {
  return [
    `${STATE_COOKIE}=${state}`,
    'Path=/v1/oauth/webflow/callback',
    `Max-Age=${maxAge}`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax'
  ].join('; ');
}

function unavailable(): Response {
  return Response.json(
    { error: 'webflow_oauth_not_configured' },
    { status: 503, headers: { 'cache-control': 'no-store' } }
  );
}

function invalidCallback(reason: string): Response {
  return Response.json(
    { error: 'invalid_webflow_oauth_callback', reason },
    { status: 400, headers: { 'cache-control': 'no-store' } }
  );
}

function redirectTo(request: Request, path: string): Response {
  return new Response(null, {
    status: 303,
    headers: {
      location: new URL(path, request.url).toString(),
      'cache-control': 'no-store'
    }
  });
}

async function recoverInvalidBrowserCallback(
  request: Request,
  env: Env,
  reason: 'state_mismatch' | 'state_unavailable'
): Promise<Response> {
  if (!(request.headers.get('accept') ?? '').includes('text/html')) {
    return invalidCallback(reason);
  }

  console.warn(
    JSON.stringify({ event: 'webflow_oauth_callback_not_completed', reason })
  );
  // No token was stored on this path. With no connection at all, start again;
  // otherwise say so plainly. Another developer's stored token must never make
  // this developer's failed connection read as complete.
  if (!(await storedWebflowAccessToken(env))) {
    return redirectTo(request, '/v1/oauth/webflow/start');
  }
  return webflowOAuthIncompletePage();
}

function configuredForStart(env: Env): boolean {
  return Boolean(env.WEBFLOW_CLIENT_ID && env.WEBFLOW_OAUTH_REDIRECT_URI);
}

function configuredForCallback(env: Env): boolean {
  return Boolean(
    configuredForStart(env) &&
      env.WEBFLOW_CLIENT_SECRET &&
      env.WEBFLOW_TOKEN_ENCRYPTION_KEY
  );
}

export async function startWebflowOAuth(env: Env): Promise<Response> {
  if (!configuredForStart(env)) return unavailable();

  const state = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const now = new Date();
  const expiresAt = new Date(now.getTime() + OAUTH_TTL_SECONDS * 1000).toISOString();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM webflow_oauth_states WHERE expires_at <= ?').bind(
      now.toISOString()
    ),
    env.DB.prepare(
      `INSERT INTO webflow_oauth_states (state_sha256, expires_at, created_at)
       VALUES (?, ?, ?)`
    ).bind(await sha256(state), expiresAt, now.toISOString())
  ]);

  const authorization = new URL('https://webflow.com/oauth/authorize');
  authorization.searchParams.set('response_type', 'code');
  authorization.searchParams.set('client_id', env.WEBFLOW_CLIENT_ID!);
  authorization.searchParams.set('scope', 'authorized_user:read');
  authorization.searchParams.set('redirect_uri', env.WEBFLOW_OAUTH_REDIRECT_URI!);
  authorization.searchParams.set('state', state);

  return new Response(null, {
    status: 302,
    headers: {
      location: authorization.toString(),
      'set-cookie': stateCookie(state),
      'cache-control': 'no-store'
    }
  });
}

async function exchangeCode(
  env: Env,
  code: string,
  redirectUri: string | undefined
): Promise<{ accessToken: string } | 'failed' | 'invalid'> {
  const exchange = await fetch('https://api.webflow.com/oauth/access_token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: env.WEBFLOW_CLIENT_ID,
      client_secret: env.WEBFLOW_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      ...(redirectUri ? { redirect_uri: redirectUri } : {})
    })
  });
  if (!exchange.ok) return 'failed';
  const body = (await exchange.json()) as AccessTokenResponse;
  if (typeof body.access_token !== 'string' || !body.access_token) {
    return 'invalid';
  }
  return { accessToken: body.access_token };
}

const WEBFLOW_USER_ID = /^[a-f0-9]{24}$/i;

/**
 * Stores the token under the Webflow user who granted it. Webflow resolves a
 * Designer ID token only when the bearer token's authorization covers the ID
 * token's site, so each developer needs their own token. Returns false when
 * the owner cannot be identified; the caller decides how to recover.
 */
async function storeUserInstallation(
  accessToken: string,
  env: Env
): Promise<boolean> {
  let userId: unknown;
  try {
    const response = await fetch(
      'https://api.webflow.com/beta/token/authorized_by',
      {
        headers: { authorization: `Bearer ${accessToken}` },
        signal: AbortSignal.timeout(10_000)
      }
    );
    if (!response.ok) return false;
    userId = ((await response.json()) as { id?: unknown }).id;
  } catch {
    return false;
  }
  if (typeof userId !== 'string' || !WEBFLOW_USER_ID.test(userId)) return false;

  const encrypted = await encryptAccessToken(accessToken, env);
  if (!encrypted) return false;
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO webflow_oauth_user_installations
       (user_id, access_token_ciphertext, access_token_iv, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       access_token_ciphertext = excluded.access_token_ciphertext,
       access_token_iv = excluded.access_token_iv,
       updated_at = excluded.updated_at`
  )
    .bind(userId.toLowerCase(), encrypted.ciphertext, encrypted.iv, now, now)
    .run();
  return true;
}

/**
 * A callback with no state comes from Webflow's own install flow (Marketplace
 * or a shared authorize link), not from /start. The token is stored only under
 * the user who granted it and never replaces the shared row, so a forged
 * callback can add nothing but the forger's own token. When the code cannot be
 * exchanged or its owner identified, the state-bound flow runs instead.
 */
async function completeDirectInstall(
  request: Request,
  env: Env,
  code: string
): Promise<Response> {
  if (!(request.headers.get('accept') ?? '').includes('text/html')) {
    return invalidCallback('state_mismatch');
  }
  const exchange = await exchangeCode(env, code, undefined);
  if (
    typeof exchange === 'object' &&
    (await storeUserInstallation(exchange.accessToken, env))
  ) {
    return redirectTo(request, '/v1/oauth/webflow/complete');
  }
  return redirectTo(request, '/v1/oauth/webflow/start');
}

interface AccessTokenResponse {
  access_token?: unknown;
}

export async function completeWebflowOAuth(
  request: Request,
  env: Env
): Promise<Response> {
  if (!configuredForCallback(env)) return unavailable();

  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const cookieState = cookieValue(request, STATE_COOKIE);
  if (!code) return invalidCallback('missing_code');
  if (!state && !cookieState) {
    return completeDirectInstall(request, env, code);
  }
  if (!state || !cookieState || state !== cookieState) {
    return recoverInvalidBrowserCallback(request, env, 'state_mismatch');
  }

  const consumed = await env.DB.prepare(
    `DELETE FROM webflow_oauth_states
      WHERE state_sha256 = ? AND expires_at > ?
      RETURNING state_sha256`
  )
    .bind(await sha256(state), new Date().toISOString())
    .first<{ state_sha256: string }>();
  if (!consumed) {
    return recoverInvalidBrowserCallback(request, env, 'state_unavailable');
  }

  const exchange = await exchangeCode(env, code, env.WEBFLOW_OAUTH_REDIRECT_URI);
  if (exchange === 'failed') {
    return Response.json(
      { error: 'webflow_oauth_exchange_failed' },
      { status: 502, headers: { 'cache-control': 'no-store' } }
    );
  }
  if (exchange === 'invalid') {
    return Response.json(
      { error: 'webflow_oauth_exchange_invalid' },
      { status: 502, headers: { 'cache-control': 'no-store' } }
    );
  }

  const encrypted = await encryptAccessToken(exchange.accessToken, env);
  if (!encrypted) return unavailable();
  const now = new Date().toISOString();
  // The shared row stays as the fallback for users who connected before
  // per-user storage, and as the token the health probe checks.
  await env.DB.prepare(
    `INSERT INTO webflow_oauth_installations
       (id, access_token_ciphertext, access_token_iv, created_at, updated_at)
     VALUES ('active', ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       access_token_ciphertext = excluded.access_token_ciphertext,
       access_token_iv = excluded.access_token_iv,
       updated_at = excluded.updated_at`
  )
    .bind(encrypted.ciphertext, encrypted.iv, now, now)
    .run();
  if (!(await storeUserInstallation(exchange.accessToken, env))) {
    console.warn(
      JSON.stringify({ event: 'webflow_oauth_user_installation_not_stored' })
    );
  }

  const completion = new URL('/v1/oauth/webflow/complete', request.url);
  return new Response(null, {
    status: 303,
    headers: {
      location: completion.toString(),
      'set-cookie': stateCookie('', 0),
      'cache-control': 'no-store'
    }
  });
}

interface OAuthPageCopy {
  status: number;
  tone: 'success' | 'warning';
  title: string;
  eyebrow: string;
  lede: string;
  note: string;
  action: { href: string; label: string };
  setCookie?: string;
}

export function webflowOAuthCompletePage(): Response {
  return oauthPage({
    status: 200,
    tone: 'success',
    title: 'Connection complete',
    eyebrow: 'Setup checkpoint complete',
    lede: 'The secure connection is ready. Return to Webflow and open the approved test site in Designer to begin runtime validation.',
    note: '<strong>Credentials stayed private.</strong> The app token was encrypted server-side and was not shown in this browser.',
    action: { href: 'https://webflow.com/dashboard', label: 'Return to Webflow' }
  });
}

/**
 * Shown when a callback could not be tied to the connection this browser
 * started (the request expired, or it began in another tab or browser).
 */
export function webflowOAuthIncompletePage(): Response {
  return oauthPage({
    status: 400,
    tone: 'warning',
    title: 'Connection not completed',
    eyebrow: 'Action needed',
    lede: 'Preflight could not match this authorization to the connection request from this browser, so nothing was saved. This happens when the request is older than 15 minutes, or when it started in a different tab or browser. Connect again and finish in the tab that opens.',
    note: '<strong>Nothing was stored.</strong> Preflight did not save a token from this attempt.',
    action: { href: '/v1/oauth/webflow/start', label: 'Connect again' },
    setCookie: stateCookie('', 0)
  });
}

function oauthPage(copy: OAuthPageCopy): Response {
  const warning = copy.tone === 'warning';
  const accent = warning ? '#f3c831' : '#5bd69b';
  const accentBackground = warning ? '#3a3116' : '#183428';
  const accentBorder = warning ? '#5c4d1c' : '#28543f';
  const icon = warning
    ? '<path d="M12 7v6"/><path d="M12 17h.01"/>'
    : '<path d="m5 12 4 4L19 6"/>';
  return new Response(
    `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>${copy.title} · App Review Preflight</title>
    <style>
      :root {
        color-scheme: dark;
        --background-1: #1e1e1e;
        --background-2: #2e2e2e;
        --background-3: #444;
        --text-1: #f5f5f5;
        --text-2: #bdbdbd;
        --text-3: #898989;
        --border-1: #3d3d3d;
        --action: #146ef5;
        --action-hover: #2f80ff;
        --success: ${accent};
        --success-background: ${accentBackground};
        --font: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }
      * { box-sizing: border-box; }
      body {
        min-width: 320px;
        min-height: 100vh;
        margin: 0;
        background:
          radial-gradient(circle at 50% 15%, rgba(20, 110, 245, .15), transparent 34rem),
          var(--background-1);
        color: var(--text-1);
        font-family: var(--font);
        -webkit-font-smoothing: antialiased;
      }
      .shell {
        display: grid;
        min-height: 100vh;
        grid-template-rows: auto 1fr auto;
      }
      header, footer {
        display: flex;
        align-items: center;
        min-height: 64px;
        padding: 0 clamp(20px, 4vw, 48px);
      }
      header { border-bottom: 1px solid var(--border-1); }
      .brand { display: flex; align-items: center; gap: 12px; font-size: 13px; font-weight: 600; }
      .brand-mark {
        display: grid;
        width: 32px;
        height: 32px;
        place-items: center;
        border-radius: 6px;
        background: var(--action);
        color: white;
        font-size: 14px;
        font-weight: 800;
        letter-spacing: -1px;
      }
      main { display: grid; place-items: center; padding: 48px 20px; }
      .card {
        width: min(100%, 480px);
        padding: clamp(28px, 5vw, 40px);
        border: 1px solid var(--border-1);
        border-radius: 10px;
        background: var(--background-2);
        box-shadow: 0 24px 70px rgba(0, 0, 0, .28);
      }
      .status {
        display: grid;
        width: 48px;
        height: 48px;
        place-items: center;
        border: 1px solid ${accentBorder};
        border-radius: 50%;
        background: var(--success-background);
        color: var(--success);
      }
      .status svg { width: 22px; height: 22px; }
      .eyebrow {
        margin: 24px 0 8px;
        color: var(--success);
        font-size: 11px;
        font-weight: 700;
        letter-spacing: .08em;
        text-transform: uppercase;
      }
      h1 { margin: 0; font-size: clamp(28px, 7vw, 38px); line-height: 1.08; letter-spacing: -.03em; }
      .lede { margin: 16px 0 0; color: var(--text-2); font-size: 14px; line-height: 1.55; }
      .privacy {
        display: flex;
        gap: 10px;
        margin: 24px 0 0;
        padding: 12px;
        border: 1px solid var(--border-1);
        border-radius: 6px;
        background: var(--background-1);
        color: var(--text-3);
        font-size: 11px;
        line-height: 1.45;
      }
      .privacy strong { color: var(--text-2); }
      .dot { flex: 0 0 8px; height: 8px; margin-top: 4px; border-radius: 50%; background: var(--success); }
      .button {
        display: inline-flex;
        min-height: 40px;
        align-items: center;
        justify-content: center;
        margin-top: 24px;
        padding: 0 18px;
        border-radius: 4px;
        background: var(--action);
        color: white;
        font-size: 13px;
        font-weight: 600;
        text-decoration: none;
        transition: background 120ms ease;
      }
      .button:hover { background: var(--action-hover); }
      .button:focus-visible { outline: 2px solid #70a7ff; outline-offset: 3px; }
      footer { justify-content: center; color: var(--text-3); font-size: 11px; text-align: center; }
      @media (max-width: 520px) {
        header { min-height: 56px; }
        main { align-items: start; padding-top: 32px; }
      }
    </style>
  </head>
  <body>
    <div class="shell">
      <header>
        <div class="brand"><span class="brand-mark" aria-hidden="true">W</span>App Review Preflight</div>
      </header>
      <main>
        <section class="card" aria-labelledby="completion-title">
          <div class="status" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">${icon}</svg>
          </div>
          <p class="eyebrow">${copy.eyebrow}</p>
          <h1 id="completion-title">${copy.title}</h1>
          <p class="lede">${copy.lede}</p>
          <div class="privacy"><span class="dot" aria-hidden="true"></span><span>${copy.note}</span></div>
          <a class="button" href="${copy.action.href}">${copy.action.label}</a>
        </section>
      </main>
      <footer>App Review Preflight · Evidence supports review; it does not make the decision.</footer>
    </div>
  </body>
</html>`,
    {
      status: copy.status,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
        ...(copy.setCookie ? { 'set-cookie': copy.setCookie } : {})
      }
    }
  );
}

export async function storedWebflowAccessToken(env: Env): Promise<string | null> {
  const row = await env.DB.prepare(
    `SELECT access_token_ciphertext, access_token_iv
       FROM webflow_oauth_installations
      WHERE id = 'active'`
  ).first<{ access_token_ciphertext: string; access_token_iv: string }>();
  if (!row) return null;
  return decryptAccessToken(
    row.access_token_ciphertext,
    row.access_token_iv,
    env
  );
}

export async function storedWebflowAccessTokenForUser(
  env: Env,
  userId: string
): Promise<string | null> {
  if (!WEBFLOW_USER_ID.test(userId)) return null;
  const row = await env.DB.prepare(
    `SELECT access_token_ciphertext, access_token_iv
       FROM webflow_oauth_user_installations
      WHERE user_id = ?`
  )
    .bind(userId.toLowerCase())
    .first<{ access_token_ciphertext: string; access_token_iv: string }>();
  if (!row) return null;
  return decryptAccessToken(
    row.access_token_ciphertext,
    row.access_token_iv,
    env
  );
}

/**
 * Prefer the most recently completed OAuth installation. The managed secret is
 * retained only as a rollback fallback for deployments without a stored
 * installation; otherwise it would make a successful reconnect a no-op.
 */
export async function webflowAccessToken(env: Env): Promise<string | null> {
  return (
    (await storedWebflowAccessToken(env)) ??
    env.WEBFLOW_APP_ACCESS_TOKEN ??
    null
  );
}
