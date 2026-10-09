import type { AuthenticatedUser, Env } from './types';
import { redeemCompanionPairing } from './companion-pairings';
import { getReview, listReviews } from './reviews';
import {
  InstallUrlCheckInputError,
  recordInstallUrlCheck,
  type StoredInstallUrlCheck
} from './install-url-checks';
import {
  listRuntimeTestPackages,
  requestReviewerRuntimeObservationReplay
} from './runtime-observations';

const SESSION_COOKIE = 'app_review_reviewer_session';

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function html(body: string, status = 200, headers: HeadersInit = {}): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      'referrer-policy': 'no-referrer',
      'x-content-type-options': 'nosniff',
      ...headers
    }
  });
}

function shell(content: string, title = 'Reviewer workspace'): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)} · App Review Preflight</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:#171717; color:#f5f5f5; }
    * { box-sizing:border-box; }
    body { margin:0; background:#171717; }
    header { position:sticky; top:0; z-index:2; display:flex; align-items:center; gap:12px; min-height:56px; padding:0 24px; background:#202020; border-bottom:1px solid #3b3b3b; }
    .mark { display:grid; place-items:center; width:28px; height:28px; border-radius:6px; background:#146ef5; font-weight:800; }
    main { width:min(1120px, calc(100% - 32px)); margin:32px auto 72px; }
    .eyebrow { margin:0 0 8px; color:#7bb2ff; font-size:11px; font-weight:700; letter-spacing:.12em; text-transform:uppercase; }
    h1 { margin:0; font-size:32px; line-height:1.15; letter-spacing:-.025em; }
    h2 { margin:0 0 14px; font-size:17px; }
    p { color:#b8b8b8; line-height:1.55; }
    .grid { display:grid; grid-template-columns:minmax(0, 2fr) minmax(260px, 1fr); gap:16px; margin-top:24px; }
    .card { background:#242424; border:1px solid #414141; border-radius:8px; padding:20px; }
    .receipt { display:flex; justify-content:space-between; gap:16px; align-items:flex-start; padding:14px 0; border-top:1px solid #3b3b3b; }
    .receipt:first-of-type { border-top:0; }
    .muted { color:#8f8f8f; font-size:13px; }
    .mono { font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; overflow-wrap:anywhere; }
    .pill { display:inline-flex; align-items:center; padding:4px 8px; border-radius:999px; background:#143f2c; color:#57d999; font-size:11px; font-weight:700; text-transform:uppercase; }
    .pill.blocked { background:#4a252a; color:#ff7180; }
    .pill.warn { background:#3d3418; color:#eab308; }
    .pill.info { background:#2b2b2b; color:#b8b8b8; }
    .findings { margin:12px 0 0; padding:0; list-style:none; }
    .findings li { display:flex; gap:10px; align-items:flex-start; padding:8px 0; border-top:1px solid #3b3b3b; font-size:13px; }
    .findings li:first-child { border-top:0; }
    .findings code { font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; color:#7bb2ff; white-space:nowrap; }
    label { display:block; margin:12px 0 6px; color:#b8b8b8; font-size:12px; font-weight:600; }
    input[type=text] { width:100%; min-height:36px; padding:0 10px; border:1px solid #414141; border-radius:4px; background:#171717; color:#f5f5f5; font:inherit; font-size:13px; }
    .actions { display:flex; gap:10px; margin-top:14px; flex-wrap:wrap; }
    button, .button { display:inline-flex; justify-content:center; align-items:center; min-height:38px; padding:0 16px; border:0; border-radius:4px; background:#146ef5; color:white; font:inherit; font-weight:650; text-decoration:none; cursor:pointer; }
    button:hover, .button:hover { background:#2d7ff8; }
    .queue { margin:0; padding:0; list-style:none; }
    .queue li { padding:12px 0; border-top:1px solid #3b3b3b; }
    .queue li:first-child { border-top:0; }
    .notice { margin:18px 0 0; padding:12px 14px; border-left:3px solid #eab308; background:#342f1d; color:#e6dfc5; font-size:13px; }
    @media (max-width:760px) { .grid { grid-template-columns:1fr; } main { margin-top:20px; } }
  </style>
</head>
<body>
  <header><span class="mark">W</span><strong>App Review Preflight</strong><span class="muted">Reviewer</span></header>
  ${content}
</body>
</html>`;
}

/**
 * Reviewer handoff. The one-time code is consumed only by an explicit POST:
 * a GET renders an interstitial confirmation form instead of redeeming, so
 * link-preview fetchers, mail scanners, and other GET-issuing intermediaries
 * cannot burn (or steal a session from) the capability. The minted session is
 * delivered exclusively as an HttpOnly cookie — never as a readable bearer.
 */
export async function connectReviewerWorkspace(request: Request, env: Env): Promise<Response> {
  if (request.method === 'GET') {
    const code = new URL(request.url).searchParams.get('code') ?? '';
    if (typeof code !== 'string' || code.length < 32 || code.length > 256) {
      return html(shell('<main><div class="card"><h1>Reviewer link unavailable</h1><p>This one-time link is invalid, expired, or already used.</p></div></main>'), 403);
    }
    return html(shell(`<main>
      <div class="card">
        <h1>Open the reviewer workspace</h1>
        <p>This one-time reviewer link signs you in with a short-lived session cookie. Continue only if you requested this handoff.</p>
        <form method="post" action="/reviewer/connect">
          <input type="hidden" name="code" value="${escapeHtml(code)}">
          <button type="submit">Enter reviewer workspace</button>
        </form>
      </div>
    </main>`));
  }

  let code: unknown = null;
  try {
    const form = await request.formData();
    code = form.get('code');
  } catch {
    code = null;
  }
  const redemption = await redeemCompanionPairing(code, env, 'reviewer');
  if (!redemption || redemption.actorRole !== 'reviewer') {
    return html(shell('<main><div class="card"><h1>Reviewer link unavailable</h1><p>This one-time link is invalid, expired, or already used.</p></div></main>'), 403);
  }

  const maxAge = Math.max(0, Math.floor((Date.parse(redemption.expiresAt) - Date.now()) / 1000));
  return new Response(null, {
    status: 303,
    headers: {
      location: '/reviewer',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'set-cookie': `${SESSION_COOKIE}=${redemption.token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`
    }
  });
}

interface ObservationHistoryRow {
  id: string;
  status: string;
  approved_at: string;
  consumed_at: string | null;
  evidence_trust: string | null;
  evidence_manifest_json: string | null;
}

async function observationHistory(testPackageId: string, env: Env): Promise<ObservationHistoryRow[]> {
  const rows = await env.DB.prepare(
    `SELECT id, status, approved_at, consumed_at, evidence_trust, evidence_manifest_json
       FROM runtime_observation_jobs
      WHERE test_package_id = ?
      ORDER BY created_at DESC
      LIMIT 20`
  ).bind(testPackageId).all<ObservationHistoryRow>();
  return rows.results;
}

export async function reviewerWorkspace(
  request: Request,
  env: Env,
  user: AuthenticatedUser
): Promise<Response> {
  const session = user.companionSession;
  if (!session || session.actorRole !== 'reviewer') {
    return html(shell('<main><div class="card"><h1>Reviewer sign-in required</h1><p>Open this workspace from App Review Preflight in Webflow Designer.</p></div></main>'), 401);
  }
  const [review, reviews, testPackages, history] = await Promise.all([
    getReview(session.reviewId, env, user, { includeAll: true }),
    listReviews(env, user, { includeAll: true }),
    listRuntimeTestPackages(session.reviewId, env, user, { includeAll: true }),
    observationHistory(session.runtimeTestPackageId, env)
  ]);
  const testPackage = testPackages?.find((item) => item.id === session.runtimeTestPackageId);
  if (!review || !testPackage) {
    return html(shell('<main><div class="card"><h1>Review unavailable</h1><p>The exact revision or Runtime Test Package is no longer available.</p></div></main>'), 404);
  }

  const historyHtml = history.length
    ? history.map((item) => {
        let securityStatus = 'pending';
        let blockers: string[] = [];
        if (item.evidence_manifest_json) {
          try {
            const manifest = JSON.parse(item.evidence_manifest_json) as {
              securityEvaluation?: { status?: unknown; blockers?: unknown };
            };
            if (manifest.securityEvaluation?.status === 'passed' || manifest.securityEvaluation?.status === 'blocked') {
              securityStatus = manifest.securityEvaluation.status;
            }
            if (Array.isArray(manifest.securityEvaluation?.blockers)) {
              blockers = manifest.securityEvaluation.blockers.filter((value): value is string => typeof value === 'string');
            }
          } catch {
            securityStatus = 'unreadable';
          }
        }
        return `<div class="receipt">
          <div><strong>${escapeHtml(securityStatus === 'pending' ? item.status : securityStatus)}</strong><div class="muted mono">${escapeHtml(item.id)}</div>${blockers.length ? `<div class="muted">${escapeHtml(blockers.join(' · '))}</div>` : ''}</div>
          <div><span class="pill ${securityStatus === 'blocked' ? 'blocked' : ''}">${escapeHtml(item.evidence_trust ?? 'awaiting evidence')}</span><div class="muted">${escapeHtml(item.consumed_at ?? item.approved_at)}</div></div>
        </div>`;
      }).join('')
    : '<p class="muted">No trusted runtime observations have run for this exact package yet.</p>';

  const started = new URL(request.url).searchParams.get('started');
  const installUrlNotice = new URL(request.url).searchParams.get('installUrl');
  const installUrlHtml = renderInstallUrlCheck(review.id, review.installUrlCheck ?? null);
  const queueHtml = reviews.map((item) => `<li><strong>${escapeHtml(item.name)}</strong><div class="muted">Revision ${item.latestSequence} · ${escapeHtml(item.updatedAt)}</div></li>`).join('');
  return html(shell(`<main>
    <p class="eyebrow">Reviewer workspace</p>
    <h1>${escapeHtml(review.name)}</h1>
    <p>Inspect the exact package, compare prior observations, and request an independent server-owned replay. Replays create evidence only; they cannot approve or reject an app.</p>
    ${started ? `<div class="notice">Replay ${escapeHtml(started)} was accepted. Refresh this page to see the Worker-derived result.</div>` : ''}
    <div class="grid">
      <section class="card">
        <h2>Runtime Test Package</h2>
        <div class="receipt"><span class="muted">Review version</span><span class="mono">${escapeHtml(testPackage.reviewVersionId)}</span></div>
        <div class="receipt"><span class="muted">Package</span><span class="mono">${escapeHtml(testPackage.id)}</span></div>
        <div class="receipt"><span class="muted">Bundle SHA-256</span><span class="mono">${escapeHtml(testPackage.bundleSha256)}</span></div>
        <div class="receipt"><span class="muted">Published target</span><span class="mono">${escapeHtml(testPackage.target.url)}</span></div>
        <div class="receipt"><span class="muted">Pinned runtimes</span><span class="mono">${testPackage.runtimeArtifacts.map((artifact) => escapeHtml(artifact.url)).join('<br>')}</span></div>
        <form method="post" action="/reviewer/runtime-test-packages/${encodeURIComponent(testPackage.id)}/replay">
          <button type="submit">Run independent replay</button>
          <a class="button" href="/reviewer">Refresh status</a>
        </form>
        <div class="notice">A pinned E2B template runs a fresh browser. Runtime bytes, SRI, created scripts, network behavior, and the proxy canary are derived by the Worker.</div>
      </section>
      <aside class="card"><h2>Submission queue</h2><ul class="queue">${queueHtml}</ul></aside>
      <section class="card" style="grid-column:1/-1"><h2>Install URL</h2>${installUrlNotice ? `<div class="notice">${escapeHtml(installUrlNotice)}</div>` : ''}${installUrlHtml}</section>
      <section class="card" style="grid-column:1/-1"><h2>Previous observations</h2>${historyHtml}</section>
    </div>
  </main>`));
}

export async function replayReviewerRuntimePackage(
  testPackageId: string,
  request: Request,
  env: Env,
  user: AuthenticatedUser
): Promise<Response> {
  const job = await requestReviewerRuntimeObservationReplay(testPackageId, request, env, user);
  if ('notFound' in job) {
    return html(shell('<main><div class="card"><h1>Runtime package unavailable</h1></div></main>'), 404);
  }
  return new Response(null, {
    status: 303,
    headers: {
      location: `/reviewer?started=${encodeURIComponent(job.id)}`,
      'cache-control': 'no-store'
    }
  });
}

function verdictPill(verdict: string): string {
  const cls = verdict === 'block' ? 'blocked' : verdict === 'warn' ? 'warn' : '';
  return `<span class="pill ${cls}">${escapeHtml(verdict)}</span>`;
}

function renderInstallUrlCheck(reviewId: string, check: StoredInstallUrlCheck | null): string {
  const action = `/reviewer/reviews/${encodeURIComponent(reviewId)}/install-url-check`;
  const form = `<form method="post" action="${action}">
      <label for="install-url">Install URL${check ? ' (leave blank to re-check the stored URL)' : ''}</label>
      <input type="text" id="install-url" name="installUrl" value="" placeholder="${escapeHtml(check?.installUrl ?? 'https://…')}" autocomplete="off">
      <label for="client-id">Client ID from the app settings</label>
      <input type="text" id="client-id" name="clientId" value="${escapeHtml(check?.clientId ?? '')}" autocomplete="off">
      <label for="configured-scopes">Configured scopes, space separated (for the IU-8 comparison)</label>
      <input type="text" id="configured-scopes" name="configuredScopes" value="${escapeHtml(check?.configuredScopes?.join(' ') ?? '')}" placeholder="sites:read cms:read" autocomplete="off">
      <div class="actions"><button type="submit">${check ? 'Re-check install URL' : 'Check install URL'}</button></div>
    </form>`;
  if (!check) {
    return `<p class="muted">The developer has not recorded an install URL check for this review. Enter the install URL from the submission to run it now.</p>${form}`;
  }
  const result = check.result;
  const findings = result.findings.length
    ? `<ul class="findings">${result.findings
        .map((finding) => `<li>${verdictPill(finding.severity)}<code>${escapeHtml(finding.rule)}</code><span>${escapeHtml(finding.message)}</span></li>`)
        .join('')}</ul>`
    : '<p class="muted">No string-rule findings.</p>';
  const probe = result.probe
    ? `<div class="receipt"><span class="muted">Probe</span><span>${verdictPill(result.probe.verdict)} <span class="mono">${escapeHtml(result.probe.code)}</span> · ${escapeHtml(result.probe.reason)}</span></div>
       <div class="receipt"><span class="muted">Redirect chain</span><span class="mono">${result.probe.hops.map((hop) => `${escapeHtml(hop.url)}${hop.status !== null ? ` → ${hop.status}` : hop.error ? ` → ${escapeHtml(hop.error)}` : ''}`).join('<br>')}</span></div>`
    : '<div class="receipt"><span class="muted">Probe</span><span class="muted">not run (string rules blocked, or not a Data Client)</span></div>';
  return `<div class="receipt"><span class="muted">Verdict</span><span>${verdictPill(result.verdict)} <span class="muted">${escapeHtml(check.actorRole)} · ${escapeHtml(check.createdAt)}</span></span></div>
    <div class="receipt"><span class="muted">Install URL</span><span class="mono">${escapeHtml(check.installUrl)}</span></div>
    <div class="receipt"><span class="muted">Client ID</span><span class="mono">${escapeHtml(check.clientId ?? 'not supplied')}</span></div>
    ${probe}
    ${findings}
    ${form}`;
}

/**
 * Reviewer re-check from the workspace form. Blank fields reuse the stored
 * inputs; configured scopes are what the reviewer read from the developer
 * workspace, which is the only source the worker has for IU-8.
 */
export async function recheckReviewerInstallUrl(
  reviewId: string,
  request: Request,
  env: Env,
  user: AuthenticatedUser
): Promise<Response> {
  if (!user.companionSession || user.companionSession.actorRole !== 'reviewer') {
    return html(shell('<main><div class="card"><h1>Reviewer sign-in required</h1></div></main>'), 401);
  }
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return html(shell('<main><div class="card"><h1>Invalid request</h1></div></main>'), 400);
  }
  const scopes = String(form.get('configuredScopes') ?? '').trim();
  try {
    const check = await recordInstallUrlCheck(
      reviewId,
      {
        installUrl: form.get('installUrl'),
        clientId: form.get('clientId'),
        configuredScopes: scopes ? scopes.split(/[\s,]+/) : undefined
      },
      env,
      user
    );
    if (!check) {
      return html(shell('<main><div class="card"><h1>Review unavailable</h1></div></main>'), 404);
    }
    return new Response(null, {
      status: 303,
      headers: {
        location: `/reviewer?installUrl=${encodeURIComponent(`Install URL check recorded: ${check.result.verdict}`)}`,
        'cache-control': 'no-store'
      }
    });
  } catch (error) {
    if (error instanceof InstallUrlCheckInputError) {
      return new Response(null, {
        status: 303,
        headers: { location: `/reviewer?installUrl=${encodeURIComponent(error.message)}`, 'cache-control': 'no-store' }
      });
    }
    throw error;
  }
}
