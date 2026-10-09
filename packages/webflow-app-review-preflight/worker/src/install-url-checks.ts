/**
 * Install URL checks stamped on a review record.
 *
 * A developer records a check from the extension against their own review;
 * a reviewer re-runs it from the reviewer workspace. Reviewers may supply
 * the scopes configured for the app (read from the developer workspace
 * during review) so the IU-8 comparison runs; the worker has no registry
 * read of its own. Every run is appended, and the newest row is the current
 * state surfaced on the review and on the submission receipt.
 */
import { checkInstallUrl, type InstallUrlCheck, type ProbeOptions } from './install-url';
import { companionRoleForUser } from './auth';
import type { AuthenticatedUser, Env } from './types';

export class InstallUrlCheckInputError extends Error {}

export interface StoredInstallUrlCheck {
  id: string;
  reviewVersionId: string;
  actorRole: 'developer' | 'reviewer';
  installUrl: string;
  clientId: string | null;
  capabilities: string[];
  configuredScopes: string[] | null;
  createdAt: string;
  result: InstallUrlCheck;
}

export interface InstallUrlCheckSummary {
  verdict: InstallUrlCheck['verdict'];
  probeCode: string | null;
  actorRole: 'developer' | 'reviewer';
  checkedAt: string;
}

interface InstallUrlCheckRow {
  id: string;
  review_version_id: string;
  actor_role: 'developer' | 'reviewer';
  install_url: string;
  client_id: string | null;
  capabilities_json: string;
  configured_scopes_json: string | null;
  verdict: InstallUrlCheck['verdict'];
  probe_code: string | null;
  result_json: string;
  created_at: string;
}

function parseStringList(value: unknown, field: string, max = 32): string[] {
  if (value === undefined || value === null) return [];
  const list = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(list) || list.length > max || list.some((item) => typeof item !== 'string' || item.length > 128)) {
    throw new InstallUrlCheckInputError(`${field} must be a list of short strings.`);
  }
  return (list as string[]).map((item) => item.trim()).filter(Boolean);
}

function rowToStored(row: InstallUrlCheckRow): StoredInstallUrlCheck {
  return {
    id: row.id,
    reviewVersionId: row.review_version_id,
    actorRole: row.actor_role,
    installUrl: row.install_url,
    clientId: row.client_id,
    capabilities: JSON.parse(row.capabilities_json) as string[],
    configuredScopes: row.configured_scopes_json ? (JSON.parse(row.configured_scopes_json) as string[]) : null,
    createdAt: row.created_at,
    result: JSON.parse(row.result_json) as InstallUrlCheck
  };
}

export async function latestInstallUrlCheck(
  reviewId: string,
  env: Env
): Promise<StoredInstallUrlCheck | null> {
  const row = await env.DB.prepare(
    `SELECT id, review_version_id, actor_role, install_url, client_id, capabilities_json,
            configured_scopes_json, verdict, probe_code, result_json, created_at
       FROM install_url_checks
      WHERE review_id = ?
      ORDER BY created_at DESC, rowid DESC
      LIMIT 1`
  )
    .bind(reviewId)
    .first<InstallUrlCheckRow>();
  return row ? rowToStored(row) : null;
}

/**
 * Minimal stamp for the submission receipt: verdict and probe code only, so
 * the form can honor a block without learning the redirect chain.
 */
export async function installUrlCheckSummaryForVersion(
  reviewVersionId: string,
  env: Env
): Promise<InstallUrlCheckSummary | null> {
  const row = await env.DB.prepare(
    `SELECT verdict, probe_code, actor_role, created_at
       FROM install_url_checks
      WHERE review_version_id = ?
      ORDER BY created_at DESC, rowid DESC
      LIMIT 1`
  )
    .bind(reviewVersionId)
    .first<{ verdict: InstallUrlCheck['verdict']; probe_code: string | null; actor_role: 'developer' | 'reviewer'; created_at: string }>();
  return row
    ? { verdict: row.verdict, probeCode: row.probe_code, actorRole: row.actor_role, checkedAt: row.created_at }
    : null;
}

export interface RecordInstallUrlCheckInput {
  installUrl?: unknown;
  clientId?: unknown;
  capabilities?: unknown;
  configuredScopes?: unknown;
}

/**
 * Run the check and append it to the review. Developers may only stamp
 * reviews they own; reviewers may stamp any review. When a reviewer re-runs
 * without inputs, the previous run's install URL, client ID and capabilities
 * are reused so the re-check is a pure re-probe.
 */
export async function recordInstallUrlCheck(
  reviewId: string,
  input: RecordInstallUrlCheckInput,
  env: Env,
  user: AuthenticatedUser,
  options: ProbeOptions = {}
): Promise<StoredInstallUrlCheck | null> {
  const role = companionRoleForUser(user, env);
  const review = await env.DB.prepare(
    `SELECT id, latest_version_id FROM reviews
      WHERE id = ? AND (? = 1 OR (owner_user_id = ? AND site_id IS ?))`
  )
    .bind(reviewId, role === 'reviewer' ? 1 : 0, user.id, user.siteId)
    .first<{ id: string; latest_version_id: string }>();
  if (!review) return null;

  const previous = await latestInstallUrlCheck(reviewId, env);
  const installUrl =
    typeof input.installUrl === 'string' && input.installUrl.trim()
      ? input.installUrl.trim()
      : previous?.installUrl ?? '';
  if (!installUrl && !previous) {
    throw new InstallUrlCheckInputError('Enter the install URL from your Marketplace listing.');
  }
  if (installUrl.length > 4096) {
    throw new InstallUrlCheckInputError('Install URL is too long.');
  }
  const clientId =
    typeof input.clientId === 'string'
      ? input.clientId.trim() || null
      : input.clientId === undefined
        ? previous?.clientId ?? null
        : null;
  if (clientId && clientId.length > 128) {
    throw new InstallUrlCheckInputError('Client ID is too long.');
  }
  let capabilities = parseStringList(input.capabilities, 'capabilities');
  if (capabilities.length === 0) capabilities = previous?.capabilities ?? ['Data Client v2'];
  const configuredScopes =
    input.configuredScopes === undefined
      ? previous?.configuredScopes ?? null
      : parseStringList(input.configuredScopes, 'configuredScopes', 64);

  const result = await checkInstallUrl(
    { installUrl, clientId, capabilities, configuredScopes: configuredScopes ?? undefined },
    options
  );
  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO install_url_checks
        (id, review_id, review_version_id, actor_user_id, actor_role, install_url, client_id,
         capabilities_json, configured_scopes_json, verdict, probe_code, result_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id,
      reviewId,
      review.latest_version_id,
      user.id,
      role,
      installUrl,
      clientId,
      JSON.stringify(capabilities),
      configuredScopes ? JSON.stringify(configuredScopes) : null,
      result.verdict,
      result.probe?.code ?? null,
      JSON.stringify(result),
      createdAt
    ),
    env.DB.prepare(
      `INSERT INTO review_events
        (id, review_id, review_version_id, actor_user_id, event_type, payload_json, created_at)
       VALUES (?, ?, ?, ?, 'install_url_checked', ?, ?)`
    ).bind(
      crypto.randomUUID(),
      reviewId,
      review.latest_version_id,
      user.id,
      JSON.stringify({ checkId: id, actorRole: role, verdict: result.verdict, probeCode: result.probe?.code ?? null }),
      createdAt
    )
  ]);
  return {
    id,
    reviewVersionId: review.latest_version_id,
    actorRole: role,
    installUrl,
    clientId,
    capabilities,
    configuredScopes,
    createdAt,
    result
  };
}
