import type { CompanionRun } from '@create-something/webflow-app-review-preflight';
import type { AuthenticatedUser, Env } from './types';

/**
 * The browser-companion WRITE paths (run creation, replay, completion, and
 * mission evidence) are retired. A partner-controlled browser can never
 * produce Webflow-trusted evidence, and reviewer companion sessions must not
 * mint `webflow_observed` receipts either — trusted evidence comes only from
 * the server-owned runtime observation pipeline.
 *
 * Historical companion runs remain readable so prior receipts stay auditable.
 */

function reviewerIds(env: Env): Set<string> {
  return new Set(
    (env.REVIEWER_USER_IDS ?? '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean)
  );
}

function actorRoleForUser(user: AuthenticatedUser, env: Env): 'developer' | 'reviewer' {
  if (user.companionSession) return user.companionSession.actorRole;
  return reviewerIds(env).has(user.id) ? 'reviewer' : 'developer';
}

export async function getCompanionRun(
  runId: string,
  env: Env,
  user: AuthenticatedUser
): Promise<CompanionRun | null> {
  const actorRole = actorRoleForUser(user, env);
  const row = await env.DB.prepare(
    `SELECT run_json
       FROM companion_runs
      WHERE id = ? AND (? = 'reviewer' OR owner_user_id = ? OR actor_user_id = ?)
        AND (? IS NULL OR (review_id = ? AND review_version_id = ?))`
  )
    .bind(
      runId,
      actorRole,
      user.id,
      user.id,
      user.companionSession?.reviewId ?? null,
      user.companionSession?.reviewId ?? null,
      user.companionSession?.reviewVersionId ?? null
    )
    .first<{ run_json: string }>();
  return row ? (JSON.parse(row.run_json) as CompanionRun) : null;
}
