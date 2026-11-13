import { json } from "./http";
import type { Env } from "./types";

/**
 * Caps on paid sandbox launches, shared by boot tests and runtime
 * observation runs. Call `checkSandboxLimits` before a job row is inserted.
 *
 * - Per user: jobs started in the trailing 24 hours, across both tables.
 *   Neither table stores who pressed the button for an observation run, so
 *   observation jobs count against the runtime test package owner; boot test
 *   jobs count against `requested_by_user_id` for the developer role.
 * - Per user, at once: that user's jobs that are launched and not yet
 *   finished or expired. Without it one developer could fill the global pool.
 * - Global: jobs that are launched and not yet finished or expired.
 */

const DEFAULT_DAILY_LIMIT_PER_USER = 30;
const DEFAULT_ACTIVE_LIMIT = 20;
const DEFAULT_ACTIVE_LIMIT_PER_USER = 3;
const WINDOW_MS = 24 * 60 * 60 * 1000;

export interface SandboxLimitHit {
  scope: "user" | "global";
  message: string;
  retryAfterSeconds?: number;
}

export class SandboxLimitError extends Error {
  constructor(readonly hit: SandboxLimitHit) {
    super(hit.message);
  }
}

function positiveInteger(value: string | undefined, fallback: number): number {
  const text = value?.trim() ?? "";
  if (!/^[1-9]\d{0,8}$/.test(text)) return fallback;
  return Number(text);
}

export function sandboxLimitResponse(
  hit: SandboxLimitHit,
  origin: string | null,
): Response {
  return json(
    {
      error: "sandbox_limit_reached",
      message: hit.message,
      ...(hit.retryAfterSeconds !== undefined
        ? { retryAfterSeconds: hit.retryAfterSeconds }
        : {}),
    },
    429,
    origin,
  );
}

function secondsUntil(
  iso: string | null | undefined,
  nowMs: number,
): number | undefined {
  const target = iso ? Date.parse(iso) : NaN;
  if (!Number.isFinite(target)) return undefined;
  return Math.max(1, Math.ceil((target - nowMs) / 1000));
}

// Jobs one user started since `?2`. Indexes on packages (owner_user_id,
// created_at) and jobs (test_package_id, created_at) bound the observation side.
const USER_JOBS = `
  SELECT j.created_at AS created_at
    FROM boot_test_jobs j
   WHERE j.requested_by_user_id = ?1 AND j.actor_role = 'developer' AND j.created_at > ?2
  UNION ALL
  SELECT o.created_at
    FROM runtime_test_packages p
    JOIN runtime_observation_jobs o ON o.test_package_id = p.id
   WHERE p.owner_user_id = ?1 AND o.created_at > ?2`;

// The same attribution as USER_JOBS, for jobs that are active at `?2`.
const USER_ACTIVE_JOBS = `
  SELECT j.expires_at AS expires_at
    FROM boot_test_jobs j
   WHERE j.requested_by_user_id = ?1 AND j.actor_role = 'developer'
     AND j.status IN ('approved', 'running') AND j.expires_at > ?2
  UNION ALL
  SELECT o.expires_at
    FROM runtime_test_packages p
    JOIN runtime_observation_jobs o ON o.test_package_id = p.id
   WHERE p.owner_user_id = ?1
     AND o.status IN ('approved', 'running', 'uploading') AND o.expires_at > ?2`;

const ACTIVE_JOBS = `
  SELECT expires_at FROM boot_test_jobs
   WHERE status IN ('approved', 'running') AND expires_at > ?1
  UNION ALL
  SELECT expires_at FROM runtime_observation_jobs
   WHERE status IN ('approved', 'running', 'uploading') AND expires_at > ?1`;

/**
 * Returns the limit that blocks a new job, or null when one may start.
 * `exemptFromUserLimit` is for reviewers; the global limit always applies.
 */
export async function checkSandboxLimits(
  env: Env,
  options: { userId: string; exemptFromUserLimit: boolean },
): Promise<SandboxLimitHit | null> {
  const nowMs = Date.now();
  const now = new Date(nowMs).toISOString();

  const activeLimit = positiveInteger(
    env.SANDBOX_ACTIVE_LIMIT,
    DEFAULT_ACTIVE_LIMIT,
  );
  const active = await env.DB.prepare(
    `SELECT COUNT(*) AS count, MIN(expires_at) AS next_expiry FROM (${ACTIVE_JOBS})`,
  )
    .bind(now)
    .first<{ count: number; next_expiry: string | null }>();
  if ((active?.count ?? 0) >= activeLimit) {
    return {
      scope: "global",
      message:
        "Too many boot tests and runtime runs are running right now. Wait a few minutes and try again.",
      retryAfterSeconds: secondsUntil(active?.next_expiry, nowMs),
    };
  }

  if (options.exemptFromUserLimit) return null;

  const userActiveLimit = positiveInteger(
    env.SANDBOX_ACTIVE_LIMIT_PER_USER,
    DEFAULT_ACTIVE_LIMIT_PER_USER,
  );
  const mine = await env.DB.prepare(
    `SELECT COUNT(*) AS count, MIN(expires_at) AS next_expiry FROM (${USER_ACTIVE_JOBS})`,
  )
    .bind(options.userId, now)
    .first<{ count: number; next_expiry: string | null }>();
  if ((mine?.count ?? 0) >= userActiveLimit) {
    return {
      scope: "user",
      message: `You have ${mine?.count} boot tests and runtime runs in progress. Wait for one to finish, then try again.`,
      retryAfterSeconds: secondsUntil(mine?.next_expiry, nowMs),
    };
  }

  const userLimit = positiveInteger(
    env.SANDBOX_DAILY_LIMIT_PER_USER,
    DEFAULT_DAILY_LIMIT_PER_USER,
  );
  const since = new Date(nowMs - WINDOW_MS).toISOString();
  const used = await env.DB.prepare(
    `SELECT COUNT(*) AS count FROM (${USER_JOBS})`,
  )
    .bind(options.userId, since)
    .first<{ count: number }>();
  const count = used?.count ?? 0;
  if (count < userLimit) return null;

  // The job whose age-out frees the first slot.
  const freeing = await env.DB.prepare(
    `SELECT created_at FROM (${USER_JOBS}) ORDER BY created_at ASC LIMIT 1 OFFSET ?3`,
  )
    .bind(options.userId, since, count - userLimit)
    .first<{ created_at: string }>();
  const freedAt = freeing
    ? new Date(Date.parse(freeing.created_at) + WINDOW_MS).toISOString()
    : null;
  return {
    scope: "user",
    message: `You reached the limit of ${userLimit} boot tests and runtime runs in 24 hours. Try again later.`,
    retryAfterSeconds: secondsUntil(freedAt, nowMs),
  };
}
