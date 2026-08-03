import { spawn } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import { closeSync, openSync } from 'node:fs';

const MAX_REQUEST_BYTES = 8_192;
// Header the Worker must send on POST /run, carrying the per-sandbox launch
// secret injected as APP_REVIEW_RUNTIME_LAUNCH_SECRET at sandbox create time.
export const LAUNCH_SECRET_HEADER = 'x-webflow-runtime-launch-secret';
const OBSERVATION_JOB_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface RuntimeTemplateInput {
  observationJobId: string;
  apiBaseUrl: string;
  capability: string;
}

export interface RuntimeProcessLauncher {
  launch(input: RuntimeTemplateInput): Promise<void>;
}

interface RuntimeTemplateHandlerOptions {
  expectedApiOrigin: string;
  runtime: RuntimeProcessLauncher;
  // Per-sandbox shared secret. When set, POST /run must present it in the
  // LAUNCH_SECRET_HEADER; when unset, no in-sandbox authentication is enforced
  // (E2B's per-sandbox token remains the only control).
  launchSecret?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Constant-time secret comparison. Both sides are hashed to a fixed 32 bytes so
// timingSafeEqual never sees unequal lengths (which would throw and could leak
// the secret length).
function secretMatches(provided: string | null, expected: string): boolean {
  if (provided === null) return false;
  const providedDigest = createHash('sha256').update(provided).digest();
  const expectedDigest = createHash('sha256').update(expected).digest();
  return timingSafeEqual(providedDigest, expectedDigest);
}

function isExactInput(
  value: unknown,
  expectedApiOrigin: string
): value is RuntimeTemplateInput {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value).sort();
  if (keys.join(',') !== 'apiBaseUrl,capability,observationJobId') return false;
  if (
    typeof value.observationJobId !== 'string' ||
    !OBSERVATION_JOB_ID.test(value.observationJobId) ||
    typeof value.apiBaseUrl !== 'string' ||
    value.apiBaseUrl !== expectedApiOrigin ||
    typeof value.capability !== 'string' ||
    value.capability.length < 20 ||
    value.capability.length > 4_096
  ) {
    return false;
  }
  return true;
}

function json(status: number, body: Record<string, unknown>): Response {
  return Response.json(body, {
    status,
    headers: { 'cache-control': 'no-store' }
  });
}

export function createRuntimeTemplateHandler({
  expectedApiOrigin,
  runtime,
  launchSecret
}: RuntimeTemplateHandlerOptions): (request: Request) => Promise<Response> {
  let launchReserved = false;

  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.pathname === '/health' && request.method === 'GET') {
      return json(200, { ready: true });
    }
    if (url.pathname !== '/run' || url.search || url.hash) {
      return json(404, { error: 'not_found' });
    }
    if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' });
    // In-sandbox backstop: when a launch secret is configured, require it before
    // any launch work so a caller merely reaching the port cannot burn the
    // one-shot launch (FIX 7).
    if (launchSecret !== undefined && !secretMatches(request.headers.get(LAUNCH_SECRET_HEADER), launchSecret)) {
      return json(401, { error: 'unauthorized' });
    }
    if (request.headers.get('content-type')?.split(';')[0]?.trim() !== 'application/json') {
      return json(415, { error: 'unsupported_media_type' });
    }
    const declaredLength = Number(request.headers.get('content-length') ?? 0);
    if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BYTES) {
      return json(413, { error: 'request_too_large' });
    }

    let text: string;
    let parsed: unknown;
    try {
      text = await request.text();
      if (new TextEncoder().encode(text).byteLength > MAX_REQUEST_BYTES) {
        return json(413, { error: 'request_too_large' });
      }
      parsed = JSON.parse(text);
    } catch {
      return json(400, { error: 'invalid_request' });
    }
    if (!isExactInput(parsed, expectedApiOrigin)) {
      return json(400, { error: 'invalid_request' });
    }
    if (launchReserved) return json(409, { error: 'already_started' });

    launchReserved = true;
    try {
      await runtime.launch(parsed);
    } catch {
      // A transient spawn failure must release the one-shot reservation so a
      // retry is not permanently bricked with 409 already_started (FIX 6).
      launchReserved = false;
      return json(500, { error: 'runner_start_failed' });
    }
    return json(202, { accepted: true });
  };
}

export const bakedRuntimeProcessLauncher: RuntimeProcessLauncher = {
  async launch(input) {
    const output = openSync('/tmp/app-review-runtime.log', 'a', 0o600);
    const child = spawn(
      process.execPath,
      ['/app/runner.mjs', '--api-base', input.apiBaseUrl, '--job', input.observationJobId],
      {
        cwd: '/app',
        detached: true,
        env: {
          HOME: process.env.HOME ?? '/home/user',
          LANG: process.env.LANG ?? 'C.UTF-8',
          PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
          PLAYWRIGHT_BROWSERS_PATH: '0',
          RUNTIME_OBSERVATION_CAPABILITY: input.capability
        },
        stdio: ['ignore', output, output]
      }
    );

    await new Promise<void>((resolve, reject) => {
      child.once('spawn', resolve);
      child.once('error', reject);
    }).finally(() => closeSync(output));
    child.unref();
  }
};
