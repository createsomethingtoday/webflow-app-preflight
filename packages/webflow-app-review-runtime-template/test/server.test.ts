import { describe, expect, it, vi } from 'vitest';
import {
  LAUNCH_SECRET_HEADER,
  createRuntimeTemplateHandler,
  type RuntimeProcessLauncher
} from '../src/server.js';

const EXPECTED_API_ORIGIN =
  'https://webflow-app-review-preflight.createsomething.workers.dev';
const input = {
  observationJobId: '7615de67-693e-467c-8b3c-947dbcbc308c',
  apiBaseUrl: EXPECTED_API_ORIGIN,
  capability: 'job-scoped-secret-capability'
};

function request(body: unknown = input): Request {
  return new Request('http://127.0.0.1:3000/run', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
}

function launcher(): RuntimeProcessLauncher & { launch: ReturnType<typeof vi.fn> } {
  return { launch: vi.fn().mockResolvedValue(undefined) };
}

describe('immutable runtime template interface', () => {
  it('starts the baked runner once without returning its capability', async () => {
    const runtime = launcher();
    const handle = createRuntimeTemplateHandler({
      expectedApiOrigin: EXPECTED_API_ORIGIN,
      runtime
    });

    const response = await handle(request());
    const text = await response.text();

    expect(response.status).toBe(202);
    expect(JSON.parse(text)).toEqual({ accepted: true });
    expect(text).not.toContain(input.capability);
    expect(runtime.launch).toHaveBeenCalledOnce();
    expect(runtime.launch).toHaveBeenCalledWith(input);

    const replay = await handle(request());
    expect(replay.status).toBe(409);
    expect(runtime.launch).toHaveBeenCalledOnce();
  });

  it('rejects query-bearing launch routes before capability handling', async () => {
    const runtime = launcher();
    const handle = createRuntimeTemplateHandler({
      expectedApiOrigin: EXPECTED_API_ORIGIN,
      runtime
    });
    const response = await handle(
      new Request('http://127.0.0.1:3000/run?forward=https://attacker.example', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(input)
      })
    );

    expect(response.status).toBe(404);
    expect(runtime.launch).not.toHaveBeenCalled();
  });

  it('FIX6: releases the reservation when launch fails so a retry can succeed', async () => {
    const runtime: RuntimeProcessLauncher & { launch: ReturnType<typeof vi.fn> } = {
      launch: vi
        .fn()
        .mockRejectedValueOnce(new Error('transient spawn failure'))
        .mockResolvedValueOnce(undefined)
    };
    const handle = createRuntimeTemplateHandler({
      expectedApiOrigin: EXPECTED_API_ORIGIN,
      runtime
    });

    const failed = await handle(request());
    expect(failed.status).toBe(500);
    expect(JSON.parse(await failed.text())).toEqual({ error: 'runner_start_failed' });

    // A retry after a transient failure must not be permanently bricked with 409.
    const retried = await handle(request());
    expect(retried.status).toBe(202);
    expect(runtime.launch).toHaveBeenCalledTimes(2);
  });

  it('FIX7: requires the launch secret when one is configured', async () => {
    const secret = 'per-sandbox-launch-secret-value';
    const runtime = launcher();
    const handle = createRuntimeTemplateHandler({
      expectedApiOrigin: EXPECTED_API_ORIGIN,
      runtime,
      launchSecret: secret
    });

    const missing = await handle(request());
    expect(missing.status).toBe(401);
    expect(runtime.launch).not.toHaveBeenCalled();

    const wrong = await handle(
      new Request('http://127.0.0.1:3000/run', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          [LAUNCH_SECRET_HEADER]: 'not-the-secret'
        },
        body: JSON.stringify(input)
      })
    );
    expect(wrong.status).toBe(401);
    expect(runtime.launch).not.toHaveBeenCalled();

    const correct = await handle(
      new Request('http://127.0.0.1:3000/run', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          [LAUNCH_SECRET_HEADER]: secret
        },
        body: JSON.stringify(input)
      })
    );
    expect(correct.status).toBe(202);
    expect(runtime.launch).toHaveBeenCalledOnce();
  });

  it('FIX7: enforces no in-sandbox secret when none is configured', async () => {
    const runtime = launcher();
    const handle = createRuntimeTemplateHandler({
      expectedApiOrigin: EXPECTED_API_ORIGIN,
      runtime
    });
    const response = await handle(request());
    expect(response.status).toBe(202);
    expect(runtime.launch).toHaveBeenCalledOnce();
  });
});
