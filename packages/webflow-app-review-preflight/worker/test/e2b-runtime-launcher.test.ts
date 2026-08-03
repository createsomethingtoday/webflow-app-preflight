import { describe, expect, it, vi } from 'vitest';
import {
  E2BRuntimeLaunchError,
  launchRuntimeObservationInE2B,
  terminateRuntimeObservationInE2B
} from '../src/e2b-runtime-launcher';
import type { Env } from '../src/types';

const input = {
  observationJobId: '7615de67-693e-467c-8b3c-947dbcbc308c',
  apiBaseUrl: 'https://webflow-app-review-preflight.createsomething.workers.dev',
  capability: 'job-scoped-secret-capability'
};

describe('E2B runtime launcher', () => {
  it('rejects a mutable template name or tag before contacting E2B', async () => {
    const request = vi.fn();
    vi.stubGlobal('fetch', request);
    const env = {
      E2B_API_KEY: 'e2b-test-key',
      E2B_RUNTIME_TEMPLATE_ID: 'app-review-companion-runtime:latest'
    } as Env;

    try {
      await expect(launchRuntimeObservationInE2B(input, env)).rejects.toEqual(
        new E2BRuntimeLaunchError('configuration')
      );
      expect(request).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('deletes a partially launched sandbox and exposes only the safe start stage', async () => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json(
          {
            templateID: '040h2lvinyukiy8eym45',
            sandboxID: 'sandbox-partial-123',
            trafficAccessToken: 'traffic-access-token'
          },
          { status: 201 }
        )
      )
      .mockResolvedValueOnce(new Response(`provider rejected ${input.capability}`, { status: 500 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(Response.json({ error: 'not_found' }, { status: 404 }));
    vi.stubGlobal('fetch', request);
    const env = {
      E2B_API_KEY: 'e2b-test-key',
      E2B_RUNTIME_TEMPLATE_ID: 'app-review-companion-runtime:f47ac10b-58cc-4372-a567-0e02b2c3d479'
    } as Env;

    try {
      const failure = await launchRuntimeObservationInE2B(input, env).catch(
        (error: unknown) => error
      );
      expect(failure).toBeInstanceOf(E2BRuntimeLaunchError);
      expect(failure).toMatchObject({
        stage: 'runner_start',
        sandboxId: 'sandbox-partial-123',
        terminationStatus: 'verified'
      });
      expect(String(failure)).not.toContain(input.capability);
      expect(request).toHaveBeenCalledTimes(4);
      expect(request.mock.calls[2]?.[0]).toBe('https://api.e2b.app/sandboxes/sandbox-partial-123');
      expect(request.mock.calls[2]?.[1]).toMatchObject({ method: 'DELETE' });
      expect(request.mock.calls[3]?.[0]).toBe('https://api.e2b.app/sandboxes/sandbox-partial-123');
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('injects a fresh per-sandbox launch secret and sends it only on the sandbox /run call', async () => {
    const observed: Array<{ url: string; headers: Record<string, string>; body: any }> = [];
    const mockFetch = vi.fn<typeof fetch>(async (target, init) => {
      const url = String(target);
      const headers = Object.fromEntries(new Headers(init?.headers).entries());
      const body = init?.body ? JSON.parse(String(init.body)) : null;
      observed.push({ url, headers, body });
      if (url === 'https://api.e2b.app/sandboxes') {
        return Response.json(
          {
            templateID: '040h2lvinyukiy8eym45',
            sandboxID: `sandbox-secret-${observed.length}`,
            trafficAccessToken: 'traffic-access-token'
          },
          { status: 201 }
        );
      }
      return new Response(JSON.stringify({ accepted: true }), { status: 202 });
    });
    vi.stubGlobal('fetch', mockFetch);
    const env = {
      E2B_API_KEY: 'e2b-test-key',
      E2B_RUNTIME_TEMPLATE_ID: 'app-review-companion-runtime:f47ac10b-58cc-4372-a567-0e02b2c3d479'
    } as Env;

    try {
      const first = await launchRuntimeObservationInE2B(input, env);
      const second = await launchRuntimeObservationInE2B(input, env);

      const [createA, runA, createB, runB] = observed;
      const secretA = createA!.body.envVars.APP_REVIEW_RUNTIME_LAUNCH_SECRET as string;
      const secretB = createB!.body.envVars.APP_REVIEW_RUNTIME_LAUNCH_SECRET as string;

      // Fresh, cryptographically sized, per-sandbox secret.
      expect(secretA).toMatch(/^[A-Za-z0-9_-]{40,}$/);
      expect(secretB).toMatch(/^[A-Za-z0-9_-]{40,}$/);
      expect(secretA).not.toBe(secretB);
      expect(secretA).not.toBe(input.capability);

      // Sent to the sandbox /run route in the agreed header.
      expect(runA!.url).toContain('/run');
      expect(runA!.headers['x-webflow-runtime-launch-secret']).toBe(secretA);
      expect(runB!.headers['x-webflow-runtime-launch-secret']).toBe(secretB);

      // Never appears in the /run body, the create metadata, or the value
      // returned toward any user surface.
      expect(JSON.stringify(runA!.body)).not.toContain(secretA);
      expect(JSON.stringify(createA!.body.metadata)).not.toContain(secretA);
      expect(JSON.stringify(first)).not.toContain(secretA);
      expect(JSON.stringify(second)).not.toContain(secretB);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('verifies sandbox termination through an E2B 404 read-back', async () => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(Response.json({ error: 'not_found' }, { status: 404 }));
    vi.stubGlobal('fetch', request);
    const env = { E2B_API_KEY: 'e2b-test-key' } as Env;

    try {
      await expect(terminateRuntimeObservationInE2B('sandbox-complete-123', env)).resolves.toBe(
        'verified'
      );
      expect(request).toHaveBeenCalledTimes(2);
      expect(request.mock.calls[0]?.[1]).toMatchObject({
        method: 'DELETE',
        signal: expect.any(AbortSignal)
      });
      expect(request.mock.calls[1]?.[1]).toMatchObject({
        signal: expect.any(AbortSignal)
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
