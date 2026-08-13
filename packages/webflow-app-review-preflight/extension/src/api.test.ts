import { afterEach, describe, expect, test, vi } from 'vitest';
import { createPreflightApi, PreflightAuthenticationError } from './api';

afterEach(() => {
  vi.unstubAllGlobals();
  delete (globalThis as typeof globalThis & { webflow?: unknown }).webflow;
});

describe('Preflight API', () => {
  test('creates a hosted runtime review through the authenticated Worker boundary', async () => {
    (globalThis as typeof globalThis & { webflow?: { getIdToken: () => Promise<string> } }).webflow = {
      getIdToken: async () => 'designer-id-token'
    };
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      Response.json({
        review: {
          id: 'runtime-review-1',
          name: 'Website Speedy runtime review'
        },
        submissionReceipt: {
          code: `wfpre_${'a'.repeat(32)}`,
          createdAt: '2026-07-15T23:00:00.000Z'
        }
      })
    );
    vi.stubGlobal('fetch', fetchMock);
    const input = {
      appName: 'Website Speedy',
      runtimeUrls: ['https://cdn.example.com/runtime-v1.js']
    };

    await expect(createPreflightApi().createRuntimeReview(input)).resolves.toMatchObject({
      review: { id: 'runtime-review-1' },
      submissionReceipt: { code: `wfpre_${'a'.repeat(32)}` }
    });
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringMatching(/\/v1\/runtime-reviews$/),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify(input),
        headers: expect.any(Headers)
      })
    );
    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers);
    expect(headers.get('authorization')).toBe('Bearer designer-id-token');
  });

  test('explains when a runtime-run request reaches an older live Worker', async () => {
    (globalThis as typeof globalThis & { webflow?: { getIdToken: () => Promise<string> } }).webflow = {
      getIdToken: async () => 'designer-id-token'
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ error: 'not_found' }), { status: 404 }))
    );

    await expect(createPreflightApi().requestRuntimeObservationRun('runtime-package-1')).rejects.toThrow(
      'The live preflight service is out of date. Ask a reviewer to deploy the runtime-run update, then try again.'
    );
  });

  test('turns a network failure into an actionable connection message', async () => {
    (globalThis as typeof globalThis & { webflow?: { getIdToken: () => Promise<string> } }).webflow = {
      getIdToken: async () => 'designer-id-token'
    };
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new TypeError('Failed to fetch');
    }));

    await expect(createPreflightApi().listReviews()).rejects.toThrow(
      'Preflight could not reach the review service. Check your connection, then try again.'
    );
  });

  test('identifies a Worker authorization failure as a reconnectable Webflow connection', async () => {
    (globalThis as typeof globalThis & { webflow?: { getIdToken: () => Promise<string> } }).webflow = {
      getIdToken: async () => 'designer-id-token'
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 }))
    );

    await expect(createPreflightApi().listReviews()).rejects.toBeInstanceOf(
      PreflightAuthenticationError
    );
  });
});
