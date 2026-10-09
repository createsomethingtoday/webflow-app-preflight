import { env, exports } from 'cloudflare:workers';
import { afterEach, describe, expect, test, vi } from 'vitest';

const CLIENT_ID = 'd0a488aa5884654d34106a6d64d00019138b3be57a4364e7b6f19ed34c7b9ede';
const DEVELOPER = { authorization: 'Bearer test-token', origin: 'http://localhost:1337' };
const REVIEWER = { authorization: 'Bearer reviewer-test-token', origin: 'http://localhost:1337' };

afterEach(() => {
  vi.unstubAllGlobals();
});

function stubInstallHost(target: string) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url === 'https://app.acme.dev/install') {
        return new Response(null, { status: 302, headers: { location: target } });
      }
      if (url === 'https://app.acme.dev/dead') {
        return new Response('gone', { status: 404 });
      }
      return new Response('unexpected', { status: 599 });
    })
  );
}

async function createDataClientReview(): Promise<{ id: string; versionId: string; receipt: string }> {
  const response = await exports.default.fetch(
    new Request('https://preflight.test/v1/runtime-reviews', {
      method: 'POST',
      headers: { ...DEVELOPER, 'content-type': 'application/json' },
      body: JSON.stringify({
        appName: 'Acme Sync',
        runtimeUrls: ['https://cdn.acme.dev/runtime/v1/acme-sync.js']
      })
    })
  );
  expect(response.status).toBe(201);
  const created = await response.json<{
    review: { id: string; latestVersion: { id: string } };
    submissionReceipt: { code: string };
  }>();
  return { id: created.review.id, versionId: created.review.latestVersion.id, receipt: created.submissionReceipt.code };
}

async function postCheck(reviewId: string, body: unknown, headers = DEVELOPER) {
  return exports.default.fetch(
    new Request(`https://preflight.test/v1/reviews/${reviewId}/install-url-check`, {
      method: 'POST',
      headers: { ...headers, 'content-type': 'application/json' },
      body: JSON.stringify(body)
    })
  );
}

describe('install URL checks on a review', () => {
  test('developer records a check; it appears on the review and the receipt', async () => {
    stubInstallHost(`https://webflow.com/oauth/authorize?response_type=code&client_id=${CLIENT_ID}&scope=sites%3Aread+cms%3Aread`);
    const review = await createDataClientReview();

    const response = await postCheck(review.id, {
      installUrl: 'https://app.acme.dev/install',
      clientId: CLIENT_ID,
      capabilities: ['Data Client v2']
    });
    expect(response.status).toBe(201);
    const { installUrlCheck } = await response.json<{
      installUrlCheck: { actorRole: string; reviewVersionId: string; result: { verdict: string; probe: { code: string } } };
    }>();
    expect(installUrlCheck.actorRole).toBe('developer');
    expect(installUrlCheck.reviewVersionId).toBe(review.versionId);
    expect(installUrlCheck.result.verdict).toBe('pass');
    expect(installUrlCheck.result.probe.code).toBe('reaches_authorize');

    const fetched = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${review.id}`, { headers: DEVELOPER })
    );
    const body = await fetched.json<{ review: { installUrlCheck: { installUrl: string; result: { verdict: string } } } }>();
    expect(body.review.installUrlCheck.installUrl).toBe('https://app.acme.dev/install');
    expect(body.review.installUrlCheck.result.verdict).toBe('pass');

    const verify = await exports.default.fetch(
      new Request('https://preflight.test/v1/submission-receipts/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code: review.receipt })
      })
    );
    const verified = await verify.json<{ receipt: { installUrl: Record<string, unknown> } }>();
    expect(verified.receipt.installUrl).toEqual({
      verdict: 'pass',
      probeCode: 'reaches_authorize',
      actorRole: 'developer',
      checkedAt: expect.any(String)
    });
    expect(Object.keys(verified.receipt.installUrl)).not.toContain('hops');

    const events = await env.DB.prepare(
      `SELECT event_type, payload_json FROM review_events WHERE review_id = ? AND event_type = 'install_url_checked'`
    )
      .bind(review.id)
      .all<{ event_type: string; payload_json: string }>();
    expect(events.results).toHaveLength(1);
    expect(JSON.parse(events.results[0]!.payload_json)).toMatchObject({ actorRole: 'developer', verdict: 'pass' });
  });

  test('a blocked install URL is stamped as a block on the receipt', async () => {
    stubInstallHost('unused');
    const review = await createDataClientReview();
    const response = await postCheck(review.id, { installUrl: 'https://app.acme.dev/dead', capabilities: 'Hybrid' });
    expect(response.status).toBe(201);
    const { installUrlCheck } = await response.json<{ installUrlCheck: { result: { verdict: string; probe: { code: string } } } }>();
    expect(installUrlCheck.result.verdict).toBe('block');
    expect(installUrlCheck.result.probe.code).toBe('not_found');

    const verify = await exports.default.fetch(
      new Request('https://preflight.test/v1/submission-receipts/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code: review.receipt })
      })
    );
    const verified = await verify.json<{ receipt: { installUrl: { verdict: string; probeCode: string } } }>();
    expect(verified.receipt.installUrl.verdict).toBe('block');
    expect(verified.receipt.installUrl.probeCode).toBe('not_found');
  });

  test('receipt carries null until a check is recorded', async () => {
    const review = await createDataClientReview();
    const verify = await exports.default.fetch(
      new Request('https://preflight.test/v1/submission-receipts/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code: review.receipt })
      })
    );
    const verified = await verify.json<{ receipt: { installUrl: unknown } }>();
    expect(verified.receipt.installUrl).toBeNull();
  });

  test('rejects an empty first check and oversized input', async () => {
    const review = await createDataClientReview();
    const empty = await postCheck(review.id, {});
    expect(empty.status).toBe(400);
    expect((await empty.json<{ error: string }>()).error).toBe('invalid_install_url_check');
    const long = await postCheck(review.id, { installUrl: `https://a.dev/${'x'.repeat(5000)}` });
    expect(long.status).toBe(400);
  });

  test('another developer cannot stamp a review they do not own', async () => {
    const review = await createDataClientReview();
    // The reviewer dev token resolves to a different developer identity when
    // REVIEWER_USER_IDS does not grant it the reviewer role for this call.
    const original = env.REVIEWER_USER_IDS;
    (env as { REVIEWER_USER_IDS?: string }).REVIEWER_USER_IDS = '';
    try {
      const response = await postCheck(review.id, { installUrl: 'https://app.acme.dev/install' }, REVIEWER);
      expect(response.status).toBe(404);
    } finally {
      (env as { REVIEWER_USER_IDS?: string }).REVIEWER_USER_IDS = original;
    }
  });

  test('reviewer re-check reuses stored inputs and adds configured scopes for IU-8', async () => {
    stubInstallHost(`https://webflow.com/oauth/authorize?response_type=code&client_id=${CLIENT_ID}&scope=sites%3Aread+cms%3Awrite`);
    const review = await createDataClientReview();
    await postCheck(review.id, { installUrl: 'https://app.acme.dev/install', clientId: CLIENT_ID });

    const response = await postCheck(review.id, { configuredScopes: ['sites:read'] }, REVIEWER);
    expect(response.status).toBe(201);
    const { installUrlCheck } = await response.json<{
      installUrlCheck: {
        actorRole: string;
        installUrl: string;
        clientId: string;
        configuredScopes: string[];
        result: { verdict: string; findings: { rule: string; severity: string }[] };
      };
    }>();
    expect(installUrlCheck.actorRole).toBe('reviewer');
    expect(installUrlCheck.installUrl).toBe('https://app.acme.dev/install');
    expect(installUrlCheck.clientId).toBe(CLIENT_ID);
    expect(installUrlCheck.configuredScopes).toEqual(['sites:read']);
    expect(installUrlCheck.result.verdict).toBe('block');
    expect(installUrlCheck.result.findings).toContainEqual(expect.objectContaining({ rule: 'IU-8', severity: 'block' }));

    const fetched = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${review.id}`, { headers: DEVELOPER })
    );
    const body = await fetched.json<{ review: { installUrlCheck: { actorRole: string } } }>();
    expect(body.review.installUrlCheck.actorRole).toBe('reviewer');
  });
});
