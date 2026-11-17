import { env, exports } from 'cloudflare:workers';
import { describe, expect, test } from 'vitest';

const DEVELOPER = { authorization: 'Bearer test-token', origin: 'http://localhost:1337' };
const SERVICE = { authorization: 'Bearer review-artifact-fetch-test-token' };
const ZIP_BYTES = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2, 3, 4]);
const ZIP_SHA = 'a'.repeat(64);

async function createReview(): Promise<{ versionId: string; receipt: string }> {
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
    review: { latestVersion: { id: string } };
    submissionReceipt: { code: string };
  }>();
  return { versionId: created.review.latestVersion.id, receipt: created.submissionReceipt.code };
}

async function storeReviewZip(versionId: string): Promise<void> {
  const key = `test/source-maps/${versionId}.zip`;
  await env.ARTIFACTS.put(key, ZIP_BYTES);
  await env.DB.prepare(
    `UPDATE review_versions
        SET source_map_sha256 = ?, source_map_key = ?, source_map_file_name = ?
      WHERE id = ?`
  )
    .bind(ZIP_SHA, key, 'webflow-source-review.zip', versionId)
    .run();
}

function fetchArtifact(code: unknown, headers: Record<string, string> = SERVICE) {
  return exports.default.fetch(
    new Request('https://preflight.test/v1/submission-receipts/source-map-artifact', {
      method: 'POST',
      headers: { ...headers, 'content-type': 'application/json' },
      body: JSON.stringify({ code })
    })
  );
}

describe('review ZIP for a receipt', () => {
  test('the service token reads the stored ZIP', async () => {
    const review = await createReview();
    await storeReviewZip(review.versionId);

    const response = await fetchArtifact(review.receipt);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('application/zip');
    expect(response.headers.get('x-source-map-sha256')).toBe(ZIP_SHA);
    expect(response.headers.get('x-source-map-file-name')).toBe('webflow-source-review.zip');
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(ZIP_BYTES);
  });

  test('the receipt code alone is refused', async () => {
    const review = await createReview();
    await storeReviewZip(review.versionId);

    expect((await fetchArtifact(review.receipt, {})).status).toBe(401);
    expect((await fetchArtifact(review.receipt, DEVELOPER)).status).toBe(401);
  });

  test('a receipt without a stored ZIP, or an unknown code, is not found', async () => {
    const review = await createReview();
    expect((await fetchArtifact(review.receipt)).status).toBe(404);
    expect((await fetchArtifact(`wfpre_${'0'.repeat(32)}`)).status).toBe(404);
    expect((await fetchArtifact('not-a-receipt')).status).toBe(404);
  });
});
