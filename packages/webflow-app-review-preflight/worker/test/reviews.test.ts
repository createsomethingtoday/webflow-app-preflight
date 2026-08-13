import { env, exports } from 'cloudflare:workers';
import JSZip from 'jszip';
import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  evaluateRuntimeSecurity,
  reconcileRuntimeObservationJobs
} from '../src/runtime-observations';
import { recordWebflowAuthorizationReadiness } from '../src/webflow-authorization';
import { isPrivateOrLocalHostname } from '../src/net';
import worker from '../src/index';
import type { Env } from '../src/types';

const TEST_RUNTIME_INTEGRITY = 'sha256-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=';

afterEach(() => {
  vi.unstubAllGlobals();
});

async function createBundle(
  options: { injectScript?: boolean; seed?: string } = {}
): Promise<Uint8Array> {
  const zip = new JSZip();
  zip.file(
    'webflow.json',
    JSON.stringify({ name: 'Consent Pro', apiVersion: '2', publicDir: 'dist' })
  );
  if (options.seed) {
    zip.file('assets/seed.txt', options.seed);
  }
  const source = [
    'const API = "https://api.consentpro.com";',
    'const runtime = "/v2/cdn/runtime.js";'
  ];
  if (options.injectScript !== false) {
    source.push('const script = document.createElement("script");', 'script.src = runtime;');
  }
  zip.file('assets/index.js', source.join('\n'));
  return zip.generateAsync({ type: 'uint8array' });
}

async function sha256Hex(value: ArrayBuffer | Uint8Array | string): Promise<string> {
  const bytes =
    typeof value === 'string'
      ? new TextEncoder().encode(value)
      : value instanceof Uint8Array
        ? value
        : new Uint8Array(value);
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function createReadyRuntimePackage(reviewId: string): Promise<string> {
  const response = await exports.default.fetch(
    new Request(`https://preflight.test/v1/reviews/${reviewId}/runtime-test-packages`, {
      method: 'POST',
      headers: {
        authorization: 'Bearer test-token',
        origin: 'http://localhost:1337',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        targetUrl: 'http://127.0.0.1:4173/runtime-fixture',
        sandboxInstallationId: 'local-webflow-site',
        sandboxOwnershipConfirmed: true,
        license: {
          mode: 'installation_allowlist',
          expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString()
        },
        runtimeArtifacts: [
          {
          url: 'http://127.0.0.1:4173/runtime-v1.js',
          sha256: 'a'.repeat(64),
          integrity: TEST_RUNTIME_INTEGRITY
          }
        ],
        negativeProxyProbe: {
          method: 'GET',
          urlTemplate: 'http://127.0.0.1:4173/proxy?url={canaryUrl}'
        },
        lifecycle: { readySelector: '[data-runtime-ready]' }
      })
    })
  );
  expect(response.status).toBe(201);
  const body = await response.json<{ testPackage: { id: string } }>();
  return body.testPackage.id;
}

describe('review API', () => {
  test('derives a blocked security verdict from click-only or substituted runtime evidence', () => {
    const contract = {
      target: { url: 'https://consent-pro-test.webflow.io/', host: 'consent-pro-test.webflow.io' },
      runtimeArtifacts: [
        {
        url: 'https://api.consentpro.com/v2/cdn/runtime.js',
        sha256: 'a'.repeat(64),
        integrity: 'sha256-reviewed-runtime'
        }
      ]
    } as any;
    const result = evaluateRuntimeSecurity(
      {
      runtimeReadyObserved: false,
        runtimeArtifacts: [
          {
        url: contract.runtimeArtifacts[0].url,
        observedSha256: 'b'.repeat(64),
        loadedByPage: false,
        domIntegrity: null
          }
        ],
      runtimeCreatedScripts: ['https://api.consentpro.com/v2/cdn/debugger.js'],
      unreviewedRuntimeScripts: ['https://api.consentpro.com/v2/cdn/debugger.js'],
      negativeProxyCanary: { outcome: 'exposed' }
      },
      contract
    );

    expect(result.status).toBe('blocked');
    expect(result.predicates).toEqual({
      publishedTarget: true,
      runtimeReadyObserved: false,
      runtimeLoadedByPage: false,
      runtimeHashMatched: false,
      runtimeIntegrityMatched: false,
      noRuntimeCreatedScripts: false,
      noUnreviewedRuntimeScripts: false,
      negativeProxyBlocked: false,
      proxyPolicySatisfied: false,
      runtimeSourceMapAvailable: false
    });
    expect(result.blockers).toHaveLength(8);
  });

  test('requires every file in a runtime set to load and match its own pins', () => {
    const runtimeArtifacts = [
      {
        url: 'https://api.consentpro.com/v2/cdn/runtime.js',
        sha256: 'a'.repeat(64),
        integrity: 'sha256-runtime'
      },
      {
        url: 'https://api.consentpro.com/v2/cdn/preferences.js',
        sha256: 'b'.repeat(64),
        integrity: 'sha256-preferences'
      }
    ];
    const contract = {
      target: { url: 'https://consent-pro-test.webflow.io/', host: 'consent-pro-test.webflow.io' },
      runtimeArtifacts
    } as any;
    const manifest = {
      runtimeReadyObserved: true,
      runtimeArtifacts: [
        {
          url: runtimeArtifacts[0].url,
          observedSha256: runtimeArtifacts[0].sha256,
          loadedByPage: true,
          domIntegrity: runtimeArtifacts[0].integrity,
          sourceMap: { available: true, url: `${runtimeArtifacts[0].url}.map` }
        },
        {
          url: runtimeArtifacts[1].url,
          observedSha256: 'c'.repeat(64),
          loadedByPage: true,
          domIntegrity: runtimeArtifacts[1].integrity,
          sourceMap: { available: true, url: `${runtimeArtifacts[1].url}.map` }
        }
      ],
      runtimeCreatedScripts: [],
      unreviewedRuntimeScripts: [],
      negativeProxyCanary: { outcome: 'blocked' }
    };

    const blocked = evaluateRuntimeSecurity(manifest, contract);
    expect(blocked.status).toBe('blocked');
    expect(blocked.predicates.runtimeLoadedByPage).toBe(true);
    expect(blocked.predicates.runtimeHashMatched).toBe(false);
    expect(blocked.blockers).toContain(
      'The executed runtime bytes did not match the pinned SHA-256.'
    );

    const passed = evaluateRuntimeSecurity(
      {
        ...manifest,
        runtimeArtifacts: manifest.runtimeArtifacts.map((artifact, index) => ({
          ...artifact,
          observedSha256: runtimeArtifacts[index].sha256
        }))
      },
      contract
    );
    expect(passed.status).toBe('passed');
    expect(passed.blockers).toEqual([]);
  });

  test('accepts a genuinely runtime-created child pin but keeps a no-proxy declaration behind manual review', () => {
    const runtimeArtifacts = [
      {
        url: 'https://api.concord.tech/site-v1/site-id/site-client',
        sha256: 'a'.repeat(64),
        integrity: 'sha256-entry',
        loadMode: 'document' as const
      },
      {
        url: 'https://api.concord.tech/site-v1/site-id/widget',
        sha256: 'b'.repeat(64),
        integrity: 'sha256-widget',
        loadMode: 'runtime_child' as const
      }
    ];
    const result = evaluateRuntimeSecurity(
      {
        runtimeReadyObserved: true,
        runtimeArtifacts: [
          {
            url: runtimeArtifacts[0].url,
            observedSha256: runtimeArtifacts[0].sha256,
            loadedByPage: true,
            domIntegrity: runtimeArtifacts[0].integrity,
            trustedRuntimeInitiator: false,
            sourceMap: { available: true, url: `${runtimeArtifacts[0].url}.map` }
          },
          {
            // A genuine child is NOT loaded by the page document; it is
            // created at runtime by another pinned runtime.
            url: runtimeArtifacts[1].url,
            observedSha256: runtimeArtifacts[1].sha256,
            loadedByPage: false,
            domIntegrity: null,
            trustedRuntimeInitiator: true,
            sourceMap: { available: true, url: `${runtimeArtifacts[1].url}.map` }
          }
        ],
        runtimeCreatedScripts: [],
        unreviewedRuntimeScripts: [],
        negativeProxyCanary: { url: null, outcome: 'not_applicable', statusCode: null }
      },
      {
        target: {
          url: 'https://app-concord-privacy.webflow.io/',
          host: 'app-concord-privacy.webflow.io'
        },
        runtimeArtifacts,
        negativeProxyProbe: {
          mode: 'none_declared',
          declaration: 'no_proxy_surface'
        }
      } as any
    );

    // The child pin is honored, but a partner "no proxy surface" declaration
    // can never remove the proxy predicate: it stays a mandatory
    // manual-review blocker, so the automated status is blocked.
    expect(result).toMatchObject({
      status: 'blocked',
      predicates: {
        runtimeLoadedByPage: true,
        runtimeIntegrityMatched: true,
        negativeProxyBlocked: false,
        proxyPolicySatisfied: false
      }
    });
    expect(result.blockers).toHaveLength(1);
    expect(result.blockers[0]).toMatch(/manually confirm/i);
  });

  test('holds a byte-perfect runtime with no reachable source map behind manual review', () => {
    const runtimeArtifacts = [
      {
        url: 'https://api.consentpro.com/v2/cdn/runtime.js',
        sha256: 'a'.repeat(64),
        integrity: 'sha256-runtime'
      }
    ];
    const contract = {
      target: { url: 'https://consent-pro-test.webflow.io/', host: 'consent-pro-test.webflow.io' },
      runtimeArtifacts,
      negativeProxyProbe: {
        mode: 'probe',
        method: 'GET',
        urlTemplate: 'https://api.consentpro.com/v2/proxy?url={canaryUrl}'
      }
    } as any;
    // Every byte-level predicate passes: the pinned runtime loaded from the
    // document, matched its SHA-256, and carried its pinned SRI.
    const observation = {
      url: runtimeArtifacts[0].url,
      observedSha256: runtimeArtifacts[0].sha256,
      loadedByPage: true,
      domIntegrity: runtimeArtifacts[0].integrity
    };
    const manifest = {
      runtimeReadyObserved: true,
      runtimeCreatedScripts: [],
      unreviewedRuntimeScripts: [],
      negativeProxyCanary: { outcome: 'blocked' }
    };

    const unmapped = evaluateRuntimeSecurity(
      { ...manifest, runtimeArtifacts: [{ ...observation, sourceMap: { available: false } }] },
      contract
    );

    // Pinning proves WHICH bytes ran, not that they are readable.
    expect(unmapped.predicates.runtimeHashMatched).toBe(true);
    expect(unmapped.predicates.runtimeIntegrityMatched).toBe(true);
    expect(unmapped.predicates.runtimeSourceMapAvailable).toBe(false);
    expect(unmapped.status).toBe('blocked');
    expect(unmapped.blockers).toHaveLength(1);
    expect(unmapped.blockers[0]).toMatch(/readable source/i);
    expect(unmapped.blockers[0]).toMatch(/manually confirm/i);

    const mapped = evaluateRuntimeSecurity(
      {
        ...manifest,
        runtimeArtifacts: [
          {
            ...observation,
            sourceMap: { available: true, url: `${runtimeArtifacts[0].url}.map` }
          }
        ]
      },
      contract
    );
    expect(mapped.predicates.runtimeSourceMapAvailable).toBe(true);
    expect(mapped.status).toBe('passed');
    expect(mapped.blockers).toEqual([]);
  });

  test('requires a source map for every pinned file in a runtime set', () => {
    const runtimeArtifacts = [
      {
        url: 'https://api.consentpro.com/v2/cdn/runtime.js',
        sha256: 'a'.repeat(64),
        integrity: 'sha256-runtime'
      },
      {
        url: 'https://api.consentpro.com/v2/cdn/preferences.js',
        sha256: 'b'.repeat(64),
        integrity: 'sha256-preferences'
      }
    ];
    const result = evaluateRuntimeSecurity(
      {
        runtimeReadyObserved: true,
        runtimeArtifacts: runtimeArtifacts.map((pin, index) => ({
          url: pin.url,
          observedSha256: pin.sha256,
          loadedByPage: true,
          domIntegrity: pin.integrity,
          // Only the first file is traceable to source.
          sourceMap: index === 0 ? { available: true, url: `${pin.url}.map` } : { available: false }
        })),
        runtimeCreatedScripts: [],
        unreviewedRuntimeScripts: [],
        negativeProxyCanary: { outcome: 'blocked' }
      },
      {
        target: {
          url: 'https://consent-pro-test.webflow.io/',
          host: 'consent-pro-test.webflow.io'
        },
        runtimeArtifacts,
        negativeProxyProbe: {
          mode: 'probe',
          method: 'GET',
          urlTemplate: 'https://api.consentpro.com/v2/proxy?url={canaryUrl}'
        }
      } as any
    );

    expect(result.predicates.runtimeSourceMapAvailable).toBe(false);
    expect(result.status).toBe('blocked');
  });

  test('does not honor a runtime_child declaration for a script the page actually loaded', () => {
    const runtimeArtifacts = [
      {
        // A partner mislabels an ordinary page-loaded script (with no SRI)
        // as runtime_child to dodge the DOM-SRI equality check.
        url: 'https://api.concord.tech/site-v1/site-id/widget',
        sha256: 'b'.repeat(64),
        integrity: 'sha256-widget',
        loadMode: 'runtime_child' as const
      }
    ];
    const result = evaluateRuntimeSecurity(
      {
        runtimeReadyObserved: true,
        runtimeArtifacts: [
          {
            url: runtimeArtifacts[0].url,
            observedSha256: runtimeArtifacts[0].sha256,
            loadedByPage: true,
            domIntegrity: null,
            trustedRuntimeInitiator: true
          }
        ],
        runtimeCreatedScripts: [],
        unreviewedRuntimeScripts: [],
        negativeProxyCanary: { url: 'https://canary.webflow.com/x', outcome: 'blocked', statusCode: 403 }
      },
      {
        target: {
          url: 'https://app-concord-privacy.webflow.io/',
          host: 'app-concord-privacy.webflow.io'
        },
        runtimeArtifacts,
        negativeProxyProbe: {
          mode: 'probe',
          method: 'GET',
          urlTemplate: 'https://api.concord.tech/proxy?url={canaryUrl}'
        }
      } as any
    );

    expect(result.status).toBe('blocked');
    expect(result.predicates.runtimeLoadedByPage).toBe(false);
    expect(result.predicates.runtimeIntegrityMatched).toBe(false);
  });

  test('returns the resolved Webflow identity and server-owned companion role', async () => {
    const developer = await exports.default.fetch(
      new Request('https://preflight.test/v1/me', {
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        }
      })
    );
    expect(developer.status).toBe(200);
    expect(await developer.json()).toEqual({
      user: {
        id: 'local-webflow-user',
        siteId: 'local-webflow-site',
        companionRole: 'developer'
      }
    });

    const reviewer = await exports.default.fetch(
      new Request('https://preflight.test/v1/me', {
        headers: {
          authorization: 'Bearer reviewer-test-token',
          origin: 'http://localhost:1337'
        }
      })
    );
    expect(reviewer.status).toBe(200);
    expect(await reviewer.json()).toEqual({
      user: {
        id: 'local-webflow-reviewer',
        siteId: 'local-webflow-review-site',
        companionRole: 'reviewer'
      }
    });
  });

  test('retires legacy runtime and companion mutations in production', async () => {
    const productionEnv = {
      DB: env.DB,
      ARTIFACTS: env.ARTIFACTS,
      ENVIRONMENT: 'production',
      ALLOWED_ORIGINS: '',
      E2B_COORDINATOR_TOKEN: 'coordinator-test-token'
    } as Env;
    const routes = [
      '/v1/runtime-jobs/legacy-job/evidence',
      '/v1/runtime-test-packages/legacy-package/observation-jobs',
      '/v1/reviews/legacy-review/runtime-jobs',
      '/v1/reviews/legacy-review/companion-runs',
      '/v1/companion-runs/legacy-run/complete',
      '/v1/companion-runs/legacy-run/replay',
      '/v1/companion-runs/legacy-run/missions/production_runtime'
    ];
    for (const path of routes) {
      const response = await worker.fetch(
        new Request(`https://preflight.test${path}`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer coordinator-test-token',
            'content-type': 'application/json'
          },
          body: '{}'
        }),
        productionEnv
      );
      expect(response.status, path).toBe(410);
      await expect(response.json()).resolves.toMatchObject({
        error: 'legacy_runtime_mutation_retired'
      });
    }
  });

  test('retires the unauthenticated redeem endpoint and every companion write path in every environment', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'consent-pro.zip', { type: 'application/zip' })
    );
    const createReviewResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: form
      })
    );
    const created = await createReviewResponse.json<{
      review: { id: string; latestVersion: { id: string } };
    }>();
    const runtimeTestPackageId = await createReadyRuntimePackage(created.review.id);

    const pairingResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/companion-pairings`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer test-token',
            origin: 'http://localhost:1337',
            'content-type': 'application/json'
          },
          body: JSON.stringify({
            reviewVersionId: created.review.latestVersion.id,
            runtimeTestPackageId
          })
      })
    );
    expect(pairingResponse.status).toBe(201);
    const paired = await pairingResponse.json<{
      pairing: { code: string; expiresAt: string };
    }>();

    // The old unauthenticated redeem endpoint is retired everywhere,
    // including development, and never returns a readable bearer.
    const redeemResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/companion-pairings/redeem', {
        method: 'POST',
        headers: {
          origin: 'http://localhost:1337',
          'content-type': 'application/json'
        },
        body: JSON.stringify({ code: paired.pairing.code })
      })
    );
    expect(redeemResponse.status).toBe(410);
    expect(await redeemResponse.json()).toMatchObject({
      error: 'legacy_runtime_mutation_retired'
    });

    // A developer-role pairing code cannot enter the reviewer surface, and
    // the failed attempt does not consume the one-time code.
    const connectForm = new FormData();
    connectForm.set('code', paired.pairing.code);
    const wrongRole = await exports.default.fetch(
      new Request('https://preflight.test/reviewer/connect', {
        method: 'POST',
        redirect: 'manual',
        body: connectForm
      })
    );
    expect(wrongRole.status).toBe(403);
    const unconsumed = await env.DB.prepare(
      `SELECT redeemed_at
         FROM companion_pairings
        ORDER BY created_at DESC
        LIMIT 1`
    ).first<{ redeemed_at: string | null }>();
    expect(unconsumed?.redeemed_at).toBeNull();

    // Every companion write route is gone in development too.
    const retiredWrites: Array<{ path: string; body: string }> = [
      {
        path: `/v1/reviews/${created.review.id}/companion-runs`,
        body: JSON.stringify({
          reviewVersionId: created.review.latestVersion.id,
          runtimeTestPackageId
        })
      },
      { path: '/v1/companion-runs/any-run/complete', body: '{}' },
      { path: '/v1/companion-runs/any-run/replay', body: '{}' },
      { path: '/v1/companion-runs/any-run/missions/production_runtime', body: '{}' }
    ];
    for (const route of retiredWrites) {
      const response = await exports.default.fetch(
        new Request(`https://preflight.test${route.path}`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer test-token',
            origin: 'http://localhost:1337',
            'content-type': 'application/json'
          },
          body: route.body
        })
      );
      expect(response.status, route.path).toBe(410);
      expect(await response.json()).toMatchObject({
        error: 'legacy_runtime_mutation_retired'
      });
    }
    const runCount = await env.DB.prepare(
      'SELECT COUNT(*) AS count FROM companion_runs'
    ).first<{ count: number }>();
    expect(runCount?.count).toBe(0);
  });

  test('keeps historical companion runs readable and blocks new webflow_observed receipts at the database', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'historical-companion.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: form
      })
    );
    const created = await createdResponse.json<{
      review: { id: string; latestVersion: { id: string; result: { artifact: { sha256: string } } } };
    }>();

    const runId = crypto.randomUUID();
    const now = new Date().toISOString();
    const historicalRun = {
      id: runId,
      reviewId: created.review.id,
      reviewVersionId: created.review.latestVersion.id,
      bundleSha256: created.review.latestVersion.result.artifact.sha256,
      runtimeTestPackageId: null,
      actorRole: 'developer',
      executionAuthority: 'partner',
      evidenceTrust: 'partner_supplied',
      policyVersion: 'companion-policy.v3',
      status: 'blocked',
      replayOfRunId: null,
      missions: [],
      createdAt: now,
      updatedAt: now
    };
    await env.DB.prepare(
      `INSERT INTO companion_runs
        (id, review_id, review_version_id, owner_user_id, actor_user_id, actor_role,
         evidence_trust, policy_version, status, replay_of_run_id, run_json,
         created_at, updated_at)
       VALUES (?, ?, ?, 'local-webflow-user', 'local-webflow-user', 'developer',
               'partner_supplied', 'companion-policy.v3', 'blocked', NULL, ?, ?, ?)`
    )
      .bind(runId, created.review.id, created.review.latestVersion.id, JSON.stringify(historicalRun), now, now)
      .run();

    const readResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/companion-runs/${runId}`, {
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        }
      })
    );
    expect(readResponse.status).toBe(200);
    expect(await readResponse.json()).toMatchObject({
      run: { id: runId, evidenceTrust: 'partner_supplied', status: 'blocked' }
    });

    // Migration 0008: new companion mission receipts can never claim the
    // Webflow-owned trust level, even through a direct database write.
    const receipt = (trust: string) =>
      env.DB.prepare(
        `INSERT INTO companion_mission_receipts
          (id, run_id, mission_id, status, evidence_trust, evidence_digest,
           event_count, artifact_count, manifest_json, observed_at, created_at, updated_at)
         VALUES (?, ?, 'production_runtime', 'passed', ?, ?, 1, 1, '{}', ?, ?, ?)`
      )
        .bind(crypto.randomUUID(), runId, trust, 'a'.repeat(64), now, now, now)
        .run();
    await expect(receipt('webflow_observed')).rejects.toThrow(/webflow_observed/);
    await expect(receipt('partner_supplied')).resolves.toMatchObject({ success: true });
  });

  test('rejects an expired pairing without issuing a companion session', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'expired-pairing.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: form
      })
    );
    const created = await createdResponse.json<{
      review: { id: string; latestVersion: { id: string } };
    }>();
    const runtimeTestPackageId = await createReadyRuntimePackage(created.review.id);
    const pairingResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/companion-pairings`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer reviewer-test-token',
            origin: 'http://localhost:1337',
            'content-type': 'application/json'
          },
          body: JSON.stringify({
            reviewVersionId: created.review.latestVersion.id,
            runtimeTestPackageId
          })
      })
    );
    const pairing = await pairingResponse.json<{ pairing: { code: string } }>();
    await env.DB.prepare(
      `UPDATE companion_pairings SET expires_at = '2000-01-01T00:00:00.000Z'
        WHERE id = (SELECT id FROM companion_pairings ORDER BY created_at DESC LIMIT 1)`
    ).run();

    const connectForm = new FormData();
    connectForm.set('code', pairing.pairing.code);
    const expired = await exports.default.fetch(
      new Request('https://preflight.test/reviewer/connect', {
        method: 'POST',
        redirect: 'manual',
        body: connectForm
      })
    );
    expect(expired.status).toBe(403);
    expect(expired.headers.get('set-cookie')).toBeNull();
    const sessionCount = await env.DB.prepare(
      `SELECT COUNT(*) AS count FROM companion_sessions
        WHERE review_id = ? AND review_version_id = ?`
    )
      .bind(created.review.id, created.review.latestVersion.id)
      .first<{ count: number }>();
    expect(sessionCount?.count).toBe(0);
  });

  test('preserves reviewer authority from Webflow identity through pairing redemption', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'reviewer-pairing.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: form
      })
    );
    const created = await createdResponse.json<{
      review: { id: string; latestVersion: { id: string } };
    }>();
    const runtimeTestPackageId = await createReadyRuntimePackage(created.review.id);
    const pairingResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/companion-pairings`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer reviewer-test-token',
            origin: 'http://localhost:1337',
            'content-type': 'application/json'
          },
          body: JSON.stringify({
            reviewVersionId: created.review.latestVersion.id,
            runtimeTestPackageId
          })
      })
    );
    const pairing = await pairingResponse.json<{ pairing: { code: string } }>();
    const connectForm = new FormData();
    connectForm.set('code', pairing.pairing.code);
    const redeemed = await exports.default.fetch(
      new Request('https://preflight.test/reviewer/connect', {
        method: 'POST',
        redirect: 'manual',
        body: connectForm
      })
    );
    // The session is delivered only as an HttpOnly cookie: no readable
    // bearer token or trust level ever appears in a response body.
    expect(redeemed.status).toBe(303);
    const cookie = redeemed.headers.get('set-cookie');
    expect(cookie).toContain('app_review_reviewer_session=');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Strict');
    expect(await redeemed.text()).toBe('');

    const session = await env.DB.prepare(
      `SELECT actor_role, review_id, review_version_id
         FROM companion_sessions
        ORDER BY created_at DESC
        LIMIT 1`
    ).first<{ actor_role: string; review_id: string; review_version_id: string }>();
    expect(session).toEqual({
      actor_role: 'reviewer',
      review_id: created.review.id,
      review_version_id: created.review.latestVersion.id
    });
  });

  test('fails closed for missing identity and untrusted origins', async () => {
    const missingIdentity = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        headers: { origin: 'http://localhost:1337' }
      })
    );
    expect(missingIdentity.status).toBe(401);

    const untrustedOrigin = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        headers: {
          authorization: 'Bearer test-token',
          origin: 'https://attacker.example'
        }
      })
    );
    expect(untrustedOrigin.status).toBe(403);
  });

  test('creates and retrieves a durable review with immutable artifact bytes', async () => {
    const bundle = await createBundle();
    const form = new FormData();
    form.set('name', 'Consent Pro preflight');
    form.set('bundle', new File([bundle], 'consent-pro.zip', { type: 'application/zip' }));

    const createResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: form
      })
    );

    expect(createResponse.status).toBe(201);
    const created = await createResponse.json<{
      review: {
        id: string;
        latestVersion: {
          id: string;
          result: { artifact: { sha256: string } };
        };
      };
    }>();

    const getResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}`, {
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        }
      })
    );

    expect(getResponse.status).toBe(200);
    const loaded = await getResponse.json<typeof created>();
    expect(loaded.review).toEqual(created.review);

    const row = await env.DB.prepare(
      'SELECT artifact_key, artifact_sha256 FROM review_versions WHERE id = ?'
    )
      .bind(created.review.latestVersion.id)
      .first<{ artifact_key: string; artifact_sha256: string }>();

    expect(row?.artifact_sha256).toBe(created.review.latestVersion.result.artifact.sha256);
    const object = await env.ARTIFACTS.get(row!.artifact_key);
    expect(object).not.toBeNull();
    expect(new Uint8Array(await object!.arrayBuffer())).toEqual(bundle);
  });

  test('keeps review history bound to the active Webflow site', async () => {
    const form = new FormData();
    form.set('bundle', new File([await createBundle()], 'other-site.zip', { type: 'application/zip' }));
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{ review: { id: string } }>();
    await env.DB.prepare('UPDATE reviews SET site_id = ? WHERE id = ?')
      .bind('a-different-webflow-site', created.review.id)
      .run();

    const [history, review] = await Promise.all([
      exports.default.fetch(
        new Request('https://preflight.test/v1/reviews', {
          headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' }
        })
      ),
      exports.default.fetch(
        new Request(`https://preflight.test/v1/reviews/${created.review.id}`, {
          headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' }
        })
      )
    ]);

    const historyBody = await history.json<{ reviews: Array<{ id: string }> }>();
    expect(historyBody.reviews.map((item) => item.id)).not.toContain(created.review.id);
    expect(review.status).toBe(404);
  });

  test('stamps a preflight run with a submission receipt the form can trace', async () => {
    const zip = new JSZip();
    zip.file(
      'webflow.json',
      JSON.stringify({ name: 'Mapped App', apiVersion: '2', publicDir: 'dist' })
    );
    zip.file('dist/main.js', 'export const ok=true;//# sourceMappingURL=main.js.map');
    const bundle = await zip.generateAsync({ type: 'uint8array' });

    const mapZip = new JSZip();
    mapZip.file(
      'main.js.map',
      JSON.stringify({ version: 3, file: 'main.js', sources: ['../src/main.ts'], mappings: '' })
    );
    const maps = await mapZip.generateAsync({ type: 'uint8array' });

    const form = new FormData();
    form.set('bundle', new File([bundle], 'mapped-app.zip', { type: 'application/zip' }));
    form.set('sourceMaps', new File([maps], 'mapped-app-maps.zip', { type: 'application/zip' }));

    const createResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: form
      })
    );

    expect(createResponse.status).toBe(201);
    const created = await createResponse.json<{
      review: {
        id: string;
        latestVersion: {
          id: string;
          result: {
            artifact: {
              sha256: string;
              sourceMaps?: { fileName: string; sha256: string; mapFileCount: number };
            };
            sourceMapSummary?: { status: string };
            summary: { readiness: string };
          };
        };
      };
      submissionReceipt: { code: string; createdAt: string };
    }>();

    expect(created.submissionReceipt.code).toMatch(/^wfpre_[a-f0-9]{32}$/);
    expect(created.review.latestVersion.result.sourceMapSummary?.status).toBe('matched');
    expect(created.review.latestVersion.result.artifact.sourceMaps?.fileName).toBe(
      'mapped-app-maps.zip'
    );
    expect(created.review.latestVersion.result.artifact.sourceMaps?.mapFileCount).toBe(1);

    // The private source-map artifact is durable and referenced by the version row.
    const versionRow = await env.DB.prepare(
      'SELECT source_map_sha256, source_map_key, source_map_file_name FROM review_versions WHERE id = ?'
    )
      .bind(created.review.latestVersion.id)
      .first<{
        source_map_sha256: string | null;
        source_map_key: string | null;
        source_map_file_name: string | null;
      }>();
    expect(versionRow?.source_map_sha256).toBe(
      created.review.latestVersion.result.artifact.sourceMaps?.sha256
    );
    expect(versionRow?.source_map_file_name).toBe('mapped-app-maps.zip');
    const storedMaps = await env.ARTIFACTS.get(versionRow!.source_map_key!);
    expect(storedMaps).not.toBeNull();
    expect(new Uint8Array(await storedMaps!.arrayBuffer())).toEqual(maps);

    // The submission form traces the receipt without authentication; the
    // code itself is the secret and only reconciliation metadata comes back.
    const verifyResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/submission-receipts/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code: created.submissionReceipt.code })
      })
    );
    expect(verifyResponse.status).toBe(200);
    const verified = await verifyResponse.json<{
      valid: boolean;
      receipt: {
        reviewId: string;
        bundleSha256: string;
        sourceMapArtifactSha256: string | null;
        readiness: string;
        sourceMapStatus: string;
        runtimeSecurityStatus: string;
      };
    }>();
    expect(verified.valid).toBe(true);
    expect(verified.receipt.reviewId).toBe(created.review.id);
    expect(verified.receipt.bundleSha256).toBe(
      created.review.latestVersion.result.artifact.sha256
    );
    expect(verified.receipt.sourceMapArtifactSha256).toBe(
      created.review.latestVersion.result.artifact.sourceMaps?.sha256
    );
    expect(verified.receipt.sourceMapStatus).toBe('matched');
    expect(verified.receipt.runtimeSecurityStatus).toBe('none');

    // Unknown or malformed codes resolve identically: not found, no probing.
    const unknownResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/submission-receipts/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code: `wfpre_${'f'.repeat(32)}` })
      })
    );
    expect(unknownResponse.status).toBe(404);
    expect(await unknownResponse.json()).toEqual({ valid: false });

    // The owner can issue a fresh receipt for the latest version at any time.
    const reissueResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/submission-receipts`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        }
      })
    );
    expect(reissueResponse.status).toBe(201);
    const reissued = await reissueResponse.json<{
      submissionReceipt: { code: string };
    }>();
    expect(reissued.submissionReceipt.code).toMatch(/^wfpre_[a-f0-9]{32}$/);
    expect(reissued.submissionReceipt.code).not.toBe(created.submissionReceipt.code);
  });

  test('rejects a source-map upload that is not a .map file or .zip archive', async () => {
    const bundle = await createBundle();
    const form = new FormData();
    form.set('bundle', new File([bundle], 'consent-pro.zip', { type: 'application/zip' }));
    form.set('sourceMaps', new File(['{}'], 'maps.json', { type: 'application/json' }));

    const response = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: form
      })
    );

    expect(response.status).toBe(400);
    const body = await response.json<{ error: string; message: string }>();
    expect(body.error).toBe('invalid_bundle');
    expect(body.message).toContain('.map file or a .zip');
  });

  test('creates a durable Data Client review from hosted runtime URLs without a bundle', async () => {
    const runtimeUrls = [
      'https://webflow-websitespeedy13.b-cdn.net/speedyscripts/ecmrx_1234/ecmrx_1234_1.js',
      'https://webflow-websitespeedy13.b-cdn.net/speedyscripts/ecmrx_1234/ecmrx_1234_2.js',
      'https://webflow-websitespeedy13.b-cdn.net/speedyscripts/ecmrx_1234/ecmrx_1234_3.js'
    ];
    const response = await exports.default.fetch(
      new Request('https://preflight.test/v1/runtime-reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337',
          'content-type': 'application/json'
        },
        body: JSON.stringify({ appName: 'Website Speedy', runtimeUrls })
      })
    );

    expect(response.status).toBe(201);
    const created = await response.json<{
      review: {
        id: string;
        name: string;
        latestVersion: {
          result: {
            artifact: { kind: string; sha256: string; fileCount: number };
            artifactScope: { primary: string; appType: string; appName: string };
            runtime: { references: string[]; status: string };
          };
        };
      };
    }>();
    expect(created.review).toMatchObject({
      name: 'Website Speedy runtime review',
      latestVersion: {
        result: {
          artifact: {
            kind: 'runtime_manifest',
            sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
            fileCount: 3
          },
          artifactScope: {
            primary: 'production_runtime',
            appType: 'data_client',
            appName: 'Website Speedy'
          },
          runtime: {
            references: runtimeUrls,
            status: 'discovered_unverified'
          }
        }
      }
    });

    const stored = await env.DB.prepare(
      `SELECT artifact_key, artifact_sha256, file_name
         FROM review_versions
        WHERE review_id = ?`
    )
      .bind(created.review.id)
      .first<{ artifact_key: string; artifact_sha256: string; file_name: string }>();
    expect(stored?.file_name).toBe('hosted-runtime-manifest.json');
    expect(stored?.artifact_key).toMatch(/\.json$/);
    const manifest = await env.ARTIFACTS.get(stored!.artifact_key);
    expect(manifest).not.toBeNull();
    expect(await sha256Hex(await manifest!.arrayBuffer())).toBe(stored?.artifact_sha256);

    const listResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        }
      })
    );
    const listed = await listResponse.json<{
      reviews: Array<{ id: string; reviewType: string }>;
    }>();
    expect(listed.reviews).toContainEqual(
      expect.objectContaining({ id: created.review.id, reviewType: 'runtime_manifest' })
    );
  });

  test('adds a revision and reports deterministic progress', async () => {
    const initialForm = new FormData();
    initialForm.set(
      'bundle',
      new File([await createBundle()], 'consent-pro.zip', { type: 'application/zip' })
    );
    const initialResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: initialForm
      })
    );
    const initial = await initialResponse.json<{ review: { id: string } }>();

    const revisionForm = new FormData();
    revisionForm.set(
      'bundle',
      new File([await createBundle({ injectScript: false })], 'consent-pro-v2.zip', {
        type: 'application/zip'
      })
    );
    const revisionResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${initial.review.id}/revisions`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: revisionForm
      })
    );

    expect(revisionResponse.status).toBe(201);
    const revised = await revisionResponse.json<{
      review: { latestVersion: { sequence: number } };
      comparison: {
        resolved: string[];
        remaining: string[];
        added: string[];
      };
      deduplicated: boolean;
    }>();

    expect(revised.review.latestVersion.sequence).toBe(2);
    expect(revised.comparison.resolved).toContain('SEC-SCRIPT-INJECTION');
    expect(revised.comparison.added).toEqual([]);
    expect(revised.deduplicated).toBe(false);

    const versionCount = await env.DB.prepare(
      'SELECT COUNT(*) AS count FROM review_versions WHERE review_id = ?'
    )
      .bind(initial.review.id)
      .first<{ count: number }>();
    expect(versionCount?.count).toBe(2);
  });

  test('treats a repeated artifact as an idempotent checkpoint', async () => {
    const bundle = await createBundle();
    const initialForm = new FormData();
    initialForm.set('bundle', new File([bundle], 'consent-pro.zip', { type: 'application/zip' }));
    const initialResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: initialForm
      })
    );
    const initial = await initialResponse.json<{
      review: { id: string; latestVersion: { sequence: number } };
    }>();

    const retryForm = new FormData();
    retryForm.set(
      'bundle',
      new File([bundle], 'consent-pro-retry.zip', { type: 'application/zip' })
    );
    const retryResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${initial.review.id}/revisions`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: retryForm
      })
    );

    expect(retryResponse.status).toBe(200);
    const retry = await retryResponse.json<{
      deduplicated: boolean;
      review: { latestVersion: { sequence: number } };
    }>();
    expect(retry.deduplicated).toBe(true);
    expect(retry.review.latestVersion.sequence).toBe(1);

    const versionCount = await env.DB.prepare(
      'SELECT COUNT(*) AS count FROM review_versions WHERE review_id = ?'
    )
      .bind(initial.review.id)
      .first<{ count: number }>();
    expect(versionCount?.count).toBe(1);
  });

  test('rejects corrupt zip content without storing review evidence', async () => {
    const countBefore = await env.DB.prepare('SELECT COUNT(*) AS count FROM reviews').first<{
      count: number;
    }>();
    const form = new FormData();
    form.set(
      'bundle',
      new File([new TextEncoder().encode('not a zip')], 'broken.zip', {
        type: 'application/zip'
      })
    );

    const response = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: form
      })
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'invalid_bundle',
      message: 'We could not read this zip. Re-export the bundle and try again.'
    });

    const reviewCount = await env.DB.prepare('SELECT COUNT(*) AS count FROM reviews').first<{
      count: number;
    }>();
    expect(reviewCount?.count).toBe(countBefore?.count);
  });

  test('lists the current users saved review checkpoints', async () => {
    const form = new FormData();
    form.set('name', 'Saved Consent Pro run');
    form.set(
      'bundle',
      new File([await createBundle()], 'consent-pro.zip', { type: 'application/zip' })
    );
    const createResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: form
      })
    );
    const created = await createResponse.json<{ review: { id: string } }>();

    const listResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        }
      })
    );

    expect(listResponse.status).toBe(200);
    const listed = await listResponse.json<{
      reviews: Array<{
        id: string;
        name: string;
        latestSequence: number;
        readiness: string;
      }>;
    }>();
    expect(listed.reviews).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: created.review.id,
          name: 'Saved Consent Pro run',
          latestSequence: 1,
          readiness: 'changes_required'
        })
      ])
    );
  });

  test('rejects Designer Extension URLs as production-runtime targets', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'consent-pro.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{ review: { id: string } }>();
    const response = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/runtime-test-packages`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer test-token',
            origin: 'http://localhost:1337',
            'content-type': 'application/json'
          },
          body: JSON.stringify({
            targetUrl: 'https://68821e9ad5797a48cfc68499.webflow-ext.com/6a552d5baa59e9a3a1ebba5d/',
          sandboxInstallationId: 'local-webflow-site',
            sandboxOwnershipConfirmed: true,
            license: {
              mode: 'installation_allowlist',
              expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString()
            },
          runtimeArtifacts: [
            {
              url: 'https://api.consentpro.com/v2/cdn/runtime.js',
              sha256: 'a'.repeat(64),
              integrity: TEST_RUNTIME_INTEGRITY
            }
          ],
            negativeProxyProbe: {
              method: 'GET',
              urlTemplate: 'https://api.consentpro.com/v2/proxy?url={canaryUrl}'
            },
            lifecycle: { readySelector: '[data-runtime-ready]' }
          })
      })
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      error: 'invalid_runtime_test_package',
      message: expect.stringMatching(/published-site origin/i)
    });
  });

  test('binds a runtime package to the authenticated Webflow site', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'consent-pro.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{ review: { id: string } }>();
    const response = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/runtime-test-packages`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          targetUrl: 'http://127.0.0.1:4173/runtime-fixture',
          sandboxInstallationId: 'another-webflow-site',
          sandboxOwnershipConfirmed: true,
          license: {
            mode: 'installation_allowlist',
            expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString()
          },
          runtimeArtifacts: [
            {
              url: 'http://127.0.0.1:4173/runtime-v1.js',
              sha256: 'a'.repeat(64),
              integrity: TEST_RUNTIME_INTEGRITY
            }
          ],
          negativeProxyProbe: {
            method: 'GET',
            urlTemplate: 'http://127.0.0.1:4173/proxy?url={canaryUrl}'
          },
          lifecycle: { readySelector: '[data-runtime-ready]' }
        })
      })
    );
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({
      testPackage: {
        sandboxInstallationId: 'local-webflow-site'
      }
    });
  });

  test('verifies the published Webflow page belongs to the authenticated site', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'consent-pro.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{ review: { id: string } }>();
    const productionEnv = {
      DB: env.DB,
      ARTIFACTS: env.ARTIFACTS,
      ENVIRONMENT: 'production',
      ALLOWED_ORIGINS: '',
      WEBFLOW_APP_ACCESS_TOKEN: 'app-token'
    } as Env;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const request = input instanceof Request ? input : new Request(input);
        if (request.url === 'https://api.webflow.com/beta/token/resolve') {
          return Response.json({ id: 'local-webflow-user', siteId: 'local-webflow-site' });
        }
        if (request.url === 'https://foreign-site.webflow.io/') {
          return new Response(
            '<!doctype html><html data-wf-site="another-webflow-site"><body></body></html>',
            { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } }
          );
        }
        return Response.json({ error: 'unexpected_request' }, { status: 500 });
      })
    );

    const response = await worker.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/runtime-test-packages`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer designer-id-token',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          targetUrl: 'https://foreign-site.webflow.io/',
          sandboxInstallationId: 'local-webflow-site',
          sandboxOwnershipConfirmed: true,
          license: {
            mode: 'installation_allowlist',
            expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString()
          },
          runtimeArtifacts: [
            {
              url: 'https://api.consentpro.com/v2/cdn/runtime.js',
              sha256: 'a'.repeat(64),
              integrity: TEST_RUNTIME_INTEGRITY
            }
          ],
          negativeProxyProbe: {
            method: 'GET',
            urlTemplate: 'https://api.consentpro.com/v2/proxy?url={canaryUrl}'
          },
          lifecycle: { readySelector: '[data-runtime-ready]' }
        })
      }),
      productionEnv
    );
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: 'invalid_runtime_test_package',
      message: expect.stringMatching(/published Webflow site/i)
    });
  });

  test('rejects a runtime package whose SRI does not describe the pinned SHA-256 bytes', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'consent-pro.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{ review: { id: string } }>();

    const response = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/runtime-test-packages`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer test-token',
            origin: 'http://localhost:1337',
            'content-type': 'application/json'
          },
          body: JSON.stringify({
            targetUrl: 'http://127.0.0.1:4173/runtime-fixture',
          sandboxInstallationId: 'local-webflow-site',
            sandboxOwnershipConfirmed: true,
            license: {
              mode: 'installation_allowlist',
              expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString()
            },
          runtimeArtifacts: [
            {
              url: 'http://127.0.0.1:4173/runtime-v1.js',
              sha256: 'a'.repeat(64),
              integrity: 'sha256-mismatched-runtime-bytes'
            }
          ],
            negativeProxyProbe: {
              method: 'GET',
              urlTemplate: 'http://127.0.0.1:4173/proxy?url={canaryUrl}'
            },
            lifecycle: { readySelector: '[data-runtime-ready]' }
          })
      })
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      error: 'invalid_runtime_test_package',
      message: expect.stringMatching(/Runtime file 1.*same SHA-256 bytes/i)
    });
  });

  test('rejects duplicate runtime URLs inside one execution scenario', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'consent-pro.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{ review: { id: string } }>();
    const duplicate = {
      url: 'http://127.0.0.1:4173/runtime-v1.js',
      sha256: 'a'.repeat(64),
      integrity: TEST_RUNTIME_INTEGRITY
    };
    const response = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/runtime-test-packages`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          targetUrl: 'http://127.0.0.1:4173/runtime-fixture',
          sandboxInstallationId: 'local-webflow-site',
          sandboxOwnershipConfirmed: true,
          license: {
            mode: 'installation_allowlist',
            expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString()
          },
          runtimeArtifacts: [duplicate, duplicate],
          negativeProxyProbe: {
            method: 'GET',
            urlTemplate: 'http://127.0.0.1:4173/proxy?url={canaryUrl}'
          },
          lifecycle: { readySelector: '[data-runtime-ready]' }
        })
      })
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: 'invalid_runtime_test_package',
      message: expect.stringMatching(/Runtime file 2.*duplicates runtime file 1/i)
    });
  });

  test('accepts partner test input but only lets the Webflow coordinator issue an observation job', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'consent-pro.zip', { type: 'application/zip' })
    );
    const createResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: form
      })
    );
    const created = await createResponse.json<{
      review: {
        id: string;
        latestVersion: {
          id: string;
          result: { artifact: { sha256: string }; officialDecision: null };
        };
      };
    }>();

    const licenseExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    const packageResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/runtime-test-packages`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer test-token',
            'content-type': 'application/json',
            origin: 'http://localhost:1337'
          },
          body: JSON.stringify({
            targetUrl: 'http://127.0.0.1:4173/runtime-fixture',
          sandboxInstallationId: 'local-webflow-site',
            sandboxOwnershipConfirmed: true,
            license: {
              mode: 'installation_allowlist',
              expiresAt: licenseExpiresAt
            },
            runtimeArtifacts: [
              {
                url: 'http://127.0.0.1:4173/runtime-v1.js',
                sha256: 'a'.repeat(64),
                integrity: TEST_RUNTIME_INTEGRITY
              },
              {
                url: 'http://127.0.0.1:4173/runtime-v2.js',
                sha256: 'a'.repeat(64),
                integrity: TEST_RUNTIME_INTEGRITY
              }
            ],
            negativeProxyProbe: {
              method: 'GET',
            urlTemplate: 'http://127.0.0.1:4173/proxy?url={canaryUrl}'
            },
            lifecycle: {
              readySelector: '[data-runtime-ready]'
            }
          })
      })
    );

    expect(packageResponse.status).toBe(201);
    const packageBody = await packageResponse.json<{
      testPackage: {
        id: string;
        status: string;
        trust: string;
        reviewVersionId: string;
        bundleSha256: string;
        target: { url: string; host: string };
        sandboxInstallationId: string;
        runtimeArtifacts: Array<{ url: string }>;
        evidence: null;
      };
    }>();
    expect(packageBody.testPackage).toMatchObject({
      status: 'ready',
      trust: 'partner_supplied',
      reviewVersionId: created.review.latestVersion.id,
      bundleSha256: created.review.latestVersion.result.artifact.sha256,
      target: {
        url: 'http://127.0.0.1:4173/runtime-fixture',
        host: '127.0.0.1'
      },
      sandboxInstallationId: 'local-webflow-site',
      runtimeArtifacts: [
        { url: 'http://127.0.0.1:4173/runtime-v1.js' },
        { url: 'http://127.0.0.1:4173/runtime-v2.js' }
      ],
      evidence: null
    });
    expect(created.review.latestVersion.result.officialDecision).toBeNull();

    const jobEndpoint = `https://preflight.test/v1/runtime-test-packages/${packageBody.testPackage.id}/observation-jobs`;
    const partnerAttempt = await exports.default.fetch(
      new Request(jobEndpoint, {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          'content-type': 'application/json'
        },
        body: JSON.stringify({ approved: true })
      })
    );
    expect(partnerAttempt.status).toBe(401);

    const unapproved = await exports.default.fetch(
      new Request(jobEndpoint, {
        method: 'POST',
        headers: {
          authorization: 'Bearer coordinator-test-token',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          approved: false,
          sandboxOwnershipVerified: false
        })
      })
    );
    expect(unapproved.status).toBe(403);
    const countBeforeApproval = await env.DB.prepare(
      'SELECT COUNT(*) AS count FROM runtime_observation_jobs'
    ).first<{ count: number }>();
    expect(countBeforeApproval?.count).toBe(0);

    const approved = await exports.default.fetch(
      new Request(jobEndpoint, {
        method: 'POST',
        headers: {
          authorization: 'Bearer coordinator-test-token',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          approved: true,
          sandboxOwnershipVerified: true
        })
      })
    );
    expect(approved.status).toBe(201);
    const approvedBody = await approved.json<{
      observationJob: {
        id: string;
        status: string;
        capability: string;
        contract: {
          schemaVersion: string;
          purpose: string;
          testPackageId: string;
          reviewVersionId: string;
          bundleSha256: string;
          nonce: string;
          target: { url: string; host: string };
          controls: {
            allowedHosts: string[];
            evidenceTrust: string;
          };
          boundaries: {
            partnerCanSubmitEvidence: boolean;
            officialDecision: null;
            canWriteGovernance: boolean;
          };
        };
      };
    }>();
    expect(approvedBody.observationJob.capability.length).toBeGreaterThanOrEqual(32);
    expect(approvedBody.observationJob).toMatchObject({
      status: 'approved',
      contract: {
        schemaVersion: 'runtime_observation_job.v1',
        purpose: 'webflow_observation',
        testPackageId: packageBody.testPackage.id,
        reviewVersionId: created.review.latestVersion.id,
        bundleSha256: created.review.latestVersion.result.artifact.sha256,
        nonce: expect.any(String),
        target: {
          url: 'http://127.0.0.1:4173/runtime-fixture',
          host: '127.0.0.1'
        },
        controls: {
          allowedHosts: ['127.0.0.1'],
          evidenceTrust: 'webflow_observed'
        },
        boundaries: {
          partnerCanSubmitEvidence: false,
          officialDecision: null,
          canWriteGovernance: false
        }
      }
    });

    const stored = await env.DB.prepare(
      `SELECT capability_sha256, contract_json, status
         FROM runtime_observation_jobs
        WHERE id = ?`
    )
      .bind(approvedBody.observationJob.id)
      .first<{
        capability_sha256: string;
        contract_json: string;
        status: string;
      }>();
    const capabilitySha256 = await sha256Hex(approvedBody.observationJob.capability);
    expect(stored?.status).toBe('approved');
    expect(stored?.capability_sha256).toBe(capabilitySha256);
    expect(stored?.contract_json).not.toContain(approvedBody.observationJob.capability);

    const fetchEndpoint = `https://preflight.test/v1/runtime-observation-jobs/${approvedBody.observationJob.id}`;
    const partnerFetch = await exports.default.fetch(
      new Request(fetchEndpoint, {
        headers: { authorization: 'Bearer test-token' }
      })
    );
    expect(partnerFetch.status).toBe(401);

    const jobFetch = await exports.default.fetch(
      new Request(`${fetchEndpoint}?targetUrl=https://attacker.example`, {
        headers: {
          authorization: `Bearer ${approvedBody.observationJob.capability}`
        }
      })
    );
    expect(jobFetch.status).toBe(200);
    const fetched = await jobFetch.json<{
      observationJob: {
        id: string;
        status: string;
        contract: typeof approvedBody.observationJob.contract;
        capability?: string;
      };
    }>();
    expect(fetched.observationJob).toEqual({
      id: approvedBody.observationJob.id,
      status: 'running',
      contract: approvedBody.observationJob.contract
    });
    expect(fetched.observationJob.contract.target.url).toBe(
      'http://127.0.0.1:4173/runtime-fixture'
    );
    expect(fetched.observationJob.capability).toBeUndefined();

    const screenshot = new Uint8Array([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x00
    ]);
    const screenshotSha256 = await sha256Hex(screenshot);
    const baseManifest = {
      schemaVersion: 'runtime_observation_evidence.v1',
      observationJobId: approvedBody.observationJob.id,
      testPackageId: packageBody.testPackage.id,
      reviewVersionId: created.review.latestVersion.id,
      bundleSha256: created.review.latestVersion.result.artifact.sha256,
      nonce: approvedBody.observationJob.contract.nonce,
      targetUrl: approvedBody.observationJob.contract.target.url,
      trust: 'webflow_observed',
      executionEvidence: 'chromium_cdp_v1',
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      redaction: {
        applied: true,
        headersRemoved: true,
        cookiesRemoved: true,
        formValuesMasked: true
      },
      runtimeReadyObserved: true,
      runtimeArtifacts: [
        {
          url: 'http://127.0.0.1:4173/runtime-v1.js',
          expectedSha256: 'a'.repeat(64),
          observedSha256: 'a'.repeat(64),
          integrity: TEST_RUNTIME_INTEGRITY,
          domIntegrity: TEST_RUNTIME_INTEGRITY,
          domCrossOrigin: 'anonymous',
          loadedByPage: true,
          trustedRuntimeInitiator: false,
          sourceMap: { available: true, url: 'http://127.0.0.1:4173/runtime-v1.js.map' }
        },
        {
          url: 'http://127.0.0.1:4173/runtime-v2.js',
          expectedSha256: 'a'.repeat(64),
          observedSha256: 'a'.repeat(64),
          integrity: TEST_RUNTIME_INTEGRITY,
          domIntegrity: TEST_RUNTIME_INTEGRITY,
          domCrossOrigin: 'anonymous',
          loadedByPage: true,
          trustedRuntimeInitiator: false,
          sourceMap: { available: true, url: 'http://127.0.0.1:4173/runtime-v2.js.map' }
        }
      ],
      runtimeCreatedScripts: [],
      unreviewedRuntimeScripts: [],
      cleanup: {
        status: 'not_tested',
        residue: []
      },
      negativeProxyCanary: {
        url: 'http://127.0.0.1:4174/webflow-runtime-canary',
        outcome: 'blocked',
        statusCode: 403
      },
      artifacts: [
        {
          field: 'screenshot_after_cleanup',
          kind: 'screenshot_after_cleanup',
          fileName: 'after-cleanup.png',
          contentType: 'image/png',
          bytes: screenshot.byteLength,
          sha256: screenshotSha256
        }
      ]
    };
    const evidenceEndpoint = `${fetchEndpoint}/evidence`;

    const substitutedEvidence = new FormData();
    substitutedEvidence.set(
      'manifest',
      JSON.stringify({ ...baseManifest, targetUrl: 'https://attacker.example/runtime' })
    );
    substitutedEvidence.set(
      'screenshot_after_cleanup',
      new File([screenshot], 'after-cleanup.png', { type: 'image/png' })
    );
    const substitutedResponse = await exports.default.fetch(
      new Request(evidenceEndpoint, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${approvedBody.observationJob.capability}`
        },
        body: substitutedEvidence
      })
    );
    expect(substitutedResponse.status).toBe(400);

    const mismatchedEvidence = new FormData();
    mismatchedEvidence.set(
      'manifest',
      JSON.stringify({
        ...baseManifest,
        artifacts: [
          {
            ...baseManifest.artifacts[0],
            sha256: 'b'.repeat(64)
          }
        ]
      })
    );
    mismatchedEvidence.set(
      'screenshot_after_cleanup',
      new File([screenshot], 'after-cleanup.png', { type: 'image/png' })
    );
    const mismatchedResponse = await exports.default.fetch(
      new Request(evidenceEndpoint, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${approvedBody.observationJob.capability}`
        },
        body: mismatchedEvidence
      })
    );
    expect(mismatchedResponse.status).toBe(400);

    const unknownArtifactEvidence = new FormData();
    unknownArtifactEvidence.set('manifest', JSON.stringify(baseManifest));
    unknownArtifactEvidence.set(
      'screenshot_after_cleanup',
      new File([screenshot], 'after-cleanup.png', { type: 'image/png' })
    );
    unknownArtifactEvidence.set(
      'raw_browser_profile',
      new File([new Uint8Array([1, 2, 3])], 'profile.bin', {
        type: 'application/octet-stream'
      })
    );
    const unknownArtifactResponse = await exports.default.fetch(
      new Request(evidenceEndpoint, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${approvedBody.observationJob.capability}`
        },
        body: unknownArtifactEvidence
      })
    );
    expect(unknownArtifactResponse.status).toBe(400);

    const oversizedScreenshot = new Uint8Array(2 * 1024 * 1024 + 1);
    oversizedScreenshot.set(screenshot.slice(0, 8));
    const oversizedEvidence = new FormData();
    oversizedEvidence.set(
      'manifest',
      JSON.stringify({
        ...baseManifest,
        artifacts: [
          {
            ...baseManifest.artifacts[0],
            bytes: oversizedScreenshot.byteLength,
            sha256: await sha256Hex(oversizedScreenshot)
          }
        ]
      })
    );
    oversizedEvidence.set(
      'screenshot_after_cleanup',
      new File([oversizedScreenshot], 'after-cleanup.png', { type: 'image/png' })
    );
    const oversizedResponse = await exports.default.fetch(
      new Request(evidenceEndpoint, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${approvedBody.observationJob.capability}`
        },
        body: oversizedEvidence
      })
    );
    expect(oversizedResponse.status).toBe(400);

    const partnerEvidence = new FormData();
    partnerEvidence.set('manifest', JSON.stringify(baseManifest));
    partnerEvidence.set(
      'screenshot_after_cleanup',
      new File([screenshot], 'after-cleanup.png', { type: 'image/png' })
    );
    const partnerEvidenceResponse = await exports.default.fetch(
      new Request(evidenceEndpoint, {
        method: 'POST',
        headers: { authorization: 'Bearer test-token' },
        body: partnerEvidence
      })
    );
    expect(partnerEvidenceResponse.status).toBe(401);

    async function createExtraObservationJob(): Promise<{
      id: string;
      capability: string;
    }> {
      const extraPackageId = await createReadyRuntimePackage(created.review.id);
      const response = await exports.default.fetch(
        new Request(
          `https://preflight.test/v1/runtime-test-packages/${extraPackageId}/observation-jobs`,
          {
          method: 'POST',
          headers: {
            authorization: 'Bearer coordinator-test-token',
            'content-type': 'application/json'
          },
          body: JSON.stringify({
            approved: true,
            sandboxOwnershipVerified: true
          })
          }
        )
      );
      expect(response.status).toBe(201);
      const body = await response.json<{
        observationJob: { id: string; capability: string };
      }>();
      return body.observationJob;
    }

    const expiredJob = await createExtraObservationJob();
    await env.DB.prepare(`UPDATE runtime_observation_jobs SET expires_at = ? WHERE id = ?`)
      .bind('2000-01-01T00:00:00.000Z', expiredJob.id)
      .run();
    const expiredResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/runtime-observation-jobs/${expiredJob.id}`, {
        headers: { authorization: `Bearer ${expiredJob.capability}` }
      })
    );
    expect(expiredResponse.status).toBe(410);

    const revokedJob = await createExtraObservationJob();
    await env.DB.prepare(`UPDATE runtime_observation_jobs SET status = 'revoked' WHERE id = ?`)
      .bind(revokedJob.id)
      .run();
    const revokedResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/runtime-observation-jobs/${revokedJob.id}`, {
        headers: { authorization: `Bearer ${revokedJob.capability}` }
      })
    );
    expect(revokedResponse.status).toBe(410);

    const forbiddenEvidence = new FormData();
    forbiddenEvidence.set(
      'manifest',
      JSON.stringify({ ...baseManifest, authorization: 'Bearer leaked-secret' })
    );
    forbiddenEvidence.set(
      'screenshot_after_cleanup',
      new File([screenshot], 'after-cleanup.png', { type: 'image/png' })
    );
    const forbiddenResponse = await exports.default.fetch(
      new Request(evidenceEndpoint, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${approvedBody.observationJob.capability}`
        },
        body: forbiddenEvidence
      })
    );
    expect(forbiddenResponse.status).toBe(400);

    // The forbidden-key list also covers common credential field names such
    // as access_token, apiKey, sessionId, bearer, and auth.
    for (const [key, value] of [
      ['access_token', 'sk-live-abcdef'],
      ['apiKey', 'abc123'],
      ['sessionId', 'sess-1'],
      ['bearer', 'x'],
      ['auth', 'x']
    ] as const) {
      const secretEvidence = new FormData();
      secretEvidence.set(
        'manifest',
        JSON.stringify({ ...baseManifest, nested: { [key]: value } })
      );
      secretEvidence.set(
        'screenshot_after_cleanup',
        new File([screenshot], 'after-cleanup.png', { type: 'image/png' })
      );
      const secretResponse = await exports.default.fetch(
        new Request(evidenceEndpoint, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${approvedBody.observationJob.capability}`
          },
          body: secretEvidence
        })
      );
      expect(secretResponse.status, key).toBe(400);
    }
    const artifactsBeforeAcceptance = await env.ARTIFACTS.list({
      prefix: 'runtime-observations/'
    });
    expect(artifactsBeforeAcceptance.objects).toHaveLength(0);
    await env.DB.prepare(
      `UPDATE runtime_observation_jobs
          SET sandbox_id = 'sandbox-evidence-123',
              sandbox_started_at = ?, sandbox_termination_status = 'pending'
        WHERE id = ?`
    )
      .bind(new Date().toISOString(), approvedBody.observationJob.id)
      .run();
    const terminateSandbox = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (
        request.url === 'https://api.e2b.app/sandboxes/sandbox-evidence-123' &&
        request.method === 'DELETE'
      ) {
        return new Response(null, { status: 204 });
      }
      if (request.url === 'https://api.e2b.app/sandboxes/sandbox-evidence-123') {
        return Response.json({ error: 'not_found' }, { status: 404 });
      }
      return Response.json({ error: 'unexpected_request' }, { status: 500 });
    });
    vi.stubGlobal('fetch', terminateSandbox);

    const evidence = new FormData();
    evidence.set('manifest', JSON.stringify(baseManifest));
    evidence.set(
      'screenshot_after_cleanup',
      new File([screenshot], 'after-cleanup.png', { type: 'image/png' })
    );
    const acceptedEvidence = await exports.default.fetch(
      new Request(evidenceEndpoint, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${approvedBody.observationJob.capability}`
        },
        body: evidence
      })
    );
    expect(acceptedEvidence.status).toBe(200);
    const acceptedBody = await acceptedEvidence.json<{
      observationJobId: string;
      status: string;
      trust: string;
      security: { status: string; blockers: string[] };
      artifacts: Array<{ kind: string; sha256: string; objectKey: string }>;
    }>();
    expect(acceptedBody).toMatchObject({
      observationJobId: approvedBody.observationJob.id,
      status: 'complete',
      trust: 'webflow_observed',
      security: { status: 'passed', blockers: [] },
      artifacts: [
        {
          kind: 'screenshot_after_cleanup',
          sha256: screenshotSha256
        }
      ]
    });

    const replay = new FormData();
    replay.set('manifest', JSON.stringify(baseManifest));
    replay.set(
      'screenshot_after_cleanup',
      new File([screenshot], 'after-cleanup.png', { type: 'image/png' })
    );
    const replayResponse = await exports.default.fetch(
      new Request(evidenceEndpoint, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${approvedBody.observationJob.capability}`
        },
        body: replay
      })
    );
    expect(replayResponse.status).toBe(410);

    const completed = await env.DB.prepare(
      `SELECT status, consumed_at, evidence_trust, evidence_manifest_json,
              sandbox_terminated_at, sandbox_termination_status
         FROM runtime_observation_jobs
        WHERE id = ?`
    )
      .bind(approvedBody.observationJob.id)
      .first<{
        status: string;
        consumed_at: string;
        evidence_trust: string;
        evidence_manifest_json: string;
        sandbox_terminated_at: string;
        sandbox_termination_status: string;
      }>();
    expect(completed).toMatchObject({
      status: 'complete',
      consumed_at: expect.any(String),
      evidence_trust: 'webflow_observed',
      sandbox_terminated_at: expect.any(String),
      sandbox_termination_status: 'verified'
    });
    expect(terminateSandbox).toHaveBeenCalledTimes(2);
    expect(JSON.parse(completed!.evidence_manifest_json)).toEqual({
      ...baseManifest,
      securityEvaluation: {
        status: 'passed',
        predicates: {
          publishedTarget: true,
          runtimeReadyObserved: true,
          runtimeLoadedByPage: true,
          runtimeHashMatched: true,
          runtimeIntegrityMatched: true,
          noRuntimeCreatedScripts: true,
          noUnreviewedRuntimeScripts: true,
          negativeProxyBlocked: true,
          proxyPolicySatisfied: true,
          runtimeSourceMapAvailable: true
        },
        blockers: []
      }
    });
    const storedArtifact = await env.ARTIFACTS.get(acceptedBody.artifacts[0]!.objectKey);
    expect(storedArtifact).not.toBeNull();
    expect(new Uint8Array(await storedArtifact!.arrayBuffer())).toEqual(screenshot);

    const packagesAfterEvidence = await exports.default.fetch(
      new Request(
        `https://preflight.test/v1/reviews/${created.review.id}/runtime-test-packages`,
        {
          headers: {
            authorization: 'Bearer test-token',
            origin: 'http://localhost:1337'
          }
        }
      )
    );
    const packagesAfterBody = await packagesAfterEvidence.json<{
      testPackages: Array<{
        id: string;
        observation: {
          evidence: {
            runtimeFiles: Array<{
              url: string;
              loadedByPage: boolean;
              hashMatched: boolean;
              integrityMatched: boolean;
            }>;
            runtimeCreatedScripts: string[];
            unreviewedRuntimeScripts: string[];
          } | null;
        } | null;
      }>;
    }>();
    expect(
      packagesAfterBody.testPackages.find((item) => item.id === packageBody.testPackage.id)
        ?.observation?.evidence?.runtimeFiles
    ).toEqual([
      {
        url: 'http://127.0.0.1:4173/runtime-v1.js',
        loadMode: 'document',
        loadedByPage: true,
        hashMatched: true,
        integrityMatched: true,
        sourceMapAvailable: true,
        sourceMapUrl: 'http://127.0.0.1:4173/runtime-v1.js.map'
      },
      {
        url: 'http://127.0.0.1:4173/runtime-v2.js',
        loadMode: 'document',
        loadedByPage: true,
        hashMatched: true,
        integrityMatched: true,
        sourceMapAvailable: true,
        sourceMapUrl: 'http://127.0.0.1:4173/runtime-v2.js.map'
      }
    ]);
    const observationEvidence = packagesAfterBody.testPackages.find(
      (item) => item.id === packageBody.testPackage.id
    )?.observation?.evidence;
    expect(observationEvidence?.runtimeCreatedScripts).toEqual([]);
    expect(observationEvidence?.unreviewedRuntimeScripts).toEqual([]);

    const reviewAfterEvidence = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}`, {
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        }
      })
    );
    const reviewAfterBody = await reviewAfterEvidence.json<{
      review: { latestVersion: { result: { officialDecision: null } } };
    }>();
    expect(reviewAfterBody.review.latestVersion.result.officialDecision).toBeNull();
  });

  test('lets the package owner launch the pinned E2B runtime without exposing its capability', async () => {
    const reviewForm = new FormData();
    reviewForm.set(
      'bundle',
      new File([await createBundle()], 'consent-pro.zip', { type: 'application/zip' })
    );
    const reviewResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: reviewForm
      })
    );
    const review = await reviewResponse.json<{ review: { id: string } }>();
    const testPackageId = await createReadyRuntimePackage(review.review.id);
    const nonOwnerResponse = await exports.default.fetch(
      new Request(
        `https://preflight.test/v1/runtime-test-packages/${testPackageId}/observation-runs`,
        {
          method: 'POST',
          headers: {
            authorization: 'Bearer reviewer-test-token',
            origin: 'http://localhost:1337'
          }
        }
      )
    );
    expect(nonOwnerResponse.status).toBe(404);
    const launched: Array<{ url: string; headers: Headers; body: unknown }> = [];
    let terminationShouldFail = false;
    const e2b = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      launched.push({
        url: request.url,
        headers: new Headers(request.headers),
        body: request.body ? await request.clone().json() : null
      });
      if (request.url === 'https://api.e2b.app/sandboxes') {
        return new Response(
          JSON.stringify({
          templateID: 'template-runtime-test',
          sandboxID: 'sandbox-test-123',
          clientID: 'client-test',
          envdVersion: '0.5.7',
          envdAccessToken: 'envd-access-token',
          trafficAccessToken: 'traffic-access-token'
          }),
          {
          status: 201,
          headers: { 'content-type': 'application/json' }
          }
        );
      }
      if (
        request.url === 'https://api.e2b.app/sandboxes/sandbox-test-123' &&
        request.method === 'DELETE'
      ) {
        if (terminationShouldFail) {
          return Response.json({ error: 'provider_unavailable' }, { status: 503 });
        }
        return new Response(null, { status: 204 });
      }
      if (request.url === 'https://api.e2b.app/sandboxes/sandbox-test-123') {
        return Response.json({ error: 'not_found' }, { status: 404 });
      }
      return new Response(JSON.stringify({ accepted: true }), {
        status: 202,
        headers: { 'content-type': 'application/json' }
      });
    });
    vi.stubGlobal('fetch', e2b);

    try {
      const response = await exports.default.fetch(
        new Request(
          `https://preflight.test/v1/runtime-test-packages/${testPackageId}/observation-runs`,
          {
            method: 'POST',
            headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' }
          }
        )
      );
      expect(response.status).toBe(201);
      const body = await response.json<{
        observationJob: { id: string; status: string; capability?: string };
      }>();
      expect(body.observationJob).toMatchObject({ status: 'approved' });
      expect(body.observationJob.capability).toBeUndefined();
      expect(e2b).toHaveBeenCalledTimes(2);
      expect(launched[0]).toMatchObject({
        url: 'https://api.e2b.app/sandboxes',
        body: {
          templateID: 'app-review-companion-runtime:f47ac10b-58cc-4372-a567-0e02b2c3d479',
          timeout: 900,
          secure: true,
          allow_internet_access: true,
          network: { allowPublicTraffic: false },
          metadata: {
            lane: 'app_review_runtime_observation',
            observation_job_id: body.observationJob.id,
            coordinator: 'webflow-app-review-preflight'
          }
        }
      });
      expect(launched[0]!.headers.get('x-api-key')).toBe('e2b-test-key');
      expect(launched[1]).toMatchObject({
        url: 'https://3000-sandbox-test-123.e2b.app/run',
        body: {
          observationJobId: body.observationJob.id,
          apiBaseUrl: 'https://preflight.test',
          capability: expect.any(String)
        }
      });
      expect(launched[1]!.headers.get('e2b-traffic-access-token')).toBe('traffic-access-token');

      // The per-sandbox launch secret is injected at create, presented on the
      // /run call, and never reaches the developer-facing response.
      const launchSecret = (launched[0]!.body as {
        envVars: Record<string, string>;
      }).envVars.APP_REVIEW_RUNTIME_LAUNCH_SECRET;
      expect(launchSecret).toMatch(/^[A-Za-z0-9_-]{40,}$/);
      expect(launched[1]!.headers.get('x-webflow-runtime-launch-secret')).toBe(launchSecret);
      expect(JSON.stringify(body)).not.toContain(launchSecret);
      const launchedLifecycle = await env.DB.prepare(
        `SELECT sandbox_id, sandbox_started_at, sandbox_termination_status
           FROM runtime_observation_jobs
          WHERE id = ?`
      )
        .bind(body.observationJob.id)
        .first<{
          sandbox_id: string;
          sandbox_started_at: string;
          sandbox_termination_status: string;
        }>();
      expect(launchedLifecycle).toMatchObject({
        sandbox_id: 'sandbox-test-123',
        sandbox_started_at: expect.any(String),
        sandbox_termination_status: 'pending'
      });

      const duplicateResponse = await exports.default.fetch(
        new Request(
          `https://preflight.test/v1/runtime-test-packages/${testPackageId}/observation-runs`,
          {
            method: 'POST',
            headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' }
          }
        )
      );
      expect(duplicateResponse.status).toBe(200);
      const duplicateBody = await duplicateResponse.json<{
        observationJob: { id: string; status: string; deduplicated: boolean };
      }>();
      expect(duplicateBody.observationJob).toMatchObject({
        id: body.observationJob.id,
        status: 'approved',
        deduplicated: true
      });
      expect(e2b).toHaveBeenCalledTimes(2);

      await env.DB.prepare(
        `UPDATE runtime_observation_jobs
            SET expires_at = '2000-01-01T00:00:00.000Z'
          WHERE id = ?`
      )
        .bind(body.observationJob.id)
        .run();
      const expiredReadback = await exports.default.fetch(
        new Request(`https://preflight.test/v1/reviews/${review.review.id}/runtime-test-packages`, {
          headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' }
        })
      );
      const expiredBody = await expiredReadback.json<{
        testPackages: Array<{ observation: { status: string } | null }>;
      }>();
      expect(expiredBody.testPackages[0]?.observation?.status).toBe('expired');

      terminationShouldFail = true;
      const blockedRelaunch = await exports.default.fetch(
        new Request(
          `https://preflight.test/v1/runtime-test-packages/${testPackageId}/observation-runs`,
          {
            method: 'POST',
            headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' }
          }
        )
      );
      // Failing to terminate the previous sandbox is an infrastructure
      // cleanup problem, not a missing approval: it surfaces as 503.
      expect(blockedRelaunch.status).toBe(503);
      expect(await blockedRelaunch.json()).toMatchObject({
        error: 'runtime_observation_cleanup_failed',
        message: 'The previous runtime sandbox could not be terminated safely.'
      });
      expect(e2b).toHaveBeenCalledTimes(3);

      const stillBlockedRelaunch = await exports.default.fetch(
        new Request(
          `https://preflight.test/v1/runtime-test-packages/${testPackageId}/observation-runs`,
          {
            method: 'POST',
            headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' }
          }
        )
      );
      expect(stillBlockedRelaunch.status).toBe(503);
      expect(e2b).toHaveBeenCalledTimes(4);

      terminationShouldFail = false;
      const relaunchedResponse = await exports.default.fetch(
        new Request(
          `https://preflight.test/v1/runtime-test-packages/${testPackageId}/observation-runs`,
          {
            method: 'POST',
            headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' }
          }
        )
      );
      expect(relaunchedResponse.status).toBe(201);
      const relaunchedBody = await relaunchedResponse.json<{
        observationJob: { id: string; deduplicated: boolean };
      }>();
      expect(relaunchedBody.observationJob).toMatchObject({ deduplicated: false });
      expect(relaunchedBody.observationJob.id).not.toBe(body.observationJob.id);
      expect(e2b).toHaveBeenCalledTimes(8);
      const expiredLifecycle = await env.DB.prepare(
        `SELECT status, sandbox_terminated_at, sandbox_termination_status
           FROM runtime_observation_jobs
          WHERE id = ?`
      )
        .bind(body.observationJob.id)
        .first<{
          status: string;
          sandbox_terminated_at: string;
          sandbox_termination_status: string;
        }>();
      expect(expiredLifecycle).toMatchObject({
        status: 'expired',
        sandbox_terminated_at: expect.any(String),
        sandbox_termination_status: 'verified'
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  test('reports an expired test package as an actionable precondition failure', async () => {
    const reviewForm = new FormData();
    reviewForm.set(
      'bundle',
      new File([await createBundle()], 'expired-runtime.zip', { type: 'application/zip' })
    );
    const reviewResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: reviewForm
      })
    );
    const review = await reviewResponse.json<{ review: { id: string } }>();
    const testPackageId = await createReadyRuntimePackage(review.review.id);
    await env.DB.prepare(
      "UPDATE runtime_test_packages SET license_expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?"
    )
      .bind(testPackageId)
      .run();

    const response = await exports.default.fetch(
      new Request(
        `https://preflight.test/v1/runtime-test-packages/${testPackageId}/observation-runs`,
        {
          method: 'POST',
          headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' }
        }
      )
    );

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      error: 'runtime_observation_approval_required',
      message: 'The runtime test package is expired or no longer available.'
    });
  });

  test('maps E2B create failures to a safe in-card launch stage without provider detail', async () => {
    const reviewForm = new FormData();
    reviewForm.set(
      'bundle',
      new File([await createBundle()], 'safe-launch-error.zip', { type: 'application/zip' })
    );
    const reviewResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: reviewForm
      })
    );
    const review = await reviewResponse.json<{ review: { id: string } }>();
    const testPackageId = await createReadyRuntimePackage(review.review.id);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('provider-internal-detail e2b-test-key', { status: 500 }))
    );

    try {
      const response = await exports.default.fetch(
        new Request(
          `https://preflight.test/v1/runtime-test-packages/${testPackageId}/observation-runs`,
          {
            method: 'POST',
            headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' }
          }
        )
      );
      const text = await response.text();
      expect(response.status).toBe(503);
      expect(JSON.parse(text)).toEqual({
        error: 'runtime_observation_dispatch_unavailable',
        message: 'The runtime runner could not create a secure sandbox.'
      });
      expect(text).not.toContain('provider-internal-detail');
      expect(text).not.toContain('e2b-test-key');

      const event = await env.DB.prepare(
        `SELECT payload_json FROM review_events
          WHERE review_id = ? AND event_type = 'runtime_observation_dispatch_failed'
          ORDER BY created_at DESC LIMIT 1`
      )
        .bind(review.review.id)
        .first<{ payload_json: string }>();
      expect(JSON.parse(event!.payload_json)).toMatchObject({
        testPackageId,
        stage: 'sandbox_create',
        message: 'The runtime runner could not create a secure sandbox.'
      });
      expect(event!.payload_json).not.toContain('provider-internal-detail');
      expect(event!.payload_json).not.toContain('e2b-test-key');
    } finally {
      vi.unstubAllGlobals();
    }
  });

  test('persists and verifies cleanup when a created E2B sandbox cannot start its runner', async () => {
    const reviewForm = new FormData();
    reviewForm.set(
      'bundle',
      new File([await createBundle()], 'partial-launch.zip', { type: 'application/zip' })
    );
    const reviewResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: reviewForm
      })
    );
    const review = await reviewResponse.json<{ review: { id: string } }>();
    const testPackageId = await createReadyRuntimePackage(review.review.id);
    let e2bCall = 0;
    const e2b = vi.fn<typeof fetch>(async () => {
      e2bCall += 1;
      if (e2bCall === 1) {
        return Response.json(
          {
            templateID: 'template-runtime-test',
            sandboxID: 'sandbox-partial-123',
            trafficAccessToken: 'traffic-access-token'
          },
          { status: 201 }
        );
      }
      if (e2bCall === 2) {
        return Response.json({ error: 'runner_unavailable' }, { status: 500 });
      }
      if (e2bCall === 3) return new Response(null, { status: 204 });
      return Response.json({ error: 'not_found' }, { status: 404 });
    });
    vi.stubGlobal('fetch', e2b);

    try {
      const response = await exports.default.fetch(
        new Request(
          `https://preflight.test/v1/runtime-test-packages/${testPackageId}/observation-runs`,
          {
            method: 'POST',
            headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' }
          }
        )
      );
      expect(response.status).toBe(503);
      expect(
        e2b.mock.calls.map(([input]) => (input instanceof Request ? input.url : String(input)))
      ).toEqual([
        'https://api.e2b.app/sandboxes',
        'https://3000-sandbox-partial-123.e2b.app/run',
        'https://api.e2b.app/sandboxes/sandbox-partial-123',
        'https://api.e2b.app/sandboxes/sandbox-partial-123'
      ]);
      expect(e2b).toHaveBeenCalledTimes(4);
      await expect(response.json()).resolves.toEqual({
        error: 'runtime_observation_dispatch_unavailable',
        message: 'The runtime runner could not start inside the secure sandbox.'
      });
      const lifecycle = await env.DB.prepare(
        `SELECT status, sandbox_id, sandbox_started_at,
                sandbox_terminated_at, sandbox_termination_status
           FROM runtime_observation_jobs
          WHERE test_package_id = ?
          ORDER BY created_at DESC LIMIT 1`
      )
        .bind(testPackageId)
        .first<{
          status: string;
          sandbox_id: string;
          sandbox_started_at: string;
          sandbox_terminated_at: string;
          sandbox_termination_status: string;
        }>();
      expect(lifecycle).toMatchObject({
        status: 'failed',
        sandbox_id: 'sandbox-partial-123',
        sandbox_started_at: expect.any(String),
        sandbox_terminated_at: expect.any(String),
        sandbox_termination_status: 'verified'
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  test('lets an authenticated reviewer open the web workspace and request an independent replay', async () => {
    const reviewForm = new FormData();
    reviewForm.set(
      'bundle',
      new File([await createBundle()], 'reviewer-runtime.zip', { type: 'application/zip' })
    );
    const reviewResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: reviewForm
      })
    );
    const review = await reviewResponse.json<{
      review: { id: string; latestVersion: { id: string } };
    }>();
    const testPackageId = await createReadyRuntimePackage(review.review.id);

    const handoffResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${review.review.id}/reviewer-handoffs`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer reviewer-test-token',
            origin: 'http://localhost:1337',
            'content-type': 'application/json'
          },
          body: JSON.stringify({
            reviewVersionId: review.review.latestVersion.id,
            runtimeTestPackageId: testPackageId
          })
      })
    );
    expect(handoffResponse.status).toBe(201);
    const handoff = await handoffResponse.json<{ handoff: { url: string } }>();
    expect(handoff.handoff.url).toMatch(/^https:\/\/preflight\.test\/reviewer\/connect\?code=/);

    // A GET (what link-preview fetchers and mail scanners issue) renders an
    // interstitial and must NOT consume the one-time code or mint a session.
    const interstitial = await exports.default.fetch(
      new Request(handoff.handoff.url, { redirect: 'manual' })
    );
    expect(interstitial.status).toBe(200);
    expect(interstitial.headers.get('set-cookie')).toBeNull();
    expect(await interstitial.text()).toContain('Enter reviewer workspace');
    const pairingAfterGet = await env.DB.prepare(
      'SELECT redeemed_at FROM companion_pairings ORDER BY created_at DESC LIMIT 1'
    ).first<{ redeemed_at: string | null }>();
    expect(pairingAfterGet?.redeemed_at).toBeNull();

    // Only the explicit POST from the interstitial consumes the code.
    const code = new URL(handoff.handoff.url).searchParams.get('code')!;
    const connectForm = new FormData();
    connectForm.set('code', code);
    const connectResponse = await exports.default.fetch(
      new Request('https://preflight.test/reviewer/connect', {
        method: 'POST',
        redirect: 'manual',
        body: connectForm
      })
    );
    expect(connectResponse.status).toBe(303);
    expect(connectResponse.headers.get('location')).toBe('/reviewer');
    const sessionCookie = connectResponse.headers.get('set-cookie');
    expect(sessionCookie).toContain('app_review_reviewer_session=');
    expect(sessionCookie).toContain('HttpOnly');
    expect(sessionCookie).toContain('SameSite=Strict');

    const workspaceResponse = await exports.default.fetch(
      new Request('https://preflight.test/reviewer', {
        headers: { cookie: sessionCookie!.split(';')[0]! }
      })
    );
    expect(workspaceResponse.status).toBe(200);
    expect(workspaceResponse.headers.get('content-type')).toContain('text/html');
    const workspaceHtml = await workspaceResponse.text();
    expect(workspaceHtml).toContain('Reviewer workspace');
    expect(workspaceHtml).toContain('Run independent replay');
    expect(workspaceHtml).toContain(testPackageId);

    const replayLaunches: Array<{ url: string; body: unknown }> = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      replayLaunches.push({
        url: request.url,
        body: request.body ? await request.clone().json() : null
      });
      if (request.url === 'https://api.e2b.app/sandboxes') {
        const createBody = replayLaunches[0]!.body as {
          templateID: string;
          metadata: { observation_job_id: string };
        };
          return new Response(
            JSON.stringify({
          templateID: createBody.templateID,
          sandboxID: 'reviewer-sandbox-test',
          clientID: 'reviewer-client-test',
          envdVersion: '0.5.7',
          envdAccessToken: 'reviewer-envd-token',
          trafficAccessToken: 'reviewer-traffic-token'
            }),
            {
          status: 201,
          headers: { 'content-type': 'application/json' }
            }
          );
      }
      return new Response(JSON.stringify({ accepted: true }), { status: 202 });
      })
    );
    try {
      const replayResponse = await exports.default.fetch(
        new Request(
          `https://preflight.test/reviewer/runtime-test-packages/${testPackageId}/replay`,
          {
            method: 'POST',
            redirect: 'manual',
            headers: { cookie: sessionCookie!.split(';')[0]! }
          }
        )
      );
      expect(replayResponse.status).toBe(303);
      expect(replayResponse.headers.get('location')).toMatch(/^\/reviewer\?started=/);
      expect(replayLaunches).toHaveLength(2);
      expect(replayLaunches[0]).toMatchObject({
        url: 'https://api.e2b.app/sandboxes',
        body: {
          templateID: 'app-review-companion-runtime:f47ac10b-58cc-4372-a567-0e02b2c3d479',
          metadata: { observation_job_id: expect.any(String) }
        }
      });
      expect(replayLaunches[1]).toEqual({
        url: 'https://3000-reviewer-sandbox-test.e2b.app/run',
        body: {
          observationJobId: expect.any(String),
          apiBaseUrl: 'https://preflight.test',
          capability: expect.any(String)
        }
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  test('fails closed until a developer explicitly approves a bounded runtime job', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'consent-pro.zip', { type: 'application/zip' })
    );
    const createResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: form
      })
    );
    const created = await createResponse.json<{ review: { id: string } }>();
    const endpoint = `https://preflight.test/v1/reviews/${created.review.id}/runtime-jobs`;

    const unapproved = await exports.default.fetch(
      new Request(endpoint, {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          'content-type': 'application/json',
          origin: 'http://localhost:1337'
        },
        body: JSON.stringify({ approved: false })
      })
    );

    expect(unapproved.status).toBe(403);
    expect(await unapproved.json()).toEqual({
      error: 'runtime_approval_required',
      message: 'Approve the bounded sandbox test before a runtime job is prepared.'
    });
    const countBeforeApproval = await env.DB.prepare(
      'SELECT COUNT(*) AS count FROM runtime_jobs'
    ).first<{ count: number }>();
    expect(countBeforeApproval?.count).toBe(0);

    const approved = await exports.default.fetch(
      new Request(endpoint, {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          'content-type': 'application/json',
          origin: 'http://localhost:1337'
        },
        body: JSON.stringify({ approved: true })
      })
    );

    expect(approved.status).toBe(201);
    const body = await approved.json<{
      runtimeJob: {
        id: string;
        status: string;
        contract: {
          schemaVersion: string;
          purpose: string;
          targets: Array<{ url: string; host: string }>;
          manualVerification: string[];
          controls: {
            allowedHosts: string[];
            maxRequests: number;
            requestTimeoutMs: number;
            totalTimeoutMs: number;
            networkMode: string;
            credentials: string;
            viewports: Array<{ width: number; height: number }>;
          };
          boundaries: {
            officialDecision: null;
            canWriteGovernance: boolean;
            acceptsSecrets: boolean;
          };
        };
      };
    }>();
    expect(body.runtimeJob.status).toBe('approved');
    expect(body.runtimeJob.contract).toMatchObject({
      schemaVersion: 'app_runtime_evidence_job.v1',
      purpose: 'evidence_only',
      targets: [
        {
          url: 'https://api.consentpro.com/v2/cdn/runtime.js',
          host: 'api.consentpro.com'
        }
      ],
      controls: {
        allowedHosts: ['api.consentpro.com'],
        maxRequests: 20,
        requestTimeoutMs: 10_000,
        totalTimeoutMs: 60_000,
        networkMode: 'exact_host_allowlist',
        credentials: 'none',
        viewports: [
          { width: 1280, height: 720 },
          { width: 390, height: 844 }
        ]
      },
      boundaries: {
        officialDecision: null,
        canWriteGovernance: false,
        acceptsSecrets: false
      }
    });
    expect(body.runtimeJob.contract.manualVerification).toEqual([
      'Licensed, account-gated, and end-to-end installation behavior remains a human verification step.'
    ]);

    const stored = await env.DB.prepare(
      'SELECT status, approved_by_user_id, evidence_json, job_json FROM runtime_jobs WHERE id = ?'
    )
      .bind(body.runtimeJob.id)
      .first<{
        status: string;
        approved_by_user_id: string;
        evidence_json: string | null;
        job_json: string;
      }>();
    expect(stored).toMatchObject({
      status: 'approved',
      approved_by_user_id: 'local-webflow-user',
      evidence_json: null
    });
    expect(JSON.parse(stored!.job_json)).toEqual(body.runtimeJob.contract);
  });

  test('accepts only normalized, credential-free evidence from the coordinator', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'consent-pro.zip', { type: 'application/zip' })
    );
    const createResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337'
        },
        body: form
      })
    );
    const created = await createResponse.json<{ review: { id: string } }>();
    const approveResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/runtime-jobs`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer test-token',
            'content-type': 'application/json',
            origin: 'http://localhost:1337'
          },
          body: JSON.stringify({ approved: true })
      })
    );
    const approved = await approveResponse.json<{ runtimeJob: { id: string } }>();
    const endpoint = `https://preflight.test/v1/runtime-jobs/${approved.runtimeJob.id}/evidence`;
    const evidence = {
      schemaVersion: 'app_runtime_evidence.v1',
      status: 'complete',
      startedAt: '2026-07-14T22:15:00.000Z',
      finishedAt: '2026-07-14T22:15:02.000Z',
      requestCount: 1,
      targetResults: [
        {
          url: 'https://api.consentpro.com/v2/cdn/runtime.js',
          statusCode: 200,
          contentType: 'application/javascript',
          bytes: 12345,
          sha256: 'f'.repeat(64),
          consoleMessages: []
        }
      ],
      screenshots: []
    };

    const unauthorized = await exports.default.fetch(
      new Request(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(evidence)
      })
    );
    expect(unauthorized.status).toBe(401);

    const credentialLeak = await exports.default.fetch(
      new Request(endpoint, {
        method: 'POST',
        headers: {
          authorization: 'Bearer coordinator-test-token',
          'content-type': 'application/json'
        },
        body: JSON.stringify({ ...evidence, authorization: 'Bearer leaked-secret' })
      })
    );
    expect(credentialLeak.status).toBe(400);
    expect(await credentialLeak.json()).toEqual({
      error: 'invalid_runtime_evidence',
      message: 'Runtime evidence contains a forbidden secret or decision field.'
    });

    const accepted = await exports.default.fetch(
      new Request(endpoint, {
        method: 'POST',
        headers: {
          authorization: 'Bearer coordinator-test-token',
          'content-type': 'application/json'
        },
        body: JSON.stringify(evidence)
      })
    );
    expect(accepted.status).toBe(200);
    expect(await accepted.json()).toEqual({
      runtimeJobId: approved.runtimeJob.id,
      status: 'complete',
      evidence
    });

    const stored = await env.DB.prepare(
      'SELECT status, evidence_json FROM runtime_jobs WHERE id = ?'
    )
      .bind(approved.runtimeJob.id)
      .first<{ status: string; evidence_json: string }>();
    expect(stored?.status).toBe('complete');
    expect(JSON.parse(stored!.evidence_json)).toEqual(evidence);
  });

  test('derives anonymized pattern proposals and requires human approval for handoff', async () => {
    for (const privateName of ['Private Partner Alpha', 'Private Partner Beta']) {
      const form = new FormData();
      form.set('name', privateName);
      form.set(
        'bundle',
        new File([await createBundle()], `${privateName}.zip`, { type: 'application/zip' })
      );
      const response = await exports.default.fetch(
        new Request('https://preflight.test/v1/reviews', {
          method: 'POST',
          headers: {
            authorization: 'Bearer test-token',
            origin: 'http://localhost:1337'
          },
          body: form
        })
      );
      expect(response.status).toBe(201);
    }

    const deriveResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/pattern-candidates/derive', {
        method: 'POST',
        headers: { authorization: 'Bearer pattern-coordinator-test-token' }
      })
    );
    expect(deriveResponse.status).toBe(200);
    const derived = await deriveResponse.json<{
      candidates: Array<{
        id: string;
        status: string;
        evidence: {
          ruleId: string;
          occurrenceCount: number;
          reviewCount: number;
          versionCount: number;
        };
        proposal: {
          ruleId: string;
          humanApprovalRequired: boolean;
          writesPerformed: boolean;
        };
      }>;
    }>();
    const candidate = derived.candidates.find(
      (item) => item.evidence.ruleId === 'SEC-SCRIPT-INJECTION'
    );
    expect(candidate).toMatchObject({
      status: 'draft',
      evidence: {
        ruleId: 'SEC-SCRIPT-INJECTION',
        occurrenceCount: expect.any(Number),
        reviewCount: expect.any(Number),
        versionCount: expect.any(Number)
      },
      proposal: {
        ruleId: 'SEC-SCRIPT-INJECTION',
        humanApprovalRequired: true,
        writesPerformed: false
      }
    });
    expect(candidate!.evidence.reviewCount).toBeGreaterThanOrEqual(2);
    const serialized = JSON.stringify(derived);
    expect(serialized).not.toContain('Private Partner Alpha');
    expect(serialized).not.toContain('Private Partner Beta');
    expect(serialized).not.toContain('assets/index.js');
    expect(serialized).not.toContain('api.consentpro.com');

    const handoffEndpoint = `https://preflight.test/v1/pattern-candidates/${candidate!.id}/handoff`;
    const unapproved = await exports.default.fetch(
      new Request(handoffEndpoint, {
        method: 'POST',
        headers: {
          authorization: 'Bearer governance-approver-test-token',
          'content-type': 'application/json'
        },
        body: JSON.stringify({ approved: false })
      })
    );
    expect(unapproved.status).toBe(403);
    const stillDraft = await env.DB.prepare('SELECT status FROM pattern_candidates WHERE id = ?')
      .bind(candidate!.id)
      .first<{ status: string }>();
    expect(stillDraft?.status).toBe('draft');

    const approved = await exports.default.fetch(
      new Request(handoffEndpoint, {
        method: 'POST',
        headers: {
          authorization: 'Bearer governance-approver-test-token',
          'content-type': 'application/json'
        },
        body: JSON.stringify({ approved: true })
      })
    );
    expect(approved.status).toBe(200);
    const handoff = await approved.json<{
      artifact: {
        schemaVersion: string;
        mutationPerformed: boolean;
        destinations: string[];
        evidence: unknown;
        proposal: unknown;
      };
    }>();
    expect(handoff.artifact).toMatchObject({
      schemaVersion: 'app_governance_guidance_handoff.v1',
      mutationPerformed: false,
      destinations: ['App Governance', 'webflow/openapi-internal']
    });
    expect(JSON.stringify(handoff)).not.toContain('Private Partner');
    const handedOff = await env.DB.prepare(
      'SELECT status, approved_by_user_id, approved_at FROM pattern_candidates WHERE id = ?'
    )
      .bind(candidate!.id)
      .first<{ status: string; approved_by_user_id: string; approved_at: string }>();
    expect(handedOff).toMatchObject({
      status: 'handed_off',
      approved_by_user_id: 'authorized-governance-reviewer'
    });
    expect(handedOff?.approved_at).toEqual(expect.any(String));
  });

  test('honors dev bypass tokens only when ENVIRONMENT is explicitly development', async () => {
    for (const environment of ['production', 'staging', '', 'Development', 'dev']) {
      const response = await worker.fetch(
        new Request('https://preflight.test/v1/reviews', {
          headers: {
            authorization: 'Bearer test-token',
            origin: 'http://localhost:1337'
          }
        }),
        {
          DB: env.DB,
          ARTIFACTS: env.ARTIFACTS,
          ENVIRONMENT: environment,
          ALLOWED_ORIGINS: 'http://localhost:1337',
          PREFLIGHT_DEV_TOKEN: 'test-token',
          PREFLIGHT_REVIEWER_DEV_TOKEN: 'reviewer-test-token'
        } as Env
      );
      expect(response.status, `ENVIRONMENT=${JSON.stringify(environment)}`).toBe(401);
    }
  });

  test('refuses to serve at all when dev tokens are bound beside non-localhost origins', async () => {
    const misconfigured = {
      DB: env.DB,
      ARTIFACTS: env.ARTIFACTS,
      ENVIRONMENT: 'production',
      ALLOWED_ORIGINS:
        'chrome-extension://eiogakldgljpbbmplgckjkoglfgabblm,http://localhost:1337',
      PREFLIGHT_DEV_TOKEN: 'test-token'
    } as Env;
    for (const path of ['/health', '/v1/reviews']) {
      const response = await worker.fetch(
        new Request(`https://preflight.test${path}`, {
          headers: { authorization: 'Bearer test-token' }
        }),
        misconfigured
      );
      expect(response.status, path).toBe(503);
      await expect(response.json()).resolves.toMatchObject({
        error: 'server_misconfigured'
      });
    }

    // Localhost-only origins remain a valid development setup.
    const healthy = await worker.fetch(
      new Request('https://preflight.test/health'),
      {
        DB: env.DB,
        ARTIFACTS: env.ARTIFACTS,
        ENVIRONMENT: 'development',
        ALLOWED_ORIGINS: 'http://localhost:1337,http://127.0.0.1:5173',
        PREFLIGHT_DEV_TOKEN: 'test-token'
      } as Env
    );
    expect(healthy.status).toBe(200);
  });

  test('publishes reconnect-required authorization readiness without exposing credentials', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(null, { status: 401 }))
    );
    const readinessEnv = {
      ...env,
      ENVIRONMENT: 'production',
      ALLOWED_ORIGINS: 'https://6a57b0fa70db1b7a0cd666ac.webflow-ext.com',
      PREFLIGHT_DEV_TOKEN: undefined,
      PREFLIGHT_REVIEWER_DEV_TOKEN: undefined,
      WEBFLOW_APP_ACCESS_TOKEN: 'revoked-token'
    } as Env;

    await expect(recordWebflowAuthorizationReadiness(readinessEnv)).resolves.toEqual({
      state: 'reconnect_required',
      statusCode: 401
    });

    const health = await worker.fetch(
      new Request('https://preflight.test/health'),
      readinessEnv
    );
    expect(health.status).toBe(503);
    await expect(health.json()).resolves.toEqual({
      ok: false,
      service: 'webflow-app-review-preflight',
      webflowAuthorization: {
        state: 'reconnect_required',
        checkedAt: expect.any(String)
      }
    });
  });

  test('caps a runtime test package at eight pinned artifacts', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'artifact-cap.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{ review: { id: string } }>();
    const response = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/runtime-test-packages`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          targetUrl: 'http://127.0.0.1:4173/runtime-fixture',
          sandboxOwnershipConfirmed: true,
          license: {
            mode: 'installation_allowlist',
            expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString()
          },
          runtimeArtifacts: Array.from({ length: 9 }, (_, index) => ({
            url: `http://127.0.0.1:4173/runtime-v${index}.js`,
            sha256: 'a'.repeat(64),
            integrity: TEST_RUNTIME_INTEGRITY
          })),
          negativeProxyProbe: {
            method: 'GET',
            urlTemplate: 'http://127.0.0.1:4173/proxy?url={canaryUrl}'
          },
          lifecycle: { readySelector: '[data-runtime-ready]' }
        })
      })
    );
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: 'invalid_runtime_test_package',
      message: expect.stringMatching(/between 1 and 8/i)
    });
  });

  test('fails closed when an observation job expires during its evidence upload', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'upload-race.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{
      review: { id: string; latestVersion: { id: string; result: { artifact: { sha256: string } } } };
    }>();
    const testPackageId = await createReadyRuntimePackage(created.review.id);

    const approved = await exports.default.fetch(
      new Request(
        `https://preflight.test/v1/runtime-test-packages/${testPackageId}/observation-jobs`,
        {
          method: 'POST',
          headers: {
            authorization: 'Bearer coordinator-test-token',
            'content-type': 'application/json'
          },
          body: JSON.stringify({ approved: true, sandboxOwnershipVerified: true })
        }
      )
    );
    expect(approved.status).toBe(201);
    const job = (
      await approved.json<{
        observationJob: {
          id: string;
          capability: string;
          contract: { nonce: string; target: { url: string } };
        };
      }>()
    ).observationJob;

    // Flip the job to running.
    const running = await exports.default.fetch(
      new Request(`https://preflight.test/v1/runtime-observation-jobs/${job.id}`, {
        headers: { authorization: `Bearer ${job.capability}` }
      })
    );
    expect(running.status).toBe(200);

    // Simulate the cron racing the upload: the moment the claim marks the job
    // 'uploading', an expiry sweep marks it 'expired' before the completion
    // batch runs.
    await env.DB.prepare(
      `CREATE TRIGGER test_expire_during_upload
        AFTER UPDATE OF status ON runtime_observation_jobs
        WHEN NEW.status = 'uploading' AND NEW.id = '${job.id}'
        BEGIN
          UPDATE runtime_observation_jobs SET status = 'expired' WHERE id = NEW.id;
        END`
    ).run();

    const screenshot = new Uint8Array([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x01
    ]);
    const screenshotSha256 = await sha256Hex(screenshot);
    const manifest = {
      schemaVersion: 'runtime_observation_evidence.v1',
      observationJobId: job.id,
      testPackageId,
      reviewVersionId: created.review.latestVersion.id,
      bundleSha256: created.review.latestVersion.result.artifact.sha256,
      nonce: job.contract.nonce,
      targetUrl: job.contract.target.url,
      trust: 'webflow_observed',
      executionEvidence: 'chromium_cdp_v1',
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      redaction: {
        applied: true,
        headersRemoved: true,
        cookiesRemoved: true,
        formValuesMasked: true
      },
      runtimeReadyObserved: true,
      runtimeArtifacts: [
        {
          url: 'http://127.0.0.1:4173/runtime-v1.js',
          expectedSha256: 'a'.repeat(64),
          observedSha256: 'a'.repeat(64),
          integrity: TEST_RUNTIME_INTEGRITY,
          domIntegrity: TEST_RUNTIME_INTEGRITY,
          domCrossOrigin: 'anonymous',
          loadedByPage: true,
          trustedRuntimeInitiator: false,
          sourceMap: { available: false }
        }
      ],
      runtimeCreatedScripts: [],
      unreviewedRuntimeScripts: [],
      cleanup: { status: 'not_tested', residue: [] },
      negativeProxyCanary: {
        url: 'http://127.0.0.1:4174/webflow-runtime-canary',
        outcome: 'blocked',
        statusCode: 403
      },
      artifacts: [
        {
          field: 'screenshot_after_observation',
          kind: 'screenshot_after_observation',
          fileName: 'after-observation.png',
          contentType: 'image/png',
          bytes: screenshot.byteLength,
          sha256: screenshotSha256
        }
      ]
    };
    const evidence = new FormData();
    evidence.set('manifest', JSON.stringify(manifest));
    evidence.set(
      'screenshot_after_observation',
      new File([screenshot], 'after-observation.png', { type: 'image/png' })
    );

    try {
      const response = await exports.default.fetch(
        new Request(`https://preflight.test/v1/runtime-observation-jobs/${job.id}/evidence`, {
          method: 'POST',
          headers: { authorization: `Bearer ${job.capability}` },
          body: evidence
        })
      );
      // The server never reports success for a job it no longer owns.
      expect(response.status).toBe(410);
      await expect(response.json()).resolves.toEqual({
        error: 'runtime_observation_job_unavailable'
      });

      const jobRow = await env.DB.prepare(
        `SELECT status, evidence_trust, evidence_manifest_json, consumed_at
           FROM runtime_observation_jobs WHERE id = ?`
      )
        .bind(job.id)
        .first<{
          status: string;
          evidence_trust: string | null;
          evidence_manifest_json: string | null;
          consumed_at: string | null;
        }>();
      expect(jobRow).toEqual({
        status: 'expired',
        evidence_trust: null,
        evidence_manifest_json: null,
        consumed_at: null
      });

      const artifactCount = await env.DB.prepare(
        'SELECT COUNT(*) AS count FROM runtime_observation_artifacts WHERE observation_job_id = ?'
      )
        .bind(job.id)
        .first<{ count: number }>();
      expect(artifactCount?.count).toBe(0);

      const completionEvents = await env.DB.prepare(
        `SELECT COUNT(*) AS count FROM review_events
          WHERE event_type = 'runtime_observation_completed'
            AND payload_json LIKE '%' || ? || '%'`
      )
        .bind(job.id)
        .first<{ count: number }>();
      expect(completionEvents?.count).toBe(0);

      const orphaned = await env.ARTIFACTS.list({
        prefix: `runtime-observations/local-webflow-user/${created.review.id}/`
      });
      expect(orphaned.objects).toHaveLength(0);
    } finally {
      await env.DB.prepare('DROP TRIGGER IF EXISTS test_expire_during_upload').run();
    }
  });

  test('gives uploading jobs a grace window before the cron expiry sweep reclaims them', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'upload-grace.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{ review: { id: string } }>();
    const testPackageId = await createReadyRuntimePackage(created.review.id);

    const jobId = crypto.randomUUID();
    const now = Date.now();
    const insertJob = (expiresAt: string) =>
      env.DB.prepare(
        `INSERT INTO runtime_observation_jobs
          (id, test_package_id, status, capability_sha256, nonce, contract_json,
           approved_by_actor, approved_at, expires_at, created_at, updated_at)
         VALUES (?, ?, 'uploading', ?, ?, '{}', 'webflow-runtime-coordinator', ?, ?, ?, ?)`
      )
        .bind(
          jobId,
          testPackageId,
          'c'.repeat(64),
          crypto.randomUUID(),
          new Date(now).toISOString(),
          expiresAt,
          new Date(now).toISOString(),
          new Date(now).toISOString()
        )
        .run();

    // Expired two minutes ago: still inside the upload grace window.
    await insertJob(new Date(now - 2 * 60 * 1000).toISOString());
    await reconcileRuntimeObservationJobs(env as unknown as Env);
    let status = await env.DB.prepare(
      'SELECT status FROM runtime_observation_jobs WHERE id = ?'
    )
      .bind(jobId)
      .first<{ status: string }>();
    expect(status?.status).toBe('uploading');

    // Past the grace window: the sweep reclaims it.
    await env.DB.prepare('UPDATE runtime_observation_jobs SET expires_at = ? WHERE id = ?')
      .bind(new Date(now - 11 * 60 * 1000).toISOString(), jobId)
      .run();
    await reconcileRuntimeObservationJobs(env as unknown as Env);
    status = await env.DB.prepare('SELECT status FROM runtime_observation_jobs WHERE id = ?')
      .bind(jobId)
      .first<{ status: string }>();
    expect(status?.status).toBe('expired');
  });

  test('computes the revision sequence transactionally instead of from a stale read', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'sequence-race.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{ review: { id: string } }>();

    // Simulate a concurrent revision that committed after this request read
    // the latest version (which still has sequence 1).
    await env.DB.prepare(
      `INSERT INTO review_versions
        (id, review_id, sequence, artifact_sha256, artifact_key, file_name,
         compressed_bytes, policy_ruleset_version, policy_config_version,
         review_json, created_at)
       VALUES (?, ?, 2, ?, 'concurrent-key', 'concurrent.zip', 1, 'r', 'c', '{}', ?)`
    )
      .bind(crypto.randomUUID(), created.review.id, 'e'.repeat(64), new Date().toISOString())
      .run();

    const revisionForm = new FormData();
    revisionForm.set(
      'bundle',
      new File([await createBundle({ injectScript: false })], 'sequence-race-v2.zip', {
        type: 'application/zip'
      })
    );
    const revisionResponse = await exports.default.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/revisions`, {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: revisionForm
      })
    );
    // The stale read would have produced sequence 2 and violated
    // UNIQUE(review_id, sequence); the in-batch MAX(sequence)+1 lands on 3.
    expect(revisionResponse.status).toBe(201);
    const revised = await revisionResponse.json<{
      review: { latestVersion: { sequence: number } };
    }>();
    expect(revised.review.latestVersion.sequence).toBe(3);

    const event = await env.DB.prepare(
      `SELECT payload_json FROM review_events
        WHERE review_id = ? AND event_type = 'revision_added'
        ORDER BY created_at DESC LIMIT 1`
    )
      .bind(created.review.id)
      .first<{ payload_json: string }>();
    expect(JSON.parse(event!.payload_json)).toMatchObject({ sequence: 3 });
  });

  test('maps a revision uniqueness race to 409 and writes no orphan artifact bytes', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'conflict-race.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{
      review: { id: string; latestVersion: { id: string } };
    }>();

    // A trigger stands in for a concurrent request: whenever this review adds
    // a version, an identical competing row is inserted first, so the actual
    // insert violates UNIQUE(review_id, sequence).
    await env.DB.prepare(
      `CREATE TRIGGER test_revision_conflict
        BEFORE INSERT ON review_versions
        WHEN NEW.review_id = '${created.review.id}'
        BEGIN
          INSERT INTO review_versions
            (id, review_id, sequence, artifact_sha256, artifact_key, file_name,
             compressed_bytes, policy_ruleset_version, policy_config_version,
             review_json, created_at)
          VALUES (NEW.id || '-race', NEW.review_id, NEW.sequence, 'f000' || substr(NEW.artifact_sha256, 5),
                  'race-key', 'race.zip', 1, 'r', 'c', '{}', NEW.created_at);
        END`
    ).run();

    try {
      const bundle = await createBundle({
        injectScript: false,
        seed: crypto.randomUUID()
      });
      const bundleSha = await sha256Hex(bundle);
      const revisionForm = new FormData();
      revisionForm.set(
        'bundle',
        new File([bundle], 'conflict-race-v2.zip', { type: 'application/zip' })
      );
      const response = await exports.default.fetch(
        new Request(`https://preflight.test/v1/reviews/${created.review.id}/revisions`, {
          method: 'POST',
          headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
          body: revisionForm
        })
      );
      expect(response.status).toBe(409);
      await expect(response.json()).resolves.toMatchObject({
        error: 'revision_conflict'
      });

      // Bytes are written to R2 only after the batch succeeds, so the failed
      // batch leaves no orphan object behind.
      const orphan = await env.ARTIFACTS.head(
        `local-webflow-user/artifacts/sha256/${bundleSha}.zip`
      );
      expect(orphan).toBeNull();

      const latest = await env.DB.prepare(
        'SELECT latest_version_id FROM reviews WHERE id = ?'
      )
        .bind(created.review.id)
        .first<{ latest_version_id: string }>();
      expect(latest?.latest_version_id).toBe(created.review.latestVersion.id);
    } finally {
      await env.DB.prepare('DROP TRIGGER IF EXISTS test_revision_conflict').run();
    }
  });

  test('reports a conflict instead of a 500 when the coordinator issues a second active job', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'coordinator-race.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{ review: { id: string } }>();
    const testPackageId = await createReadyRuntimePackage(created.review.id);

    const issue = () =>
      exports.default.fetch(
        new Request(
          `https://preflight.test/v1/runtime-test-packages/${testPackageId}/observation-jobs`,
          {
            method: 'POST',
            headers: {
              authorization: 'Bearer coordinator-test-token',
              'content-type': 'application/json'
            },
            body: JSON.stringify({ approved: true, sandboxOwnershipVerified: true })
          }
        )
      );

    const first = await issue();
    expect(first.status).toBe(201);

    // Migration 0007's one-active-job partial unique index used to surface
    // here as an uncaught constraint error (HTTP 500).
    const second = await issue();
    expect(second.status).toBe(403);
    await expect(second.json()).resolves.toMatchObject({
      error: 'runtime_observation_approval_required',
      message: expect.stringMatching(/already active/i)
    });
  });

  test('recognizes decimal, octal, hex, and shorthand private IPv4 hostnames', () => {
    for (const host of [
      '2130706433', // 127.0.0.1 decimal
      '0x7f000001', // 127.0.0.1 hex
      '017700000001', // 127.0.0.1 octal
      '127.1', // shorthand
      '0xc0.0xa8.0x1.0x1', // 192.168.1.1 hex parts
      '10.0.0.1',
      '192.168.4.20',
      '172.16.0.9',
      '169.254.1.1',
      'localhost',
      'printer.local',
      '[::1]'
    ]) {
      expect(isPrivateOrLocalHostname(host), host).toBe(true);
    }
    for (const host of [
      'api.consentpro.com',
      '8.8.8.8',
      '172.32.0.1',
      '3221225985' // 192.0.2.1 decimal (public TEST-NET)
    ]) {
      expect(isPrivateOrLocalHostname(host), host).toBe(false);
    }
  });

  test('caps and error-isolates the cron sandbox reconciliation batch', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'cron-batch.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{ review: { id: string } }>();
    const testPackageId = await createReadyRuntimePackage(created.review.id);

    const now = new Date().toISOString();
    const contract = JSON.stringify({
      reviewId: created.review.id,
      reviewVersionId: 'v',
      testPackageId
    });
    for (let index = 0; index < 12; index += 1) {
      await env.DB.prepare(
        `INSERT INTO runtime_observation_jobs
          (id, test_package_id, status, capability_sha256, nonce, contract_json,
           approved_by_actor, approved_at, expires_at, created_at, updated_at,
           sandbox_id, sandbox_termination_status)
         VALUES (?, ?, 'failed', ?, ?, ?, 'webflow-runtime-coordinator', ?, ?, ?, ?,
                 ?, 'pending')`
      )
        .bind(
          `cron-batch-job-${index}`,
          testPackageId,
          `${index}`.padStart(4, '0') + 'd'.repeat(60),
          crypto.randomUUID(),
          contract,
          now,
          now,
          now,
          now,
          `cron-batch-sandbox-${index}`
        )
        .run();
    }

    // Every provider call fails: the cron must not throw, must cap the batch,
    // and must report the failures.
    const failingFetch = vi.fn(async () => {
      throw new Error('provider unavailable');
    });
    vi.stubGlobal('fetch', failingFetch);
    try {
      const outcome = await reconcileRuntimeObservationJobs(env as unknown as Env);
      expect(outcome.reconciled).toBe(0);
      expect(outcome.failed).toBe(10);
    } finally {
      vi.unstubAllGlobals();
      await env.DB.prepare(
        "DELETE FROM runtime_observation_jobs WHERE id LIKE 'cron-batch-job-%'"
      ).run();
    }
  });

  test('produces actionable configuration errors for missing reviewer and canary settings', async () => {
    const form = new FormData();
    form.set(
      'bundle',
      new File([await createBundle()], 'config-errors.zip', { type: 'application/zip' })
    );
    const createdResponse = await exports.default.fetch(
      new Request('https://preflight.test/v1/reviews', {
        method: 'POST',
        headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' },
        body: form
      })
    );
    const created = await createdResponse.json<{
      review: { id: string; latestVersion: { id: string } };
    }>();
    const testPackageId = await createReadyRuntimePackage(created.review.id);

    const noReviewerEnv = {
      DB: env.DB,
      ARTIFACTS: env.ARTIFACTS,
      ENVIRONMENT: 'development',
      ALLOWED_ORIGINS: 'http://localhost:1337',
      PREFLIGHT_DEV_TOKEN: 'test-token'
    } as Env;
    const handoff = await worker.fetch(
      new Request(`https://preflight.test/v1/reviews/${created.review.id}/reviewer-handoffs`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer test-token',
          origin: 'http://localhost:1337',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          reviewVersionId: created.review.latestVersion.id,
          runtimeTestPackageId: testPackageId
        })
      }),
      noReviewerEnv
    );
    expect(handoff.status).toBe(403);
    await expect(handoff.json()).resolves.toMatchObject({
      error: 'reviewer_required',
      message: expect.stringMatching(/REVIEWER_USER_IDS/)
    });

    const noCanaryEnv = {
      DB: env.DB,
      ARTIFACTS: env.ARTIFACTS,
      ENVIRONMENT: 'development',
      ALLOWED_ORIGINS: 'http://localhost:1337',
      PREFLIGHT_DEV_TOKEN: 'test-token',
      E2B_API_KEY: 'e2b-test-key',
      E2B_RUNTIME_TEMPLATE_ID:
        'app-review-companion-runtime:f47ac10b-58cc-4372-a567-0e02b2c3d479'
    } as Env;
    const run = await worker.fetch(
      new Request(
        `https://preflight.test/v1/runtime-test-packages/${testPackageId}/observation-runs`,
        {
          method: 'POST',
          headers: { authorization: 'Bearer test-token', origin: 'http://localhost:1337' }
        }
      ),
      noCanaryEnv
    );
    expect(run.status).toBe(503);
    await expect(run.json()).resolves.toMatchObject({
      error: 'runtime_observation_dispatch_unavailable',
      message: expect.stringMatching(/RUNTIME_CANARY_URL/)
    });
  });
});
