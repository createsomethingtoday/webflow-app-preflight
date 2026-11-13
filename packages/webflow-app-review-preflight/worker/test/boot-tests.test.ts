import { env } from "cloudflare:workers";
import JSZip from "jszip";
import {
  DESIGNER_EXTENSION_HOST_CSP,
  type BootTestEvidence,
  type BootTestJobContract,
} from "@create-something/webflow-app-review-preflight";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import {
  bootTestSummaryForVersion,
  compareBootTestRuns,
  validateBootTestEvidence,
} from "../src/boot-tests";
import worker from "../src/index";
import type { Env } from "../src/types";

const ORIGIN = "http://localhost:1337";

afterEach(() => {
  vi.unstubAllGlobals();
});

function enabledEnv(overrides: Partial<Env> = {}): Env {
  return {
    ...(env as unknown as Env),
    BOOT_TEST_ENABLED: "true",
    ...overrides,
  };
}

async function call(
  path: string,
  init: RequestInit & { token?: string } = {},
  workerEnv: Env = enabledEnv(),
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("origin", ORIGIN);
  if (init.token) headers.set("authorization", `Bearer ${init.token}`);
  return worker.fetch(
    new Request(`https://preflight.test${path}`, { ...init, headers }),
    workerEnv,
  );
}

async function createReview(
  seed: string,
): Promise<{ reviewId: string; versionId: string; bundle: Uint8Array }> {
  const zip = new JSZip();
  zip.file("index.html", `<!doctype html><title>Fixture</title><p>${seed}</p>`);
  zip.file(
    "webflow.json",
    JSON.stringify({
      name: "Fixture extension",
      apiVersion: "2",
      publicDir: "dist",
    }),
  );
  const bundle = await zip.generateAsync({ type: "uint8array" });
  const form = new FormData();
  form.set(
    "bundle",
    new File([bundle], "fixture.zip", { type: "application/zip" }),
  );
  const response = await call("/v1/reviews", {
    method: "POST",
    body: form,
    token: "test-token",
  });
  expect(response.status).toBe(201);
  const body = await response.json<{
    review: { id: string; latestVersion: { id: string } };
  }>();
  return {
    reviewId: body.review.id,
    versionId: body.review.latestVersion.id,
    bundle,
  };
}

interface E2BStub {
  runBodies: Array<Record<string, unknown>>;
  createBodies: Array<Record<string, unknown>>;
}

// Plays E2B's control plane and the template's /run route.
function stubE2B(): E2BStub {
  const stub: E2BStub = { runBodies: [], createBodies: [] };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request =
        input instanceof Request ? input : new Request(input, init);
      if (
        request.url === "https://api.e2b.app/sandboxes" &&
        request.method === "POST"
      ) {
        stub.createBodies.push(await request.json());
        return Response.json(
          {
            templateID: "template-boot-test",
            sandboxID: "sandbox-boot-123",
            trafficAccessToken: "traffic-access-token",
          },
          { status: 201 },
        );
      }
      if (request.url === "https://api.e2b.app/sandboxes/sandbox-boot-123") {
        return request.method === "DELETE"
          ? new Response(null, { status: 204 })
          : Response.json({ error: "not_found" }, { status: 404 });
      }
      if (request.url === "https://3000-sandbox-boot-123.e2b.app/run") {
        stub.runBodies.push(await request.json());
        return Response.json({ accepted: true }, { status: 202 });
      }
      return new Response("unexpected", { status: 500 });
    }),
  );
  return stub;
}

async function startJob(
  reviewId: string,
  workerEnv: Env = enabledEnv(),
): Promise<{ jobId: string; capability: string; stub: E2BStub }> {
  const stub = stubE2B();
  const response = await call(
    `/v1/reviews/${reviewId}/boot-tests`,
    { method: "POST", token: "test-token" },
    workerEnv,
  );
  expect(response.status).toBe(201);
  const body = await response.json<{
    bootTest: { id: string; status: string };
  }>();
  expect(body.bootTest.status).toBe("approved");
  expect(JSON.stringify(body)).not.toMatch(/capability/i);
  const capability = String(stub.runBodies[0]?.capability ?? "");
  return { jobId: body.bootTest.id, capability, stub };
}

async function fetchContract(
  jobId: string,
  capability: string,
): Promise<BootTestJobContract> {
  const response = await call(`/v1/boot-test-jobs/${jobId}`, {
    token: capability,
  });
  expect(response.status).toBe(200);
  const body = await response.json<{
    bootTestJob: { contract: BootTestJobContract };
  }>();
  return body.bootTestJob.contract;
}

function evidence(
  contract: BootTestJobContract,
  overrides: Partial<BootTestEvidence["bootTest"]> = {},
): BootTestEvidence {
  const startedAt = new Date(Date.now() - 5_000).toISOString();
  return {
    schemaVersion: "designer_extension_boot_test_evidence.v1",
    bootTestJobId: contract.bootTestJobId,
    reviewVersionId: contract.reviewVersionId,
    bundleSha256: contract.bundleSha256,
    nonce: contract.nonce,
    trust: "webflow_observed",
    startedAt,
    finishedAt: new Date().toISOString(),
    bootTest: {
      status: "passed",
      failures: [],
      cspViolations: [],
      missingFiles: [],
      uncaughtErrors: [],
      externalHostsRequested: ["api.example.test"],
      renderedTextLength: 12,
      renderedElementCount: 3,
      ...overrides,
    },
  };
}

async function postResult(
  jobId: string,
  capability: string,
  body: unknown,
): Promise<Response> {
  return call(`/v1/boot-test-jobs/${jobId}/result`, {
    method: "POST",
    token: capability,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("Designer Extension boot test API", () => {
  test("answers 404 on every boot test route while BOOT_TEST_ENABLED is off", async () => {
    const { reviewId } = await createReview("switch-off");
    const off = { ...(env as unknown as Env) };
    delete off.BOOT_TEST_ENABLED;
    for (const workerEnv of [off, enabledEnv({ BOOT_TEST_ENABLED: "false" })]) {
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);
      const responses = await Promise.all([
        call(
          `/v1/reviews/${reviewId}/boot-tests`,
          { method: "POST", token: "test-token" },
          workerEnv,
        ),
        call(
          `/v1/reviews/${reviewId}/boot-tests`,
          { token: "test-token" },
          workerEnv,
        ),
        call(
          "/v1/boot-test-jobs/some-job",
          { token: "x".repeat(43) },
          workerEnv,
        ),
        call(
          "/v1/boot-test-jobs/some-job/bundle",
          { token: "x".repeat(43) },
          workerEnv,
        ),
        call(
          "/v1/boot-test-jobs/some-job/result",
          { method: "POST", body: "{}" },
          workerEnv,
        ),
        call(
          "/reviewer/review-versions/some-version/boot-test-replay",
          { method: "POST" },
          workerEnv,
        ),
      ]);
      expect(responses.map((response) => response.status)).toEqual([
        404, 404, 404, 404, 404, 404,
      ]);
      expect(fetchSpy).not.toHaveBeenCalled();
      vi.unstubAllGlobals();
    }
    const rows = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM boot_test_jobs",
    ).first<{ count: number }>();
    expect(rows?.count).toBe(0);
    await expect(
      bootTestSummaryForVersion("any-version", off),
    ).resolves.toEqual({ status: "not_run" });
  });

  test("lets only the review owner start a boot test, and keeps the capability server-side", async () => {
    const { reviewId, versionId } = await createReview("owner-only");
    stubE2B();
    expect(
      (await call(`/v1/reviews/${reviewId}/boot-tests`, { method: "POST" }))
        .status,
    ).toBe(401);
    expect(
      (
        await call(`/v1/reviews/${reviewId}/boot-tests`, {
          method: "POST",
          token: "reviewer-test-token",
        })
      ).status,
    ).toBe(404);
    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM boot_test_jobs WHERE review_version_id = ?",
    )
      .bind(versionId)
      .first<{ count: number }>();
    expect(count?.count).toBe(0);

    const { jobId, capability, stub } = await startJob(reviewId);
    expect(stub.createBodies[0]).toMatchObject({
      secure: true,
      network: { allowPublicTraffic: false },
      metadata: { lane: "app_review_boot_test", observation_job_id: jobId },
    });
    expect(stub.runBodies[0]).toEqual({
      observationJobId: jobId,
      apiBaseUrl: "https://preflight.test",
      capability: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      jobKind: "boot_test",
    });
    const stored = await env.DB.prepare(
      "SELECT capability_sha256, status, sandbox_id FROM boot_test_jobs WHERE id = ?",
    )
      .bind(jobId)
      .first<{
        capability_sha256: string;
        status: string;
        sandbox_id: string;
      }>();
    expect(stored).toMatchObject({
      status: "approved",
      sandbox_id: "sandbox-boot-123",
    });
    expect(stored?.capability_sha256).not.toContain(capability);

    // One active job per review version: a second request returns the same job.
    const again = await call(`/v1/reviews/${reviewId}/boot-tests`, {
      method: "POST",
      token: "test-token",
    });
    expect(again.status).toBe(200);
    expect(await again.json()).toMatchObject({
      deduplicated: true,
      bootTest: { id: jobId },
    });

    // A reviewer may read the result list; the owner sees it too.
    const listed = await call(`/v1/reviews/${reviewId}/boot-tests`, {
      token: "reviewer-test-token",
    });
    expect(listed.status).toBe(200);
    expect(await listed.json()).toMatchObject({
      bootTests: [{ id: jobId, advisory: true, bootTest: null }],
    });
  });

  test("issues a bounded contract and serves only that version bundle to the job capability", async () => {
    const { reviewId, versionId, bundle } = await createReview("contract");
    const { jobId, capability } = await startJob(reviewId);

    expect(
      (await call(`/v1/boot-test-jobs/${jobId}`, { token: "w".repeat(43) }))
        .status,
    ).toBe(401);
    expect(
      (await call(`/v1/boot-test-jobs/${jobId}/bundle`, { token: capability }))
        .status,
    ).toBe(410);

    const contract = await fetchContract(jobId, capability);
    const version = await env.DB.prepare(
      "SELECT artifact_sha256, compressed_bytes FROM review_versions WHERE id = ?",
    )
      .bind(versionId)
      .first<{ artifact_sha256: string; compressed_bytes: number }>();
    expect(contract).toMatchObject({
      schemaVersion: "designer_extension_boot_test_job.v1",
      purpose: "designer_extension_boot_test",
      bootTestJobId: jobId,
      reviewId,
      reviewVersionId: versionId,
      bundleSha256: version!.artifact_sha256,
      bundleBytes: version!.compressed_bytes,
      contentSecurityPolicy: DESIGNER_EXTENSION_HOST_CSP,
      controls: {
        networkMode: "local_static_server_only",
        settleMs: 3_000,
        totalTimeoutMs: 60_000,
        evidenceTrust: "webflow_observed",
      },
      boundaries: {
        advisoryOnly: true,
        affectsReadiness: false,
        officialDecision: null,
        canWriteGovernance: false,
        acceptsAccountCredentials: false,
      },
    });
    expect(contract.nonce).toMatch(/^[0-9a-f-]{36}$/);
    expect(Date.parse(contract.expiresAt) - Date.now()).toBeLessThanOrEqual(
      15 * 60 * 1000,
    );

    const download = await call(`/v1/boot-test-jobs/${jobId}/bundle`, {
      token: capability,
    });
    expect(download.status).toBe(200);
    expect(download.headers.get("content-type")).toBe("application/zip");
    expect(new Uint8Array(await download.arrayBuffer())).toEqual(bundle);
    expect(
      (
        await call(`/v1/boot-test-jobs/${jobId}/bundle`, {
          token: "w".repeat(43),
        })
      ).status,
    ).toBe(401);
  });

  test("takes the policy from BOOT_TEST_CSP when an operator sets it", async () => {
    const { reviewId } = await createReview("policy-override");
    const policy =
      "default-src 'self'; frame-ancestors https://*.design.webflow.com";
    const workerEnv = enabledEnv({ BOOT_TEST_CSP: policy });
    const { jobId, capability } = await startJob(reviewId, workerEnv);
    const response = await call(
      `/v1/boot-test-jobs/${jobId}`,
      { token: capability },
      workerEnv,
    );
    const body = await response.json<{
      bootTestJob: { contract: BootTestJobContract };
    }>();
    expect(body.bootTestJob.contract.contentSecurityPolicy).toBe(policy);

    const { reviewId: other } = await createReview("policy-invalid");
    stubE2B();
    const rejected = await call(
      `/v1/reviews/${other}/boot-tests`,
      { method: "POST", token: "test-token" },
      enabledEnv({ BOOT_TEST_CSP: "script-src 'self'\nx-injected: 1" }),
    );
    expect(rejected.status).toBe(503);
  });

  test("rejects malformed runner results, then stores one valid advisory result", async () => {
    const { reviewId, versionId } = await createReview("results");
    const before = await call(`/v1/reviews/${reviewId}`, {
      token: "test-token",
    });
    const readinessBefore = (
      await before.json<{
        review: { latestVersion: { result: { summary: unknown } } };
      }>()
    ).review.latestVersion.result.summary;
    const { jobId, capability } = await startJob(reviewId);
    const contract = await fetchContract(jobId, capability);
    const good = evidence(contract);

    const malformed: Array<[string, unknown]> = [
      ["a wrong nonce", { ...good, nonce: "other-nonce" }],
      ["another review version", { ...good, reviewVersionId: "other-version" }],
      ["an extra field", { ...good, officialDecision: "approve" }],
      [
        "an unknown failure code",
        evidence(contract, {
          status: "failed",
          failures: ["slow_panel" as never],
        }),
      ],
      [
        "passed with a failure",
        evidence(contract, {
          status: "passed",
          failures: ["blank_panel"],
          renderedTextLength: 0,
          renderedElementCount: 0,
        }),
      ],
      ["failed without a failure", evidence(contract, { status: "failed" })],
      [
        "a blank panel the counts contradict",
        evidence(contract, { status: "failed", failures: ["blank_panel"] }),
      ],
      [
        "missing files without the failure",
        evidence(contract, { missingFiles: ["assets/app.js"] }),
      ],
      [
        "a CSP failure without a script violation",
        evidence(contract, {
          status: "failed",
          failures: ["bundled_script_blocked_by_csp"],
          cspViolations: [
            {
              directive: "img-src",
              blocked: "images.example.test",
              source: "document",
            },
          ],
        }),
      ],
      ["a negative count", evidence(contract, { renderedElementCount: -1 })],
      [
        "an error result with failures",
        evidence(contract, {
          status: "error",
          failures: ["blank_panel"],
          renderedTextLength: 0,
          renderedElementCount: 0,
        }),
      ],
      [
        "timestamps beyond the budget",
        {
          ...good,
          startedAt: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
        },
      ],
    ];
    for (const [label, body] of malformed) {
      const response = await postResult(jobId, capability, body);
      expect(response.status, label).toBe(400);
    }
    expect(
      (
        await call(`/v1/boot-test-jobs/${jobId}/result`, {
          method: "POST",
          body: "not json",
          token: capability,
        })
      ).status,
    ).toBe(400);
    expect((await postResult(jobId, "w".repeat(43), good)).status).toBe(401);
    const stillRunning = await env.DB.prepare(
      "SELECT status, result_json FROM boot_test_jobs WHERE id = ?",
    )
      .bind(jobId)
      .first<{ status: string; result_json: string | null }>();
    expect(stillRunning).toEqual({ status: "running", result_json: null });
    await expect(
      bootTestSummaryForVersion(versionId, enabledEnv()),
    ).resolves.toEqual({ status: "not_run" });

    const accepted = await postResult(jobId, capability, good);
    expect(accepted.status).toBe(200);
    expect(await accepted.json()).toMatchObject({
      status: "complete",
      trust: "webflow_observed",
      bootTest: { status: "passed" },
    });
    expect((await postResult(jobId, capability, good)).status).toBe(410);
    expect(
      (await call(`/v1/boot-test-jobs/${jobId}/bundle`, { token: capability }))
        .status,
    ).toBe(410);

    const stored = await env.DB.prepare(
      "SELECT status, evidence_trust, result_status, sandbox_termination_status FROM boot_test_jobs WHERE id = ?",
    )
      .bind(jobId)
      .first();
    expect(stored).toEqual({
      status: "complete",
      evidence_trust: "webflow_observed",
      result_status: "passed",
      sandbox_termination_status: "verified",
    });

    // Advisory only: the static review summary is unchanged.
    const after = await call(`/v1/reviews/${reviewId}`, {
      token: "test-token",
    });
    expect(
      (
        await after.json<{
          review: { latestVersion: { result: { summary: unknown } } };
        }>()
      ).review.latestVersion.result.summary,
    ).toEqual(readinessBefore);
  });

  test("stores the verdict when bundle-controlled labels fail their format rules", async () => {
    const { reviewId, versionId } = await createReview("tolerant-labels");
    const { jobId, capability } = await startJob(reviewId);
    const contract = await fetchContract(jobId, capability);
    const bad = evidence(contract, {
      status: "failed",
      failures: ["bundled_file_missing", "bundled_script_blocked_by_csp"],
      missingFiles: ["assets/a?b.js", "ok.js", "\u00e9.js"],
      cspViolations: [
        {
          directive: "script-src-elem",
          blocked: "assets/x?.js",
          source: "document",
        },
        {
          directive: "img-src",
          blocked: "https://images.example.test/a.png?id=1",
          source: "document",
        },
      ],
      externalHostsRequested: [
        `${"a".repeat(300)}.example.test`,
        "my_host.example.test",
        "api.example.test",
      ],
      uncaughtErrors: ["x".repeat(500), "Bearer abcdefghijklmnop failed"],
    });
    // A wrong nonce or job id is still refused: only labels are tolerant.
    expect(
      (await postResult(jobId, capability, { ...bad, nonce: "other-nonce" }))
        .status,
    ).toBe(400);
    expect(
      (
        await postResult(jobId, capability, {
          ...bad,
          bootTestJobId: "other-job",
        })
      ).status,
    ).toBe(400);

    expect((await postResult(jobId, capability, bad)).status).toBe(200);
    await expect(
      bootTestSummaryForVersion(versionId, enabledEnv()),
    ).resolves.toEqual({ status: "failed" });
    const stored = await env.DB.prepare(
      "SELECT result_json FROM boot_test_jobs WHERE id = ?",
    )
      .bind(jobId)
      .first<{ result_json: string }>();
    expect(JSON.parse(stored!.result_json)).toMatchObject({
      status: "failed",
      failures: ["bundled_script_blocked_by_csp", "bundled_file_missing"],
      missingFiles: ["[unreadable]", "ok.js"],
      cspViolations: [
        {
          directive: "script-src-elem",
          blocked: "[unreadable]",
          source: "document",
        },
        { directive: "img-src", blocked: "[unreadable]", source: "document" },
      ],
      externalHostsRequested: ["[unreadable]", "api.example.test"],
      uncaughtErrors: ["x".repeat(300), "[unreadable]"],
      labelsReplaced: 7,
    });
  });

  test("cuts over-long label lists to their caps instead of refusing the result", () => {
    const contract = {
      bootTestJobId: "job-1",
      reviewVersionId: "version-1",
      bundleSha256: "a".repeat(64),
      nonce: "nonce-1",
      controls: { totalTimeoutMs: 60_000 },
      limits: {
        cspViolations: 20,
        missingFiles: 20,
        uncaughtErrors: 10,
        externalHosts: 20,
        messageLength: 300,
      },
    } as BootTestJobContract;
    const clean = validateBootTestEvidence(
      evidence(contract),
      "job-1",
      contract,
    );
    expect(clean).not.toHaveProperty("labelsReplaced");
    const result = validateBootTestEvidence(
      evidence(contract, {
        externalHostsRequested: Array.from(
          { length: 25 },
          (_, i) => `h${i}.example.test`,
        ),
        uncaughtErrors: Array.from({ length: 12 }, (_, i) => `error ${i}`),
        cspViolations: Array.from({ length: 22 }, (_, i) => ({
          directive: "img-src",
          blocked: `h${i}.test`,
          source: "document",
        })),
      }),
      "job-1",
      contract,
    );
    expect(result.externalHostsRequested).toHaveLength(20);
    expect(result.uncaughtErrors).toHaveLength(10);
    expect(result.cspViolations).toHaveLength(20);
    expect(result.labelsReplaced).toBe(5 + 2 + 2);
    // A verdict the labels cannot explain is still rejected.
    expect(() =>
      validateBootTestEvidence(
        evidence(contract, { status: "failed", failures: [] }),
        "job-1",
        contract,
      ),
    ).toThrow();
  });

  test("summarizes the latest boot test per version as not_run, passed, or failed", async () => {
    const passing = await createReview("summary-passed");
    const failing = await createReview("summary-failed");
    const workerEnv = enabledEnv();
    await expect(
      bootTestSummaryForVersion(passing.versionId, workerEnv),
    ).resolves.toEqual({ status: "not_run" });

    const first = await startJob(passing.reviewId);
    const firstContract = await fetchContract(first.jobId, first.capability);
    expect(
      (await postResult(first.jobId, first.capability, evidence(firstContract)))
        .status,
    ).toBe(200);
    await expect(
      bootTestSummaryForVersion(passing.versionId, workerEnv),
    ).resolves.toEqual({ status: "passed" });

    const second = await startJob(failing.reviewId);
    const secondContract = await fetchContract(second.jobId, second.capability);
    const failed = evidence(secondContract, {
      status: "failed",
      failures: ["blank_panel", "bundled_script_blocked_by_csp"],
      cspViolations: [
        {
          directive: "script-src-elem",
          blocked: "assets/app.js",
          source: "document",
        },
      ],
      renderedTextLength: 0,
      renderedElementCount: 0,
    });
    expect(
      (await postResult(second.jobId, second.capability, failed)).status,
    ).toBe(200);
    await expect(
      bootTestSummaryForVersion(failing.versionId, workerEnv),
    ).resolves.toEqual({ status: "failed" });
    await expect(
      bootTestSummaryForVersion(passing.versionId, workerEnv),
    ).resolves.toEqual({ status: "passed" });
  });

  test("reports a dispatch failure without leaving an active job", async () => {
    const { reviewId, versionId } = await createReview("dispatch-failure");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({ error: "unavailable" }, { status: 503 }),
      ),
    );
    const response = await call(`/v1/reviews/${reviewId}/boot-tests`, {
      method: "POST",
      token: "test-token",
    });
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({
      error: "boot_test_dispatch_unavailable",
      message: "The boot test runner could not create a secure sandbox.",
    });
    const row = await env.DB.prepare(
      "SELECT status FROM boot_test_jobs WHERE review_version_id = ?",
    )
      .bind(versionId)
      .first<{ status: string }>();
    expect(row?.status).toBe("failed");
    await expect(
      bootTestSummaryForVersion(versionId, enabledEnv()),
    ).resolves.toEqual({ status: "not_run" });
  });

  test("normalizes failure order in an accepted result", () => {
    const contract = {
      bootTestJobId: "job-1",
      reviewVersionId: "version-1",
      bundleSha256: "a".repeat(64),
      nonce: "nonce-1",
      controls: { totalTimeoutMs: 60_000 },
      limits: {
        cspViolations: 20,
        missingFiles: 20,
        uncaughtErrors: 10,
        externalHosts: 20,
        messageLength: 300,
      },
    } as BootTestJobContract;
    const result = validateBootTestEvidence(
      evidence(contract, {
        status: "failed",
        failures: ["bundled_file_missing", "blank_panel"],
        missingFiles: ["index.html"],
        renderedTextLength: 0,
        renderedElementCount: 0,
      }),
      "job-1",
      contract,
    );
    expect(result.failures).toEqual(["blank_panel", "bundled_file_missing"]);
  });

  test("lists each run with the role that ran it", async () => {
    const { reviewId } = await createReview("actor-listing");
    const { jobId } = await startJob(reviewId);
    const listed = await call(`/v1/reviews/${reviewId}/boot-tests`, {
      token: "test-token",
    });
    expect(await listed.json()).toMatchObject({
      bootTests: [{ id: jobId, actorRole: "developer" }],
    });
    const row = await env.DB.prepare(
      "SELECT actor_role, requested_by_user_id FROM boot_test_jobs WHERE id = ?",
    )
      .bind(jobId)
      .first();
    expect(row).toEqual({
      actor_role: "developer",
      requested_by_user_id: "local-webflow-user",
    });
  });

  test("compares a replay with the developer run by status and failure set", () => {
    const run = (
      status: "passed" | "failed" | "error",
      failures: BootTestEvidence["bootTest"]["failures"] = [],
    ) => ({
      status,
      failures,
      cspViolations: [],
      missingFiles: [],
      uncaughtErrors: [],
      externalHostsRequested: [],
      renderedTextLength: 0,
      renderedElementCount: 0,
    });
    expect(compareBootTestRuns(run("passed"), run("passed"))).toBe(
      "reproduced_pass",
    );
    expect(
      compareBootTestRuns(
        run("failed", ["blank_panel", "bundled_file_missing"]),
        run("failed", ["bundled_file_missing", "blank_panel"]),
      ),
    ).toBe("reproduced_failure");
    expect(
      compareBootTestRuns(
        run("failed", ["blank_panel"]),
        run("failed", ["bundled_file_missing"]),
      ),
    ).toBe("mixed_evidence");
    expect(
      compareBootTestRuns(run("passed"), run("failed", ["blank_panel"])),
    ).toBe("mixed_evidence");
    expect(compareBootTestRuns(run("passed"), run("error"))).toBe(
      "infrastructure_incomplete",
    );
    expect(compareBootTestRuns(run("passed"), null)).toBe("not_compared");
    expect(compareBootTestRuns(null, run("passed"))).toBe("not_compared");
  });
});

async function createRuntimePackage(reviewId: string): Promise<string> {
  const response = await call(`/v1/reviews/${reviewId}/runtime-test-packages`, {
    method: "POST",
    token: "test-token",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      targetUrl: "http://127.0.0.1:4173/runtime-fixture",
      sandboxInstallationId: "local-webflow-site",
      sandboxOwnershipConfirmed: true,
      license: {
        mode: "installation_allowlist",
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      },
      runtimeArtifacts: [
        {
          url: "http://127.0.0.1:4173/runtime-v1.js",
          sha256: "a".repeat(64),
          integrity: "sha256-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=",
        },
      ],
      negativeProxyProbe: {
        method: "GET",
        urlTemplate: "http://127.0.0.1:4173/proxy?url={canaryUrl}",
      },
      lifecycle: { readySelector: "[data-runtime-ready]" },
    }),
  });
  expect(response.status).toBe(201);
  return (await response.json<{ testPackage: { id: string } }>()).testPackage
    .id;
}

// The existing reviewer path: a reviewer identity creates a one-time handoff
// for an exact version and package, and the explicit POST mints the
// HttpOnly session cookie.
async function reviewerSession(
  reviewId: string,
  versionId: string,
): Promise<string> {
  const testPackageId = await createRuntimePackage(reviewId);
  const handoff = await call(`/v1/reviews/${reviewId}/reviewer-handoffs`, {
    method: "POST",
    token: "reviewer-test-token",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      reviewVersionId: versionId,
      runtimeTestPackageId: testPackageId,
    }),
  });
  expect(handoff.status).toBe(201);
  const code = new URL(
    (await handoff.json<{ handoff: { url: string } }>()).handoff.url,
  ).searchParams.get("code")!;
  const form = new FormData();
  form.set("code", code);
  const connected = await worker.fetch(
    new Request("https://preflight.test/reviewer/connect", {
      method: "POST",
      redirect: "manual",
      body: form,
    }),
    enabledEnv(),
  );
  expect(connected.status).toBe(303);
  return connected.headers.get("set-cookie")!.split(";")[0]!;
}

async function reviewerCall(
  path: string,
  cookie: string | null,
  init: RequestInit = {},
  token?: string,
  workerEnv: Env = enabledEnv(),
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("origin", "https://preflight.test");
  if (cookie) headers.set("cookie", cookie);
  if (token) headers.set("authorization", `Bearer ${token}`);
  return worker.fetch(
    new Request(`https://preflight.test${path}`, {
      ...init,
      headers,
      redirect: "manual",
    }),
    workerEnv,
  );
}

describe("reviewer boot test replay", () => {
  test("lets only a reviewer workspace session replay the exact version, and shows both results", async () => {
    const { reviewId, versionId } = await createReview("reviewer-replay");
    const other = await createReview("reviewer-replay-other");
    const cookie = await reviewerSession(reviewId, versionId);
    const replayPath = `/reviewer/review-versions/${versionId}/boot-test-replay`;

    // The developer finishes a passing run first.
    const developer = await startJob(reviewId);
    const developerContract = await fetchContract(
      developer.jobId,
      developer.capability,
    );
    expect(
      (
        await postResult(
          developer.jobId,
          developer.capability,
          evidence(developerContract),
        )
      ).status,
    ).toBe(200);

    // No session, a developer bearer, a reviewer bearer without a workspace
    // session, and a session for a different version are all refused.
    const spy = stubE2B();
    expect(
      (await reviewerCall(replayPath, null, { method: "POST" })).status,
    ).toBe(401);
    expect(
      (await reviewerCall(replayPath, null, { method: "POST" }, "test-token"))
        .status,
    ).toBe(403);
    expect(
      (
        await reviewerCall(
          replayPath,
          null,
          { method: "POST" },
          "reviewer-test-token",
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await reviewerCall(
          `/reviewer/review-versions/${other.versionId}/boot-test-replay`,
          cookie,
          { method: "POST" },
        )
      ).status,
    ).toBe(403);
    expect(spy.createBodies).toHaveLength(0);

    const before = await (await reviewerCall("/reviewer", cookie)).text();
    expect(before).toContain("Designer Extension boot test");
    expect(before).toContain("Developer run");
    expect(before).toContain(
      "Not compared: one of the two runs has no result yet",
    );
    expect(before).toContain(
      `/reviewer/review-versions/${versionId}/boot-test-replay`,
    );

    // A running developer job does not block the reviewer's replay.
    const developerAgain = await startJob(reviewId);
    const replayStub = stubE2B();
    const replay = await reviewerCall(replayPath, cookie, { method: "POST" });
    expect(replay.status).toBe(303);
    expect(replay.headers.get("location")).toMatch(
      /^\/reviewer\?bootTestStarted=/,
    );
    const replayJobId = decodeURIComponent(
      replay.headers.get("location")!.split("=")[1]!,
    );
    expect(replayJobId).not.toBe(developerAgain.jobId);
    expect(replayStub.runBodies[0]).toMatchObject({
      observationJobId: replayJobId,
      jobKind: "boot_test",
    });
    const stored = await env.DB.prepare(
      "SELECT actor_role, requested_by_user_id, review_version_id FROM boot_test_jobs WHERE id = ?",
    )
      .bind(replayJobId)
      .first();
    expect(stored).toEqual({
      actor_role: "reviewer",
      requested_by_user_id: "local-webflow-reviewer",
      review_version_id: versionId,
    });
    const event = await env.DB.prepare(
      `SELECT actor_user_id FROM review_events WHERE event_type = 'boot_test_replay_requested' AND payload_json LIKE ?`,
    )
      .bind(`%${replayJobId}%`)
      .first();
    expect(event).toEqual({ actor_user_id: "local-webflow-reviewer" });

    // A second replay while the first runs returns a notice, not a new job.
    const duplicate = await reviewerCall(replayPath, cookie, {
      method: "POST",
    });
    expect(decodeURIComponent(duplicate.headers.get("location")!)).toContain(
      "already running",
    );

    // The sandbox reports a blank panel. The Worker validates it the same way.
    const replayCapability = String(replayStub.runBodies[0]!.capability);
    const replayContract = await fetchContract(replayJobId, replayCapability);
    expect(replayContract.reviewVersionId).toBe(versionId);
    expect(
      (
        await postResult(replayJobId, replayCapability, {
          ...evidence(replayContract),
          nonce: "forged",
        })
      ).status,
    ).toBe(400);
    const blank = evidence(replayContract, {
      status: "failed",
      failures: ["blank_panel"],
      renderedTextLength: 0,
      renderedElementCount: 0,
    });
    expect(
      (await postResult(replayJobId, replayCapability, blank)).status,
    ).toBe(200);

    const after = await (await reviewerCall("/reviewer", cookie)).text();
    expect(after).toContain("Reviewer replay");
    expect(after).toContain("Failures: blank_panel");
    expect(after).toContain("Differs: the status or the failures do not match");
    expect(after).toContain("A newer run is in progress");

    // The receipt keeps the developer's result; the replay never rewrites it.
    await expect(
      bootTestSummaryForVersion(versionId, enabledEnv()),
    ).resolves.toEqual({ status: "passed" });
  });

  test("hides the boot test from the reviewer workspace while the switch is off", async () => {
    const { reviewId, versionId } = await createReview("reviewer-switch-off");
    const cookie = await reviewerSession(reviewId, versionId);
    const off = { ...(env as unknown as Env) };
    delete off.BOOT_TEST_ENABLED;
    const page = await worker.fetch(
      new Request("https://preflight.test/reviewer", { headers: { cookie } }),
      off,
    );
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("Run independent replay");
    expect(html).not.toContain("Designer Extension boot test");
  });
});

async function seedBootJob(
  versionId: string,
  options: {
    userId?: string;
    role?: "developer" | "reviewer";
    status?: "approved" | "running" | "complete";
    createdAt?: Date;
    expiresAt?: Date;
  } = {},
): Promise<string> {
  const id = crypto.randomUUID();
  const created = (options.createdAt ?? new Date()).toISOString();
  await env.DB.prepare(
    `INSERT INTO boot_test_jobs
      (id, review_version_id, requested_by_user_id, actor_role, status, capability_sha256,
       nonce, contract_json, approved_at, expires_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, ?)`,
  )
    .bind(
      id,
      versionId,
      options.userId ?? "local-webflow-user",
      options.role ?? "developer",
      options.status ?? "complete",
      `sha-${id}`,
      `nonce-${id}`,
      created,
      (
        options.expiresAt ?? new Date(Date.now() + 10 * 60 * 1000)
      ).toISOString(),
      created,
      created,
    )
    .run();
  return id;
}

async function seedObservationJob(
  packageId: string,
  options: {
    status?: "running" | "complete";
    createdAt?: Date;
    expiresAt?: Date;
  } = {},
): Promise<void> {
  const id = crypto.randomUUID();
  const created = (options.createdAt ?? new Date()).toISOString();
  await env.DB.prepare(
    `INSERT INTO runtime_observation_jobs
      (id, test_package_id, status, capability_sha256, nonce, contract_json, approved_by_actor,
       approved_at, expires_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, '{}', 'webflow-runtime-coordinator', ?, ?, ?, ?)`,
  )
    .bind(
      id,
      packageId,
      options.status ?? "complete",
      `sha-${id}`,
      `nonce-${id}`,
      created,
      (
        options.expiresAt ?? new Date(Date.now() + 10 * 60 * 1000)
      ).toISOString(),
      created,
      created,
    )
    .run();
}

const HOURS = 60 * 60 * 1000;

describe("sandbox launch limits", () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM runtime_observation_jobs"),
      env.DB.prepare("DELETE FROM boot_test_jobs"),
    ]);
  });

  async function startBoot(
    reviewId: string,
    workerEnv: Env,
  ): Promise<Response> {
    return call(
      `/v1/reviews/${reviewId}/boot-tests`,
      { method: "POST", token: "test-token" },
      workerEnv,
    );
  }

  async function jobCount(): Promise<number> {
    const row = await env.DB.prepare(
      `SELECT (SELECT COUNT(*) FROM boot_test_jobs) + (SELECT COUNT(*) FROM runtime_observation_jobs) AS count`,
    ).first<{ count: number }>();
    return row!.count;
  }

  test("refuses a developer past the 24 hour limit, with no job and no sandbox", async () => {
    const { reviewId, versionId } = await createReview("limit-user");
    const limited = enabledEnv({ SANDBOX_DAILY_LIMIT_PER_USER: "2" });
    await seedBootJob(versionId, {
      createdAt: new Date(Date.now() - 23 * HOURS),
    });
    await seedBootJob(versionId, {
      createdAt: new Date(Date.now() - 1 * HOURS),
    });
    const stub = stubE2B();
    const response = await startBoot(reviewId, limited);
    expect(response.status).toBe(429);
    const body = await response.json<{
      error: string;
      message: string;
      retryAfterSeconds: number;
    }>();
    expect(body).toMatchObject({
      error: "sandbox_limit_reached",
      message: expect.stringContaining("2"),
    });
    // The oldest job leaves the window in about one hour.
    expect(body.retryAfterSeconds).toBeGreaterThan(3_500);
    expect(body.retryAfterSeconds).toBeLessThanOrEqual(3_601);
    expect(stub.createBodies).toHaveLength(0);
    expect(await jobCount()).toBe(2);
  });

  test("does not count other users, reviewer replays, or jobs older than 24 hours", async () => {
    const { reviewId, versionId } = await createReview("limit-scope");
    const limited = enabledEnv({ SANDBOX_DAILY_LIMIT_PER_USER: "2" });
    await seedBootJob(versionId, { userId: "another-developer" });
    await seedBootJob(versionId, { userId: "another-developer" });
    await seedBootJob(versionId, {
      role: "reviewer",
      userId: "local-webflow-user",
    });
    await seedBootJob(versionId, {
      createdAt: new Date(Date.now() - 25 * HOURS),
    });
    await seedBootJob(versionId, {
      createdAt: new Date(Date.now() - 25 * HOURS),
    });
    stubE2B();
    expect((await startBoot(reviewId, limited)).status).toBe(201);
  });

  test("refuses a developer who already has the allowed number of sandboxes active", async () => {
    const first = await createReview("active-user-a");
    const second = await createReview("active-user-b");
    const limited = enabledEnv({ SANDBOX_ACTIVE_LIMIT_PER_USER: "1" });
    // One active job on another version of the same developer.
    await seedBootJob(first.versionId, { status: "running" });
    const stub = stubE2B();
    const response = await startBoot(second.reviewId, limited);
    expect(response.status).toBe(429);
    const body = await response.json<{
      error: string;
      message: string;
      retryAfterSeconds: number;
    }>();
    expect(body).toMatchObject({
      error: "sandbox_limit_reached",
      message: expect.stringContaining("in progress"),
    });
    expect(body.retryAfterSeconds).toBeGreaterThan(0);
    expect(stub.createBodies).toHaveLength(0);
    // Another developer's active job does not count against this developer.
    await env.DB.prepare("DELETE FROM boot_test_jobs").run();
    await seedBootJob(first.versionId, {
      status: "running",
      userId: "another-developer",
    });
    expect((await startBoot(second.reviewId, limited)).status).toBe(201);
  });

  test("counts boot tests and runtime observation runs together", async () => {
    const { reviewId, versionId } = await createReview("limit-both");
    const packageId = await createRuntimePackage(reviewId);
    const limited = enabledEnv({ SANDBOX_DAILY_LIMIT_PER_USER: "2" });
    await seedObservationJob(packageId);
    await seedBootJob(versionId);
    const stub = stubE2B();
    expect((await startBoot(reviewId, limited)).status).toBe(429);
    const run = await call(
      `/v1/runtime-test-packages/${packageId}/observation-runs`,
      { method: "POST", token: "test-token" },
      limited,
    );
    expect(run.status).toBe(429);
    expect(await run.json()).toMatchObject({ error: "sandbox_limit_reached" });
    expect(stub.createBodies).toHaveLength(0);
    expect(await jobCount()).toBe(2);

    // Raising the limit lets the same run start.
    const raised = await call(
      `/v1/runtime-test-packages/${packageId}/observation-runs`,
      { method: "POST", token: "test-token" },
      enabledEnv({ SANDBOX_DAILY_LIMIT_PER_USER: "3" }),
    );
    expect(raised.status).toBe(201);
  });

  test("defaults to 30 a day, and falls back to it for a bad override", async () => {
    const { reviewId, versionId } = await createReview("limit-default");
    for (let index = 0; index < 30; index += 1) await seedBootJob(versionId);
    stubE2B();
    for (const value of [undefined, "", "0", "-3", "abc", "2.5", "1e3", " "]) {
      const response = await startBoot(
        reviewId,
        enabledEnv({ SANDBOX_DAILY_LIMIT_PER_USER: value }),
      );
      expect(response.status, String(value)).toBe(429);
    }
    expect(
      (
        await startBoot(
          reviewId,
          enabledEnv({ SANDBOX_DAILY_LIMIT_PER_USER: "31" }),
        )
      ).status,
    ).toBe(201);
  });

  test("applies the global active limit to developers and reviewer replays", async () => {
    const first = await createReview("limit-active-a");
    const second = await createReview("limit-active-b");
    const cookie = await reviewerSession(second.reviewId, second.versionId);
    const limited = enabledEnv({ SANDBOX_ACTIVE_LIMIT: "1" });
    const stub = stubE2B();
    expect((await startBoot(first.reviewId, limited)).status).toBe(201);
    const before = await jobCount();

    const developer = await startBoot(second.reviewId, limited);
    expect(developer.status).toBe(429);
    const body = await developer.json<{
      error: string;
      retryAfterSeconds: number;
    }>();
    expect(body.error).toBe("sandbox_limit_reached");
    expect(body.retryAfterSeconds).toBeGreaterThan(0);
    expect(body.retryAfterSeconds).toBeLessThanOrEqual(15 * 60);

    const replay = await reviewerCall(
      `/reviewer/review-versions/${second.versionId}/boot-test-replay`,
      cookie,
      { method: "POST" },
      undefined,
      limited,
    );
    expect(replay.status).toBe(303);
    expect(replay.headers.get("location")).toMatch(/^\/reviewer\?bootTest=/);
    expect(stub.createBodies).toHaveLength(1);
    expect(await jobCount()).toBe(before);

    // An observation replay is held by the same global limit.
    const packageId = await createRuntimePackage(second.reviewId);
    const observation = await call(
      `/v1/runtime-test-packages/${packageId}/observation-runs`,
      { method: "POST", token: "test-token" },
      limited,
    );
    expect(observation.status).toBe(429);
    expect(await jobCount()).toBe(before);

    // With room again, the same replay starts.
    const roomy = enabledEnv({ SANDBOX_ACTIVE_LIMIT: "2" });
    const started = await reviewerCall(
      `/reviewer/review-versions/${second.versionId}/boot-test-replay`,
      cookie,
      { method: "POST" },
      undefined,
      roomy,
    );
    expect(started.headers.get("location")).toMatch(
      /^\/reviewer\?bootTestStarted=/,
    );
  });

  test("exempts a reviewer replay from the per-user limit", async () => {
    const { reviewId, versionId } = await createReview("limit-reviewer");
    const cookie = await reviewerSession(reviewId, versionId);
    for (let index = 0; index < 3; index += 1) {
      await seedBootJob(versionId, { userId: "local-webflow-reviewer" });
    }
    stubE2B();
    const replay = await reviewerCall(
      `/reviewer/review-versions/${versionId}/boot-test-replay`,
      cookie,
      { method: "POST" },
      undefined,
      enabledEnv({ SANDBOX_DAILY_LIMIT_PER_USER: "1" }),
    );
    expect(replay.headers.get("location")).toMatch(
      /^\/reviewer\?bootTestStarted=/,
    );
  });

  test("does not count finished or expired jobs as active", async () => {
    const { reviewId, versionId } = await createReview("limit-expired");
    const limited = enabledEnv({ SANDBOX_ACTIVE_LIMIT: "1" });
    await seedBootJob(versionId, { status: "complete" });
    await seedBootJob(versionId, {
      status: "running",
      expiresAt: new Date(Date.now() - 1000),
    });
    stubE2B();
    expect((await startBoot(reviewId, limited)).status).toBe(201);
  });
});
