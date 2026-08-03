import { readFile, readdir } from "node:fs/promises";
import { basename, dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import JSZip from "jszip";
import { productionApiBase } from "./production-config.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const textFile = /\.(?:css|html|js|json|map|md|svg|txt)$/i;
const forbiddenSignatures = [
  {
    label: "development React warning URL",
    pattern: /https:\/\/reactjs\.org\/link\//g,
  },
  { label: "dynamic eval execution", pattern: /\beval\s*\(/g },
  { label: "stub identity token", pattern: /\btest-token\b/g },
  { label: "localhost", pattern: /\blocalhost\b/g },
  { label: "loopback host", pattern: /\b127\.0\.0\.1\b/g },
  { label: "wildcard local host", pattern: /\b0\.0\.0\.0\b/g },
  { label: "ngrok tunnel", pattern: /\bngrok\b/g },
  { label: "Cloudflare quick tunnel", pattern: /\btrycloudflare\b/g },
  { label: "localtunnel host", pattern: /\bloca\.lt\b/g },
  { label: ".local host", pattern: /\.local\b/g },
];

// Absolute origins that legitimately appear in shipped text payloads as inert
// literals: XML namespaces, React's production error-decoder URL, and
// placeholder/example URLs rendered as UI copy. Anything outside this set —
// including hosts that merely *start with* the production API base — fails
// verification, so the production API origin must appear as an exact,
// fully-delimited host rather than a substring of a longer one.
const allowedInertOrigins = new Set([
  "http://www.w3.org", // SVG/XML namespace identifiers
  "https://reactjs.org", // React production error-decoder URL
  "https://api.example.com", // placeholder text in UI copy
  "https://cdn.example.com", // placeholder text in UI copy
  "https://your-test-site.webflow.io", // documentation example in UI copy
  "https://app-review-sandbox.webflow.io", // input placeholder in UI copy
]);
const absoluteOriginPattern =
  /\bhttps?:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d+)?/gi;

export function extractAbsoluteOrigins(text) {
  return new Set(
    (text.match(absoluteOriginPattern) ?? []).map((origin) =>
      origin.toLowerCase(),
    ),
  );
}

async function directoryEntries(directory, prefix = "") {
  const entries = new Map();
  for (const item of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, item.name);
    const name = prefix ? `${prefix}/${item.name}` : item.name;
    if (item.isDirectory()) {
      for (const [nestedName, contents] of await directoryEntries(path, name)) {
        entries.set(nestedName, contents);
      }
    } else if (item.isFile()) {
      entries.set(name, await readFile(path));
    }
  }
  return entries;
}

async function archiveEntries(archivePath) {
  const zip = await JSZip.loadAsync(await readFile(archivePath));
  const entries = new Map();
  for (const [name, entry] of Object.entries(zip.files)) {
    if (!entry.dir) entries.set(name, await entry.async("nodebuffer"));
  }
  return entries;
}

function findByBasename(entries, expected) {
  return [...entries.entries()].find(([name]) => basename(name) === expected);
}

export function inspectProductionEntries(entries, label) {
  const problems = [];
  const bundleEntry = findByBasename(entries, "bundle.js");
  const mapEntry = findByBasename(entries, "bundle.js.map");

  if (!bundleEntry) {
    problems.push(`${label} is missing bundle.js`);
    return problems;
  }

  const bundle = bundleEntry[1].toString("utf8");
  // Binding check, not a substring check: the production API base must be
  // present as an exact extracted origin. A bundle whose only API origin is
  // e.g. `${productionApiBase}.attacker.example` extracts as the attacker
  // host and fails both this check and the unexpected-origin scan below.
  if (!extractAbsoluteOrigins(bundle).has(productionApiBase)) {
    problems.push(
      `${label} bundle.js does not bind the production API origin ${productionApiBase}`,
    );
  }

  const lineCount = bundle.split("\n").length;
  if (lineCount > 500) {
    problems.push(`${label} bundle.js is not minified (${lineCount} lines)`);
  }

  const sourceMapReference = bundle.match(
    /\/\/#\s*sourceMappingURL=([^\s]+)/,
  )?.[1];
  if (!sourceMapReference) {
    problems.push(`${label} bundle.js has no sourceMappingURL`);
  } else if (basename(sourceMapReference) !== "bundle.js.map") {
    problems.push(
      `${label} bundle.js references unexpected source map ${sourceMapReference}`,
    );
  }

  if (!mapEntry) {
    problems.push(`${label} is missing bundle.js.map`);
  } else {
    try {
      const sourceMap = JSON.parse(mapEntry[1].toString("utf8"));
      if (!Array.isArray(sourceMap.sources) || sourceMap.sources.length === 0) {
        problems.push(`${label} bundle.js.map has no source paths`);
      }
      if (
        !Array.isArray(sourceMap.sourcesContent) ||
        sourceMap.sourcesContent.length !== sourceMap.sources.length ||
        !sourceMap.sourcesContent.some(
          (source) => typeof source === "string" && source.length > 0,
        )
      ) {
        problems.push(
          `${label} bundle.js.map does not contain reviewer-readable source content`,
        );
      }
    } catch {
      problems.push(`${label} bundle.js.map is not valid JSON`);
    }
  }

  for (const [name, contents] of entries) {
    if (!textFile.test(name)) continue;
    const text = contents.toString("utf8");
    for (const { label: signature, pattern } of forbiddenSignatures) {
      pattern.lastIndex = 0;
      const matches = text.match(pattern) ?? [];
      if (matches.length > 0) {
        problems.push(
          `${label} ${name} contains ${matches.length} ${signature} signature(s)`,
        );
      }
    }
    for (const origin of extractAbsoluteOrigins(text)) {
      if (origin !== productionApiBase && !allowedInertOrigins.has(origin)) {
        problems.push(
          `${label} ${name} contains unexpected absolute origin ${origin}`,
        );
      }
    }
  }

  return problems;
}

export async function verifyProductionArtifacts({
  publicDirectory = resolve(root, "public"),
  archivePath = resolve(root, "bundle.zip"),
} = {}) {
  const publicFiles = await directoryEntries(publicDirectory);
  const archivedFiles = await archiveEntries(archivePath);
  const problems = [
    ...inspectProductionEntries(publicFiles, "Public payload"),
    ...inspectProductionEntries(archivedFiles, "Archive"),
  ];

  for (const required of ["webflow.json", "index.html", "styles.css"]) {
    if (!findByBasename(archivedFiles, required))
      problems.push(`Archive is missing ${required}`);
  }

  if (problems.length > 0) {
    throw new Error(
      `Designer Extension production artifacts failed verification:\n${problems
        .map((problem) => `  - ${problem}`)
        .join("\n")}`,
    );
  }

  return {
    archive: relative(process.cwd(), archivePath),
    archiveFiles: archivedFiles.size,
    publicFiles: publicFiles.size,
  };
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const result = await verifyProductionArtifacts();
  console.log(
    `Production artifacts verified: ${result.publicFiles} public file(s), ` +
      `${result.archiveFiles} archived file(s), archive ${result.archive}.`,
  );
}
