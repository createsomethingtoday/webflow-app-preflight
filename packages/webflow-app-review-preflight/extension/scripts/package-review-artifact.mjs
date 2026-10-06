import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import JSZip from "jszip";

// The private review ZIP the submission form and App Review Preflight both
// require: the source map, package.json, and lockfile from the exact build
// that produced bundle.zip. It is uploaded through the form, never shipped.
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const reviewArtifactPath = resolve(root, "review-artifact.zip");

export async function packageReviewArtifact({
  sourceMapPath = resolve(root, "review-artifact/bundle.js.map"),
  packageJsonPath = resolve(root, "package.json"),
  lockfilePath = resolve(root, "../../../pnpm-lock.yaml"),
  outputPath = reviewArtifactPath,
} = {}) {
  const zip = new JSZip();
  zip.file("bundle.js.map", await readFile(sourceMapPath));
  zip.file("package.json", await readFile(packageJsonPath));
  zip.file("pnpm-lock.yaml", await readFile(lockfilePath));
  await writeFile(
    outputPath,
    await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" }),
  );
  return outputPath;
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  console.log(`Review artifact written: ${await packageReviewArtifact()}`);
}
