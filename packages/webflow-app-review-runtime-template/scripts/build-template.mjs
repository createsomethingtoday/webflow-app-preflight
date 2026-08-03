import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Sandbox, Template, defaultBuildLogger } from 'e2b';
import {
  BASE_IMAGE,
  NODE_VERSION,
  PLAYWRIGHT_VERSION,
  runtimeTemplate
} from '../template.mjs';

// Probes the BUILT sandbox for the facts the declared inputs do NOT determine:
// the resolved Chromium revision, the resolved playwright-core version, and a
// hash of the installed OS package set (dpkg -l). These make two builds
// comparable after the fact even though the browser/OS layers are captured, not
// reproducible (FIX 8).
async function captureResolvedFacts(templateRef, hash) {
  const facts = {
    chromiumRevision: null,
    chromiumInstallReport: null,
    playwrightCoreVersion: null,
    dpkgListSha256: null,
    probeError: null
  };
  let sandbox;
  try {
    sandbox = await Sandbox.create(templateRef, { timeoutMs: 120_000 });
    const dryRun = await sandbox.commands.run(
      'PLAYWRIGHT_BROWSERS_PATH=0 npx playwright install --dry-run chromium',
      { cwd: '/app' }
    );
    facts.chromiumInstallReport = dryRun.stdout.trim();
    facts.chromiumRevision = /chromium[^\n]*?(\d{4,})/i.exec(dryRun.stdout)?.[1] ?? null;
    const pkg = await sandbox.commands.run(
      'node -p "require(\'/app/node_modules/playwright-core/package.json\').version"'
    );
    facts.playwrightCoreVersion = pkg.stdout.trim() || null;
    const dpkg = await sandbox.commands.run('dpkg -l');
    facts.dpkgListSha256 = hash(dpkg.stdout);
  } catch (error) {
    facts.probeError = error instanceof Error ? error.message : String(error);
  } finally {
    if (sandbox) await sandbox.kill().catch(() => {});
  }
  return facts;
}

const packageDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const name = process.env.E2B_RUNTIME_TEMPLATE_NAME?.trim() || 'app-review-companion-runtime';
if (!/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(name)) {
  throw new Error('E2B_RUNTIME_TEMPLATE_NAME must be a stable lowercase template name.');
}
if (!process.env.E2B_API_KEY) {
  throw new Error('E2B_API_KEY is required to build the runtime template.');
}

const receiptFlag = process.argv.indexOf('--receipt');
const receiptPath = receiptFlag >= 0 ? process.argv[receiptFlag + 1] : undefined;
if (receiptFlag >= 0 && !receiptPath) throw new Error('--receipt requires a path.');

const [server, runner] = await Promise.all([
  readFile(path.join(packageDir, 'context/server.mjs')),
  readFile(path.join(packageDir, 'context/runner.mjs'))
]);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const build = await Template.build(runtimeTemplate, name, {
  cpuCount: 2,
  memoryMB: 2_048,
  onBuildLogs: defaultBuildLogger()
});
const immutableTemplateRef = `${name}:${build.buildId}`;
// `declaredInputs` are the build recipe (what we asked for). They do NOT
// determine the browser and OS layers — only the built artifact
// (immutableTemplateRef) is actually immutable. `resolved` records what those
// non-reproducible layers actually became.
const resolved = await captureResolvedFacts(immutableTemplateRef, sha256);
const receipt = {
  schema: 'app-review-runtime-template-build.v2',
  builtAt: new Date().toISOString(),
  name: build.name,
  templateId: build.templateId,
  buildId: build.buildId,
  immutableTemplateRef,
  tags: build.tags,
  declaredInputs: {
    baseImage: BASE_IMAGE,
    node: NODE_VERSION,
    playwright: PLAYWRIGHT_VERSION,
    chromiumInstall: 'PLAYWRIGHT_BROWSERS_PATH=0 npx playwright install --with-deps chromium',
    serverSha256: sha256(server),
    runnerSha256: sha256(runner)
  },
  resolved
};

if (receiptPath) {
  const absoluteReceiptPath = path.resolve(process.cwd(), receiptPath);
  await mkdir(path.dirname(absoluteReceiptPath), { recursive: true });
  await writeFile(absoluteReceiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
}
process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
