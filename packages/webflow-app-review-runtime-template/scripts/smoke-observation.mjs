// Runtime observation smoke for a built sandbox template.
//
// Starts one sandbox from the immutable template reference in a build
// receipt, and runs the baked runner through one complete runtime observation
// of a fixture page that is served inside the same sandbox. The fixture's
// runtime script marks itself ready, creates an inline script, and calls
// eval, so the observation, the advisory static scan, and the advisory
// strict-CSP replay all have something to report.
//
// The runner refuses loopback targets unless RUNTIME_ALLOW_PRIVATE_HOSTS=1.
// This smoke sets that variable for its own runner process only. The template
// server never sets it, so a production job cannot use a loopback target.
//
// Usage:
//   E2B_API_KEY=... node scripts/smoke-observation.mjs \
//     --template-receipt /absolute/path/e2b-receipt.json \
//     --receipt /absolute/path/observation-smoke-receipt.json
//
// This is an operator check. It is not evidence about any developer runtime.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { Sandbox } from 'e2b';

const valueAfter = (flag) => {
  const index = process.argv.indexOf(flag);
  return index >= 0 ? process.argv[index + 1] : undefined;
};
const templateReceiptPath = valueAfter('--template-receipt');
const outputPath = valueAfter('--receipt');
if (!templateReceiptPath || !outputPath) {
  throw new Error('--template-receipt and --receipt are required.');
}
if (!process.env.E2B_API_KEY) throw new Error('E2B_API_KEY is required.');

const templateReceipt = JSON.parse(await readFile(templateReceiptPath, 'utf8'));
const templateRef = templateReceipt.immutableTemplateRef;
if (typeof templateRef !== 'string' || !templateRef.endsWith(`:${templateReceipt.buildId}`)) {
  throw new Error('The template receipt does not contain an immutable build reference.');
}

const PORT = 8788;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const WORK_DIR = '/tmp/observation-smoke';

// The fixture runtime: ready first, then one inline script and one eval.
const RUNTIME_SOURCE = [
  'document.documentElement.setAttribute("data-runtime-ready", "");',
  'var inline = document.createElement("script");',
  'inline.textContent = "window.__fixtureInline = true;";',
  'try { document.head.appendChild(inline); } catch (error) {}',
  'try { eval("window.__fixtureEval = true"); } catch (error) {}',
  ''
].join('\n');
const runtimeDigest = createHash('sha256').update(RUNTIME_SOURCE).digest();
const runtimeIntegrity = `sha256-${runtimeDigest.toString('base64')}`;

const jobId = randomUUID();
const capability = randomBytes(32).toString('hex');
const contract = {
  schemaVersion: 'runtime_observation_job.v1',
  purpose: 'webflow_observation',
  testPackageId: randomUUID(),
  reviewId: randomUUID(),
  reviewVersionId: randomUUID(),
  bundleSha256: 'b'.repeat(64),
  nonce: randomBytes(16).toString('hex'),
  target: { url: `${ORIGIN}/runtime-fixture`, host: '127.0.0.1' },
  sandboxInstallationId: randomUUID(),
  runtimeArtifacts: [
    {
      url: `${ORIGIN}/runtime-1.0.0.js`,
      sha256: runtimeDigest.toString('hex'),
      integrity: runtimeIntegrity
    }
  ],
  negativeProxyProbe: { mode: 'none_declared', declaration: 'no_proxy_surface' },
  lifecycle: { readySelector: '[data-runtime-ready]' },
  controls: {
    allowedHosts: ['127.0.0.1'],
    maxRequests: 100,
    requestTimeoutMs: 10_000,
    totalTimeoutMs: 90_000,
    networkMode: 'exact_host_allowlist',
    evidenceTrust: 'webflow_observed',
    executionEvidence: 'chromium_cdp_v1',
    negativeProxyCanaryUrl: null
  },
  boundaries: {
    partnerCanSubmitEvidence: false,
    officialDecision: null,
    canWriteGovernance: false,
    acceptsAccountCredentials: false
  },
  expiresAt: new Date(Date.now() + 10 * 60_000).toISOString()
};

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Runtime fixture</title></head><body><h1>Runtime fixture</h1><script src="${ORIGIN}/runtime-1.0.0.js" integrity="${runtimeIntegrity}" crossorigin="anonymous"></script></body></html>`;

// The stand-in for the Worker API and the fixture site, in one server. It
// gives the contract to the holder of the capability and keeps only the
// `manifest` field of the uploaded evidence.
const STAND_IN = `
import { createServer } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
const dir = ${JSON.stringify(WORK_DIR)};
const job = JSON.parse(readFileSync(dir + '/job.json', 'utf8'));
const jobPath = '/v1/runtime-observation-jobs/' + job.id;
createServer((request, response) => {
  const url = new URL(request.url ?? '/', ${JSON.stringify(ORIGIN)});
  const authorized = request.headers.authorization === 'Bearer ' + job.capability;
  if (url.pathname === jobPath && request.method === 'GET') {
    if (!authorized) return void response.writeHead(401).end();
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ observationJob: { contract: job.contract } }));
  } else if (url.pathname === jobPath + '/evidence' && request.method === 'POST') {
    if (!authorized) return void response.writeHead(401).end();
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      const body = Buffer.concat(chunks);
      const marker = Buffer.from('name="manifest"');
      const start = body.indexOf(marker);
      const headerEnd = start < 0 ? -1 : body.indexOf('\\r\\n\\r\\n', start);
      const partEnd = headerEnd < 0 ? -1 : body.indexOf('\\r\\n--', headerEnd);
      if (partEnd > 0) writeFileSync(dir + '/manifest.json', body.subarray(headerEnd + 4, partEnd));
      writeFileSync(dir + '/evidence-bytes.txt', String(body.length));
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ status: 'complete' }));
    });
  } else if (url.pathname === '/runtime-fixture') {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(readFileSync(dir + '/page.html'));
  } else if (url.pathname === '/runtime-1.0.0.js') {
    response.writeHead(200, {
      'content-type': 'application/javascript; charset=utf-8',
      'access-control-allow-origin': '*'
    });
    response.end(readFileSync(dir + '/runtime.js'));
  } else {
    response.writeHead(404).end();
  }
}).listen(${PORT}, '127.0.0.1');
`;

let sandbox;
let run = { exitCode: null, stdout: '', stderr: '' };
let manifest = null;
try {
  sandbox = await Sandbox.create(templateRef, { timeoutMs: 300_000 });
  await sandbox.files.write(`${WORK_DIR}/job.json`, JSON.stringify({ id: jobId, capability, contract }));
  await sandbox.files.write(`${WORK_DIR}/page.html`, PAGE);
  await sandbox.files.write(`${WORK_DIR}/runtime.js`, RUNTIME_SOURCE);
  await sandbox.files.write(`${WORK_DIR}/stand-in.mjs`, STAND_IN);
  await sandbox.commands.run(`node ${WORK_DIR}/stand-in.mjs`, { background: true });
  await new Promise((resolve) => setTimeout(resolve, 1_500));

  run = await sandbox.commands
    .run(`node /app/runner.mjs --api-base ${ORIGIN} --job ${jobId}`, {
      cwd: '/app',
      envs: {
        PLAYWRIGHT_BROWSERS_PATH: '0',
        RUNTIME_OBSERVATION_CAPABILITY: capability,
        RUNTIME_ALLOW_PRIVATE_HOSTS: '1'
      },
      timeoutMs: 240_000
    })
    .catch((error) => ({
      exitCode: error?.exitCode ?? 1,
      stdout: error?.stdout ?? '',
      stderr: error?.stderr ?? String(error?.message ?? error)
    }));

  try {
    manifest = JSON.parse(await sandbox.files.read(`${WORK_DIR}/manifest.json`));
  } catch {
    manifest = null;
  }
} finally {
  if (sandbox) await sandbox.kill().catch(() => undefined);
}

const file = manifest?.runtimeArtifacts?.[0] ?? null;
const scan = manifest?.runtimeStaticScan ?? null;
const replay = manifest?.cspReplay ?? null;
const checks = {
  evidenceUploaded: manifest !== null,
  bindingsMatch:
    manifest?.nonce === contract.nonce &&
    manifest?.reviewVersionId === contract.reviewVersionId &&
    manifest?.trust === 'webflow_observed',
  runtimeLoadedAndHashMatched:
    file?.loadedByPage === true && file?.observedSha256 === contract.runtimeArtifacts[0].sha256,
  staticScanFoundEval:
    scan?.status === 'scanned' &&
    scan.filesScanned >= 1 &&
    (scan.findings ?? []).some((finding) => finding.ruleId === 'SEC-NO-DCE' && finding.count >= 1),
  cspReplayReportedRuntimeViolation:
    replay?.status === 'violations' &&
    replay.runtimeReadyObserved === true &&
    (replay.violations ?? []).some((violation) => violation.fromRuntime === true)
};

const receipt = {
  schema: 'app-review-runtime-observation-smoke.v1',
  probedAt: new Date().toISOString(),
  immutableTemplateRef: templateRef,
  templateId: templateReceipt.templateId,
  buildId: templateReceipt.buildId,
  runnerSha256: templateReceipt.declaredInputs?.runnerSha256 ?? null,
  sandboxId: sandbox?.sandboxId ?? null,
  runnerExitCode: run.exitCode,
  checks,
  allPassed: Object.values(checks).every(Boolean),
  observed: {
    runtimeFile: file
      ? {
          loadedByPage: file.loadedByPage,
          hashMatched: file.observedSha256 === contract.runtimeArtifacts[0].sha256
        }
      : null,
    runtimeStaticScan: scan,
    cspReplay: replay
  },
  ...(Object.values(checks).every(Boolean)
    ? {}
    : { runnerOutput: `${run.stdout ?? ''}${run.stderr ?? ''}`.slice(-1_200) })
};
const absoluteOutput = path.resolve(outputPath);
await mkdir(path.dirname(absoluteOutput), { recursive: true });
await writeFile(absoluteOutput, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
if (!receipt.allPassed) process.exitCode = 1;
