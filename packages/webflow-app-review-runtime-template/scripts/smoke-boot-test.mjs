// Boot test smoke for a built sandbox template.
//
// Starts one sandbox from the immutable template reference in a build
// receipt, and runs the baked runner in boot-test mode against four fixture
// bundles. A stand-in for the Worker API runs inside the same sandbox on
// 127.0.0.1, so the smoke needs no deployed Worker and reaches nothing
// outside the sandbox. It proves that the template's own Chromium and runner
// produce the expected result for each fixture.
//
// Usage:
//   E2B_API_KEY=... node scripts/smoke-boot-test.mjs \
//     --template-receipt /absolute/path/e2b-receipt.json \
//     --receipt /absolute/path/boot-test-smoke-receipt.json
//
// This is an operator check. It is not evidence about any developer bundle.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { crc32 } from 'node:zlib';
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

const API_PORT = 8787;
const WORK_DIR = '/tmp/boot-test-smoke';
// The policy the Worker writes into a job contract by default.
const HOST_POLICY = 'frame-ancestors https://*.design.webflow.com https://webflow.com';

/** A stored (uncompressed) ZIP. Enough for small text fixtures. */
function zip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, text] of Object.entries(files)) {
    const nameBytes = Buffer.from(name, 'utf8');
    const data = Buffer.from(text, 'utf8');
    const checksum = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    locals.push(local, nameBytes, data);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBytes);
    offset += local.length + nameBytes.length + data.length;
  }
  const centralSize = centrals.reduce((total, part) => total + part.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(files).length, 8);
  end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, ...centrals, end]);
}

const MANIFEST = JSON.stringify({ name: 'Smoke Extension', apiVersion: '2', publicDir: '.' });
const page = (head, body) =>
  `<!doctype html><html><head><meta charset="utf-8"><title>Smoke Extension</title>${head}</head><body>${body}</body></html>`;

const CASES = [
  {
    name: 'renders',
    files: {
      'webflow.json': MANIFEST,
      'index.html': page(
        '<link rel="stylesheet" href="./styles.css">',
        '<div id="root"></div><script src="./app.js"></script>'
      ),
      'styles.css': 'h1 { font-size: 16px; }',
      'app.js':
        'const root = document.getElementById("root");' +
        'const title = document.createElement("h1");' +
        'title.textContent = "Smoke extension is ready";' +
        'root.append(title);' +
        'fetch("https://api.example-vendor.test/ping").catch(() => {});'
    },
    expect: { status: 'passed', failures: [], externalHost: 'api.example-vendor.test' }
  },
  {
    name: 'missing_file',
    files: {
      'webflow.json': MANIFEST,
      'index.html': page('', '<h1>Smoke extension</h1><script src="./missing.js"></script>')
    },
    expect: { status: 'failed', failures: ['bundled_file_missing'], missingFile: 'missing.js' }
  },
  {
    name: 'blank_panel',
    files: {
      'webflow.json': MANIFEST,
      'index.html': page('', '<div id="root"></div><script src="./app.js"></script>'),
      'app.js': 'void 0;'
    },
    expect: { status: 'failed', failures: ['blank_panel'] }
  },
  {
    name: 'script_blocked_by_own_policy',
    files: {
      'webflow.json': MANIFEST,
      'index.html': page(
        '<meta http-equiv="Content-Security-Policy" content="script-src \'none\'">',
        '<h1>Smoke extension</h1><script src="./app.js"></script>'
      ),
      'app.js': 'document.title = "ran";'
    },
    expect: { status: 'failed', failures: ['bundled_script_blocked_by_csp'] }
  }
];

function contractFor(jobId, bundle) {
  return {
    schemaVersion: 'designer_extension_boot_test_job.v1',
    purpose: 'designer_extension_boot_test',
    bootTestJobId: jobId,
    reviewId: randomUUID(),
    reviewVersionId: randomUUID(),
    bundleSha256: createHash('sha256').update(bundle).digest('hex'),
    bundleBytes: bundle.length,
    nonce: randomBytes(16).toString('hex'),
    contentSecurityPolicy: HOST_POLICY,
    controls: {
      networkMode: 'local_static_server_only',
      viewport: { width: 420, height: 720 },
      navigationTimeoutMs: 15_000,
      settleMs: 1_500,
      totalTimeoutMs: 60_000,
      evidenceTrust: 'webflow_observed'
    },
    limits: {
      cspViolations: 20,
      missingFiles: 20,
      uncaughtErrors: 10,
      externalHosts: 20,
      messageLength: 300
    },
    boundaries: {
      advisoryOnly: true,
      affectsReadiness: false,
      officialDecision: null,
      canWriteGovernance: false,
      acceptsAccountCredentials: false
    },
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString()
  };
}

// The stand-in API. It serves each job's contract and bundle to the holder of
// that job's capability and stores the uploaded result.
const STAND_IN_API = `
import { createServer } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
const dir = ${JSON.stringify(WORK_DIR)};
const jobs = JSON.parse(readFileSync(dir + '/jobs.json', 'utf8'));
createServer((request, response) => {
  const match = /^\\/v1\\/boot-test-jobs\\/([^/]+)(\\/bundle|\\/result)?$/.exec(request.url ?? '');
  const job = match && jobs[decodeURIComponent(match[1])];
  if (!job || request.headers.authorization !== 'Bearer ' + job.capability) {
    response.writeHead(401).end();
    return;
  }
  if (!match[2] && request.method === 'GET') {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ bootTestJob: { id: job.id, status: 'running', contract: job.contract } }));
  } else if (match[2] === '/bundle' && request.method === 'GET') {
    const bytes = readFileSync(dir + '/' + job.id + '.zip');
    response.writeHead(200, { 'content-type': 'application/zip', 'content-length': bytes.length });
    response.end(bytes);
  } else if (match[2] === '/result' && request.method === 'POST') {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      writeFileSync(dir + '/' + job.id + '.result.json', Buffer.concat(chunks));
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{"ok":true}');
    });
  } else {
    response.writeHead(404).end();
  }
}).listen(${API_PORT}, '127.0.0.1');
`;

const sameSet = (left, right) =>
  left.length === right.length && [...left].sort().join() === [...right].sort().join();

let sandbox;
const results = [];
try {
  sandbox = await Sandbox.create(templateRef, { timeoutMs: 300_000 });

  const jobs = {};
  for (const testCase of CASES) {
    const id = randomUUID();
    const bundle = zip(testCase.files);
    testCase.jobId = id;
    testCase.capability = randomBytes(32).toString('hex');
    jobs[id] = { id, capability: testCase.capability, contract: contractFor(id, bundle) };
    await sandbox.files.write(
      `${WORK_DIR}/${id}.zip`,
      bundle.buffer.slice(bundle.byteOffset, bundle.byteOffset + bundle.byteLength)
    );
  }
  await sandbox.files.write(`${WORK_DIR}/jobs.json`, JSON.stringify(jobs));
  await sandbox.files.write(`${WORK_DIR}/api.mjs`, STAND_IN_API);
  await sandbox.commands.run(`node ${WORK_DIR}/api.mjs`, { background: true });
  await new Promise((resolve) => setTimeout(resolve, 1_500));

  for (const testCase of CASES) {
    // Same arguments and environment as the template server gives the runner.
    const run = await sandbox.commands
      .run(
        `node /app/runner.mjs --api-base http://127.0.0.1:${API_PORT} --job ${testCase.jobId} --kind boot-test`,
        {
          cwd: '/app',
          envs: { PLAYWRIGHT_BROWSERS_PATH: '0', RUNTIME_OBSERVATION_CAPABILITY: testCase.capability },
          timeoutMs: 120_000
        }
      )
      .catch((error) => ({ exitCode: error?.exitCode ?? 1, stdout: '', stderr: String(error?.message ?? error) }));

    let bootTest = null;
    try {
      const stored = await sandbox.files.read(`${WORK_DIR}/${testCase.jobId}.result.json`);
      bootTest = JSON.parse(stored).bootTest ?? null;
    } catch {
      bootTest = null;
    }

    const expected = testCase.expect;
    const matched =
      bootTest !== null &&
      bootTest.status === expected.status &&
      sameSet(bootTest.failures ?? [], expected.failures) &&
      (!expected.missingFile || (bootTest.missingFiles ?? []).includes(expected.missingFile)) &&
      (!expected.externalHost ||
        (bootTest.externalHostsRequested ?? []).includes(expected.externalHost));

    results.push({
      case: testCase.name,
      expected: { status: expected.status, failures: expected.failures },
      runnerExitCode: run.exitCode,
      status: bootTest?.status ?? null,
      failures: bootTest?.failures ?? null,
      missingFiles: bootTest?.missingFiles ?? null,
      cspViolations: bootTest?.cspViolations ?? null,
      externalHostsRequested: bootTest?.externalHostsRequested ?? null,
      renderedTextLength: bootTest?.renderedTextLength ?? null,
      renderedElementCount: bootTest?.renderedElementCount ?? null,
      matched,
      ...(matched ? {} : { runnerOutput: `${run.stdout ?? ''}${run.stderr ?? ''}`.slice(-600) })
    });
  }
} finally {
  if (sandbox) await sandbox.kill().catch(() => undefined);
}

const receipt = {
  schema: 'app-review-runtime-boot-test-smoke.v1',
  probedAt: new Date().toISOString(),
  immutableTemplateRef: templateRef,
  templateId: templateReceipt.templateId,
  buildId: templateReceipt.buildId,
  runnerSha256: templateReceipt.declaredInputs?.runnerSha256 ?? null,
  sandboxId: sandbox?.sandboxId ?? null,
  allMatched: results.length === CASES.length && results.every((result) => result.matched),
  results
};
const absoluteOutput = path.resolve(outputPath);
await mkdir(path.dirname(absoluteOutput), { recursive: true });
await writeFile(absoluteOutput, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
if (!receipt.allMatched) process.exitCode = 1;
