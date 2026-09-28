import JSZip from 'jszip';
import { describe, expect, test } from 'vitest';
import {
  createBundleReview,
  createHostedRuntimeReviewArtifact,
  HostedRuntimeReviewInputError,
  SourceMapArtifactError
} from '../src/index';
import { boundedEvidenceSnippet } from '../src/create-review';

async function createDesignerExtensionFixture(): Promise<ArrayBuffer> {
  const zip = new JSZip();

  zip.file(
    'webflow.json',
    JSON.stringify({
      name: 'Consent Pro',
      apiVersion: '2',
      publicDir: 'dist',
      size: 'large'
    })
  );

  zip.file(
    'dist/index.js',
    [
      'const runtimeUrl = "https://api.consentpro.com/v2/cdn/runtime.js";',
      'const script = document.createElement("script");',
      'script.src = runtimeUrl;',
      'document.head.appendChild(script);'
    ].join('\n')
  );

  return zip.generateAsync({ type: 'arraybuffer' });
}

/**
 * A bundle whose ONLY executable file carries an eval(atob(...)) payload and
 * an unpinned CDN loader. `fileName` lets the same payload be exercised under
 * a minified name (app.min.js) and a plain name (app.js).
 */
async function createSingleExecutableFixture(fileName: string): Promise<ArrayBuffer> {
  const zip = new JSZip();

  zip.file(
    'webflow.json',
    JSON.stringify({
      name: 'Loader App',
      apiVersion: '2',
      publicDir: 'public'
    })
  );

  zip.file(
    `public/${fileName}`,
    [
      'const payload=eval(atob("Y29uc29sZS5sb2coMSk="));',
      'const s=document.createElement("script");',
      's.src="https://cdn.vendor-app.net/loader.js";',
      'document.head.appendChild(s);'
    ].join('')
  );

  return zip.generateAsync({ type: 'arraybuffer' });
}

function blockerRuleIds(review: Awaited<ReturnType<typeof createBundleReview>>): string[] {
  return review.guidance
    .filter((item) => item.label === 'Security blocker')
    .map((item) => item.id)
    .sort();
}

describe('createBundleReview', () => {
  test('creates a scope-aware review without claiming production runtime coverage', async () => {
    const review = await createBundleReview({
      bundle: await createDesignerExtensionFixture(),
      fileName: 'consent-pro.zip'
    });

    expect(review.artifactScope.primary).toBe('designer_extension');
    expect(review.coverage).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ surface: 'designer_extension', status: 'reviewed' }),
        expect.objectContaining({ surface: 'production_runtime', status: 'needs_verification' })
      ])
    );
    expect(review.runtime.references).toContain('https://api.consentpro.com/v2/cdn/runtime.js');
    expect(review.summary.securityBlockers).toBeGreaterThan(0);
    expect(review.summary.readiness).toBe('changes_required');
    expect(review.guidance[0]).toEqual(
      expect.objectContaining({ label: 'Security blocker', nextMove: expect.any(String) })
    );
    expect(review.policySnapshot.rulesetVersion).toBeTruthy();
    expect(review.policySnapshot.configVersion).toBeTruthy();
    expect(review.officialDecision).toBeNull();
  });

  test('scans minified production output identically to non-minified output', async () => {
    const minified = await createBundleReview({
      bundle: await createSingleExecutableFixture('app.min.js'),
      fileName: 'loader-app.zip'
    });
    const plain = await createBundleReview({
      bundle: await createSingleExecutableFixture('app.js'),
      fileName: 'loader-app.zip'
    });

    // Renaming the file must not change the security outcome.
    const minifiedBlockers = blockerRuleIds(minified);
    expect(minifiedBlockers).toContain('SEC-NO-DCE');
    expect(minifiedBlockers).toContain('SEC-SCRIPT-INJECTION');
    expect(minifiedBlockers).toEqual(blockerRuleIds(plain));

    expect(minified.summary.securityBlockers).toBeGreaterThan(0);
    expect(minified.summary.readiness).toBe('changes_required');
    expect(minified.summary.readiness).toBe(plain.summary.readiness);

    // The minified file was actually scanned, not skipped.
    expect(minified.scanCoverage).toBeDefined();
    expect(minified.scanCoverage?.skippedExecutablePaths).not.toContain('public/app.min.js');
    expect(
      minified.guidance.some((item) =>
        item.evidence.some((evidence) => evidence.filePath === 'public/app.min.js')
      )
    ).toBe(true);
  });

  test('reports skipped executable files as manual-review input, not a pass', async () => {
    const zip = new JSZip();
    zip.file('webflow.json', JSON.stringify({ name: 'Skips', apiVersion: '2', publicDir: 'dist' }));
    zip.file('dist/index.js', 'export const ok = true;');
    // Excluded path: never decoded, so it must be surfaced, not silently passed.
    zip.file('node_modules/helper/index.js', 'eval(atob("aGlkZGVu"));');
    // Binary executable format: cannot be text-scanned.
    zip.file('dist/module.wasm', new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));

    const review = await createBundleReview({
      bundle: await zip.generateAsync({ type: 'arraybuffer' }),
      fileName: 'skips.zip'
    });

    expect(review.scanCoverage).toBeDefined();
    const coverage = review.scanCoverage!;
    expect(coverage.fileCount).toBe(4);
    expect(coverage.scannedFileCount + coverage.skippedFileCount).toBe(coverage.fileCount);
    expect(coverage.skippedExecutablePaths).toEqual([
      'dist/module.wasm',
      'node_modules/helper/index.js'
    ]);
    expect(coverage.manualReviewRequired).toBe(true);
  });

  test('reports full coverage when every executable file is scanned', async () => {
    const review = await createBundleReview({
      bundle: await createSingleExecutableFixture('app.js'),
      fileName: 'loader-app.zip'
    });

    expect(review.scanCoverage).toBeDefined();
    expect(review.scanCoverage?.skippedExecutablePaths).toEqual([]);
    expect(review.scanCoverage?.unsafeEntryPaths).toEqual([]);
    expect(review.scanCoverage?.manualReviewRequired).toBe(false);
  });

  test('flags a minified bundle with no source maps as not traceable to source', async () => {
    const review = await createBundleReview({
      bundle: await createSingleExecutableFixture('app.min.js'),
      fileName: 'loader-app.zip'
    });

    expect(review.sourceMapSummary).toBeDefined();
    expect(review.sourceMapSummary?.status).toBe('missing');
    expect(review.sourceMapSummary?.artifactProvided).toBe(false);
    expect(review.sourceMapSummary?.missingGeneratedFiles).toContain('public/app.min.js');

    const finding = review.guidance.find((item) => item.id === 'SRC-MAP-CORRESPONDENCE');
    expect(finding).toBeDefined();
    expect(finding?.label).toBe('Required update');
    expect(
      finding?.evidence.some((evidence) => evidence.filePath === 'public/app.min.js')
    ).toBe(true);
    expect(review.summary.readiness).toBe('changes_required');
  });

  test('accepts a minified bundle whose source map matches the generated file', async () => {
    const zip = new JSZip();
    zip.file(
      'webflow.json',
      JSON.stringify({ name: 'Mapped App', apiVersion: '2', publicDir: 'public' })
    );
    zip.file('public/app.min.js', 'export const ok=true;//# sourceMappingURL=app.min.js.map');
    zip.file(
      'public/app.min.js.map',
      JSON.stringify({ version: 3, file: 'app.min.js', sources: ['../src/app.ts'], mappings: '' })
    );

    const review = await createBundleReview({
      bundle: await zip.generateAsync({ type: 'arraybuffer' }),
      fileName: 'mapped-app.zip'
    });

    expect(review.sourceMapSummary?.status).toBe('matched');
    expect(review.sourceMapSummary?.artifactProvided).toBe(true);
    expect(review.guidance.find((item) => item.id === 'SRC-MAP-CORRESPONDENCE')).toBeUndefined();
  });

  test('reconciles a privately uploaded source-map artifact against the bundle', async () => {
    const zip = new JSZip();
    zip.file(
      'webflow.json',
      JSON.stringify({ name: 'Mapped App', apiVersion: '2', publicDir: 'public' })
    );
    zip.file('public/app.min.js', 'export const ok=true;//# sourceMappingURL=app.min.js.map');

    const mapZip = new JSZip();
    mapZip.file(
      'app.min.js.map',
      JSON.stringify({ version: 3, file: 'app.min.js', sources: ['../src/app.ts'], mappings: '' })
    );

    const review = await createBundleReview({
      bundle: await zip.generateAsync({ type: 'arraybuffer' }),
      fileName: 'mapped-app.zip',
      sourceMapArtifact: {
        fileName: 'mapped-app-maps.zip',
        bytes: await mapZip.generateAsync({ type: 'arraybuffer' })
      }
    });

    expect(review.sourceMapSummary?.status).toBe('matched');
    expect(review.guidance.find((item) => item.id === 'SRC-MAP-CORRESPONDENCE')).toBeUndefined();
    expect(review.artifact.sourceMaps?.fileName).toBe('mapped-app-maps.zip');
    expect(review.artifact.sourceMaps?.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(review.artifact.sourceMaps?.mapFileCount).toBe(1);
  });

  test('accepts a single .map file as the source-map artifact', async () => {
    const zip = new JSZip();
    zip.file(
      'webflow.json',
      JSON.stringify({ name: 'Mapped App', apiVersion: '2', publicDir: 'public' })
    );
    zip.file('public/app.min.js', 'export const ok=true;//# sourceMappingURL=app.min.js.map');

    const review = await createBundleReview({
      bundle: await zip.generateAsync({ type: 'arraybuffer' }),
      fileName: 'mapped-app.zip',
      sourceMapArtifact: {
        fileName: 'app.min.js.map',
        bytes: new TextEncoder().encode(
          JSON.stringify({ version: 3, file: 'app.min.js', sources: ['../src/app.ts'], mappings: '' })
        ).buffer as ArrayBuffer
      }
    });

    expect(review.sourceMapSummary?.status).toBe('matched');
  });

  test('rejects a source-map artifact that contains no maps', async () => {
    const zip = new JSZip();
    zip.file(
      'webflow.json',
      JSON.stringify({ name: 'Mapped App', apiVersion: '2', publicDir: 'public' })
    );
    zip.file('public/app.min.js', 'export const ok=true;');

    const emptyArtifact = new JSZip();
    emptyArtifact.file('README.txt', 'no maps here');

    await expect(
      createBundleReview({
        bundle: await zip.generateAsync({ type: 'arraybuffer' }),
        fileName: 'mapped-app.zip',
        sourceMapArtifact: {
          fileName: 'not-maps.zip',
          bytes: await emptyArtifact.generateAsync({ type: 'arraybuffer' })
        }
      })
    ).rejects.toThrow(SourceMapArtifactError);
  });

  test('flags unparseable source maps instead of treating them as coverage', async () => {
    const zip = new JSZip();
    zip.file(
      'webflow.json',
      JSON.stringify({ name: 'Broken Map App', apiVersion: '2', publicDir: 'public' })
    );
    zip.file('public/app.min.js', 'export const ok=true;//# sourceMappingURL=app.min.js.map');
    zip.file('public/app.min.js.map', 'not-json');

    const review = await createBundleReview({
      bundle: await zip.generateAsync({ type: 'arraybuffer' }),
      fileName: 'broken-map-app.zip'
    });

    expect(review.sourceMapSummary?.status).toBe('invalid');
    const finding = review.guidance.find((item) => item.id === 'SRC-MAP-CORRESPONDENCE');
    expect(finding).toBeDefined();
    expect(finding?.evidence[0]?.filePath).toBe('public/app.min.js.map');
  });

  test('does not demand source maps from a plain-source bundle', async () => {
    const review = await createBundleReview({
      bundle: await createDesignerExtensionFixture(),
      fileName: 'consent-pro.zip'
    });

    expect(review.sourceMapSummary).toBeDefined();
    expect(['not_provided', 'not_required']).toContain(review.sourceMapSummary?.status);
    expect(review.guidance.find((item) => item.id === 'SRC-MAP-CORRESPONDENCE')).toBeUndefined();
  });

  test('keeps a useful bounded excerpt from a large minified source line', () => {
    const prefix = 'const a=1;'.repeat(20_000);
    const trigger = 'document.createElement("script")';
    const line = `${prefix}${trigger}${'const b=2;'.repeat(20_000)}`;
    const excerpt = boundedEvidenceSnippet(line, prefix.length + 1, 'createElement');

    expect(excerpt).toContain(trigger);
    expect(excerpt.length).toBeLessThanOrEqual(500);
    expect(excerpt.startsWith('…')).toBe(true);
    expect(excerpt.endsWith('…')).toBe(true);
  });
});

describe('createHostedRuntimeReviewArtifact', () => {
  test('creates one immutable Data Client manifest for an ordered runtime set', async () => {
    const runtimeUrls = [
      'https://cdn.example.com/runtime-v1.js',
      'https://cdn.example.com/child-v1.js'
    ];
    const artifact = await createHostedRuntimeReviewArtifact({
      appName: 'Website Speedy',
      runtimeUrls
    });
    const manifestSha256 = Array.from(
      new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(artifact.manifest))
      )
    )
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');

    expect(artifact.review.artifact).toMatchObject({
      kind: 'runtime_manifest',
      sha256: manifestSha256,
      fileCount: 2
    });
    expect(artifact.review.artifactScope).toMatchObject({
      primary: 'production_runtime',
      appType: 'data_client',
      appName: 'Website Speedy'
    });
    expect(artifact.review.runtime.references).toEqual(runtimeUrls);
    expect(artifact.review.officialDecision).toBeNull();
  });

  test('keeps every runtime URL in a larger execution scenario', async () => {
    const runtimeUrls = Array.from(
      { length: 10 },
      (_, index) => `https://cdn.example.com/runtime-v1-${index + 1}.js`
    );

    const artifact = await createHostedRuntimeReviewArtifact({
      appName: 'Multi-file runtime',
      runtimeUrls
    });

    expect(artifact.review.runtime.references).toEqual(runtimeUrls);
    expect(artifact.review.artifact.fileCount).toBe(10);
  });

  test.each([
    {
      label: 'credential-bearing URL',
      input: { appName: 'Unsafe', runtimeUrls: ['https://user:secret@example.com/runtime.js'] }
    },
    {
      label: 'non-HTTPS URL',
      input: { appName: 'Unsafe', runtimeUrls: ['http://example.com/runtime.js'] }
    },
    {
      label: 'duplicate URL',
      input: {
        appName: 'Unsafe',
        runtimeUrls: ['https://example.com/runtime.js', 'https://example.com/runtime.js']
      }
    }
  ])('rejects $label before persistence', async ({ input }) => {
    await expect(createHostedRuntimeReviewArtifact(input)).rejects.toBeInstanceOf(
      HostedRuntimeReviewInputError
    );
  });

});

describe('scope-alignment checks (openapi-internal #964 retained gates)', () => {
  async function bundleWith(files: Record<string, string>, appName = 'Checkout App'): Promise<ArrayBuffer> {
    const zip = new JSZip();
    zip.file('webflow.json', JSON.stringify({ name: appName, apiVersion: '2', publicDir: 'dist' }));
    for (const [path, content] of Object.entries(files)) {
      zip.file(path, content);
    }
    return zip.generateAsync({ type: 'arraybuffer' });
  }

  test('flags a credential travelling in a URL query string as a blocker', async () => {
    const bundle = await bundleWith({
      'dist/auth.js': 'const url = `/v1/auth/webflow/sign-in?access_token=${token}`;\nfetch(url);'
    });
    const review = await createBundleReview({ fileName: 'bundle.zip', bundle });

    const finding = review.guidance.find((item) => item.id === 'SEC-NO-TOKEN-IN-URL');
    expect(finding?.label).toBe('Security blocker');
    expect(review.summary.readiness).toBe('changes_required');
  });

  test('flags debug routes and bypass flags left in the production bundle', async () => {
    const bundle = await bundleWith({
      'dist/app.js':
        'const prefill = "/v1/debug/merchant/prefill";\nif (config.bypassOnboarding) { start(); }'
    });
    const review = await createBundleReview({ fileName: 'bundle.zip', bundle });

    const finding = review.guidance.find((item) => item.id === 'PROD-NO-DEBUG-RESIDUE');
    expect(finding?.label).toBe('Required update');
  });

  test('asks for an explanation when Designer API mutations are present', async () => {
    const bundle = await bundleWith({
      'dist/extension.js': 'await webflow.createStyle("north-button");\nawait webflow.createVariable(collection, "spacing");'
    });
    const review = await createBundleReview({ fileName: 'bundle.zip', bundle });

    expect(review.guidance.some((item) => item.id === 'UX-NO-MUTATION-ON-LOAD')).toBe(true);
  });

  test('flags a development identity in the app manifest', async () => {
    const bundle = await bundleWith({ 'dist/app.js': 'export const ok = true;' }, 'North Staging App');
    const review = await createBundleReview({ fileName: 'bundle.zip', bundle });

    const finding = review.guidance.find((item) => item.id === 'PROD-DEV-IDENTITY');
    expect(finding?.label).toBe('Required update');
    expect(finding?.evidence[0]?.snippet).toContain('North Staging App');
  });

  test('does not flag legitimate names containing "test"', async () => {
    const bundle = await bundleWith({ 'dist/app.js': 'export const ok = true;' }, 'A/B Test Wizard');
    const review = await createBundleReview({ fileName: 'bundle.zip', bundle });

    expect(review.guidance.find((item) => item.id === 'PROD-DEV-IDENTITY')).toBeUndefined();
  });

  test('suggests including the package manifest and lockfile for compiled bundles', async () => {
    const bundle = await bundleWith({ 'dist/app.js': 'export const ok = true;' });
    const review = await createBundleReview({ fileName: 'bundle.zip', bundle });

    const finding = review.guidance.find((item) => item.id === 'PROD-PACKAGE-MANIFEST');
    expect(finding?.label).toBe('Suggested update');
    expect(review.summary.readiness).toBe('ready');
  });

  test('stays quiet when the manifest and lockfile ship with the bundle', async () => {
    const bundle = await bundleWith({
      'dist/app.js': 'export const ok = true;',
      'package.json': JSON.stringify({ name: 'checkout-app', version: '1.0.0' }),
      'pnpm-lock.yaml': 'lockfileVersion: 9'
    });
    const review = await createBundleReview({ fileName: 'bundle.zip', bundle });

    expect(review.guidance.find((item) => item.id === 'PROD-PACKAGE-MANIFEST')).toBeUndefined();
  });
});

describe('Marketplace Guidelines alignment (developers.webflow.com, read 2026-09-28)', () => {
  async function bundleWith(files: Record<string, string>): Promise<ArrayBuffer> {
    const zip = new JSZip();
    zip.file('webflow.json', JSON.stringify({ name: 'Checkout App', apiVersion: '2', publicDir: 'dist' }));
    zip.file('package.json', JSON.stringify({ name: 'checkout-app', version: '1.0.0' }));
    zip.file('pnpm-lock.yaml', 'lockfileVersion: 9');
    for (const [path, content] of Object.entries(files)) zip.file(path, content);
    return zip.generateAsync({ type: 'arraybuffer' });
  }

  const review = async (files: Record<string, string>) =>
    createBundleReview({ fileName: 'bundle.zip', bundle: await bundleWith(files) });
  const find = (result: Awaited<ReturnType<typeof review>>, id: string) =>
    result.guidance.find((item) => item.id === id);

  test('a compliant networked extension reaches ready', async () => {
    const result = await review({
      'dist/index.js': [
        'const API = "https://api.example-app.com";',
        'async function load() { const r = await fetch(API + "/v1/items"); return r.json(); }',
        'button.addEventListener("click", () => { window.open("https://api.example-app.com/oauth/start", "_blank"); });',
        'function exportPng(canvas) { return canvas.toBlob((blob) => blob); }',
        'window.addEventListener("message", (event) => {',
        '  if (event.origin !== "https://api.example-app.com") return;',
        '});'
      ].join('\n')
    });

    expect(result.summary.securityBlockers).toBe(0);
    expect(result.summary.requiredUpdates).toBe(0);
    expect(result.summary.readiness).toBe('ready');
    expect(find(result, 'UX-NO-POPUPS')?.label).toBe('Suggested update');
    expect(find(result, 'NET-EXTERNAL-EGRESS')?.label).toBe('Suggested update');
    expect(find(result, 'PRIV-NO-FINGERPRINTING')).toBeUndefined();
    expect(find(result, 'SEC-MESSAGE-ORIGIN')).toBeUndefined();
  });

  test('flags a message handler that never checks event.origin', async () => {
    const result = await review({
      'dist/index.js': 'window.addEventListener("message", (event) => {\n  run(event.data);\n});'
    });
    expect(find(result, 'SEC-MESSAGE-ORIGIN')?.label).toBe('Required update');
  });

  test('flags native prototype and global function overrides', async () => {
    const result = await review({
      'dist/index.js': 'Array.prototype.push = function () {};\nwindow.fetch = wrappedFetch;'
    });
    const finding = find(result, 'SEC-NO-NATIVE-OVERRIDE');
    expect(finding?.label).toBe('Required update');
    expect(finding?.evidence).toHaveLength(2);
  });

  test('does not treat a comparison as an override', async () => {
    const result = await review({ 'dist/index.js': 'if (window.fetch === nativeFetch) start();' });
    expect(find(result, 'SEC-NO-NATIVE-OVERRIDE')).toBeUndefined();
  });

  test('blocks inline event handlers and javascript: URIs', async () => {
    const result = await review({
      'dist/index.html': '<a href="javascript:void(0)">x</a><button onclick="go()">Go</button>'
    });
    const finding = find(result, 'SEC-CSP-INLINE');
    expect(finding?.label).toBe('Security blocker');
    expect(finding?.evidence.length).toBeGreaterThanOrEqual(2);
  });

  test('flags modifier-key shortcuts but not plain key handling', async () => {
    const shortcut = await review({ 'dist/index.js': 'if (e.metaKey && e.key === "k") openPalette();' });
    expect(find(shortcut, 'UX-NO-KEYBOARD-SHORTCUTS')?.label).toBe('Required update');

    const enter = await review({ 'dist/index.js': 'if (e.key === "Enter") submit();' });
    expect(find(enter, 'UX-NO-KEYBOARD-SHORTCUTS')).toBeUndefined();
  });

  test('flags private network and cloud metadata URLs, and asks about staging hosts', async () => {
    const result = await review({
      'dist/index.js': [
        'const lan = "https://192.168.1.20:8443/api";',
        'const meta = "http://169.254.169.254/latest";',
        'const stg = "https://staging.example-app.com/api";'
      ].join('\n')
    });
    expect(find(result, 'PROD-NO-LOCALHOST')?.label).toBe('Required update');
    expect(find(result, 'PROD-STAGING-HOST')?.label).toBe('Suggested update');
  });

  test('asks about runtime base64 decoding without blocking', async () => {
    const result = await review({ 'dist/index.js': 'const claims = JSON.parse(atob(token.split(".")[1]));' });
    expect(find(result, 'SEC-RUNTIME-DECODING')?.label).toBe('Suggested update');
    expect(result.summary.readiness).toBe('ready');
  });

  test('flags bundles over the 5MB upload limit', async () => {
    const zip = new JSZip();
    zip.file('webflow.json', JSON.stringify({ name: 'Checkout App', apiVersion: '2', publicDir: 'dist' }));
    zip.file('dist/index.js', 'export const ok = true;');
    // Random bytes do not compress, so the archive itself exceeds 5MB.
    const noise = new Uint8Array(5.5 * 1024 * 1024);
    for (let offset = 0; offset < noise.length; offset += 65536) {
      crypto.getRandomValues(noise.subarray(offset, offset + 65536));
    }
    zip.file('dist/noise.bin', noise);
    const bundle = await zip.generateAsync({ type: 'arraybuffer', compression: 'STORE' });
    const result = await createBundleReview({ fileName: 'bundle.zip', bundle });

    expect(find(result, 'BUNDLE-SIZE-LIMIT')?.label).toBe('Required update');
  });
});

describe('Marketplace Guidelines alignment: precision review', () => {
  async function bundleWith(files: Record<string, string>): Promise<ArrayBuffer> {
    const zip = new JSZip();
    zip.file('webflow.json', JSON.stringify({ name: 'Checkout App', apiVersion: '2', publicDir: 'dist' }));
    zip.file('package.json', '{}');
    zip.file('pnpm-lock.yaml', 'lockfileVersion: 9');
    for (const [path, content] of Object.entries(files)) zip.file(path, content);
    return zip.generateAsync({ type: 'arraybuffer' });
  }
  const review = async (files: Record<string, string>) =>
    createBundleReview({ fileName: 'bundle.zip', bundle: await bundleWith(files) });
  const find = (result: Awaited<ReturnType<typeof review>>, id: string) =>
    result.guidance.find((item) => item.id === id);

  // --- message handlers -------------------------------------------------
  test('WebSocket and Worker message handlers are not window message handlers', async () => {
    const result = await review({
      'dist/index.js': [
        'const ws = new WebSocket("wss://api.example-app.com/live");',
        'ws.onmessage = (event) => { render(JSON.parse(event.data)); };',
        'ws.addEventListener("message", (event) => { log(event.data); });',
        'worker.addEventListener("message", (event) => { done(event.data); });'
      ].join('\n')
    });
    expect(find(result, 'SEC-MESSAGE-ORIGIN')).toBeUndefined();
  });

  test('a bare or window.onmessage handler without an origin check is flagged', async () => {
    const result = await review({
      'dist/index.js': 'window.onmessage = (event) => { run(event.data); };\naddEventListener("message", (e) => run(e.data));'
    });
    expect(find(result, 'SEC-MESSAGE-ORIGIN')?.evidence).toHaveLength(2);
  });

  test('a delegated handler is asked about, not required', async () => {
    const result = await review({
      'dist/index.js': 'useEffect(() => {\n  window.addEventListener("message", handleMessage);\n  return () => window.removeEventListener("message", handleMessage);\n}, []);'
    });
    expect(find(result, 'SEC-MESSAGE-ORIGIN')).toBeUndefined();
    expect(find(result, 'SEC-MESSAGE-ORIGIN-DELEGATED')?.label).toBe('Suggested update');
  });

  test('an unrelated location.origin nearby does not count as a check', async () => {
    const result = await review({
      'dist/index.js': 'window.addEventListener("message", (event) => {\n  const base = location.origin;\n  run(event.data, base);\n});'
    });
    expect(find(result, 'SEC-MESSAGE-ORIGIN')?.label).toBe('Required update');
  });

  test('destructured and allowlist-style origin checks count', async () => {
    const result = await review({
      'dist/index.js': [
        'window.addEventListener("message", ({ origin, data }) => {',
        '  if (origin !== "https://api.example-app.com") return;',
        '  run(data);',
        '});',
        'window.addEventListener("message", (e) => {',
        '  if (!ALLOWED.includes(e.origin)) return;',
        '  run(e.data);',
        '});'
      ].join('\n')
    });
    expect(find(result, 'SEC-MESSAGE-ORIGIN')).toBeUndefined();
  });

  // --- native overrides --------------------------------------------------
  test('guarded polyfills are not native overrides', async () => {
    const result = await review({
      'dist/index.js': [
        'if (!self.fetch) { self.fetch = fetchPolyfill; }',
        'Element.prototype.matches = Element.prototype.matches || Element.prototype.msMatchesSelector;'
      ].join('\n')
    });
    expect(find(result, 'SEC-NO-NATIVE-OVERRIDE')).toBeUndefined();
  });

  // --- CSP inline ----------------------------------------------------------
  test('a javascript: string used for sanitizing is not a blocker', async () => {
    const result = await review({
      'dist/index.js': 'function safe(url) {\n  if (url.trim().toLowerCase().startsWith("javascript:")) return "#";\n  return url;\n}'
    });
    expect(find(result, 'SEC-CSP-INLINE')).toBeUndefined();
  });

  test('a javascript: href assigned in code is a blocker', async () => {
    const result = await review({
      'dist/index.js': 'link.href = "javascript:void(0)";\nconst el = { href: "javascript:go()" };\na.setAttribute("href", "javascript:void(0)");'
    });
    expect(find(result, 'SEC-CSP-INLINE')?.evidence).toHaveLength(3);
  });

  test('non-handler attributes starting with "on" are not inline handlers', async () => {
    const result = await review({
      'dist/index.html': '<div one="1" data-onboarding="step" onboarding="x"></div>'
    });
    expect(find(result, 'SEC-CSP-INLINE')).toBeUndefined();
  });

  // --- keyboard shortcuts --------------------------------------------------
  test('grouped modifiers and hotkey libraries are shortcuts', async () => {
    const result = await review({
      'dist/index.js': [
        'if ((e.metaKey || e.ctrlKey) && e.key === "k") open();',
        'hotkeys("cmd+k, ctrl+k", open);',
        'useHotkeys("mod+shift+p", open);',
        'Mousetrap.bind("ctrl+s", save);'
      ].join('\n')
    });
    expect(find(result, 'UX-NO-KEYBOARD-SHORTCUTS')?.evidence).toHaveLength(3);
  });

  // --- staging hosts -------------------------------------------------------
  test('hyphenated staging labels are caught and well-known dev hosts are not', async () => {
    const result = await review({
      'dist/a.js': 'const a = "https://api-staging.example-app.com";',
      'dist/b.js': 'const b = "https://dev.to/article";',
      'dist/c.js': 'const c = "https://developer.mozilla.org";'
    });
    const finding = find(result, 'PROD-STAGING-HOST');
    expect(finding?.evidence.map((item) => item.filePath)).toEqual(['dist/a.js']);
  });
});

describe('Marketplace Guidelines alignment: real-bundle false positives', () => {
  async function bundleWith(files: Record<string, string>): Promise<ArrayBuffer> {
    const zip = new JSZip();
    zip.file('webflow.json', JSON.stringify({ name: 'Checkout App', apiVersion: '2', publicDir: 'dist' }));
    zip.file('package.json', '{}');
    zip.file('pnpm-lock.yaml', 'lockfileVersion: 9');
    for (const [path, content] of Object.entries(files)) zip.file(path, content);
    return zip.generateAsync({ type: 'arraybuffer' });
  }
  const review = async (files: Record<string, string>) =>
    createBundleReview({ fileName: 'bundle.zip', bundle: await bundleWith(files) });
  const find = (result: Awaited<ReturnType<typeof review>>, id: string) =>
    result.guidance.find((item) => item.id === id);

  test('a match inside a comment is advisory, because comments do not execute', async () => {
    const result = await review({
      'dist/index.js': [
        '// As Andi Smith suggests (http://www.andismith.com/blog/2012/02/modernizr-prefixed/)',
        '/* legacy: eval("x") was used here */',
        'export const ok = true;'
      ].join('\n')
    });
    expect(find(result, 'NET-URL-HYGIENE')?.label).toBe('Suggested update');
    expect(find(result, 'SEC-NO-DCE')?.label).toBe('Suggested update');
    expect(result.summary.readiness).toBe('ready');
  });

  test('the same patterns in live code stay required or blocking', async () => {
    const result = await review({
      'dist/index.js': 'const url = "http://www.andismith.com/";\neval("x");'
    });
    expect(find(result, 'NET-URL-HYGIENE')?.label).toBe('Required update');
    expect(find(result, 'SEC-NO-DCE')?.label).toBe('Security blocker');
  });

  test('framework-internal innerHTML is a confirmation, not a required update', async () => {
    const result = await review({
      'dist/index.js': 'function setInnerHTML(node, html) {\n  node.innerHTML = html;\n}\nel.insertAdjacentHTML("beforeend", markup);'
    });
    expect(find(result, 'SEC-UNSAFE-HTML')?.label).toBe('Suggested update');
    expect(result.summary.readiness).toBe('ready');
  });

  test('a block comment that closes before the match is live code', async () => {
    const result = await review({ 'dist/index.js': '/* legacy */ eval("x");' });
    expect(find(result, 'SEC-NO-DCE')?.label).toBe('Security blocker');
  });

  test('document.write stays a required update', async () => {
    const result = await review({ 'dist/index.js': 'document.write("<p>hi</p>");' });
    expect(find(result, 'SEC-UNSAFE-HTML')?.label).toBe('Required update');
  });

  test('script markup pushed through innerHTML is still a blocker', async () => {
    const result = await review({
      'dist/index.js': 'container.innerHTML = \'<script src="https://cdn.example.com/x.js"></script>\';'
    });
    expect(find(result, 'SEC-SCRIPT-INJECTION')?.label).toBe('Security blocker');
  });
});
