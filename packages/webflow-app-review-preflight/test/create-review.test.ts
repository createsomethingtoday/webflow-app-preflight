import JSZip from 'jszip';
import { describe, expect, test } from 'vitest';
import {
  createBundleReview,
  createHostedRuntimeReviewArtifact,
  HostedRuntimeReviewInputError,
  SourceMapArtifactError
} from '../src/index';
import {
  boundedEvidenceSnippet,
  effectiveFindingSeverity,
  guidanceLabel,
  guidanceSeverity
} from '../src/create-review';
import { defaultRuleset, type FindingGroup } from '@create-something/bundle-scanner-core';

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

    // The gap is a developer-visible finding and readiness is not `ready`.
    const finding = review.guidance.find((item) => item.id === 'SCAN-UNSCANNED-EXECUTABLE');
    expect(finding?.label).toBe('Manual review');
    expect(finding?.evidence.map((item) => item.filePath)).toEqual([
      'dist/module.wasm',
      'node_modules/helper/index.js'
    ]);
    expect(review.summary.manualReviews).toBe(1);
    expect(review.summary.securityBlockers).toBe(0);
    expect(review.summary.readiness).toBe('needs_review');
  });

  test('rejected zip-slip entries are a required update, not a silent skip', async () => {
    const zip = new JSZip();
    zip.file('webflow.json', JSON.stringify({ name: 'Slip', apiVersion: '2', publicDir: 'dist' }));
    zip.file('dist/index.js', 'export const ok = true;');
    // JSZip collapses forward-slash `../`; backslash names survive and are
    // normalized back into traversal paths by the extractor.
    zip.file('dist\\..\\..\\evil.js', 'eval("x")');

    const review = await createBundleReview({
      bundle: await zip.generateAsync({ type: 'arraybuffer' }),
      fileName: 'slip.zip'
    });

    expect(review.scanCoverage?.unsafeEntryPaths).toEqual(['dist/../../evil.js']);
    const finding = review.guidance.find((item) => item.id === 'BUNDLE-UNSAFE-ENTRY');
    expect(finding?.label).toBe('Required update');
    expect(finding?.evidence[0]?.filePath).toBe('dist/../../evil.js');
    expect(review.summary.readiness).toBe('changes_required');
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
    expect(review.guidance.find((item) => item.id === 'SCAN-UNSCANNED-EXECUTABLE')).toBeUndefined();
    expect(review.summary.manualReviews).toBe(0);
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

  test('a map shipped inside the public bundle satisfies correspondence but is itself a required update', async () => {
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
    expect(review.sourceMapSummary?.publicExposure).toBe(true);
    expect(review.guidance.find((item) => item.id === 'SRC-MAP-CORRESPONDENCE')).toBeUndefined();

    // Maps belong in the private source-map upload, not the public artifact.
    const exposure = review.guidance.find((item) => item.id === 'SRC-MAP-PUBLIC-EXPOSURE');
    expect(exposure?.label).toBe('Required update');
    expect(exposure?.evidence.map((item) => item.filePath)).toEqual(['public/app.min.js.map']);
    expect(review.summary.readiness).toBe('changes_required');
  });

  test('an inline data: source map counts as public exposure', async () => {
    const zip = new JSZip();
    zip.file('webflow.json', JSON.stringify({ name: 'Inline', apiVersion: '2', publicDir: 'dist' }));
    zip.file(
      'dist/index.js',
      'export const ok=true;//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ=='
    );

    const review = await createBundleReview({
      bundle: await zip.generateAsync({ type: 'arraybuffer' }),
      fileName: 'inline.zip'
    });

    const exposure = review.guidance.find((item) => item.id === 'SRC-MAP-PUBLIC-EXPOSURE');
    expect(exposure?.label).toBe('Required update');
    expect(exposure?.evidence[0]?.filePath).toBe('dist/index.js');
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
    mapZip.file('package.json', JSON.stringify({ name: 'mapped-app', version: '1.0.0' }));
    mapZip.file('pnpm-lock.yaml', 'lockfileVersion: 9');

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
    expect(review.guidance.find((item) => item.id === 'SRC-MAP-PUBLIC-EXPOSURE')).toBeUndefined();
    expect(review.summary.readiness).toBe('ready');
    expect(review.artifact.sourceMaps?.fileName).toBe('mapped-app-maps.zip');
    expect(review.artifact.sourceMaps?.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(review.artifact.sourceMaps?.mapFileCount).toBe(1);
  });

  test('rejects a bare .map file now that the artifact must be a ZIP', async () => {
    const zip = new JSZip();
    zip.file(
      'webflow.json',
      JSON.stringify({ name: 'Mapped App', apiVersion: '2', publicDir: 'public' })
    );
    zip.file('public/app.min.js', 'export const ok=true;//# sourceMappingURL=app.min.js.map');

    await expect(
      createBundleReview({
        bundle: await zip.generateAsync({ type: 'arraybuffer' }),
        fileName: 'mapped-app.zip',
        sourceMapArtifact: {
          fileName: 'app.min.js.map',
          bytes: new TextEncoder().encode(
            JSON.stringify({ version: 3, file: 'app.min.js', sources: ['../src/app.ts'], mappings: '' })
          ).buffer as ArrayBuffer
        }
      })
    ).rejects.toThrow(/one \.zip/);
  });

  test('rejects a source-map ZIP without package.json and a lockfile', async () => {
    const zip = new JSZip();
    zip.file(
      'webflow.json',
      JSON.stringify({ name: 'Mapped App', apiVersion: '2', publicDir: 'public' })
    );
    zip.file('public/app.min.js', 'export const ok=true;//# sourceMappingURL=app.min.js.map');

    const mapsOnly = new JSZip();
    mapsOnly.file(
      'app.min.js.map',
      JSON.stringify({ version: 3, file: 'app.min.js', sources: ['../src/app.ts'], mappings: '' })
    );

    const attempt = createBundleReview({
      bundle: await zip.generateAsync({ type: 'arraybuffer' }),
      fileName: 'mapped-app.zip',
      sourceMapArtifact: {
        fileName: 'maps-only.zip',
        bytes: await mapsOnly.generateAsync({ type: 'arraybuffer' })
      }
    });

    await expect(attempt).rejects.toThrow(SourceMapArtifactError);
    await expect(attempt).rejects.toThrow(/package\.json and a lockfile/);
  });

  async function unchangedSourceFixture(zipSource: string, bundleSource = zipSource, bundleFile = 'public/app.js') {
    const zip = new JSZip();
    zip.file(
      'webflow.json',
      JSON.stringify({ name: 'Plain App', apiVersion: '2', publicDir: 'public' })
    );
    zip.file(bundleFile, bundleSource);
    const review = new JSZip();
    review.file(`src/${bundleFile.split('/').pop()}`, zipSource);
    review.file('README.md', 'Shipped as-is: public/ is copied into the bundle without a build step.');
    return {
      bundle: await zip.generateAsync({ type: 'arraybuffer' }),
      fileName: 'plain-app.zip',
      sourceMapArtifact: {
        fileName: 'review-source.zip',
        bytes: await review.generateAsync({ type: 'arraybuffer' })
      }
    };
  }

  test('accepts unchanged source plus a README as the review ZIP when it matches the bundle', async () => {
    const source = "export function ready() { return 'ok'; }\n";
    const review = await createBundleReview(await unchangedSourceFixture(source));

    expect(review.artifact.sourceMaps?.shape).toBe('unchanged-source');
    expect(review.artifact.sourceMaps?.mapFileCount).toBe(0);
    expect(review.artifact.sourceMaps?.sourceFileCount).toBe(1);
    expect(review.guidance.find((item) => item.id === 'SRC-REVIEW-FILES-MISMATCH')).toBeUndefined();
    expect(review.guidance.find((item) => item.id === 'PROD-PACKAGE-MANIFEST')).toBeUndefined();
    expect(review.guidance.find((item) => item.id === 'SRC-MAP-CORRESPONDENCE')).toBeUndefined();
    expect(review.summary.readiness).toBe('ready');
  });

  test('requires unchanged-source review files to be byte-identical to what ships', async () => {
    const review = await createBundleReview(
      await unchangedSourceFixture(
        "export function ready() { return 'ok'; }\n",
        "export function ready() { return 'changed'; }\n"
      )
    );

    const finding = review.guidance.find((item) => item.id === 'SRC-REVIEW-FILES-MISMATCH');
    expect(finding?.label).toBe('Required update');
    expect(finding?.evidence[0]?.filePath).toBe('public/app.js');
    expect(review.summary.readiness).toBe('changes_required');
  });

  test('does not let unchanged source stand in for the maps of a generated bundle', async () => {
    const minified = 'export const ok=true;//# sourceMappingURL=app.min.js.map';
    const review = await createBundleReview(
      await unchangedSourceFixture(minified, minified, 'public/app.min.js')
    );

    expect(review.sourceMapSummary?.status).toBe('missing');
    expect(review.guidance.find((item) => item.id === 'SRC-MAP-CORRESPONDENCE')?.label).toBe('Required update');
  });

  test('rejects a review ZIP with source files but no README', async () => {
    const zip = new JSZip();
    zip.file('webflow.json', JSON.stringify({ name: 'Plain App', apiVersion: '2', publicDir: 'public' }));
    zip.file('public/app.js', 'export const ok = true;');
    const review = new JSZip();
    review.file('app.js', 'export const ok = true;');

    await expect(
      createBundleReview({
        bundle: await zip.generateAsync({ type: 'arraybuffer' }),
        fileName: 'plain-app.zip',
        sourceMapArtifact: { fileName: 'review.zip', bytes: await review.generateAsync({ type: 'arraybuffer' }) }
      })
    ).rejects.toThrow(/no README/);
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

  test('never reports an unscanned hosted runtime as ready', async () => {
    const { review } = await createHostedRuntimeReviewArtifact({
      appName: 'Website Speedy',
      runtimeUrls: ['https://cdn.example.com/runtime-v1.js']
    });

    expect(review.summary.readiness).toBe('needs_review');
    expect(review.summary.manualReviews).toBe(1);
    expect(review.guidance).toEqual([
      expect.objectContaining({
        id: 'RUNTIME-NOT-EVALUATED',
        label: 'Manual review',
        explanation: expect.stringContaining('did not download or scan')
      })
    ]);
    expect(
      review.coverage.find((item) => item.surface === 'production_runtime')?.detail
    ).toContain('not been scanned');
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
    expect(finding?.label).toBe('Manual review');
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
    expect(finding?.label).toBe('Manual review');
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

  test('stays quiet when the source-map ZIP carries the manifest and lockfile', async () => {
    const bundle = await bundleWith({ 'dist/app.js': 'export const ok = true;' });
    const artifact = new JSZip();
    artifact.file('dist/app.js.map', JSON.stringify({ version: 3, file: 'app.js', sources: ['../src/app.ts'], mappings: '' }));
    artifact.file('package.json', JSON.stringify({ name: 'checkout-app', version: '1.0.0' }));
    artifact.file('pnpm-lock.yaml', 'lockfileVersion: 9');
    const review = await createBundleReview({
      fileName: 'bundle.zip',
      bundle,
      sourceMapArtifact: {
        fileName: 'review-files.zip',
        bytes: await artifact.generateAsync({ type: 'arraybuffer' })
      }
    });

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
    expect(find(result, 'SEC-MESSAGE-ORIGIN')?.label).toBe('Manual review');
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
    expect(find(shortcut, 'UX-NO-KEYBOARD-SHORTCUTS')?.label).toBe('Manual review');

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
    expect(find(result, 'SEC-MESSAGE-ORIGIN')?.label).toBe('Manual review');
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

  test('the same patterns in live code are reviewed or blocking', async () => {
    const result = await review({
      'dist/index.js': 'const url = "http://www.andismith.com/";\neval("x");'
    });
    // A bare http:// literal is the mechanism, not the request: a reviewer
    // confirms it is an endpoint. A request helper called with it is certain.
    expect(find(result, 'NET-URL-HYGIENE')?.label).toBe('Manual review');
    expect(find(result, 'SEC-NO-DCE')?.label).toBe('Security blocker');

    const request = await review({ 'dist/index.js': 'fetch("http://api.andismith.com/v1");' });
    expect(find(request, 'NET-URL-HYGIENE')?.label).toBe('Required update');
    expect(request.summary.readiness).toBe('changes_required');
  });

  test('a commented-out match never masks a live match of the same rule', async () => {
    // Regression: severity used to come from the FIRST match only, so the
    // comment on line 1 downgraded the whole rule and readiness read `ready`.
    const result = await review({ 'dist/index.js': '// eval("x")\neval(y);' });
    const finding = find(result, 'SEC-NO-DCE');
    expect(finding?.label).toBe('Security blocker');
    expect(finding?.severity).toBe('BLOCKER');
    // The live match leads the evidence, not the comment.
    expect(finding?.evidence[0]?.line).toBe(2);
    expect(result.summary.securityBlockers).toBe(1);
    expect(result.summary.readiness).toBe('changes_required');
  });

  test('a bare localhost literal in library code is a suggestion, a dev endpoint stays required', async () => {
    // react-router's production build carries `new URL(p, "http://localhost")`
    // as a URL-parsing fallback; the skill says that is not dev residue.
    const library = await review({
      'dist/router.js': 'function parsePath(p){ return new URL(p, "http://localhost"); }'
    });
    expect(find(library, 'PROD-NO-LOCALHOST')?.label).toBe('Suggested update');
    expect(library.summary.readiness).toBe('ready');

    const blocklist = await review({
      'dist/app.js': "const blocked = ['http://localhost/', 'http://127.0.0.1'];"
    });
    expect(find(blocklist, 'PROD-NO-LOCALHOST')?.label).toBe('Suggested update');

    const devServer = await review({
      'dist/app.js': 'fetch("http://localhost:3000/api/session");'
    });
    expect(find(devServer, 'PROD-NO-LOCALHOST')?.label).toBe('Required update');
    expect(devServer.summary.readiness).toBe('changes_required');

    const tunnel = await review({ 'dist/app.js': 'const api = "https://abc.ngrok.io";' });
    expect(find(tunnel, 'PROD-NO-LOCALHOST')?.label).toBe('Required update');
  });

  test('a dev endpoint next to a bare localhost literal is not downgraded with it', async () => {
    const result = await review({
      'dist/app.js': [
        'const base = new URL(path, "http://localhost");',
        'fetch("http://localhost:5173/__vite_hmr");'
      ].join('\n')
    });
    const finding = find(result, 'PROD-NO-LOCALHOST');
    expect(finding?.label).toBe('Required update');
    expect(finding?.evidence[0]?.line).toBe(2);
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

  test('document.write goes to a reviewer: the sink is certain, the script insert is not', async () => {
    const result = await review({ 'dist/index.js': 'document.write("<p>hi</p>");' });
    expect(find(result, 'SEC-UNSAFE-HTML')?.label).toBe('Manual review');
  });

  test('script markup pushed through innerHTML is still a blocker', async () => {
    const result = await review({
      'dist/index.js': 'container.innerHTML = \'<script src="https://cdn.example.com/x.js"></script>\';'
    });
    expect(find(result, 'SEC-SCRIPT-INJECTION')?.label).toBe('Security blocker');
  });
});

describe('Designer API contract fragility (Zeltac, ZD 1193976)', () => {
  async function bundleWith(files: Record<string, string>): Promise<ArrayBuffer> {
    const zip = new JSZip();
    zip.file('webflow.json', JSON.stringify({ name: 'Slider App', apiVersion: '2', publicDir: 'dist' }));
    zip.file('package.json', '{}');
    zip.file('pnpm-lock.yaml', 'lockfileVersion: 9');
    for (const [path, content] of Object.entries(files)) zip.file(path, content);
    return zip.generateAsync({ type: 'arraybuffer' });
  }
  const review = async (files: Record<string, string>) =>
    createBundleReview({ fileName: 'bundle.zip', bundle: await bundleWith(files) });
  const find = (result: Awaited<ReturnType<typeof review>>, id: string) =>
    result.guidance.find((item) => item.id === id);

  test('identifying a section by element.type is a suggested update that points at getTag()', async () => {
    const result = await review({
      'dist/extension.js': [
        'const el = await selected.append(webflow.elementPresets.Section);',
        "if (el.type === 'Section') { await buildSlider(el); }"
      ].join('\n')
    });

    const finding = find(result, 'API-ELEMENT-TYPE-DISCRIMINATOR');
    expect(finding?.label).toBe('Suggested update');
    expect(finding?.nextMove).toContain('getTag()');
    expect(finding?.evidence[0]?.line).toBe(2);
    expect(result.summary.readiness).toBe('ready');
  });

  test('identifying a section by getTag() is not flagged', async () => {
    const result = await review({
      'dist/extension.js': [
        'const el = await selected.append(webflow.elementPresets.Section);',
        "if ((await el.getTag()) === 'section') { await buildSlider(el); }"
      ].join('\n')
    });

    expect(find(result, 'API-ELEMENT-TYPE-DISCRIMINATOR')).toBeUndefined();
    expect(result.summary.readiness).toBe('ready');
  });
});

describe('review correctness: severity, buckets, and labels agree', () => {
  test('every AUTO_REJECT rule is a BLOCKER and vice versa', () => {
    // The developer label is derived from severity AND bucket; a split rule
    // (HIGH + AUTO_REJECT) used to show as Required while the scanner
    // verdict counted it as a blocker.
    const split = defaultRuleset.rules.filter(
      (rule) => (rule.reviewBucket === 'AUTO_REJECT') !== (rule.severity === 'BLOCKER')
    );
    expect(split.map((rule) => rule.ruleId)).toEqual([]);
  });

  test('NET-URL-HYGIENE and IFRAME-EXTERNAL-SRC are Required updates by bucket and severity', () => {
    for (const id of ['NET-URL-HYGIENE', 'IFRAME-EXTERNAL-SRC']) {
      const rule = defaultRuleset.rules.find((item) => item.ruleId === id);
      expect(rule).toMatchObject({
        reviewBucket: 'ACTION_REQUIRED',
        severity: 'HIGH',
        disposition: 'ACTION_REQUIRED'
      });
    }
  });

  test('an AUTO_REJECT match is a blocker even when its severity field says HIGH', () => {
    const rule = {
      ruleId: 'X',
      name: 'x',
      category: 'SECURITY',
      reviewBucket: 'ACTION_REQUIRED' as const,
      severity: 'HIGH' as const,
      disposition: 'ACTION_REQUIRED' as const,
      description: '',
      matchers: []
    };
    const base = {
      ruleId: 'X',
      matcherId: 'm',
      filePath: 'a.js',
      col: 1,
      snippet: '',
      triggerToken: '',
      locationType: 'CODE' as const
    };
    const group: FindingGroup = {
      rule,
      count: 3,
      items: [
        { ...base, line: 1, confidence: 'LOW', severity: 'LOW', reviewBucket: 'INFO' },
        { ...base, line: 2, confidence: 'MEDIUM' },
        { ...base, line: 3, confidence: 'HIGH', reviewBucket: 'AUTO_REJECT' }
      ]
    };

    expect(effectiveFindingSeverity(group.items[2]!, rule)).toBe('BLOCKER');
    const derived = guidanceSeverity(group);
    expect(derived.severity).toBe('BLOCKER');
    expect(derived.confidence).toBe('HIGH');
    expect(derived.items.map((item) => item.line)).toEqual([3, 2, 1]);
  });

  test('an external iframe in live code goes to a reviewer (auth-flow iframes are allowed)', async () => {
    const zip = new JSZip();
    zip.file('webflow.json', JSON.stringify({ name: 'Embed', apiVersion: '2', publicDir: 'dist' }));
    zip.file('dist/index.html', '<iframe src="https://widgets.example.com/ui"></iframe>');
    const review = await createBundleReview({
      bundle: await zip.generateAsync({ type: 'arraybuffer' }),
      fileName: 'embed.zip'
    });
    const finding = review.guidance.find((item) => item.id === 'IFRAME-EXTERNAL-SRC');
    expect(finding?.label).toBe('Manual review');
    expect(review.summary.readiness).toBe('needs_review');
  });
});

describe('docs-aligned gating (ruleset 1.7.0): severity is the doc level, confidence is the gate', () => {
  async function bundleWith(files: Record<string, string>): Promise<ArrayBuffer> {
    const zip = new JSZip();
    zip.file('webflow.json', JSON.stringify({ name: 'Aligned App', apiVersion: '2', publicDir: 'dist' }));
    zip.file('package.json', JSON.stringify({ name: 'aligned-app', version: '1.0.0' }));
    zip.file('pnpm-lock.yaml', 'lockfileVersion: 9');
    for (const [path, content] of Object.entries(files)) zip.file(path, content);
    return zip.generateAsync({ type: 'arraybuffer' });
  }

  const review = async (files: Record<string, string>) =>
    createBundleReview({ fileName: 'bundle.zip', bundle: await bundleWith(files) });
  const find = (result: Awaited<ReturnType<typeof review>>, id: string) =>
    result.guidance.find((item) => item.id === id);

  test('the label is a function of doc level and match confidence', () => {
    expect(guidanceLabel('BLOCKER', 'HIGH')).toBe('Security blocker');
    expect(guidanceLabel('HIGH', 'HIGH')).toBe('Required update');
    expect(guidanceLabel('MEDIUM', 'HIGH')).toBe('Required update');
    expect(guidanceLabel('BLOCKER', 'MEDIUM')).toBe('Manual review');
    expect(guidanceLabel('HIGH', 'MEDIUM')).toBe('Manual review');
    expect(guidanceLabel('HIGH', 'LOW')).toBe('Suggested update');
    expect(guidanceLabel('BLOCKER', 'LOW')).toBe('Suggested update');
    expect(guidanceLabel('LOW', 'HIGH')).toBe('Suggested update');
    expect(guidanceLabel('INFO', 'HIGH')).toBe('Suggested update');
  });

  test('every rule that can gate readiness is a published MUST with at least one HIGH-confidence matcher', () => {
    // Severity LOW/INFO never gates; HIGH/BLOCKER rules gate only through a
    // HIGH-confidence matcher (base or override). A MUST rule whose matchers
    // are all MEDIUM/LOW can only ever ask for a reviewer.
    const gating = defaultRuleset.rules.filter((rule) => rule.severity === 'BLOCKER' || rule.severity === 'HIGH');
    const neverGates = gating
      .filter((rule) => !rule.matchers.some((m) => m.confidence === 'HIGH' || m.conditionalOverrides?.some((o) => o.newConfidence === 'HIGH')))
      .map((rule) => rule.ruleId)
      .sort();
    expect(neverGates).toEqual([
      'IFRAME-EXTERNAL-SRC',
      'PROD-NO-DEBUG-RESIDUE',
      'PROD-STAGING-HOST',
      'SEC-MESSAGE-ORIGIN',
      'SEC-NO-SENSITIVE-TOKENS-IN-STORAGE',
      'SEC-RUNTIME-DECODING',
      'SEC-UNSAFE-HTML',
      'SEC-WEBRTC-HARDWARE',
      'UX-NO-MUTATION-ON-LOAD',
      'UX-NO-POPUPS',
      'UX-NO-SILENT-MUTATIONS'
    ]);
  });

  test('a MUST matched at medium confidence asks for a reviewer and never blocks', async () => {
    const result = await review({ 'dist/index.js': 'localStorage.setItem("auth_token", token);' });
    const finding = find(result, 'SEC-NO-SENSITIVE-TOKENS-IN-STORAGE');
    expect(finding?.label).toBe('Manual review');
    expect(result.summary.requiredUpdates).toBe(0);
    expect(result.summary.securityBlockers).toBe(0);
    expect(result.summary.manualReviews).toBe(1);
    expect(result.summary.readiness).toBe('needs_review');
  });

  test('a MUST matched at low confidence is a suggestion and leaves readiness alone', async () => {
    const result = await review({
      'dist/index.js': [
        'button.onclick = () => window.open("https://docs.example.com", "_blank");',
        'const obs = new MutationObserver(() => {});',
        'const claims = JSON.parse(atob(parts[1]));',
        'async function apply() { await webflow.createStyle("hero"); }'
      ].join('\n')
    });
    for (const id of ['UX-NO-POPUPS', 'UX-NO-SILENT-MUTATIONS', 'SEC-RUNTIME-DECODING', 'UX-NO-MUTATION-ON-LOAD']) {
      expect(find(result, id)?.label, id).toBe('Suggested update');
    }
    expect(result.summary.readiness).toBe('ready');
  });

  test('camera and microphone access goes to a reviewer (user-triggered + disclosure cannot be seen statically)', async () => {
    const result = await review({ 'dist/index.js': 'const s = await navigator.mediaDevices.getUserMedia({ audio: true });' });
    expect(find(result, 'SEC-WEBRTC-HARDWARE')?.label).toBe('Manual review');
    expect(result.summary.readiness).toBe('needs_review');
  });

  test('a string timer is dynamic code execution with certainty', async () => {
    const result = await review({ 'dist/index.js': 'setTimeout("refresh()", 1000);' });
    expect(find(result, 'SEC-NO-DCE')?.label).toBe('Security blocker');
    expect(result.summary.readiness).toBe('changes_required');
  });

  test('minified code keeps the matcher confidence: an eval in a production bundle still blocks', async () => {
    const result = await review({ 'dist/app.min.js': 'var a=1;function b(c){return eval(c)}' });
    const finding = find(result, 'SEC-NO-DCE');
    expect(finding?.label).toBe('Security blocker');
    expect(finding?.confidence).toBe('HIGH');
    expect(result.summary.readiness).toBe('changes_required');
  });

  test('host-document access requires the global parent or top, not any object named parent', async () => {
    const library = await review({ 'dist/index.js': 'const doc = node.parent.document; const own = el.top.document;' });
    expect(find(library, 'SEC-NO-HOST-DOM')).toBeUndefined();

    const escape = await review({ 'dist/index.js': 'window.top.document.body.append(panel); top.document.title = "x";' });
    expect(find(escape, 'SEC-NO-HOST-DOM')?.label).toBe('Security blocker');
  });

  test('redirecting the host catches href assignment and replace/assign, not comparisons', async () => {
    const compare = await review({ 'dist/index.js': 'if (top.location === self.location) start();' });
    expect(find(compare, 'SEC-UNTRUSTED-REDIRECT')).toBeUndefined();

    const href = await review({ 'dist/index.js': 'top.location.href = next;' });
    expect(find(href, 'SEC-UNTRUSTED-REDIRECT')?.label).toBe('Security blocker');

    const replace = await review({ 'dist/index.js': 'window.parent.location.replace(next);' });
    expect(find(replace, 'SEC-UNTRUSTED-REDIRECT')?.label).toBe('Security blocker');
  });

  test('tunnel hosts are development endpoints', async () => {
    for (const host of ['https://a1b2.ngrok-free.app', 'https://demo.trycloudflare.com', 'https://my-app.loca.lt']) {
      const result = await review({ 'dist/index.js': `const API = "${host}";` });
      expect(find(result, 'PROD-NO-LOCALHOST')?.label, host).toBe('Required update');
    }
  });

  test('a <script src> string is certain only next to a DOM sink', async () => {
    const custom = await review({
      'dist/index.js': 'const snippet = \'<script src="https://cdn.example.com/x.js"></script>\';\nawait registerCustomCode(snippet);'
    });
    expect(find(custom, 'SEC-SCRIPT-INJECTION')?.label).toBe('Manual review');

    const injected = await review({
      'dist/index.js': 'host.insertAdjacentHTML("beforeend", \'<script src="https://cdn.example.com/x.js"></script>\');'
    });
    expect(find(injected, 'SEC-SCRIPT-INJECTION')?.label).toBe('Security blocker');
  });

  test('an external iframe asks for a reviewer because auth-flow iframes are allowed', async () => {
    const result = await review({ 'dist/index.html': '<iframe src="https://app.vendor.com/embed"></iframe>' });
    expect(find(result, 'IFRAME-EXTERNAL-SRC')?.label).toBe('Manual review');
    expect(result.summary.readiness).toBe('needs_review');
  });
});
