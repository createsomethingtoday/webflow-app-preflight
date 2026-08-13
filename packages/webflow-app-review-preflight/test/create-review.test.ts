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
