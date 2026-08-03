import { describe, expect, it } from 'vitest';
import JSZip from 'jszip';

import { processZipBuffer, isUnsafeEntryPath, normalizeEntryPath } from './zip';
import { defaultConfig } from '../policy/default-config';
import type { ScanConfig } from '../types';

const noop = () => {};

async function makeZip(
  files: Record<string, string>,
  options?: JSZip.JSZipGeneratorOptions<'arraybuffer'>
): Promise<ArrayBuffer> {
  const zip = new JSZip();
  for (const [path, content] of Object.entries(files)) {
    zip.file(path, content);
  }
  return zip.generateAsync({ type: 'arraybuffer', ...options });
}

function withZipSafety(overrides: Partial<ScanConfig['globalScanConfig']['zipSafety']>): ScanConfig {
  return {
    ...defaultConfig,
    globalScanConfig: {
      ...defaultConfig.globalScanConfig,
      zipSafety: { ...defaultConfig.globalScanConfig.zipSafety, ...overrides }
    }
  };
}

describe('processZipBuffer', () => {
  it('extracts safe files and normalizes path separators', async () => {
    const buffer = await makeZip({ 'src/app.js': 'ok', 'sub\\nested.js': 'ok' });
    const { files, skippedUnsafePaths } = await processZipBuffer(buffer, defaultConfig, noop);

    const paths = files.map((f) => f.path).sort();
    expect(paths).toEqual(['src/app.js', 'sub/nested.js']);
    expect(skippedUnsafePaths).toEqual([]);
  });

  it('skips __MACOSX system paths silently during extraction', async () => {
    const buffer = await makeZip({ 'good.js': 'ok', '__MACOSX/._app.js': 'junk' });
    const { files, skippedUnsafePaths } = await processZipBuffer(buffer, defaultConfig, noop);

    expect(files.map((f) => f.path)).toEqual(['good.js']);
    // macOS resource-fork junk is not reviewer-relevant, so it is not reported
    expect(skippedUnsafePaths).toEqual([]);
  });

  it('reports zip-slip traversal entries as skipped instead of extracting or logging them', async () => {
    // JSZip collapses `../` in forward-slash names when building a fixture,
    // but preserves backslash names verbatim; our normalization converts them
    // back to traversal paths, exercising the guard end to end.
    const buffer = await makeZip({ 'good.js': 'ok', 'dir\\..\\..\\evil.js': 'bad' });
    const { files, skippedUnsafePaths } = await processZipBuffer(buffer, defaultConfig, noop);

    expect(files.map((f) => f.path)).toEqual(['good.js']);
    expect(skippedUnsafePaths).toEqual(['dir/../../evil.js']);
  });

  it('extracts legitimate directory names that merely contain two dots', async () => {
    const buffer = await makeZip({ 'a..b/file.js': 'ok' });
    const { files, skippedUnsafePaths } = await processZipBuffer(buffer, defaultConfig, noop);

    expect(files.map((f) => f.path)).toEqual(['a..b/file.js']);
    expect(skippedUnsafePaths).toEqual([]);
  });

  it('throws when file count exceeds the limit', async () => {
    const buffer = await makeZip({ 'a.js': '1', 'b.js': '2', 'c.js': '3' });
    const config = withZipSafety({ maxFiles: 2 });

    await expect(processZipBuffer(buffer, config, noop)).rejects.toThrow(/too many files/i);
  });

  it('throws when total unzipped size exceeds the limit', async () => {
    const buffer = await makeZip({ 'big.js': 'x'.repeat(1000) });
    const config = withZipSafety({ maxTotalUnzippedBytes: 100 });

    await expect(processZipBuffer(buffer, config, noop)).rejects.toThrow(/exceeds limit/i);
  });

  it('rejects a single-entry decompression bomb from its declared size, before decompressing', async () => {
    // Highly compressible payload: large declared uncompressed size, tiny
    // compressed size. The per-entry check must fire on the DECLARED size
    // (the error cites it), proving the entry was never materialized.
    const uncompressedBytes = 5 * 1024 * 1024;
    const buffer = await makeZip(
      { 'bomb.js': 'x'.repeat(uncompressedBytes) },
      { compression: 'DEFLATE' }
    );
    expect(buffer.byteLength).toBeLessThan(uncompressedBytes / 100);

    const config = withZipSafety({
      maxTotalUnzippedBytes: 200 * 1024 * 1024,
      maxEntryUnzippedBytes: 1024 * 1024
    });

    await expect(processZipBuffer(buffer, config, noop)).rejects.toThrow(
      /per-entry unzipped size limit .* \(declared /i
    );
  });

  it('rejects a single entry whose declared size exceeds the remaining total budget, before decompressing', async () => {
    const buffer = await makeZip(
      { 'small.js': 'ok', 'bomb.js': 'x'.repeat(1024 * 1024) },
      { compression: 'DEFLATE' }
    );
    const config = withZipSafety({ maxTotalUnzippedBytes: 4096 });

    await expect(processZipBuffer(buffer, config, noop)).rejects.toThrow(
      /Total unzipped size exceeds limit/i
    );
  });

  it('wraps invalid ZIP input in a descriptive error', async () => {
    const notAZip = new TextEncoder().encode('this is not a zip file').buffer;
    await expect(processZipBuffer(notAZip, defaultConfig, noop)).rejects.toThrow(/Failed to process ZIP/i);
  });
});

describe('isUnsafeEntryPath', () => {
  it('flags zip-slip, absolute, and __MACOSX paths as unsafe', () => {
    expect(isUnsafeEntryPath('../evil.js')).toBe(true);
    expect(isUnsafeEntryPath('nested/../../evil.js')).toBe(true);
    expect(isUnsafeEntryPath('/etc/passwd')).toBe(true);
    expect(isUnsafeEntryPath('__MACOSX/._app.js')).toBe(true);
    expect(isUnsafeEntryPath('src/app.js')).toBe(false);
  });

  it('uses path segments, not substrings, for the traversal check', () => {
    expect(isUnsafeEntryPath('a..b/file.js')).toBe(false);
    expect(isUnsafeEntryPath('src/version..2/app.js')).toBe(false);
    expect(isUnsafeEntryPath('a..b/../file.js')).toBe(true);
  });
});

describe('normalizeEntryPath', () => {
  it('normalizes backslashes and strips leading slashes', () => {
    expect(normalizeEntryPath('sub\\nested\\file.js')).toBe('sub/nested/file.js');
    expect(normalizeEntryPath('/leading/slash.js')).toBe('leading/slash.js');
  });
});
