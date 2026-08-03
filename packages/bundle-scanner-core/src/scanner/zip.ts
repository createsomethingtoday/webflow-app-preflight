import JSZip from 'jszip';
import type { ScanConfig, UnzippedFile, ProgressCallback } from '../types';

/**
 * Normalize a raw ZIP entry name to a POSIX-style relative path:
 * convert backslashes to forward slashes and strip leading slashes.
 */
export function normalizeEntryPath(rawFilename: string): string {
  return rawFilename.replace(/\\/g, '/').replace(/^\/+/, '');
}

/**
 * Determine whether a normalized entry path is unsafe to extract.
 * Guards against zip-slip traversal (a `..` path segment), absolute paths,
 * and macOS resource-fork (`__MACOSX`) metadata directories.
 *
 * The traversal check is segment-based so legitimate names that merely
 * contain two dots (e.g. `a..b/file.js`) are not rejected.
 */
export function isUnsafeEntryPath(normalizedPath: string): boolean {
  if (normalizedPath.startsWith('/')) return true;

  const segments = normalizedPath.split('/');
  return segments.includes('..') || segments.includes('__MACOSX');
}

/** macOS resource-fork metadata; skipped silently as OS junk, not reported. */
function isMacResourceForkPath(normalizedPath: string): boolean {
  return normalizedPath.split('/').includes('__MACOSX');
}

/**
 * Read the uncompressed size declared in the ZIP entry's metadata without
 * decompressing the entry. JSZip exposes it on the entry's internal
 * `_data.uncompressedSize`; returns null if the field is absent or malformed
 * so callers can fall back to post-decompression checks.
 */
function getDeclaredUncompressedSize(entry: JSZip.JSZipObject): number | null {
  const data = (entry as unknown as { _data?: { uncompressedSize?: unknown } })._data;
  const size = data?.uncompressedSize;
  return typeof size === 'number' && Number.isFinite(size) && size >= 0 ? size : null;
}

function formatMB(bytes: number): string {
  return (bytes / 1024 / 1024).toFixed(1);
}

/**
 * Result of ZIP extraction.
 *
 * `skippedUnsafePaths` lists entries rejected by the unsafe-path guard
 * (zip-slip traversal, absolute paths). They are surfaced so reviewers can
 * see exactly what was not extracted instead of it disappearing into logs.
 * macOS `__MACOSX` resource-fork junk is skipped silently.
 */
export interface ZipExtractionResult {
  files: UnzippedFile[];
  skippedUnsafePaths: string[];
}

/**
 * Process a ZIP file and extract its contents with safety checks
 *
 * @param file - The ZIP file to process
 * @param config - Scanner configuration with safety limits
 * @param onProgress - Progress callback
 * @returns Extracted files plus any entry paths skipped as unsafe
 * @throws Error if ZIP is invalid or exceeds safety limits
 */
export async function processZipFile(
  file: File | Blob | ArrayBuffer | Uint8Array,
  config: ScanConfig,
  onProgress: ProgressCallback
): Promise<ZipExtractionResult> {
  onProgress('Reading ZIP file...');
  const zip = new JSZip();

  try {
    const loadedZip = await zip.loadAsync(file);
    const files: UnzippedFile[] = [];
    const skippedUnsafePaths: string[] = [];
    let totalBytes = 0;

    const { maxTotalUnzippedBytes, maxFiles } = config.globalScanConfig.zipSafety;
    // Per-entry decompression cap. A single crafted entry can expand ~1000:1,
    // so each entry must be bounded BEFORE it is materialized in memory;
    // otherwise a small compressed payload can exhaust the runtime (e.g. a
    // 128MB Worker isolate) before the cumulative total check ever runs.
    const maxEntryUnzippedBytes =
      config.globalScanConfig.zipSafety.maxEntryUnzippedBytes ?? maxTotalUnzippedBytes;

    const entries = Object.keys(loadedZip.files);

    // Safety Check: Max Files
    if (entries.length > maxFiles) {
      throw new Error(
        `ZIP contains too many files (${entries.length}). ` +
        `Limit: ${maxFiles}`
      );
    }

    onProgress(`Unpacking ${entries.length} files...`);

    for (const rawFilename of entries) {
      const entry = loadedZip.files[rawFilename];
      if (!entry) continue;

      // Skip directories
      if (entry.dir) continue;

      // Normalize to a POSIX-style relative path.
      const normalizedPath = normalizeEntryPath(rawFilename);

      // Zip Slip Protection & Basic Traversal Check.
      // Skipped paths are returned to the caller (report-visible), not logged:
      // partner file paths must not leak into shared Worker logs.
      if (isUnsafeEntryPath(normalizedPath)) {
        if (!isMacResourceForkPath(normalizedPath)) {
          skippedUnsafePaths.push(normalizedPath);
        }
        continue;
      }

      // Safety Check (pre-decompression): validate the DECLARED uncompressed
      // size against the per-entry cap and the remaining total budget before
      // allocating anything. This blocks single-entry decompression bombs.
      const remainingBudget = maxTotalUnzippedBytes - totalBytes;
      const declaredSize = getDeclaredUncompressedSize(entry);
      if (declaredSize !== null) {
        if (declaredSize > maxEntryUnzippedBytes) {
          throw new Error(
            `Entry exceeds per-entry unzipped size limit of ${formatMB(maxEntryUnzippedBytes)}MB ` +
            `(declared ${formatMB(declaredSize)}MB)`
          );
        }
        if (declaredSize > remainingBudget) {
          throw new Error(
            `Total unzipped size exceeds limit of ${formatMB(maxTotalUnzippedBytes)}MB`
          );
        }
      }

      // Decompress
      const content = await entry.async('uint8array');

      // Safety Check (post-decompression): re-validate against the actual
      // bytes in case the ZIP metadata under-declared the entry size.
      if (content.length > maxEntryUnzippedBytes) {
        throw new Error(
          `Entry exceeds per-entry unzipped size limit of ${formatMB(maxEntryUnzippedBytes)}MB`
        );
      }

      totalBytes += content.length;

      // Safety Check: Max Total Bytes
      if (totalBytes > maxTotalUnzippedBytes) {
        throw new Error(`Total unzipped size exceeds limit of ${formatMB(maxTotalUnzippedBytes)}MB`);
      }

      files.push({
        path: normalizedPath,
        data: content
      });
    }

    return { files, skippedUnsafePaths };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    throw new Error(`Failed to process ZIP: ${message}`);
  }
}

/**
 * Process a ZIP file from a buffer (for Node.js / Cloudflare Workers usage).
 *
 * Loads the ArrayBuffer directly rather than wrapping it in a Blob. JSZip reads
 * Blobs via FileReader, which is unavailable in Node and on the Workers runtime;
 * ArrayBuffer input is supported everywhere.
 */
export async function processZipBuffer(
  buffer: ArrayBuffer,
  config: ScanConfig,
  onProgress: ProgressCallback
): Promise<ZipExtractionResult> {
  return processZipFile(buffer, config, onProgress);
}
