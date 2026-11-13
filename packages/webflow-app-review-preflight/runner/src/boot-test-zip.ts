import { inflateRawSync } from 'node:zlib';

/**
 * A small, bounded ZIP reader for the boot test. The sandbox bundle carries
 * only Playwright, so the runner reads the archive with node:zlib instead of
 * a bundled ZIP library. It accepts stored and deflated entries, rejects
 * ZIP64, encrypted entries, and anything outside the size budget, and skips
 * unsafe paths the same way the static scanner does.
 */

export interface BundleZipLimits {
  maxFiles: number;
  maxTotalBytes: number;
}

export const BUNDLE_ZIP_LIMITS: BundleZipLimits = {
  maxFiles: 2_000,
  maxTotalBytes: 50 * 1024 * 1024
};

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;

function normalizeEntryPath(raw: string): string {
  return raw.replace(/\\/g, '/').replace(/^\/+/, '');
}

function isUnsafeEntryPath(path: string): boolean {
  const segments = path.split('/');
  return segments.includes('..') || segments.includes('__MACOSX') || path.includes('\0');
}

export function readBundleZip(
  bytes: Uint8Array,
  limits: BundleZipLimits = BUNDLE_ZIP_LIMITS
): Map<string, Uint8Array> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const minEnd = Math.max(0, bytes.byteLength - 22 - 0xffff);
  let eocd = -1;
  for (let offset = bytes.byteLength - 22; offset >= minEnd; offset -= 1) {
    if (view.getUint32(offset, true) === EOCD_SIGNATURE) {
      eocd = offset;
      break;
    }
  }
  if (eocd < 0) throw new Error('The bundle is not a ZIP archive.');

  const entryCount = view.getUint16(eocd + 10, true);
  const directorySize = view.getUint32(eocd + 12, true);
  const directoryOffset = view.getUint32(eocd + 16, true);
  if (entryCount === 0xffff || directoryOffset === 0xffffffff || directorySize === 0xffffffff) {
    throw new Error('ZIP64 bundles are not supported by the boot test.');
  }
  if (entryCount > limits.maxFiles) throw new Error('The bundle has too many files.');
  if (directoryOffset + directorySize > eocd) throw new Error('The ZIP directory is invalid.');

  const files = new Map<string, Uint8Array>();
  const decoder = new TextDecoder();
  let totalBytes = 0;
  let cursor = directoryOffset;
  for (let index = 0; index < entryCount; index += 1) {
    if (cursor + 46 > eocd || view.getUint32(cursor, true) !== CENTRAL_SIGNATURE) {
      throw new Error('The ZIP directory is invalid.');
    }
    const flags = view.getUint16(cursor + 8, true);
    const method = view.getUint16(cursor + 10, true);
    const compressedSize = view.getUint32(cursor + 20, true);
    const uncompressedSize = view.getUint32(cursor + 24, true);
    const nameLength = view.getUint16(cursor + 28, true);
    const extraLength = view.getUint16(cursor + 30, true);
    const commentLength = view.getUint16(cursor + 32, true);
    const localOffset = view.getUint32(cursor + 42, true);
    const rawName = decoder.decode(bytes.subarray(cursor + 46, cursor + 46 + nameLength));
    cursor += 46 + nameLength + extraLength + commentLength;

    if (rawName.endsWith('/')) continue;
    const path = normalizeEntryPath(rawName);
    if (!path || isUnsafeEntryPath(path) || files.has(path)) continue;
    if (flags & 0x1) throw new Error('Encrypted ZIP entries are not supported.');
    if (uncompressedSize > limits.maxTotalBytes - totalBytes) {
      throw new Error('The bundle exceeds the uncompressed size limit.');
    }

    if (localOffset + 30 > bytes.byteLength || view.getUint32(localOffset, true) !== LOCAL_SIGNATURE) {
      throw new Error('A ZIP entry header is invalid.');
    }
    const dataStart =
      localOffset + 30 + view.getUint16(localOffset + 26, true) + view.getUint16(localOffset + 28, true);
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > bytes.byteLength) throw new Error('A ZIP entry is truncated.');
    const data = bytes.subarray(dataStart, dataEnd);

    let content: Uint8Array;
    if (method === 0) {
      content = data;
    } else if (method === 8) {
      try {
        content = inflateRawSync(data, { maxOutputLength: Math.max(1, uncompressedSize) });
      } catch {
        throw new Error('A ZIP entry could not be decompressed within its declared size.');
      }
    } else {
      throw new Error('A ZIP entry uses an unsupported compression method.');
    }
    if (content.byteLength !== uncompressedSize) {
      throw new Error('A ZIP entry does not match its declared size.');
    }
    totalBytes += content.byteLength;
    files.set(path, content);
  }
  return files;
}

/**
 * The directory Webflow would serve as the extension root: the one that
 * holds the shallowest `index.html`. Returns the files re-keyed relative to
 * that directory, or null when the bundle has no `index.html`.
 */
export function extensionSiteRoot(
  files: Map<string, Uint8Array>
): { root: string; files: Map<string, Uint8Array> } | null {
  const candidates = [...files.keys()]
    .filter((path) => path === 'index.html' || path.endsWith('/index.html'))
    .sort((left, right) => left.split('/').length - right.split('/').length || left.localeCompare(right));
  const entry = candidates[0];
  if (!entry) return null;
  const root = entry.slice(0, entry.length - 'index.html'.length);
  const served = new Map<string, Uint8Array>();
  for (const [path, content] of files) {
    if (path.startsWith(root)) served.set(path.slice(root.length), content);
  }
  return { root, files: served };
}
