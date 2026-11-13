import type { FileEntry } from '@create-something/bundle-scanner-core';

const ABSOLUTE_URL_PATTERN = /https:\/\/[^\s"'`<>\\)]+/g;
const RUNTIME_PATH_PATTERN = /\/v\d+\/cdn\/runtime(?:\/[^\s"'`<>\\)]*)?\.js/g;
const RUNTIME_URL_HINT = /(?:\/runtime(?:\/|\.|$)|\/loader(?:\/|\.|$)|\/cdn\/[^/?#]+\.js)/i;
const API_ORIGIN_HINT = /\b(?:api|cdn)\./i;
const NON_PRODUCTION_HOST_HINT = /(?:^|\.)(?:example|example\.com|localhost)(?:\.|$)|mywebsite/i;

function cleanUrl(value: string): string | null {
  try {
    const url = new URL(value.replace(/[},;]+$/, ''));
    if (url.protocol !== 'https:') return null;
    return url.toString();
  } catch {
    return null;
  }
}

export function discoverRuntimeReferences(inventory: FileEntry[]): string[] {
  const absoluteUrls = new Set<string>();
  const runtimePaths = new Set<string>();

  for (const file of inventory) {
    if (!file.content) continue;

    for (const match of file.content.matchAll(ABSOLUTE_URL_PATTERN)) {
      const normalized = cleanUrl(match[0]);
      if (normalized) absoluteUrls.add(normalized);
    }

    for (const match of file.content.matchAll(RUNTIME_PATH_PATTERN)) {
      runtimePaths.add(match[0]);
    }
  }

  const references = new Set<string>();
  const candidateOrigins = new Set<string>();

  for (const value of absoluteUrls) {
    const url = new URL(value);
    if (
      url.pathname === '/' &&
      API_ORIGIN_HINT.test(url.hostname) &&
      !NON_PRODUCTION_HOST_HINT.test(url.hostname)
    ) {
      candidateOrigins.add(url.origin);
    }
    if (RUNTIME_URL_HINT.test(url.pathname)) references.add(value);
  }

  for (const path of runtimePaths) {
    const normalizedPath = path.replace(/\$\{[^}]+\}/g, '{id}');
    for (const origin of candidateOrigins) {
      references.add(`${origin}${normalizedPath}`);
    }
  }

  return [...references].sort();
}

export type RuntimeUrlMutability = 'versioned' | 'content_hashed' | 'mutable';

/** Developer-facing advisory shown beside every mutable runtime URL. */
export const MUTABLE_RUNTIME_URL_GUIDANCE =
  'This runtime URL has no version or content hash. The served bytes can change after review. Publish each release at a new versioned URL.';

// A semantic version (major.minor.patch, optional "v") set off by a path or
// name delimiter: /v1.2.3/, /1.4.0/, pkg@1.2.3, name-1.2.3.js, name.1.2.3.min.js.
// A bare major ("/v1/", "@1") or a range ("@1.2", "latest") does not match.
const SEMVER_IN_SEGMENT = /(?<![0-9A-Za-z])v?\d{1,4}\.\d{1,4}\.\d{1,4}(?!\d)/;
const HEX_DIGEST = /^[0-9a-f]{8,}$/i;
const BASE36_DIGEST = /^[0-9a-z]{8,}$/;

function looksLikeDigest(part: string): boolean {
  if (part.length < 8 || part.length > 128) return false;
  const hasDigit = /\d/.test(part);
  const hasLetter = /[a-z]/i.test(part);
  // Hex digests: both digits and letters, so a long word or a bare number
  // (a date, a build counter) is not mistaken for a digest.
  if (HEX_DIGEST.test(part)) return hasDigit && hasLetter;
  if (!BASE36_DIGEST.test(part) || !hasDigit || !hasLetter) return false;
  // Base36 digests flip between letters and digits constantly; words with a
  // number inside ("es2015bundle") flip only a few times.
  let flips = 0;
  for (let index = 1; index < part.length; index += 1) {
    if (/\d/.test(part[index - 1] as string) !== /\d/.test(part[index] as string)) flips += 1;
  }
  return flips >= 4;
}

/**
 * Classifies whether a runtime script URL pins the served bytes by name.
 * `content_hashed`: the file name or a path segment carries a digest of at
 * least 8 hex or base36 characters. `versioned`: a semantic version segment or
 * suffix. Everything else, including bare major aliases, `@latest` and query
 * string versions (`?v=3`), is `mutable`: the owner can replace the bytes at
 * the same URL after review. A content hash wins over a version when both are
 * present. The check is advisory and looks at the URL only.
 */
export function classifyRuntimeUrlMutability(value: string): RuntimeUrlMutability {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'mutable';
  }
  let segments: string[];
  try {
    segments = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
  } catch {
    segments = url.pathname.split('/').filter(Boolean);
  }
  if (
    segments.some((segment) =>
      segment.split(/[.\-_~@]/).some((part) => looksLikeDigest(part))
    )
  ) {
    return 'content_hashed';
  }
  if (segments.some((segment) => SEMVER_IN_SEGMENT.test(segment))) return 'versioned';
  return 'mutable';
}

/** The declared runtime URLs that are neither versioned nor content-hashed. */
export function mutableRuntimeUrls(urls: readonly string[]): string[] {
  return urls.filter((url) => classifyRuntimeUrlMutability(url) === 'mutable');
}
