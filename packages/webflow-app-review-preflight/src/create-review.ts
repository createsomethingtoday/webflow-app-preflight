import {
  analyzeSourceMaps,
  buildInventory,
  defaultConfig,
  defaultRuleset,
  generateReport,
  processZipBuffer,
  runScan,
  type FileEntry,
  type FindingGroup,
  type ScanConfig,
  type Severity,
  type SourceMapSummary
} from '@create-something/bundle-scanner-core';
import { discoverRuntimeReferences } from './runtime-references';
import type {
  ArtifactSurface,
  BundleReview,
  CreateBundleReviewInput,
  ReviewGuidance
} from './types';

const PREFLIGHT_CONFIG: ScanConfig = {
  ...defaultConfig,
  globalScanConfig: {
    ...defaultConfig.globalScanConfig,
    zipSafety: {
      ...defaultConfig.globalScanConfig.zipSafety,
      maxTotalUnzippedBytes: 50 * 1024 * 1024,
      maxFiles: 2000
    },
    // App-bundle review deliberately narrows the shipped default exclusions.
    // The uploaded bundle IS the production artifact: minified output
    // (**/*.min.js), vendored code (**/vendor/**, **/third_party/**), and
    // built output (**/dist/**, **/build/**) execute on customer sites
    // exactly as uploaded, so excluding them would let a partner hide
    // blockers behind a filename ("if it is in your bundle, you own it").
    // Only paths that are never part of the shipped artifact stay excluded.
    hardExcludeGlobs: [
      '**/node_modules/**',
      '**/.git/**',
      '**/__MACOSX/**',
      '**/.DS_Store'
    ]
  }
};

/**
 * Extensions whose content can execute (or embed executable code) on a
 * customer site. Any such file the scanner did not decode is surfaced as a
 * manual-review input rather than silently passing.
 */
const EXECUTABLE_EXTENSIONS = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.jsx',
  '.tsx',
  '.html',
  '.wasm'
]);

const NEXT_MOVES: Record<string, string> = {
  'SEC-SCRIPT-INJECTION':
    'Package the reviewed runtime with the app, or use one immutable, reviewed runtime with a defined removal lifecycle.',
  'SEC-NO-DCE': 'Remove runtime code compilation and replace it with reviewed, bundled functions.',
  'SEC-NO-CLIENT-SECRETS': 'Remove the secret, rotate it, and keep privileged credentials on a server boundary.',
  'SEC-CODE-TRANSPARENCY': 'Provide reviewable source and matching source maps for every executable production file.'
};

const MAX_EVIDENCE_SNIPPET_LENGTH = 500;

export function boundedEvidenceSnippet(
  value: string,
  column: number,
  triggerToken: string
): string {
  if (value.length <= MAX_EVIDENCE_SNIPPET_LENGTH) return value;

  const columnIndex = Number.isFinite(column) && column > 0 ? column - 1 : -1;
  const triggerIndex = triggerToken ? value.indexOf(triggerToken) : -1;
  const focus = columnIndex >= 0 && columnIndex < value.length
    ? columnIndex
    : triggerIndex >= 0
      ? triggerIndex
      : 0;
  const contentLength = MAX_EVIDENCE_SNIPPET_LENGTH - 2;
  const start = Math.max(0, Math.min(value.length - contentLength, focus - 160));
  const end = Math.min(value.length, start + contentLength);

  return `${start > 0 ? '…' : ''}${value.slice(start, end)}${end < value.length ? '…' : ''}`;
}

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(bundle: ArrayBuffer): Promise<string> {
  return toHex(await crypto.subtle.digest('SHA-256', bundle));
}

function findManifest(inventory: FileEntry[]): {
  primary: ArtifactSurface;
  appName: string | null;
  manifestPath: string | null;
} {
  const manifest = inventory.find((file) => /(^|\/)webflow\.json$/i.test(file.path));
  if (!manifest?.content) {
    return { primary: 'unknown', appName: null, manifestPath: null };
  }

  try {
    const parsed = JSON.parse(manifest.content) as {
      name?: unknown;
      apiVersion?: unknown;
      publicDir?: unknown;
      designer?: unknown;
    };
    const isDesignerExtension =
      String(parsed.apiVersion ?? '') === '2' &&
      (typeof parsed.publicDir === 'string' || typeof parsed.designer === 'object');

    return {
      primary: isDesignerExtension ? 'designer_extension' : 'unknown',
      appName: typeof parsed.name === 'string' ? parsed.name : null,
      manifestPath: manifest.path
    };
  } catch {
    return { primary: 'unknown', appName: null, manifestPath: manifest.path };
  }
}

function guidanceLabel(severity: Severity): ReviewGuidance['label'] {
  if (severity === 'BLOCKER') return 'Security blocker';
  if (severity === 'HIGH' || severity === 'MEDIUM') return 'Required update';
  return 'Suggested update';
}

function compareGuidance(left: ReviewGuidance, right: ReviewGuidance): number {
  const order: Record<ReviewGuidance['label'], number> = {
    'Security blocker': 0,
    'Required update': 1,
    'Suggested update': 2
  };
  return order[left.label] - order[right.label] || left.title.localeCompare(right.title);
}

const SOURCE_MAP_GUIDANCE_EVIDENCE_LIMIT = 3;

/**
 * Statuses where minified/generated executable files cannot be traced back
 * to readable source. Mirrors the Marketplace reviewable-source standard:
 * a bundle whose executable output has no matching version-3 source map is
 * not sufficiently reviewable.
 */
const UNREVIEWABLE_SOURCE_MAP_STATUSES: ReadonlySet<SourceMapSummary['status']> = new Set([
  'missing',
  'partial',
  'mismatch',
  'invalid'
]);

function sourceMapGuidance(summary: SourceMapSummary): ReviewGuidance | null {
  if (!UNREVIEWABLE_SOURCE_MAP_STATUSES.has(summary.status)) return null;

  const explanationByStatus: Record<string, string> = {
    missing:
      'The bundle contains minified or generated executable files, but no source maps were provided for them. Without a matching source map, the code that ships to customers cannot be traced back to readable source.',
    partial:
      'Some minified or generated executable files have matching source maps, but others do not. Every executable production file must be traceable to readable source.',
    mismatch:
      'Source maps were provided, but none of them correspond to the generated executable files in this bundle. The maps must be produced by the exact build that produced the submitted bundle.',
    invalid:
      'The provided source map files could not be parsed as version-3 source maps, so the generated executable files cannot be traced back to readable source.'
  };

  const evidence =
    summary.status === 'invalid'
      ? summary.invalidSourceMaps
          .slice(0, SOURCE_MAP_GUIDANCE_EVIDENCE_LIMIT)
          .map((map) => ({ filePath: map.path, line: 1, snippet: map.error }))
      : summary.missingGeneratedFiles
          .slice(0, SOURCE_MAP_GUIDANCE_EVIDENCE_LIMIT)
          .map((path) => ({
            filePath: path,
            line: 1,
            snippet: 'No matching version-3 source map was found for this generated file.'
          }));

  return {
    id: 'SRC-MAP-CORRESPONDENCE',
    label: 'Required update',
    title: 'Generated code is not traceable to readable source',
    explanation: explanationByStatus[summary.status] ?? explanationByStatus.missing,
    nextMove:
      'Ship a complete version-3 source map for every minified or generated production file (adjacent .map file or sourceMappingURL), generated by the exact build that produced this bundle.',
    severity: 'HIGH',
    confidence: 'HIGH',
    evidence
  } satisfies ReviewGuidance;
}

function toGuidance(groups: Record<string, FindingGroup>): ReviewGuidance[] {
  return Object.values(groups)
    .map((group) => {
      const severity = group.items[0]?.severity ?? group.rule.severity;
      const confidence = group.items[0]?.confidence ?? 'MEDIUM';

      return {
        id: group.rule.ruleId,
        label: guidanceLabel(severity),
        title: group.rule.name,
        explanation: group.rule.description,
        nextMove:
          NEXT_MOVES[group.rule.ruleId] ??
          'Update the implementation, upload a revision, and use the next scan to confirm the finding is resolved.',
        severity,
        confidence,
        evidence: group.items.slice(0, 3).map((finding) => ({
          filePath: finding.filePath,
          line: finding.line,
          snippet: boundedEvidenceSnippet(
            finding.snippet,
            finding.col,
            finding.triggerToken
          )
        }))
      } satisfies ReviewGuidance;
    })
    .sort(compareGuidance);
}

export async function createBundleReview(
  input: CreateBundleReviewInput
): Promise<BundleReview> {
  const { files: unzipped, skippedUnsafePaths } = await processZipBuffer(
    input.bundle,
    PREFLIGHT_CONFIG,
    () => undefined
  );
  const inventory = buildInventory(unzipped, PREFLIGHT_CONFIG);
  const findings = runScan(inventory, defaultRuleset, PREFLIGHT_CONFIG, () => undefined);
  const scannedFileCount = inventory.filter(
    (file) => file.isTextCandidate && !file.isIgnored
  ).length;
  const skippedFileCount = inventory.length - scannedFileCount;
  // Executable-looking files whose content the scanner never decoded
  // (excluded paths, undecodable text, or binary formats like .wasm).
  // Zero findings in these files means "not scanned", never "clean".
  const skippedExecutablePaths = inventory
    .filter(
      (file) =>
        EXECUTABLE_EXTENSIONS.has(file.ext) && !(file.isTextCandidate && !file.isIgnored)
    )
    .map((file) => file.path)
    .sort();
  // Source maps travel inside the uploaded bundle (adjacent .map files).
  // Reconciling them against the generated executables is what makes a
  // minified bundle reviewable — served bytes must trace to readable source.
  const bundledSourceMaps = unzipped.filter((file) =>
    file.path.toLowerCase().endsWith('.map')
  );
  const sourceMapSummary = analyzeSourceMaps(
    inventory,
    bundledSourceMaps.length > 0 ? bundledSourceMaps : undefined
  );
  const report = generateReport(findings, defaultRuleset, PREFLIGHT_CONFIG, {
    fileCount: inventory.length,
    totalBytes: inventory.reduce((total, file) => total + file.sizeBytes, 0),
    textFilesScanned: scannedFileCount,
    skippedFileCount,
    sourceMapSummary
  });
  const artifactScope = findManifest(inventory);
  const runtimeReferences = discoverRuntimeReferences(inventory);
  const sourceMapFinding = sourceMapGuidance(sourceMapSummary);
  const guidance = [...toGuidance(report.findings), ...(sourceMapFinding ? [sourceMapFinding] : [])]
    .sort(compareGuidance);
  const securityBlockers = guidance.filter((item) => item.label === 'Security blocker').length;
  const requiredUpdates = guidance.filter((item) => item.label === 'Required update').length;
  const suggestedUpdates = guidance.filter((item) => item.label === 'Suggested update').length;

  return {
    schemaVersion: 'app_review_preflight.v1',
    reviewId: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    artifact: {
      fileName: input.fileName,
      sha256: await sha256(input.bundle),
      compressedBytes: input.bundle.byteLength,
      fileCount: inventory.length
    },
    artifactScope,
    coverage: [
      {
        surface: 'designer_extension',
        status: artifactScope.primary === 'designer_extension' ? 'reviewed' : 'not_provided',
        label:
          artifactScope.primary === 'designer_extension'
            ? 'Designer Extension reviewed'
            : 'Designer Extension not identified',
        detail:
          artifactScope.primary === 'designer_extension'
            ? 'The uploaded configuration interface was included in this review.'
            : 'A Webflow Designer Extension manifest was not identified in this bundle.'
      },
      {
        surface: 'production_runtime',
        status: 'needs_verification',
        label: 'Production runtime not yet verified',
        detail:
          runtimeReferences.length > 0
            ? 'Runtime references were discovered, but their executed behavior is outside this bundle review.'
            : 'No complete production runtime artifact was included in this review.'
      }
    ],
    runtime: {
      references: runtimeReferences,
      status: runtimeReferences.length > 0 ? 'discovered_unverified' : 'not_discovered',
      manualVerificationRequired: true
    },
    summary: {
      readiness:
        securityBlockers > 0 || requiredUpdates > 0 ? 'changes_required' : 'ready',
      securityBlockers,
      requiredUpdates,
      suggestedUpdates
    },
    guidance,
    policySnapshot: {
      rulesetVersion: defaultRuleset.rulesetVersion,
      configVersion: PREFLIGHT_CONFIG.configVersion
    },
    evidence: {
      scanReportVersion: report.scanReportVersion,
      scanRunId: report.runId
    },
    scanCoverage: {
      fileCount: inventory.length,
      scannedFileCount,
      skippedFileCount,
      skippedExecutablePaths,
      unsafeEntryPaths: [...skippedUnsafePaths].sort(),
      manualReviewRequired:
        skippedExecutablePaths.length > 0 || skippedUnsafePaths.length > 0
    },
    sourceMapSummary,
    officialDecision: null
  };
}
