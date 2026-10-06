import {
  analyzeSourceMaps,
  buildInventory,
  defaultConfig,
  defaultRuleset,
  generateReport,
  processZipBuffer,
  runScan,
  type FileEntry,
  type Finding,
  type FindingGroup,
  type ScanConfig,
  type ScanRule,
  type Severity,
  type SourceMapSummary,
  type UnzippedFile
} from '@create-something/bundle-scanner-core';
import { discoverRuntimeReferences } from './runtime-references';
import type {
  ArtifactSurface,
  BundleReview,
  CreateBundleReviewInput,
  ReviewGuidance,
  ReviewGuidanceLabel
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
  'SEC-CODE-TRANSPARENCY': 'Provide reviewable source and matching source maps for every executable production file.',
  'SEC-NO-TOKEN-IN-URL':
    'Move the credential out of the URL: send it in an Authorization header or a protected request body, and change any GET route that carries it to POST.',
  'PROD-NO-DEBUG-RESIDUE':
    'Remove the debug routes and bypass flags from the production build, rebuild the exact artifact you will ship, and rescan.',
  'UX-NO-MUTATION-ON-LOAD':
    'Tie site-mutating Designer API calls to a deliberate user action (a button, not extension mount). If they already are, say so in your review notes so the reviewer can verify quickly.',
  'API-ELEMENT-TYPE-DISCRIMINATOR':
    "Replace the element.type comparison with a tag check: (await element.getTag()) === 'section'. It returns the same value for preset-created and hand-added sections, so the app keeps working when the type label differs. A Div Block retagged to section also passes this check — add a guard if your app removes or rewrites what it identifies."
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

const PACKAGE_MANIFEST_NAMES = new Set(['package.json']);
const LOCKFILE_NAMES = new Set([
  'pnpm-lock.yaml',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'bun.lockb',
  'bun.lock'
]);

/** The uploaded review artifact cannot be used as review input. */
export class SourceMapArtifactError extends Error {}

const README_PATTERN = /^readme(\.(md|txt|markdown))?$/;
const SOURCE_FILE_PATTERN = /\.(js|mjs|cjs|jsx|ts|tsx|html|css|vue|svelte)$/;
const REVIEW_FILE_MATCH_EVIDENCE_LIMIT = 3;

export type ReviewArtifactShape = 'source-maps' | 'unchanged-source';

interface ReviewArtifact {
  shape: ReviewArtifactShape;
  /** Version-3 maps (empty for the unchanged-source shape). */
  maps: UnzippedFile[];
  /** Source files as shipped (empty for the source-maps shape). */
  sourceFiles: UnzippedFile[];
}

const REVIEW_ZIP_SHAPES_MESSAGE =
  'Upload one .zip in one of two shapes: the source maps, package.json, and lockfile from the build that produced this bundle; or, for an app that ships its source unchanged, the source files plus a short README explaining how the bundle is packaged.';

/**
 * Expand the privately uploaded review artifact. It is one `.zip` — the same
 * ZIP the submission form requires (developers.webflow.com
 * submitting-your-app → Submission artifacts) — in one of two shapes:
 *
 * - source maps: the version-3 maps, package.json, and lockfile from the
 *   build that produced the bundle;
 * - unchanged source: for apps with no build or transform step, the source
 *   files exactly as they ship plus a short README on how the bundle is
 *   packaged (package.json and lockfile only when the app uses them).
 *
 * An incomplete artifact is an input error, not a silent "missing": the
 * developer believes they supplied it, so tell them why the upload did not
 * count. Missing maps for a generated bundle are not an "unchanged source"
 * case; analyzeSourceMaps still reports those as missing.
 */
async function extractReviewArtifact(artifact: {
  fileName: string;
  bytes: ArrayBuffer;
}): Promise<ReviewArtifact> {
  const lowerName = artifact.fileName.toLowerCase();
  if (artifact.bytes.byteLength === 0) {
    throw new SourceMapArtifactError('The review ZIP upload is empty.');
  }
  if (!lowerName.endsWith('.zip')) {
    throw new SourceMapArtifactError(REVIEW_ZIP_SHAPES_MESSAGE);
  }
  let entries: UnzippedFile[];
  try {
    ({ files: entries } = await processZipBuffer(
      artifact.bytes,
      PREFLIGHT_CONFIG,
      () => undefined
    ));
  } catch {
    throw new SourceMapArtifactError(
      'We could not read the review ZIP. Re-export the archive and try again.'
    );
  }
  const base = (file: UnzippedFile) => file.path.split('/').pop()?.toLowerCase() ?? '';
  const maps = entries.filter((file) => base(file).endsWith('.map'));
  const baseNames = new Set(entries.map(base));
  const hasManifest = [...PACKAGE_MANIFEST_NAMES].some((name) => baseNames.has(name));
  const hasLockfile = [...LOCKFILE_NAMES].some((name) => baseNames.has(name));

  if (maps.length > 0) {
    const missing = [
      ...(hasManifest ? [] : ['package.json']),
      ...(hasLockfile ? [] : ['a lockfile'])
    ];
    if (missing.length > 0) {
      throw new SourceMapArtifactError(
        `The review ZIP has source maps but is missing ${missing.join(' and ')}. Include them from the exact build that produced this bundle.`
      );
    }
    return { shape: 'source-maps', maps, sourceFiles: [] };
  }

  const sourceFiles = entries.filter((file) => SOURCE_FILE_PATTERN.test(base(file)));
  const hasReadme = [...baseNames].some((name) => README_PATTERN.test(name));
  if (sourceFiles.length > 0 && hasReadme) {
    return { shape: 'unchanged-source', maps: [], sourceFiles };
  }
  if (sourceFiles.length > 0) {
    throw new SourceMapArtifactError(
      'The review ZIP has no source maps and no README. If your app ships its source unchanged, add a short README that explains how the bundle is packaged. Otherwise include the .map files, package.json, and lockfile from the build that produced the bundle.'
    );
  }
  throw new SourceMapArtifactError(`The review ZIP has no source maps. ${REVIEW_ZIP_SHAPES_MESSAGE}`);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let index = 0; index < a.byteLength; index += 1) {
    if (a[index] !== b[index]) return false;
  }
  return true;
}

/**
 * For the unchanged-source shape, the review files must be the bytes that
 * ship: every executable in the bundle needs a byte-identical file of the
 * same name in the review ZIP. A bundle whose code differs from the supplied
 * source is not reviewable from that source (the review team verifies the
 * review files match what ships).
 */
export function reviewFileMatchGuidance(
  bundleFiles: ReadonlyArray<UnzippedFile>,
  artifact: ReviewArtifact | null
): ReviewGuidance | null {
  if (!artifact || artifact.shape !== 'unchanged-source') return null;
  const base = (path: string) => path.split('/').pop()?.toLowerCase() ?? '';
  const executables = bundleFiles.filter((file) => {
    const name = base(file.path);
    const dot = name.lastIndexOf('.');
    return dot >= 0 && EXECUTABLE_EXTENSIONS.has(name.slice(dot)) && !name.endsWith('.wasm');
  });
  const unmatched = executables.filter(
    (file) =>
      !artifact.sourceFiles.some(
        (candidate) => base(candidate.path) === base(file.path) && bytesEqual(candidate.data, file.data)
      )
  );
  if (executables.length === 0 || unmatched.length === 0) return null;

  return {
    id: 'SRC-REVIEW-FILES-MISMATCH',
    label: 'Required update',
    title: 'Review ZIP source does not match the shipped bundle',
    explanation: `The review ZIP was submitted as unchanged source, but ${unmatched.length} of ${executables.length} executable file${executables.length === 1 ? '' : 's'} in the bundle ${unmatched.length === 1 ? 'has' : 'have'} no byte-identical file of the same name in the ZIP. Unchanged source means the files in the ZIP are exactly the files that ship.`,
    nextMove:
      'If the bundle is built or transformed from this source, submit the source maps, package.json, and lockfile from that build instead. If it really ships unchanged, re-create the review ZIP from the same files that went into the bundle.',
    severity: 'HIGH',
    confidence: 'HIGH',
    evidence: unmatched.slice(0, REVIEW_FILE_MATCH_EVIDENCE_LIMIT).map((file) => ({
      filePath: file.path,
      line: 1,
      snippet: 'No byte-identical file with this name in the review ZIP.'
    }))
  } satisfies ReviewGuidance;
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

function guidanceLabel(severity: Severity): ReviewGuidanceLabel {
  if (severity === 'BLOCKER') return 'Security blocker';
  if (severity === 'HIGH' || severity === 'MEDIUM') return 'Required update';
  return 'Suggested update';
}

const SEVERITY_RANK: Record<Severity, number> = {
  BLOCKER: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

const CONFIDENCE_RANK: Record<ReviewGuidance['confidence'], number> = {
  HIGH: 2,
  MEDIUM: 1,
  LOW: 0
};

/**
 * The severity one match contributes to its rule's finding. A finding-level
 * override (comment downgrade, contextual escalation) wins over the rule
 * default, and an AUTO_REJECT review bucket is a blocker whatever the
 * severity field says — the scanner's own verdict treats it that way, and
 * the developer label must not disagree with it.
 */
export function effectiveFindingSeverity(finding: Finding, rule: ScanRule): Severity {
  const severity = finding.severity ?? rule.severity;
  const reviewBucket = finding.reviewBucket ?? rule.reviewBucket;
  return reviewBucket === 'AUTO_REJECT' ? 'BLOCKER' : severity;
}

/**
 * A rule's finding takes the MOST severe match, not the first one. Matches
 * arrive in file order, so a downgraded match (a commented-out `eval`) can
 * precede a live one; taking `items[0]` let the comment mask the real call
 * and report readiness `ready`. Confidence follows the match that set the
 * severity (highest confidence among the top-severity matches), and the
 * items come back ordered so evidence shows the strongest matches first.
 */
export function guidanceSeverity(group: FindingGroup): {
  severity: Severity;
  confidence: ReviewGuidance['confidence'];
  items: Finding[];
} {
  const ranked = group.items
    .map((finding, index) => ({
      finding,
      index,
      severity: effectiveFindingSeverity(finding, group.rule)
    }))
    .sort(
      (left, right) =>
        SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity] ||
        CONFIDENCE_RANK[right.finding.confidence] - CONFIDENCE_RANK[left.finding.confidence] ||
        left.index - right.index
    );
  const top = ranked[0];
  return {
    severity: top?.severity ?? group.rule.severity,
    confidence: top?.finding.confidence ?? 'MEDIUM',
    items: ranked.map((entry) => entry.finding)
  };
}

function compareGuidance(left: ReviewGuidance, right: ReviewGuidance): number {
  const order: Record<ReviewGuidanceLabel, number> = {
    'Security blocker': 0,
    'Required update': 1,
    'Manual review': 2,
    'Suggested update': 3
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
      'Provide a complete version-3 source map for every minified or generated production file, generated by the exact build that produced this bundle. Upload the maps as the private source-map artifact next to the bundle (the same upload the submission form asks for) rather than shipping them inside the public bundle.',
    severity: 'HIGH',
    confidence: 'HIGH',
    evidence
  } satisfies ReviewGuidance;
}

const COVERAGE_GUIDANCE_EVIDENCE_LIMIT = 3;

/**
 * Source maps inside the public bundle ship readable source to every visitor
 * of a customer site. The submission form takes them as a separate private
 * upload (developers.webflow.com/apps/docs/marketplace/submitting-your-app),
 * so their presence in the artifact is a Required update, independent of
 * whether they correspond to the generated files. Inline `data:` maps embed
 * the source directly and count the same way.
 */
export function sourceMapExposureGuidance(summary: SourceMapSummary): ReviewGuidance | null {
  const inlineReferences = summary.sourceMappingUrlReferences.filter((ref) => ref.inline);
  const exposedCount = summary.exposedSourceMapFiles.length + inlineReferences.length;
  if (exposedCount === 0) return null;

  const evidence = [
    ...summary.exposedSourceMapFiles.map((path) => ({
      filePath: path,
      line: 1,
      snippet: 'Source map file shipped inside the public bundle.'
    })),
    ...inlineReferences.map((ref) => ({
      filePath: ref.filePath,
      line: 1,
      snippet: 'Inline (data:) source map embedded in a public executable file.'
    }))
  ].slice(0, COVERAGE_GUIDANCE_EVIDENCE_LIMIT);

  return {
    id: 'SRC-MAP-PUBLIC-EXPOSURE',
    label: 'Required update',
    title: 'Source maps are shipped inside the public bundle',
    explanation: `This bundle ships ${exposedCount} source map${exposedCount === 1 ? '' : 's'} in the public artifact. Source maps expose readable source to anyone who loads the extension. The Marketplace submission form takes source maps as a separate private upload; they must not be part of the bundle that ships to customers.`,
    nextMove:
      'Remove the .map files (and any inline data: maps) from the public bundle, rebuild, and upload the maps as the private source-map artifact next to this bundle and on the submission form.',
    severity: 'HIGH',
    confidence: 'HIGH',
    evidence
  } satisfies ReviewGuidance;
}

/**
 * Executable-looking files the scanner never decoded produced zero findings
 * by construction. Surfacing them as a Manual review finding keeps the run
 * from reading as a pass; readiness becomes `needs_review`.
 */
export function unscannedExecutableGuidance(paths: readonly string[]): ReviewGuidance | null {
  if (paths.length === 0) return null;
  return {
    id: 'SCAN-UNSCANNED-EXECUTABLE',
    label: 'Manual review',
    title: 'Executable files were not scanned',
    explanation: `${paths.length} executable-looking file${paths.length === 1 ? ' was' : 's were'} not scanned: binary formats such as .wasm, undecodable text, or excluded directories such as node_modules. Zero findings in these files means "not evaluated", not "clean". A reviewer has to inspect them by hand.`,
    nextMove:
      'Ship only the built output the extension needs (drop node_modules and other unshipped directories from the zip). For binary executables such as WebAssembly, include the readable source that produced them in your review notes so the reviewer can verify them.',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    evidence: paths.slice(0, COVERAGE_GUIDANCE_EVIDENCE_LIMIT).map((path) => ({
      filePath: path,
      line: 1,
      snippet: 'Not scanned: content was not decoded by the rule engine.'
    }))
  } satisfies ReviewGuidance;
}

/**
 * Entries rejected by the zip safety guard (absolute paths, `..` traversal)
 * were never extracted, so nothing in them was scanned. The archive itself
 * has to be rebuilt.
 */
export function unsafeEntryGuidance(paths: readonly string[]): ReviewGuidance | null {
  if (paths.length === 0) return null;
  return {
    id: 'BUNDLE-UNSAFE-ENTRY',
    label: 'Required update',
    title: 'Archive contains unsafe entry paths',
    explanation: `${paths.length} zip entr${paths.length === 1 ? 'y uses' : 'ies use'} an absolute path or directory traversal (..). Such entries were not extracted or scanned, and the Workspace upload will not accept them either.`,
    nextMove:
      'Rebuild the zip from inside the built output directory so every entry has a relative path within the archive, then rescan.',
    severity: 'HIGH',
    confidence: 'HIGH',
    evidence: paths.slice(0, COVERAGE_GUIDANCE_EVIDENCE_LIMIT).map((path) => ({
      filePath: path,
      line: 1,
      snippet: 'Rejected by the zip safety guard; not extracted.'
    }))
  } satisfies ReviewGuidance;
}

/**
 * The app manifest is part of the reviewed surface: an app that identifies
 * itself as a development or staging build is production residue (Marketplace
 * submission artifacts), independent of anything the code does.
 */
// Deliberately excludes "test": legitimate app names carry it (A/B test
// tooling), while "dev"/"staging"/"sandbox" in a marketplace app name reliably
// mean the wrong artifact was packaged.
const DEV_IDENTITY_PATTERN = /\b(dev|development|staging|stage|sandbox)\b/i;

function manifestIdentityGuidance(scope: {
  appName: string | null;
  manifestPath: string | null;
}): ReviewGuidance | null {
  if (!scope.appName || !scope.manifestPath) return null;
  if (!DEV_IDENTITY_PATTERN.test(scope.appName)) return null;

  return {
    id: 'PROD-DEV-IDENTITY',
    label: 'Required update',
    title: 'App manifest carries a development identity',
    explanation: `The app name in the manifest ("${scope.appName}") reads as a development or staging build. Production submissions must ship under the production identity — a dev-named bundle is the clearest sign the wrong artifact was packaged.`,
    nextMove:
      'Set the production app name in the manifest, rebuild the exact artifact you will submit, and rescan.',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    evidence: [
      {
        filePath: scope.manifestPath,
        line: 1,
        snippet: `"name": "${scope.appName}"`
      }
    ]
  } satisfies ReviewGuidance;
}


/**
 * Webflow rejects Designer Extension uploads over 5MB
 * (developers.webflow.com/apps/docs/publishing-your-app). Catch it here so
 * the developer learns before the Workspace upload fails.
 */
const MAX_DESIGNER_EXTENSION_BUNDLE_BYTES = 5 * 1024 * 1024;

export function bundleSizeGuidance(compressedBytes: number): ReviewGuidance | null {
  if (compressedBytes <= MAX_DESIGNER_EXTENSION_BUNDLE_BYTES) return null;
  const megabytes = (compressedBytes / (1024 * 1024)).toFixed(1);
  return {
    id: 'BUNDLE-SIZE-LIMIT',
    label: 'Required update',
    title: 'Bundle is over the 5MB upload limit',
    explanation: `This bundle is ${megabytes}MB. Webflow does not accept Designer Extension bundles larger than 5MB.`,
    nextMove:
      'Remove unused assets and dependencies, keep source maps out of the public bundle, and rebuild with webflow extension bundle.',
    severity: 'HIGH',
    confidence: 'HIGH',
    evidence: []
  } satisfies ReviewGuidance;
}

/**
 * The package manifest and lockfile travel in the private review ZIP, not
 * the bundle (Submission artifacts docs). A provided ZIP is validated in
 * extractReviewArtifact, so this only nudges when no ZIP was attached.
 * Absence is a suggestion, not a gate — the submission form is the
 * enforcement point.
 */
function manifestPresenceGuidance(
  inventory: ReadonlyArray<{ ext: string }>,
  sourceMapArtifactProvided: boolean
): ReviewGuidance | null {
  if (sourceMapArtifactProvided) return null;
  if (!inventory.some((file) => EXECUTABLE_EXTENSIONS.has(file.ext))) return null;

  return {
    id: 'PROD-PACKAGE-MANIFEST',
    label: 'Suggested update',
    title: 'Attach the review ZIP (source maps, package.json, lockfile)',
    explanation:
      'This bundle contains executables, but no review ZIP was attached. The submission form requires one ZIP with the source maps, package.json, and lockfile from the exact build that produced the bundle (or, for an app that ships its source unchanged, the source files plus a short README), so review can reconcile the artifact with its dependencies.',
    nextMove:
      'Run Preflight again with that ZIP attached, and upload the same ZIP in the submission form\'s Source map artifact field. Keep these files out of the production bundle.',
    severity: 'LOW',
    confidence: 'HIGH',
    evidence: []
  } satisfies ReviewGuidance;
}

function toGuidance(groups: Record<string, FindingGroup>): ReviewGuidance[] {
  return Object.values(groups)
    .map((group) => {
      const { severity, confidence, items } = guidanceSeverity(group);

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
        evidence: items.slice(0, 3).map((finding) => ({
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
  // Source maps arrive two ways: inside the uploaded bundle (adjacent .map
  // files) and as a private artifact uploaded next to it — the same one the
  // developer attaches to the official submission form. Reconciling them
  // against the generated executables is what makes a minified bundle
  // reviewable — served bytes must trace to readable source.
  const bundledSourceMaps = unzipped.filter((file) =>
    file.path.toLowerCase().endsWith('.map')
  );
  const reviewArtifact = input.sourceMapArtifact
    ? await extractReviewArtifact(input.sourceMapArtifact)
    : null;
  const externalSourceMaps = reviewArtifact?.maps ?? [];
  const sourceMapFiles = [...bundledSourceMaps, ...externalSourceMaps];
  const sourceMapSummary = analyzeSourceMaps(
    inventory,
    sourceMapFiles.length > 0 ? sourceMapFiles : undefined
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
  const unsafeEntryPaths = [...skippedUnsafePaths].sort();
  const guidance = [
    ...toGuidance(report.findings),
    sourceMapGuidance(sourceMapSummary),
    sourceMapExposureGuidance(sourceMapSummary),
    reviewFileMatchGuidance(unzipped, reviewArtifact),
    manifestIdentityGuidance(artifactScope),
    manifestPresenceGuidance(inventory, Boolean(input.sourceMapArtifact)),
    bundleSizeGuidance(input.bundle.byteLength),
    unscannedExecutableGuidance(skippedExecutablePaths),
    unsafeEntryGuidance(unsafeEntryPaths)
  ]
    .filter((item): item is ReviewGuidance => item !== null)
    .sort(compareGuidance);
  const countLabel = (label: ReviewGuidanceLabel) =>
    guidance.filter((item) => item.label === label).length;
  const securityBlockers = countLabel('Security blocker');
  const requiredUpdates = countLabel('Required update');
  const suggestedUpdates = countLabel('Suggested update');
  const manualReviews = countLabel('Manual review');

  return {
    schemaVersion: 'app_review_preflight.v1',
    reviewId: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    artifact: {
      fileName: input.fileName,
      sha256: await sha256(input.bundle),
      compressedBytes: input.bundle.byteLength,
      fileCount: inventory.length,
      ...(input.sourceMapArtifact
        ? {
            sourceMaps: {
              fileName: input.sourceMapArtifact.fileName,
              sha256: await sha256(input.sourceMapArtifact.bytes),
              mapFileCount: externalSourceMaps.length,
              shape: reviewArtifact?.shape ?? 'source-maps',
              sourceFileCount: reviewArtifact?.sourceFiles.length ?? 0
            }
          }
        : {})
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
        securityBlockers > 0 || requiredUpdates > 0
          ? 'changes_required'
          : manualReviews > 0
            ? 'needs_review'
            : 'ready',
      securityBlockers,
      requiredUpdates,
      suggestedUpdates,
      manualReviews
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
      unsafeEntryPaths,
      manualReviewRequired:
        skippedExecutablePaths.length > 0 || unsafeEntryPaths.length > 0
    },
    sourceMapSummary,
    officialDecision: null
  };
}
