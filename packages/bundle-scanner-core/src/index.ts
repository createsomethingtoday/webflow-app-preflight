/**
 * @create-something/bundle-scanner-core
 *
 * Core scanning engine for Webflow Marketplace bundle analysis.
 * Provides deterministic rule-based scanning for security, privacy,
 * network, and UX policy compliance.
 */

// Scanner functions
export { processZipFile, processZipBuffer } from './scanner/zip';
export type { ZipExtractionResult } from './scanner/zip';
export { buildInventory } from './scanner/inventory';
export { runScan } from './scanner/scan';
export { generateReport } from './scanner/report';
export type { ReportSummaryInput } from './scanner/report';
export { analyzeSourceMaps } from './scanner/source-map';

// Policy
export { defaultRuleset } from './policy/default-ruleset';
export { defaultConfig } from './policy/default-config';

// Utilities
export { matchesAnyGlob, shouldExclude, getExtension } from './utils/glob';

// NOTE: the former analytics (correlation/priority/routing), AI, and email
// modules were removed from this package. They were never used by the review
// preflight path, and the routing module embedded reviewer personnel data
// that must not ship inside a library bundled into the review Worker.

// All types
export type {
  // Verdict & Severity
  Verdict,
  Severity,
  ReviewBucket,
  Disposition,
  Confidence,
  LocationType,

  // Configuration
  ScanConfig,

  // Ruleset
  Ruleset,
  ScanRule,
  RuleMatcher,
  ConditionalOverride,

  // File handling
  FileEntry,
  UnzippedFile,

  // Findings
  Finding,
  FindingGroup,

  // Reports
  ScanReport,
  BundleSummary,
  SourceMapArtifactStatus,
  SourceMapReference,
  SourceMapSummary,
  ScanHistoryEntry,

  // Callbacks
  ProgressCallback
} from './types';
