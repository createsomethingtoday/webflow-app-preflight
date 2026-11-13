/**
 * Designer Extension boot test: load the uploaded bundle's `index.html` in a
 * server-owned headless Chromium, under the extension host's Content
 * Security Policy, and report whether the panel would open blank.
 *
 * The result is advisory evidence. It never changes `readiness`, a static
 * finding, or a runtime-observation security status, and it is never an
 * official decision.
 */

/**
 * The `content-security-policy` response header that Webflow's Designer
 * Extension host sent for a live extension page. Captured 2026-11-13 with one
 * read-only HEAD request. The host sent no other CSP header. A bundle can
 * still add its own policy with a `<meta http-equiv="Content-Security-Policy">`
 * tag; Chromium enforces both, and the boot test reports violations of both.
 *
 * Operators can replace this value without a runner rebuild: the Worker reads
 * `BOOT_TEST_CSP` and writes the policy into each job contract.
 */
export const DESIGNER_EXTENSION_HOST_CSP =
  'frame-ancestors https://*.design.webflow.com https://webflow.com';

export type BootTestStatus = 'passed' | 'failed' | 'error';

export type BootTestFailure =
  | 'blank_panel'
  | 'bundled_script_blocked_by_csp'
  | 'bundled_file_missing';

export const BOOT_TEST_FAILURES: readonly BootTestFailure[] = [
  'blank_panel',
  'bundled_script_blocked_by_csp',
  'bundled_file_missing'
];

/** Caps on every list in a boot test result, and on each error message. */
export const BOOT_TEST_LIMITS = {
  cspViolations: 20,
  missingFiles: 20,
  uncaughtErrors: 10,
  externalHosts: 20,
  messageLength: 300
} as const;

export interface BootTestCspViolation {
  /** The effective directive Chromium reports, for example `script-src-elem`. */
  directive: string;
  /**
   * `inline`, `eval`, `trusted-types`, the host of a blocked external URL, or
   * the bundle-relative path of a blocked same-origin file. Never a full URL.
   */
  blocked: string;
  /** Bundle-relative path of the file that caused the violation, or `document`. */
  source: string;
}

export interface BootTestResult {
  /** `error` means the test itself could not run; it says nothing about the bundle. */
  status: BootTestStatus;
  failures: BootTestFailure[];
  cspViolations: BootTestCspViolation[];
  /** Bundle-relative paths the page requested that are not in the ZIP. */
  missingFiles: string[];
  /** Informational: uncaught error messages, redacted and truncated. */
  uncaughtErrors: string[];
  /** Informational: hosts the page tried to reach. The test blocks all of them. */
  externalHostsRequested: string[];
  renderedTextLength: number;
  renderedElementCount: number;
}

export interface BootTestJobContract {
  schemaVersion: 'designer_extension_boot_test_job.v1';
  purpose: 'designer_extension_boot_test';
  bootTestJobId: string;
  reviewId: string;
  reviewVersionId: string;
  bundleSha256: string;
  bundleBytes: number;
  nonce: string;
  /** The policy the local static server sends with every response. */
  contentSecurityPolicy: string;
  controls: {
    /** The browser may reach only the sandbox-local static server. */
    networkMode: 'local_static_server_only';
    viewport: { width: number; height: number };
    /** At most 15 seconds. */
    navigationTimeoutMs: number;
    /** How long the panel may render after `load`; at most 3 seconds. */
    settleMs: number;
    /** At most 60 seconds, including the bundle download. */
    totalTimeoutMs: number;
    evidenceTrust: 'webflow_observed';
  };
  limits: typeof BOOT_TEST_LIMITS;
  boundaries: {
    advisoryOnly: true;
    affectsReadiness: false;
    officialDecision: null;
    canWriteGovernance: false;
    acceptsAccountCredentials: false;
  };
  expiresAt: string;
}

/** What the runner uploads. The Worker re-validates every field. */
export interface BootTestEvidence {
  schemaVersion: 'designer_extension_boot_test_evidence.v1';
  bootTestJobId: string;
  reviewVersionId: string;
  bundleSha256: string;
  nonce: string;
  trust: 'webflow_observed';
  startedAt: string;
  finishedAt: string;
  bootTest: BootTestResult;
}

export interface BootTestSummary {
  id: string;
  reviewVersionId: string;
  status: 'approved' | 'running' | 'complete' | 'failed' | 'expired';
  trust: 'webflow_observed' | null;
  advisory: true;
  approvedAt: string;
  expiresAt: string;
  completedAt: string | null;
  bootTest: BootTestResult | null;
}
