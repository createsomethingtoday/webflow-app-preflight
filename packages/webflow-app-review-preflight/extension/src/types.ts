import type {
  BundleReview,
  CreateHostedRuntimeReviewInput,
  RuntimeTestPackageInput,
  RuntimeTestPackageView
} from '@create-something/webflow-app-review-preflight';

export type { RuntimeTestPackageInput, RuntimeTestPackageView };
export type { CreateHostedRuntimeReviewInput };

export interface ReviewVersion {
  id: string;
  sequence: number;
  createdAt: string;
  result: BundleReview;
}

export interface InstallUrlFinding {
  rule: string;
  severity: 'block' | 'warn' | 'info';
  message: string;
}

export interface InstallUrlProbe {
  verdict: 'pass' | 'warn' | 'block';
  code: string;
  reason: string;
  hops: { url: string; status: number | null; error?: string }[];
  finalUrl: string | null;
  finalStatus: number | null;
  durationMs: number;
}

export interface InstallUrlCheckResult {
  installUrl: string | null;
  requiresInstallUrl: boolean;
  verdict: 'pass' | 'warn' | 'block';
  findings: InstallUrlFinding[];
  probe: InstallUrlProbe | null;
}

export interface InstallUrlCheck {
  id: string;
  reviewVersionId: string;
  actorRole: 'developer' | 'reviewer';
  installUrl: string;
  clientId: string | null;
  capabilities: string[];
  configuredScopes: string[] | null;
  createdAt: string;
  result: InstallUrlCheckResult;
}

export interface InstallUrlCheckInput {
  installUrl: string;
  clientId?: string;
  capabilities?: string[];
}

export interface StoredReview {
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  latestVersion: ReviewVersion;
  installUrlCheck?: InstallUrlCheck | null;
}

export interface ReviewSummary {
  id: string;
  name: string;
  updatedAt: string;
  latestSequence: number;
  readiness: BundleReview['summary']['readiness'];
  appName: string | null;
  reviewType?: 'bundle' | 'runtime_manifest';
  coverage: BundleReview['coverage'];
}

export interface ReviewComparison {
  resolved: string[];
  remaining: string[];
  added: string[];
}

export interface SubmissionReceipt {
  code: string;
  createdAt: string;
}

export interface CreatedReview {
  review: StoredReview;
  submissionReceipt: SubmissionReceipt;
}

export interface RevisionResult {
  review: StoredReview;
  comparison: ReviewComparison;
  deduplicated: boolean;
  submissionReceipt: SubmissionReceipt;
}

export interface PreflightIdentity {
  id: string;
  siteId: string | null;
  companionRole: 'developer' | 'reviewer';
}

export interface ReviewerHandoff {
  url: string;
  expiresAt: string;
}

export interface PreflightApi {
  getIdentity(): Promise<PreflightIdentity>;
  listReviews(): Promise<ReviewSummary[]>;
  getReview(id: string): Promise<StoredReview>;
  createReview(
    file: File,
    options?: { name?: string; sourceMaps?: File }
  ): Promise<CreatedReview>;
  createRuntimeReview(input: CreateHostedRuntimeReviewInput): Promise<CreatedReview>;
  addRevision(reviewId: string, file: File, sourceMaps?: File): Promise<RevisionResult>;
  reissueSubmissionReceipt(reviewId: string): Promise<SubmissionReceipt>;
  checkInstallUrl(reviewId: string, input: InstallUrlCheckInput): Promise<InstallUrlCheck>;
  listRuntimeTestPackages(reviewId: string): Promise<RuntimeTestPackageView[]>;
  createRuntimeTestPackage(
    reviewId: string,
    input: RuntimeTestPackageInput
  ): Promise<RuntimeTestPackageView>;
  requestRuntimeObservationRun(testPackageId: string): Promise<RuntimeTestPackageView['observation']>;
  createReviewerHandoff(
    reviewId: string,
    reviewVersionId: string,
    runtimeTestPackageId: string
  ): Promise<ReviewerHandoff>;
}
