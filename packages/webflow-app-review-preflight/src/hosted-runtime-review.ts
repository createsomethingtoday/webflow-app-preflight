import {
  defaultConfig,
  defaultRuleset
} from '@create-something/bundle-scanner-core';
import type {
  BundleReview,
  CreateHostedRuntimeReviewInput
} from './types';

export class HostedRuntimeReviewInputError extends Error {}

export interface HostedRuntimeReviewArtifact {
  manifest: string;
  review: BundleReview;
}

function normalizedInput(input: CreateHostedRuntimeReviewInput): CreateHostedRuntimeReviewInput {
  const appName = typeof input.appName === 'string' ? input.appName.trim() : '';
  if (!appName || appName.length > 120) {
    throw new HostedRuntimeReviewInputError('App name must be between 1 and 120 characters.');
  }
  if (
    !Array.isArray(input.runtimeUrls) ||
    input.runtimeUrls.length === 0
  ) {
    throw new HostedRuntimeReviewInputError('Provide at least one hosted runtime URL.');
  }

  const seen = new Set<string>();
  const runtimeUrls = input.runtimeUrls.map((value, index) => {
    if (typeof value !== 'string' || value.length === 0 || value.length > 2048) {
      throw new HostedRuntimeReviewInputError(`Runtime URL ${index + 1} is missing or too long.`);
    }
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new HostedRuntimeReviewInputError(`Runtime URL ${index + 1} is invalid.`);
    }
    if (url.protocol !== 'https:' || url.username || url.password) {
      throw new HostedRuntimeReviewInputError(
        `Runtime URL ${index + 1} must be public HTTPS and must not contain credentials.`
      );
    }
    if (url.href.includes('{') || url.href.includes('}')) {
      throw new HostedRuntimeReviewInputError(
        `Runtime URL ${index + 1} must be the exact production URL, not a template.`
      );
    }
    url.hash = '';
    const normalized = url.toString();
    if (seen.has(normalized)) {
      throw new HostedRuntimeReviewInputError(`Runtime URL ${index + 1} is duplicated.`);
    }
    seen.add(normalized);
    return normalized;
  });

  return { appName, runtimeUrls };
}

function sha256Hex(value: string): Promise<string> {
  return crypto.subtle
    .digest('SHA-256', new TextEncoder().encode(value))
    .then((bytes) =>
      Array.from(new Uint8Array(bytes))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('')
    );
}

export async function createHostedRuntimeReviewArtifact(
  input: CreateHostedRuntimeReviewInput
): Promise<HostedRuntimeReviewArtifact> {
  const normalized = normalizedInput(input);
  const manifest = JSON.stringify({
    schemaVersion: 'hosted_runtime_manifest.v1',
    appType: 'data_client',
    appName: normalized.appName,
    runtimeUrls: normalized.runtimeUrls
  });
  const createdAt = new Date().toISOString();

  return {
    manifest,
    review: {
      schemaVersion: 'app_review_preflight.v1',
      reviewId: crypto.randomUUID(),
      createdAt,
      artifact: {
        kind: 'runtime_manifest',
        fileName: 'hosted-runtime-manifest.json',
        sha256: await sha256Hex(manifest),
        compressedBytes: new TextEncoder().encode(manifest).byteLength,
        fileCount: normalized.runtimeUrls.length
      },
      artifactScope: {
        primary: 'production_runtime',
        appType: 'data_client',
        appName: normalized.appName,
        manifestPath: null
      },
      coverage: [
        {
          surface: 'designer_extension',
          status: 'not_provided',
          label: 'Designer Extension not required',
          detail: 'This review starts from a hosted Data Client runtime.'
        },
        {
          surface: 'production_runtime',
          status: 'needs_verification',
          label: 'Production runtime not yet verified',
          detail: 'The hosted runtime is declared but has not been observed by Webflow.'
        }
      ],
      runtime: {
        references: normalized.runtimeUrls,
        status: 'discovered_unverified',
        manualVerificationRequired: true
      },
      summary: {
        readiness: 'ready',
        securityBlockers: 0,
        requiredUpdates: 0,
        suggestedUpdates: 0
      },
      guidance: [],
      policySnapshot: {
        rulesetVersion: defaultRuleset.rulesetVersion,
        configVersion: defaultConfig.configVersion
      },
      evidence: {
        scanReportVersion: 'hosted-runtime-manifest.v1',
        scanRunId: crypto.randomUUID()
      },
      officialDecision: null
    }
  };
}

export async function createHostedRuntimeReview(
  input: CreateHostedRuntimeReviewInput
): Promise<BundleReview> {
  return (await createHostedRuntimeReviewArtifact(input)).review;
}
