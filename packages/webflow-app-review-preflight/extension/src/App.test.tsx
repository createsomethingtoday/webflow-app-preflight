import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { App } from './App';
import { PreflightAuthenticationError } from './api';
import type { PreflightApi, StoredReview, SubmissionReceipt } from './types';

afterEach(() => {
  cleanup();
  localStorage.clear();
});

const api: PreflightApi = {
  getIdentity: async () => ({
    id: 'local-webflow-user',
    siteId: 'local-webflow-site',
    companionRole: 'developer'
  }),
  listReviews: async () => [],
  getReview: async () => Promise.reject(new Error('not used')),
  createReview: async () => Promise.reject(new Error('not used')),
  createRuntimeReview: async () => Promise.reject(new Error('not used')),
  addRevision: async () => Promise.reject(new Error('not used')),
  reissueSubmissionReceipt: async () => Promise.reject(new Error('not used')),
  listRuntimeTestPackages: async () => [],
  createRuntimeTestPackage: async () => Promise.reject(new Error('not used')),
  requestRuntimeObservationRun: async () => Promise.reject(new Error('not used')),
  createReviewerHandoff: async () => Promise.reject(new Error('not used'))
};

function sampleSubmissionReceipt(): SubmissionReceipt {
  return {
    code: `wfpre_${'a'.repeat(32)}`,
    createdAt: '2026-07-15T23:00:00.000Z'
  };
}

function websiteSpeedyRuntimeReview(): StoredReview {
  const review = consentProReview();
  review.id = 'review-website-speedy';
  review.name = 'Website Speedy runtime review';
  review.latestVersion.id = 'version-website-speedy-runtime';
  review.latestVersion.result.reviewId = review.id;
  review.latestVersion.result.artifact = {
    kind: 'runtime_manifest',
    fileName: 'hosted-runtime-manifest.json',
    sha256: 'c'.repeat(64),
    compressedBytes: 512,
    fileCount: 3
  };
  review.latestVersion.result.artifactScope = {
    primary: 'production_runtime',
    appType: 'data_client',
    appName: 'Website Speedy',
    manifestPath: null
  };
  review.latestVersion.result.coverage = [
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
  ];
  review.latestVersion.result.runtime = {
    references: [
      'https://webflow-websitespeedy13.b-cdn.net/speedyscripts/ecmrx_1234/ecmrx_1234_1.js',
      'https://webflow-websitespeedy13.b-cdn.net/speedyscripts/ecmrx_1234/ecmrx_1234_2.js',
      'https://webflow-websitespeedy13.b-cdn.net/speedyscripts/ecmrx_1234/ecmrx_1234_3.js'
    ],
    status: 'discovered_unverified',
    manualVerificationRequired: true
  };
  review.latestVersion.result.summary = {
    readiness: 'ready',
    securityBlockers: 0,
    requiredUpdates: 0,
    suggestedUpdates: 0
  };
  review.latestVersion.result.guidance = [];
  return review;
}

function sriFromHex(value: string): string {
  const bytes = value.match(/.{2}/g)!.map((pair) => String.fromCharCode(Number.parseInt(pair, 16)));
  return `sha256-${btoa(bytes.join(''))}`;
}

function consentProReview(sequence = 1): StoredReview {
  const createdAt = '2026-07-14T22:00:00.000Z';
  return {
    id: 'review-consent-pro',
    name: 'Consent Pro preflight',
    createdAt,
    updatedAt: createdAt,
    latestVersion: {
      id: `version-${sequence}`,
      sequence,
      createdAt,
      result: {
        schemaVersion: 'app_review_preflight.v1',
        reviewId: 'review-consent-pro',
        createdAt,
        artifact: {
          fileName: 'consent-pro.zip',
          sha256: 'abc123',
          compressedBytes: 2048,
          fileCount: 4
        },
        artifactScope: {
          primary: 'designer_extension',
          appName: 'Consent Pro by Finsweet',
          manifestPath: 'webflow.json'
        },
        coverage: [
          {
            surface: 'designer_extension',
            status: 'reviewed',
            label: 'Designer Extension reviewed',
            detail: 'The uploaded Designer Extension bundle was scanned.'
          },
          {
            surface: 'production_runtime',
            status: 'needs_verification',
            label: 'Production runtime not yet verified',
            detail: 'Runtime references were discovered, but the production code has not run.'
          }
        ],
        runtime: {
          references: ['https://api.consentpro.com/v2/cdn/runtime.js'],
          status: 'discovered_unverified',
          manualVerificationRequired: true
        },
        summary: {
          readiness: 'changes_required',
          securityBlockers: 1,
          requiredUpdates: 1,
          suggestedUpdates: 0
        },
        guidance: [
          {
            id: 'SEC-SCRIPT-INJECTION',
            label: 'Security blocker',
            title: 'Runtime-created scripts',
            explanation: 'The runtime creates a script element and loads code dynamically.',
            nextMove: 'Bundle the reviewed runtime code and use the approved lifecycle.',
            severity: 'BLOCKER',
            confidence: 'HIGH',
            evidence: [
              {
                filePath: 'assets/index.js',
                line: 20,
                snippet: 'document.createElement("script")'
              }
            ]
          },
          {
            id: 'SEC-MUTABLE-DELIVERY',
            label: 'Required update',
            title: 'Mutable runtime delivery',
            explanation: 'The referenced runtime can change after review.',
            nextMove: 'Publish an immutable, versioned runtime artifact.',
            severity: 'HIGH',
            confidence: 'HIGH',
            evidence: [
              {
                filePath: 'assets/index.js',
                line: 8,
                snippet: '/v2/cdn/runtime.js'
              }
            ]
          }
        ],
        policySnapshot: {
          rulesetVersion: '1.3.0-checklist-complete',
          configVersion: '1.0.0'
        },
        evidence: {
          scanReportVersion: '1',
          scanRunId: 'scan-1'
        },
        officialDecision: null
      }
    }
  };
}

describe('App Review Preflight extension', () => {
  test('starts a Data Client production-runtime review without requiring a bundle', async () => {
    const created = websiteSpeedyRuntimeReview();
    const createRuntimeReview = vi.fn(async () => ({
      review: created,
      submissionReceipt: sampleSubmissionReceipt()
    }));
    const runtimeApi: PreflightApi = {
      ...api,
      createRuntimeReview
    };

    render(<App api={runtimeApi} />);

    fireEvent.click(await screen.findByRole('button', { name: 'Enter script URLs' }));
    expect(screen.getByText(/Add every JavaScript URL that runs in the same test/i)).toBeVisible();
    expect(screen.getByLabelText('App name')).toHaveAttribute('placeholder', 'Your app name');
    fireEvent.change(screen.getByLabelText('App name'), {
      target: { value: 'Website Speedy' }
    });
    fireEvent.change(screen.getByLabelText('Hosted runtime URLs'), {
      target: {
        value: created.latestVersion.result.runtime.references.join('\n')
      }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    await waitFor(() => expect(createRuntimeReview).toHaveBeenCalledWith({
      appName: 'Website Speedy',
      runtimeUrls: created.latestVersion.result.runtime.references
    }));
    expect(await screen.findByRole('heading', { name: 'Website Speedy' })).toBeVisible();
    expect(screen.getByText('Script list saved. Set up a Webflow test to observe the published runtime.')).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Test the published runtime' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Runtime review' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Versioned runtime URL')).toHaveValue(
      created.latestVersion.result.runtime.references[0]
    );
    expect(screen.getByLabelText('Versioned runtime URL — file 2')).toHaveValue(
      created.latestVersion.result.runtime.references[1]
    );
    expect(screen.getByLabelText('Versioned runtime URL — file 3')).toHaveValue(
      created.latestVersion.result.runtime.references[2]
    );
    expect(screen.queryByText('Upload a revised bundle')).not.toBeInTheDocument();
  });

  test('shows a plain connected-site status without exposing the identity ID', async () => {
    render(<App api={api} />);

    expect(await screen.findByText('Connected to this Webflow site')).toBeVisible();
    expect(screen.queryByText('local-webflow-user')).not.toBeInTheDocument();
    expect(screen.queryByText('Developer identity')).not.toBeInTheDocument();
  });

  test('labels every saved run with its next review state', async () => {
    const runtimeReview = websiteSpeedyRuntimeReview();
    const changesReview = consentProReview();
    const readyReview = consentProReview();
    readyReview.id = 'review-ready';
    readyReview.name = 'Ready app preflight';
    readyReview.latestVersion.result.summary.readiness = 'ready';
    readyReview.latestVersion.result.coverage = readyReview.latestVersion.result.coverage.map(
      (item) => ({ ...item, status: 'reviewed' as const })
    );
    const historyApi: PreflightApi = {
      ...api,
      listReviews: async () => [runtimeReview, changesReview, readyReview].map((review) => ({
        id: review.id,
        name: review.name,
        updatedAt: review.updatedAt,
        latestSequence: review.latestVersion.sequence,
        readiness: review.latestVersion.result.summary.readiness,
        reviewType: review.latestVersion.result.artifact.kind === 'runtime_manifest'
          ? 'runtime_manifest' as const
          : 'bundle' as const,
        appName: review.latestVersion.result.artifactScope.appName,
        coverage: review.latestVersion.result.coverage
      }))
    };

    render(<App api={historyApi} />);

    expect(await screen.findByText('Runtime test needed')).toBeVisible();
    expect(screen.getByText('Changes needed')).toBeVisible();
    expect(screen.getByText('Ready for review')).toBeVisible();
  });

  test('starts with two clear paths based on what the app ships', async () => {
    render(<App api={api} />);

    expect(await screen.findByRole('heading', { name: 'Start a preflight' })).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Upload your app bundle' })).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Review production scripts' })).toBeVisible();
    expect(
      screen.queryByRole('heading', { name: 'App Review Preflight' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText('Clear fixes before Marketplace review')
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Choose what the app ships/i)).toBeVisible();
    expect(screen.getByText('Choose bundle')).toBeVisible();
    expect(screen.getByText('Choose source maps (.zip or .map)')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Run preflight' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Enter script URLs' })).toBeVisible();
    expect(screen.queryByText('Share')).not.toBeInTheDocument();
  });

  test('turns an uploaded bundle into plain-language, scope-aware feedback', async () => {
    const created = consentProReview();
    const receipt = sampleSubmissionReceipt();
    const uploadApi: PreflightApi = {
      ...api,
      listReviews: async () => [],
      createReview: vi.fn(async () => ({ review: created, submissionReceipt: receipt }))
    };
    const { container } = render(<App api={uploadApi} />);
    const file = new File(['zip-bytes'], 'consent-pro.zip', { type: 'application/zip' });
    const maps = new File(['map-bytes'], 'consent-pro-maps.zip', { type: 'application/zip' });

    const [bundleInput, sourceMapInput] = container.querySelectorAll('input[type="file"]');
    fireEvent.change(bundleInput!, { target: { files: [file] } });
    fireEvent.change(sourceMapInput!, { target: { files: [maps] } });
    fireEvent.click(screen.getByRole('button', { name: 'Run preflight' }));

    expect(await screen.findByRole('heading', { name: 'Consent Pro by Finsweet' })).toBeVisible();
    expect(screen.getByText('Designer Extension reviewed')).toBeVisible();
    expect(screen.getByText('Production runtime not yet verified')).toBeVisible();
    expect(screen.getByText('Saved')).toBeVisible();
    expect(screen.getByText('Security blockers')).toBeVisible();
    expect(screen.getByText('Runtime-created scripts')).toBeVisible();
    expect(screen.getByText('Upload a revised bundle')).toBeVisible();
    expect(screen.getByText(receipt.code)).toBeVisible();
    expect(screen.queryByText('Share')).not.toBeInTheDocument();
    expect(uploadApi.createReview).toHaveBeenCalledWith(file, { sourceMaps: maps });
  });

  test('gives reviewers a one-time handoff into the server-owned workspace', async () => {
    const review = consentProReview();
    const testPackage = {
      schemaVersion: 'runtime_test_package.v1' as const,
      id: 'reviewer-package-1',
      reviewId: review.id,
      reviewVersionId: review.latestVersion.id,
      bundleSha256: review.latestVersion.result.artifact.sha256,
      status: 'ready' as const,
      trust: 'partner_supplied' as const,
      target: {
        url: 'https://app-review-sandbox.webflow.io/',
        host: 'app-review-sandbox.webflow.io'
      },
      sandboxInstallationId: 'webflow-sandbox-site-123',
      license: {
        mode: 'installation_allowlist' as const,
        expiresAt: '2026-07-16T00:00:00.000Z'
      },
      runtimeArtifacts: [{
        url: 'https://api.consentpro.com/v2/cdn/runtime-v1.js',
        sha256: 'a'.repeat(64),
        integrity: 'sha256-runtime-v1'
      }],
      negativeProxyProbe: {
        method: 'GET' as const,
        urlTemplate: 'https://api.consentpro.com/v2/proxy?url={canaryUrl}'
      },
      lifecycle: { readySelector: '[data-runtime-ready]' },
      evidence: null,
      createdAt: '2026-07-15T23:00:00.000Z',
      observation: null
    };
    const createReviewerHandoff = vi.fn(async () => ({
      url: 'https://preflight.test/reviewer/connect?code=one-time-code',
      expiresAt: '2026-07-15T23:05:00.000Z'
    }));
    const reviewerApi: PreflightApi = {
      ...api,
      getIdentity: async () => ({
        id: 'local-webflow-reviewer',
        siteId: 'local-review-site',
        companionRole: 'reviewer'
      }),
      listReviews: async () => [{
        id: review.id,
        name: review.name,
        updatedAt: review.updatedAt,
        latestSequence: 1,
        readiness: 'changes_required',
        appName: 'Consent Pro by Finsweet',
        coverage: review.latestVersion.result.coverage
      }],
      getReview: async () => review,
      listRuntimeTestPackages: async () => [testPackage],
      createReviewerHandoff
    };

    render(<App api={reviewerApi} />);
    fireEvent.click(await screen.findByRole('button', { name: /Consent Pro preflight/i }));
    fireEvent.click(await screen.findByRole('button', { name: 'Create reviewer workspace' }));

    expect(createReviewerHandoff).toHaveBeenCalledWith(
      review.id,
      review.latestVersion.id,
      testPackage.id
    );
    const link = await screen.findByRole('link', { name: 'Open reviewer workspace' });
    expect(link).toHaveAttribute('href', 'https://preflight.test/reviewer/connect?code=one-time-code');
    expect(link).toHaveAttribute('target', '_blank');
  });

  test('shows revision progress and keeps the review usable after an upload error', async () => {
    const initial = consentProReview();
    const revised = consentProReview(2);
    revised.latestVersion.result.summary.securityBlockers = 0;
    revised.latestVersion.result.guidance = revised.latestVersion.result.guidance.slice(1);

    const addRevision = vi
      .fn<PreflightApi['addRevision']>()
      .mockRejectedValueOnce(new Error('The bundle could not be read.'))
      .mockResolvedValueOnce({
        review: revised,
        comparison: {
          resolved: ['SEC-SCRIPT-INJECTION'],
          remaining: ['SEC-MUTABLE-DELIVERY'],
          added: []
        },
        deduplicated: false,
        submissionReceipt: sampleSubmissionReceipt()
      });
    const revisionApi: PreflightApi = {
      ...api,
      listReviews: async () => [
        {
          id: initial.id,
          name: initial.name,
          updatedAt: initial.updatedAt,
          latestSequence: 1,
          readiness: 'changes_required',
          appName: 'Consent Pro by Finsweet',
          coverage: initial.latestVersion.result.coverage
        }
      ],
      getReview: async () => initial,
      addRevision
    };
    const { container } = render(<App api={revisionApi} />);

    fireEvent.click(await screen.findByRole('button', { name: /Consent Pro preflight/i }));
    expect(await screen.findByText('Upload a revised bundle')).toBeVisible();

    const revisionInput = container.querySelector('input[type="file"]')!;
    fireEvent.change(revisionInput, {
      target: { files: [new File(['bad'], 'broken.zip', { type: 'application/zip' })] }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Run preflight again' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The bundle could not be read.');
    expect(screen.getByText('Upload a revised bundle')).toBeVisible();

    fireEvent.change(revisionInput, {
      target: { files: [new File(['fixed'], 'consent-pro-v2.zip', { type: 'application/zip' })] }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Run preflight again' }));

    await waitFor(() => expect(addRevision).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('Resolved')).toBeVisible();
    expect(screen.getByText('Remaining')).toBeVisible();
    expect(screen.getByText('New')).toBeVisible();
    expect(screen.getByText('Revision 2')).toBeVisible();
  });

  test('prepares partner test input but shows evidence only after a Webflow run', async () => {
    const review = consentProReview();
    const createdAt = '2026-07-14T23:00:00.000Z';
    const prepared = {
      schemaVersion: 'runtime_test_package.v1' as const,
      id: 'test-package-1',
      reviewId: review.id,
      reviewVersionId: review.latestVersion.id,
      bundleSha256: review.latestVersion.result.artifact.sha256,
      status: 'ready' as const,
      trust: 'partner_supplied' as const,
      target: {
        url: 'https://app-review-sandbox.webflow.io/',
        host: 'app-review-sandbox.webflow.io'
      },
      sandboxInstallationId: 'webflow-sandbox-site-123',
      license: {
        mode: 'installation_allowlist' as const,
        expiresAt: '2026-07-15T00:00:00.000Z'
      },
      runtimeArtifacts: [
        {
          url: 'https://api.consentpro.com/v2/cdn/runtime-v1.js',
          sha256: 'a'.repeat(64),
          integrity: 'sha256-runtime-v1'
        },
        {
          url: 'https://api.consentpro.com/v2/cdn/preferences-v1.js',
          sha256: 'b'.repeat(64),
          integrity: 'sha256-preferences-v1'
        }
      ],
      negativeProxyProbe: {
        method: 'GET' as const,
        urlTemplate: 'https://api.consentpro.com/v2/proxy?url={canaryUrl}'
      },
      lifecycle: {
        readySelector: '[data-runtime-ready]'
      },
      evidence: null,
      createdAt,
      observation: null
    };
    const completed = {
      ...prepared,
      observation: {
        id: 'observation-1',
        status: 'complete' as const,
        trust: 'webflow_observed' as const,
        approvedAt: createdAt,
        expiresAt: '2026-07-14T23:15:00.000Z',
        completedAt: '2026-07-14T23:01:00.000Z',
        evidence: {
          securityStatus: 'blocked' as const,
          securityPredicates: {
            publishedTarget: true,
            runtimeReadyObserved: false,
            runtimeLoadedByPage: true,
            runtimeHashMatched: false,
            runtimeIntegrityMatched: true,
            noRuntimeCreatedScripts: false,
            noUnreviewedRuntimeScripts: false,
            negativeProxyBlocked: true
          },
          blockers: [
            'The runtime-ready signal was not observed on the published page.',
            'The executed runtime bytes did not match the pinned SHA-256.',
            'The runtime created additional script elements at execution time.',
            'The runtime loaded additional unreviewed scripts.'
          ],
          runtimeCreatedScripts: ['https://api.consentpro.com/v2/cdn/debugger.js'],
          unreviewedRuntimeScripts: ['https://api.consentpro.com/v2/cdn/debugger.js'],
          runtimeFiles: [
            {
              url: 'https://api.consentpro.com/v2/cdn/runtime-v1.js',
              loadedByPage: true,
              hashMatched: true,
              integrityMatched: true,
              sourceMapAvailable: true
            },
            {
              url: 'https://api.consentpro.com/v2/cdn/preferences-v1.js',
              loadedByPage: true,
              hashMatched: false,
              integrityMatched: true,
              sourceMapAvailable: false
            }
          ],
          cleanupStatus: 'not_tested' as const,
          cleanupResidue: [],
          negativeProxyOutcome: 'blocked' as const,
          artifactCount: 1,
          artifacts: [
            {
              kind: 'screenshot_after_observation',
              contentType: 'image/png',
              bytes: 12000,
              sha256: 'c'.repeat(64)
            }
          ]
        }
      }
    };
    const listRuntimeTestPackages = vi
      .fn<PreflightApi['listRuntimeTestPackages']>()
      .mockResolvedValueOnce([])
      .mockResolvedValue([completed]);
    const createRuntimeTestPackage = vi.fn(async () => prepared);
    const requestRuntimeObservationRun = vi
      .fn<PreflightApi['requestRuntimeObservationRun']>()
      .mockRejectedValueOnce(
        new Error('The runtime runner could not start inside the secure sandbox.')
      )
      .mockResolvedValue(prepared.observation);
    const runtimeApi: PreflightApi = {
      ...api,
      listReviews: async () => [
        {
          id: review.id,
          name: review.name,
          updatedAt: review.updatedAt,
          latestSequence: 1,
          readiness: 'changes_required',
          appName: 'Consent Pro by Finsweet',
          coverage: review.latestVersion.result.coverage
        }
      ],
      getReview: async () => review,
      listRuntimeTestPackages,
      createRuntimeTestPackage,
      requestRuntimeObservationRun
    };
    render(<App api={runtimeApi} />);

    fireEvent.click(await screen.findByRole('button', { name: /Consent Pro preflight/i }));
    const runtimeHeading = await screen.findByRole('heading', {
      name: 'Test the published runtime'
    });
    expect(runtimeHeading).toBeVisible();
    const runtimeCard = runtimeHeading.closest('section')!;
    const scrollIntoView = vi.fn();
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
      configurable: true,
      writable: true,
      value: scrollIntoView
    });
    fireEvent.change(screen.getByLabelText('Published Webflow test URL'), {
      target: { value: 'https://app-review-sandbox.webflow.io' }
    });
    expect(screen.getByLabelText('Webflow installation or site ID')).toHaveValue(
      'local-webflow-site'
    );
    expect(screen.getByLabelText('Webflow installation or site ID')).toHaveAttribute('readonly');
    fireEvent.change(screen.getByLabelText('Versioned runtime URL'), {
      target: { value: 'https://api.consentpro.com/v2/cdn/runtime-v1.js' }
    });
    fireEvent.change(screen.getByLabelText('SHA-256'), {
      target: { value: 'a'.repeat(64) }
    });
    fireEvent.change(screen.getByLabelText('Proxy probe URL template'), {
      target: { value: 'https://api.consentpro.com/v2/proxy?url={canaryUrl}' }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Review test setup' }));

    expect(screen.getByRole('heading', { name: 'Confirm test access' })).toBeVisible();
    expect(createRuntimeTestPackage).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Save test setup' }));

    expect(await screen.findByLabelText('Current evidence: Partner supplied')).toBeVisible();
    expect(screen.getByText('Ready to test')).toBeVisible();
    expect(createRuntimeTestPackage).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: 'Run Webflow test' }));
    await waitFor(() => expect(requestRuntimeObservationRun).toHaveBeenCalledWith(prepared.id));
    const runtimeError = await screen.findByRole('alert');
    expect(runtimeCard).toContainElement(runtimeError);
    expect(runtimeError).toHaveTextContent(
      'The runtime runner could not start inside the secure sandbox.'
    );
    expect(runtimeError).toHaveFocus();
    expect(scrollIntoView).toHaveBeenCalledWith({
      behavior: 'smooth',
      block: 'center'
    });

    fireEvent.click(screen.getByRole('button', { name: 'Run Webflow test' }));
    await waitFor(() => expect(requestRuntimeObservationRun).toHaveBeenCalledTimes(2));
    expect(await screen.findByLabelText('Current evidence: Webflow observed')).toBeVisible();
    expect(screen.getByText('Production runtime observed')).toBeVisible();
    expect(screen.queryByText('Production runtime not yet verified')).not.toBeInTheDocument();
    expect(
      screen.getByText(/Recommended-practice findings for published-site code are in the result below/i)
    ).toBeVisible();
    expect(screen.getByText('4 checks need attention')).toBeVisible();
    expect(screen.getByText('Ready signal not found')).toBeVisible();
    expect(screen.getByText('Runtime bytes changed')).toBeVisible();
    expect(screen.getByText('New script elements were created')).toBeVisible();
    expect(screen.getByText('Unreviewed scripts loaded')).toBeVisible();
    expect(screen.getAllByText('debugger.js')).toHaveLength(2);
    expect(screen.getByText(/Address them, publish the test site, then run the test again/i))
      .toBeVisible();
    expect(screen.getByText('Proxy canary blocked')).toBeVisible();
    expect(screen.getByText('2 declared runtime files observed · 1 evidence artifact')).toBeVisible();
    const failedRuntime = screen.getByRole('listitem', {
      name: 'Runtime file result: preferences-v1.js'
    });
    expect(within(failedRuntime).getByText('Loaded')).toBeVisible();
    expect(within(failedRuntime).getByText('Hash mismatch')).toBeVisible();
    expect(within(failedRuntime).getByText('SRI matched')).toBeVisible();
    expect(screen.getByText('What the evidence labels mean')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Run Webflow test again' }));
    await waitFor(() => {
      expect(requestRuntimeObservationRun).toHaveBeenCalledTimes(3);
      expect(requestRuntimeObservationRun).toHaveBeenLastCalledWith(prepared.id);
    });
    expect(screen.getByRole('button', { name: 'Edit test setup' })).toBeVisible();
    expect(screen.queryByText('Share')).not.toBeInTheDocument();
  });

  test('prepares one execution scenario with every reviewed runtime file', async () => {
    const review = consentProReview();
    const createRuntimeTestPackage = vi.fn<PreflightApi['createRuntimeTestPackage']>(
      async (_reviewId, input) => ({
        schemaVersion: 'runtime_test_package.v1',
        id: 'runtime-set-package',
        reviewId: review.id,
        reviewVersionId: review.latestVersion.id,
        bundleSha256: review.latestVersion.result.artifact.sha256,
        status: 'ready',
        trust: 'partner_supplied',
        target: { url: input.targetUrl, host: 'app-review-sandbox.webflow.io' },
        sandboxInstallationId: input.sandboxInstallationId,
        license: input.license,
        runtimeArtifacts: input.runtimeArtifacts,
        negativeProxyProbe: input.negativeProxyProbe,
        lifecycle: input.lifecycle,
        evidence: null,
        createdAt: '2026-07-15T00:00:00.000Z',
        observation: null
      })
    );
    const runtimeApi: PreflightApi = {
      ...api,
      listReviews: async () => [{
        id: review.id,
        name: review.name,
        updatedAt: review.updatedAt,
        latestSequence: 1,
        readiness: 'changes_required',
        appName: 'Consent Pro by Finsweet',
        coverage: review.latestVersion.result.coverage
      }],
      getReview: async () => review,
      listRuntimeTestPackages: async () => [],
      createRuntimeTestPackage
    };

    render(<App api={runtimeApi} />);
    fireEvent.click(await screen.findByRole('button', { name: /Consent Pro preflight/i }));

    expect(await screen.findByRole('heading', { name: 'Runtime file 1' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Runtime file 2' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('More runtime files'));
    expect(screen.getByText(/must execute in this same test/i)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Add another runtime file' }));
    expect(screen.getByRole('heading', { name: 'Runtime file 2' })).toBeVisible();

    fireEvent.change(screen.getByLabelText('Published Webflow test URL'), {
      target: { value: 'https://app-review-sandbox.webflow.io' }
    });
    fireEvent.change(screen.getByLabelText('Webflow installation or site ID'), {
      target: { value: 'webflow-sandbox-site-123' }
    });
    fireEvent.change(screen.getByLabelText('Versioned runtime URL'), {
      target: { value: 'https://api.consentpro.com/v2/cdn/runtime-v1.js' }
    });
    fireEvent.change(screen.getByLabelText('SHA-256'), {
      target: { value: 'a'.repeat(64) }
    });
    expect(screen.getByLabelText('Script integrity (SRI)')).toHaveValue(
      sriFromHex('a'.repeat(64))
    );
    expect(screen.getByLabelText('Script integrity (SRI)')).toHaveAttribute('readonly');
    fireEvent.change(screen.getByLabelText('Versioned runtime URL — file 2'), {
      target: { value: 'https://api.consentpro.com/v2/cdn/preferences-v1.js' }
    });
    expect(screen.getByText('preferences-v1.js')).toBeVisible();
    fireEvent.change(screen.getByLabelText('SHA-256 — file 2'), {
      target: { value: 'b'.repeat(64) }
    });
    expect(screen.getByLabelText('Script integrity (SRI) — file 2')).toHaveValue(
      sriFromHex('b'.repeat(64))
    );
    fireEvent.change(screen.getByLabelText('Proxy probe URL template'), {
      target: { value: 'https://api.consentpro.com/v2/proxy?url={canaryUrl}' }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Review test setup' }));
    expect(screen.getByText('2 runtime files will be tested together.')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Save test setup' }));

    await waitFor(() => expect(createRuntimeTestPackage).toHaveBeenCalledTimes(1));
    expect(createRuntimeTestPackage).toHaveBeenCalledWith(
      review.id,
      expect.objectContaining({
        runtimeArtifacts: [
          {
            url: 'https://api.consentpro.com/v2/cdn/runtime-v1.js',
            sha256: 'a'.repeat(64),
            integrity: sriFromHex('a'.repeat(64)),
            loadMode: 'document'
          },
          {
            url: 'https://api.consentpro.com/v2/cdn/preferences-v1.js',
            sha256: 'b'.repeat(64),
            integrity: sriFromHex('b'.repeat(64)),
            loadMode: 'runtime_child'
          }
        ]
      })
    );
  });

  test('guides a junior developer through locating and pinning production runtimes', async () => {
    const review = consentProReview();
    const runtimeApi: PreflightApi = {
      ...api,
      listReviews: async () => [{
        id: review.id,
        name: review.name,
        updatedAt: review.updatedAt,
        latestSequence: 1,
        readiness: 'changes_required',
        appName: 'Consent Pro by Finsweet',
        coverage: review.latestVersion.result.coverage
      }],
      getReview: async () => review,
      listRuntimeTestPackages: async () => []
    };

    render(<App api={runtimeApi} />);
    fireEvent.click(await screen.findByRole('button', { name: /Consent Pro preflight/i }));

    expect(await screen.findByText('How to find and pin runtime files')).toBeVisible();
    fireEvent.click(screen.getByText('How to find and pin runtime files'));

    expect(screen.getByText(/A runtime is JavaScript that your app loads on the published site/i)).toBeVisible();
    expect(screen.getByText(/include every child script it creates/i)).toBeVisible();
    expect(screen.getByText(/SHA-256 is the 64-character fingerprint/i)).toBeVisible();
    expect(screen.getByText(/SRI is the same fingerprint encoded for a script tag/i)).toBeVisible();
    expect(screen.getByText(/If the vendor does not send that header, browser SRI will block the script/i)).toBeVisible();
    expect(screen.getByText(/If you are unsure whether your app has one/i)).toBeVisible();
    fireEvent.click(screen.getByText('Ready signal'));
    expect(screen.getByText(/A JavaScript flag such as/i)).toBeVisible();
    expect(screen.getByText(/Use the exact JavaScript request from the published test page/i)).toBeVisible();
    expect(screen.getByText(/This app calculates SRI from the SHA-256/i)).toBeVisible();
  });

  test('records no proxy surface without inventing a canary result', async () => {
    const review = consentProReview();
    const createRuntimeTestPackage = vi
      .fn<PreflightApi['createRuntimeTestPackage']>()
      .mockRejectedValue(new Error('Test stopped after package submission.'));
    const runtimeApi: PreflightApi = {
      ...api,
      listReviews: async () => [{
        id: review.id,
        name: review.name,
        updatedAt: review.updatedAt,
        latestSequence: 1,
        readiness: 'changes_required',
        appName: 'Consent Pro by Finsweet',
        coverage: review.latestVersion.result.coverage
      }],
      getReview: async () => review,
      listRuntimeTestPackages: async () => [],
      createRuntimeTestPackage
    };

    render(<App api={runtimeApi} />);
    fireEvent.click(await screen.findByRole('button', { name: /Consent Pro preflight/i }));
    fireEvent.change(await screen.findByLabelText('Published Webflow test URL'), {
      target: { value: 'https://app-review-sandbox.webflow.io' }
    });
    fireEvent.change(screen.getByLabelText('Webflow installation or site ID'), {
      target: { value: 'webflow-sandbox-site-123' }
    });
    fireEvent.change(screen.getByLabelText('Versioned runtime URL'), {
      target: { value: 'https://api.consentpro.com/v2/cdn/runtime-v1.js' }
    });
    fireEvent.change(screen.getByLabelText('SHA-256'), {
      target: { value: 'a'.repeat(64) }
    });
    fireEvent.click(
      screen.getByRole('radio', { name: 'No — this app has no proxy or fetch-through surface' })
    );

    expect(screen.queryByLabelText('Proxy probe URL template')).not.toBeInTheDocument();
    expect(screen.getByText('Proxy check: not applicable')).toBeVisible();
    const setupButton = screen.getByRole('button', { name: 'Review test setup' });
    fireEvent.click(setupButton);
    const dialog = screen.getByRole('dialog');
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();
    fireEvent.keyDown(dialog, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(setupButton).toHaveFocus();
    fireEvent.click(setupButton);
    fireEvent.click(screen.getByRole('button', { name: 'Save test setup' }));

    await waitFor(() => expect(createRuntimeTestPackage).toHaveBeenCalledTimes(1));
    expect(createRuntimeTestPackage).toHaveBeenCalledWith(
      review.id,
      expect.objectContaining({
        negativeProxyProbe: {
          mode: 'none_declared',
          declaration: 'no_proxy_surface'
        }
      })
    );
  });

  test('keeps a rejected runtime package editable beside its actionable error', async () => {
    const review = consentProReview();
    const createRuntimeTestPackage = vi
      .fn<PreflightApi['createRuntimeTestPackage']>()
      .mockRejectedValue(
        new Error('Runtime file 1: the SHA-256 and SRI must describe the same bytes.')
      );
    const runtimeApi: PreflightApi = {
      ...api,
      listReviews: async () => [{
        id: review.id,
        name: review.name,
        updatedAt: review.updatedAt,
        latestSequence: 1,
        readiness: 'changes_required',
        appName: 'Consent Pro by Finsweet',
        coverage: review.latestVersion.result.coverage
      }],
      getReview: async () => review,
      listRuntimeTestPackages: async () => [],
      createRuntimeTestPackage
    };

    render(<App api={runtimeApi} />);
    fireEvent.click(await screen.findByRole('button', { name: /Consent Pro preflight/i }));
    const runtimeHeading = await screen.findByRole('heading', {
      name: 'Test the published runtime'
    });
    const runtimeCard = runtimeHeading.closest('section')!;
    const scrollIntoView = vi.fn();
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
      configurable: true,
      writable: true,
      value: scrollIntoView
    });
    fireEvent.change(screen.getByLabelText('Published Webflow test URL'), {
      target: { value: 'https://app-review-sandbox.webflow.io' }
    });
    fireEvent.change(screen.getByLabelText('Webflow installation or site ID'), {
      target: { value: 'webflow-sandbox-site-123' }
    });
    fireEvent.change(screen.getByLabelText('Versioned runtime URL'), {
      target: { value: 'https://api.consentpro.com/v2/cdn/runtime-v1.js' }
    });
    fireEvent.change(screen.getByLabelText('SHA-256'), {
      target: { value: 'a'.repeat(64) }
    });
    fireEvent.change(screen.getByLabelText('Proxy probe URL template'), {
      target: { value: 'https://api.consentpro.com/v2/proxy?url={canaryUrl}' }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Review test setup' }));
    fireEvent.click(screen.getByRole('button', { name: 'Save test setup' }));

    const runtimeError = await screen.findByRole('alert');
    expect(runtimeCard).toContainElement(runtimeError);
    expect(runtimeError).toHaveTextContent('Runtime file 1');
    expect(runtimeError).toHaveFocus();
    expect(scrollIntoView).toHaveBeenCalledWith({
      behavior: 'smooth',
      block: 'center'
    });
    expect(screen.getByLabelText('Versioned runtime URL')).toHaveValue(
      'https://api.consentpro.com/v2/cdn/runtime-v1.js'
    );
    expect(screen.getByRole('button', { name: 'Review test setup' })).toBeVisible();
    fireEvent.change(screen.getByLabelText('SHA-256'), {
      target: { value: 'b'.repeat(64) }
    });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  test('blocks a duplicate runtime URL before package confirmation', async () => {
    const review = consentProReview();
    const createRuntimeTestPackage = vi.fn<PreflightApi['createRuntimeTestPackage']>();
    const runtimeApi: PreflightApi = {
      ...api,
      listReviews: async () => [{
        id: review.id,
        name: review.name,
        updatedAt: review.updatedAt,
        latestSequence: 1,
        readiness: 'changes_required',
        appName: 'Consent Pro by Finsweet',
        coverage: review.latestVersion.result.coverage
      }],
      getReview: async () => review,
      listRuntimeTestPackages: async () => [],
      createRuntimeTestPackage
    };

    render(<App api={runtimeApi} />);
    fireEvent.click(await screen.findByRole('button', { name: /Consent Pro preflight/i }));
    const runtimeCard = (await screen.findByRole('heading', {
      name: 'Test the published runtime'
    })).closest('section')!;
    runtimeCard.scrollIntoView = vi.fn();
    fireEvent.click(screen.getByText('More runtime files'));
    fireEvent.click(screen.getByRole('button', { name: 'Add another runtime file' }));
    const duplicateUrl = 'https://api.consentpro.com/v2/cdn/runtime-v1.js';
    fireEvent.change(screen.getByLabelText('Published Webflow test URL'), {
      target: { value: 'https://app-review-sandbox.webflow.io' }
    });
    fireEvent.change(screen.getByLabelText('Webflow installation or site ID'), {
      target: { value: 'webflow-sandbox-site-123' }
    });
    fireEvent.change(screen.getByLabelText('Versioned runtime URL'), {
      target: { value: duplicateUrl }
    });
    fireEvent.change(screen.getByLabelText('SHA-256'), {
      target: { value: 'a'.repeat(64) }
    });
    fireEvent.change(screen.getByLabelText('Versioned runtime URL — file 2'), {
      target: { value: duplicateUrl }
    });
    fireEvent.change(screen.getByLabelText('SHA-256 — file 2'), {
      target: { value: 'b'.repeat(64) }
    });
    fireEvent.change(screen.getByLabelText('Proxy probe URL template'), {
      target: { value: 'https://api.consentpro.com/v2/proxy?url={canaryUrl}' }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Review test setup' }));

    const error = screen.getByRole('alert');
    expect(runtimeCard).toContainElement(error);
    expect(error).toHaveTextContent('Runtime file 2 duplicates runtime file 1');
    expect(screen.queryByRole('heading', { name: 'Confirm test access' }))
      .not.toBeInTheDocument();
    expect(createRuntimeTestPackage).not.toHaveBeenCalled();
  });

  test('lets the operator add every runtime file in the execution scenario', async () => {
    const review = consentProReview();
    const runtimeApi: PreflightApi = {
      ...api,
      listReviews: async () => [{
        id: review.id,
        name: review.name,
        updatedAt: review.updatedAt,
        latestSequence: 1,
        readiness: 'changes_required',
        appName: 'Consent Pro by Finsweet',
        coverage: review.latestVersion.result.coverage
      }],
      getReview: async () => review
    };

    render(<App api={runtimeApi} />);
    fireEvent.click(await screen.findByRole('button', { name: /Consent Pro preflight/i }));
    fireEvent.click(await screen.findByText('More runtime files'));
    const add = screen.getByRole('button', { name: 'Add another runtime file' });
    for (let count = 1; count < 10; count += 1) fireEvent.click(add);

    expect(screen.getByRole('heading', { name: 'Runtime file 10' })).toBeVisible();
    expect(add).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: 'Remove runtime file 10' }));
    expect(screen.queryByRole('heading', { name: 'Runtime file 10' })).not.toBeInTheDocument();
  });

  test('does not reopen a previously selected run after the extension reloads', async () => {
    const review = consentProReview(2);
    localStorage.setItem('app-review-preflight.selected-review', review.id);
    const getReview = vi.fn(async () => review);
    const persistedApi: PreflightApi = {
      ...api,
      listReviews: async () => [
        {
          id: review.id,
          name: review.name,
          updatedAt: review.updatedAt,
          latestSequence: 2,
          readiness: 'changes_required',
          appName: 'Consent Pro by Finsweet',
          coverage: review.latestVersion.result.coverage
        }
      ],
      getReview
    };

    render(<App api={persistedApi} />);

    expect(await screen.findByRole('heading', { name: 'Start a preflight' })).toBeVisible();
    expect(screen.queryByText('Revision 2')).not.toBeInTheDocument();
    expect(getReview).not.toHaveBeenCalled();
  });

  test('shows a reconnect recovery when the Worker rejects the Webflow authorization', async () => {
    const reconnectingApi: PreflightApi = {
      ...api,
      listReviews: async () => Promise.reject(new PreflightAuthenticationError())
    };

    render(<App api={reconnectingApi} reconnectUrl="https://preflight.test/v1/oauth/webflow/start" />);

    expect(await screen.findByRole('heading', { name: 'Reconnect Webflow to continue' })).toBeVisible();
    expect(screen.getByRole('link', { name: 'Reconnect Webflow' })).toHaveAttribute(
      'href',
      'https://preflight.test/v1/oauth/webflow/start'
    );
    expect(screen.getByText(/did not upload files or create a receipt/i)).toBeVisible();
  });

  test('prefills a new revision from the previous package without inheriting its evidence', async () => {
    const review = consentProReview(2);
    const previousPackage = {
      schemaVersion: 'runtime_test_package.v1' as const,
      id: 'runtime-package-version-1',
      reviewId: review.id,
      reviewVersionId: 'version-1',
      bundleSha256: 'previous-bundle-sha',
      status: 'expired' as const,
      trust: 'partner_supplied' as const,
      target: {
        url: 'https://consent-pro-test.webflow.io/',
        host: 'consent-pro-test.webflow.io'
      },
      sandboxInstallationId: 'consent-pro-test-site',
      license: {
        mode: 'installation_allowlist' as const,
        expiresAt: '2026-07-15T18:00:00.000Z'
      },
      runtimeArtifacts: [{
        url: 'https://api.consentpro.com/v2/cdn/runtime/immutable.js',
        sha256: 'd'.repeat(64),
        integrity: 'sha256-3d3d3d3d'
      }, {
        url: 'https://api.consentpro.com/v2/cdn/preferences/immutable.js',
        sha256: 'e'.repeat(64),
        integrity: 'sha256-4e4e4e4e'
      }],
      negativeProxyProbe: {
        method: 'GET' as const,
        urlTemplate: 'https://api.consentpro.com/v2/proxy?url={canaryUrl}'
      },
      lifecycle: { readySelector: '[data-consent-pro-ready]' },
      evidence: null,
      createdAt: '2026-07-15T17:00:00.000Z',
      observation: {
        id: 'observation-version-1',
        status: 'complete' as const,
        trust: 'webflow_observed' as const,
        approvedAt: '2026-07-15T17:05:00.000Z',
        expiresAt: '2026-07-15T17:20:00.000Z',
        completedAt: '2026-07-15T17:10:00.000Z',
        evidence: {
          securityStatus: 'passed' as const,
          securityPredicates: {
            publishedTarget: true,
            runtimeReadyObserved: true,
            runtimeLoadedByPage: true,
            runtimeHashMatched: true,
            runtimeIntegrityMatched: true,
            noRuntimeCreatedScripts: true,
            noUnreviewedRuntimeScripts: true,
            negativeProxyBlocked: true
          },
          blockers: [],
          runtimeFiles: [
            {
              url: 'https://api.consentpro.com/v2/cdn/runtime/immutable.js',
              loadedByPage: true,
              hashMatched: true,
              integrityMatched: true,
              sourceMapAvailable: true
            },
            {
              url: 'https://api.consentpro.com/v2/cdn/preferences/immutable.js',
              loadedByPage: true,
              hashMatched: true,
              integrityMatched: true,
              sourceMapAvailable: true
            }
          ],
          cleanupStatus: 'not_tested' as const,
          cleanupResidue: [],
          negativeProxyOutcome: 'blocked' as const,
          artifactCount: 8,
          artifacts: []
        }
      }
    };
    const runtimeApi: PreflightApi = {
      ...api,
      listReviews: async () => [{
        id: review.id,
        name: review.name,
        updatedAt: review.updatedAt,
        latestSequence: 2,
        readiness: 'changes_required',
        appName: 'Consent Pro by Finsweet',
        coverage: review.latestVersion.result.coverage
      }],
      getReview: async () => review,
      listRuntimeTestPackages: async () => [previousPackage]
    };

    render(<App api={runtimeApi} />);
    fireEvent.click(await screen.findByRole('button', { name: /Consent Pro preflight/i }));

    expect(await screen.findByText('Previous setup loaded')).toBeVisible();
    expect(screen.getByLabelText('Published Webflow test URL')).toHaveValue(
      'https://consent-pro-test.webflow.io/'
    );
    expect(screen.getByLabelText('Webflow installation or site ID')).toHaveValue(
      'local-webflow-site'
    );
    expect(screen.getByLabelText('Versioned runtime URL')).toHaveValue(
      'https://api.consentpro.com/v2/cdn/runtime/immutable.js'
    );
    expect(screen.getByLabelText('SHA-256')).toHaveValue('d'.repeat(64));
    expect(screen.getByLabelText('Script integrity (SRI)')).toHaveValue('sha256-3d3d3d3d');
    expect(screen.getByRole('heading', { name: 'Runtime file 2' })).toBeVisible();
    expect(screen.getByLabelText('Versioned runtime URL — file 2')).toHaveValue(
      'https://api.consentpro.com/v2/cdn/preferences/immutable.js'
    );
    expect(screen.getByLabelText('SHA-256 — file 2')).toHaveValue('e'.repeat(64));
    expect(screen.getByLabelText('Script integrity (SRI) — file 2')).toHaveValue(
      'sha256-4e4e4e4e'
    );
    expect(screen.getByLabelText('Ready selector')).toHaveValue('[data-consent-pro-ready]');
    expect(screen.getByLabelText('Proxy probe URL template')).toHaveValue(
      'https://api.consentpro.com/v2/proxy?url={canaryUrl}'
    );
    expect(screen.getByLabelText('Current evidence: Not prepared')).toBeVisible();
    expect(screen.getByText('Production runtime not yet verified')).toBeVisible();
    expect(screen.queryByText('Production runtime observed')).not.toBeInTheDocument();
  });

  test('keeps production validation inside the Designer app without a browser companion', async () => {
    const review = consentProReview();
    const runtimeApi = {
      ...api,
      listReviews: async () => [
        {
          id: review.id,
          name: review.name,
          updatedAt: review.updatedAt,
          latestSequence: 1,
          readiness: 'changes_required' as const,
          appName: 'Consent Pro by Finsweet',
          coverage: review.latestVersion.result.coverage
        }
      ],
      getReview: async () => review,
      listRuntimeTestPackages: async () => [{
        schemaVersion: 'runtime_test_package.v1' as const,
        id: 'runtime-package-consent-pro',
        reviewId: review.id,
        reviewVersionId: review.latestVersion.id,
        bundleSha256: review.latestVersion.result.artifact.sha256,
        status: 'ready' as const,
        trust: 'partner_supplied' as const,
        target: { url: 'https://consent-pro-test.webflow.io/', host: 'consent-pro-test.webflow.io' },
        sandboxInstallationId: 'consent-pro-test-site',
        license: { mode: 'installation_allowlist' as const, expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
        runtimeArtifacts: [{ url: 'https://api.consentpro.com/v2/cdn/runtime.js', sha256: 'a'.repeat(64), integrity: 'sha256-runtime' }],
        negativeProxyProbe: { method: 'GET' as const, urlTemplate: 'https://api.consentpro.com/v2/proxy?url={canaryUrl}' },
        lifecycle: { readySelector: '[data-runtime-ready]' },
        evidence: null,
        createdAt: new Date().toISOString(),
        observation: null
      }]
    } as PreflightApi;

    render(<App api={runtimeApi} />);
    fireEvent.click(await screen.findByRole('button', { name: /Consent Pro preflight/i }));

    expect(await screen.findByRole('heading', { name: 'Consent Pro by Finsweet' })).toBeVisible();
    expect(screen.queryByText('Browser companion')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Connect browser companion' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve sandbox test' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Run Webflow test' })).toBeVisible();
    expect(screen.getByText('Ready to test')).toBeVisible();
  });
});
