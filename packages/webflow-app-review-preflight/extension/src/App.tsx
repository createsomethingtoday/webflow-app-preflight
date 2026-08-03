import { useEffect, useId, useRef, useState } from 'react';
import type { ReviewGuidance } from '@create-something/webflow-app-review-preflight';
import type {
  PreflightIdentity,
  PreflightApi,
  CreateHostedRuntimeReviewInput,
  ReviewComparison,
  ReviewSummary,
  RuntimeTestPackageInput,
  RuntimeTestPackageView,
  ReviewerHandoff,
  StoredReview
} from './types';

const SELECTED_REVIEW_KEY = 'app-review-preflight.selected-review';

function rememberedReviewId(): string | null {
  try {
    return localStorage.getItem(SELECTED_REVIEW_KEY);
  } catch {
    return null;
  }
}

function rememberReview(id: string | null): void {
  try {
    if (id) localStorage.setItem(SELECTED_REVIEW_KEY, id);
    else localStorage.removeItem(SELECTED_REVIEW_KEY);
  } catch {
    // Durable review history still lives in D1 when iframe storage is unavailable.
  }
}

function statusLabel(item: ReviewGuidance): string {
  if (item.label === 'Security blocker') return 'Blocker';
  if (item.label === 'Required update') return 'Required';
  return 'Suggested';
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit'
  }).format(new Date(value));
}

function sriFromSha256(value: string): string {
  if (!/^[a-f0-9]{64}$/.test(value)) return '';
  const bytes = value
    .match(/.{2}/g)!
    .map((pair) => String.fromCharCode(Number.parseInt(pair, 16)))
    .join('');
  return `sha256-${btoa(bytes)}`;
}

function normalizedRuntimeUrl(value: string): string | null {
  try {
    return new URL(value).toString();
  } catch {
    return null;
  }
}

function runtimeFileName(value: string): string | null {
  try {
    const url = new URL(value);
    const name = url.pathname.split('/').filter(Boolean).at(-1);
    return name ? decodeURIComponent(name) : url.hostname;
  } catch {
    return null;
  }
}

function duplicateRuntimePosition(
  artifacts: RuntimeTestPackageInput['runtimeArtifacts'],
  index: number
): number | null {
  const candidate = normalizedRuntimeUrl(artifacts[index]?.url ?? '');
  if (!candidate) return null;
  const previous = artifacts.findIndex(
    (artifact, artifactIndex) =>
      artifactIndex < index && normalizedRuntimeUrl(artifact.url) === candidate
  );
  return previous >= 0 ? previous : null;
}

interface RuntimeIssue {
  title: string;
  detail: string;
  nextMove: string;
  urls?: string[];
}

function runtimeIssues(testPackage: RuntimeTestPackageView): RuntimeIssue[] {
  const evidence = testPackage.observation?.evidence;
  if (!evidence || evidence.securityStatus === 'passed') return [];
  const issues: RuntimeIssue[] = [];
  const runtimeFiles = evidence.runtimeFiles;
  const failedFiles = (predicate: (file: typeof runtimeFiles[number]) => boolean) =>
    runtimeFiles.filter(predicate).map((file) => file.url);

  if (!evidence.securityPredicates.publishedTarget) {
    issues.push({
      title: 'Published test page required',
      detail: 'The test URL points to Designer or another page that cannot prove the live runtime.',
      nextMove: 'Publish a dedicated Webflow test site, then prepare a new test package with that URL.'
    });
  }
  if (!evidence.securityPredicates.runtimeReadyObserved) {
    issues.push({
      title: 'Ready signal not found',
      detail: `Webflow did not find ${testPackage.lifecycle.readySelector} after the page loaded.`,
      nextMove: 'Add this marker only after the runtime is usable, or prepare a new test package with the correct selector.'
    });
  }
  if (!evidence.securityPredicates.runtimeLoadedByPage) {
    issues.push({
      title: 'Declared runtime did not load',
      detail: 'The published page did not request every file in the reviewed runtime set.',
      nextMove: 'Publish the exact runtime URL on the test page, then run the test again.',
      urls: failedFiles((file) => !file.loadedByPage)
    });
  }
  if (!evidence.securityPredicates.runtimeHashMatched) {
    issues.push({
      title: 'Runtime bytes changed',
      detail: 'The downloaded JavaScript does not match the SHA-256 saved in this test package.',
      nextMove: 'Restore the reviewed file, or download the current file and prepare a new test package with its new SHA-256.',
      urls: failedFiles((file) => !file.hashMatched)
    });
  }
  if (!evidence.securityPredicates.runtimeIntegrityMatched) {
    const pageFiles = failedFiles(
      (file) => file.loadMode !== 'runtime_child' && !file.integrityMatched
    );
    const childFiles = failedFiles(
      (file) => file.loadMode === 'runtime_child' && !file.integrityMatched
    );
    if (pageFiles.length > 0) {
      issues.push({
        title: 'Script integrity is missing or wrong',
        detail: 'A page-loaded script does not use the SRI value saved in this test package.',
        nextMove: 'Add the saved integrity value and crossorigin="anonymous" to each script tag. Make sure the CDN allows cross-origin SRI.',
        urls: pageFiles
      });
    }
    if (childFiles.length > 0) {
      issues.push({
        title: 'Reviewed parent was not detected',
        detail: 'A child runtime did not start from another pinned runtime in this test.',
        nextMove: 'Load the child from a pinned parent, or mark it as page-loaded and publish its SRI on the script tag.',
        urls: childFiles
      });
    }
  }
  if (!evidence.securityPredicates.noRuntimeCreatedScripts) {
    issues.push({
      title: 'New script elements were created',
      detail: 'The runtime added script elements after the page began running.',
      nextMove: 'Review every added script. Remove it, bundle it into reviewed code, or add it to the pinned runtime set.',
      urls: evidence.runtimeCreatedScripts ?? []
    });
  }
  if (!evidence.securityPredicates.noUnreviewedRuntimeScripts) {
    issues.push({
      title: 'Unreviewed scripts loaded',
      detail: 'The page requested JavaScript that is not part of the reviewed runtime set.',
      nextMove: 'Remove each script, bundle it into reviewed code, or add its immutable URL and SHA-256 to a new test package.',
      urls: evidence.unreviewedRuntimeScripts ?? []
    });
  }
  if (evidence.securityPredicates.proxyPolicySatisfied === false) {
    issues.push({
      title: 'Proxy check did not match the declaration',
      detail: 'The browser result does not match the proxy setting saved in this test package.',
      nextMove: 'Check the proxy declaration or endpoint, prepare a corrected test package, and run it again.'
    });
  }
  return issues;
}

function UploadCard({
  busy,
  onFile
}: {
  busy: boolean;
  onFile: (file: File) => void;
}) {
  const id = useId();
  return (
    <section className="upload-card entry-card" aria-labelledby={`${id}-title`}>
      <div className="upload-icon" aria-hidden="true">↑</div>
      <span className="eyebrow">ZIP bundle</span>
      <h2 id={`${id}-title`}>Review a submitted bundle</h2>
      <p>
        Choose the exact ZIP you plan to submit. Preflight will scan it and show what
        to fix or verify next.
      </p>
      <label className="button button-primary" htmlFor={id}>
        {busy ? 'Scanning bundle…' : 'Choose ZIP bundle'}
      </label>
      <input
        id={id}
        className="visually-hidden"
        type="file"
        accept=".zip,application/zip"
        disabled={busy}
        onChange={(event) => {
          const file = event.currentTarget.files?.[0];
          if (file) onFile(file);
          event.currentTarget.value = '';
        }}
      />
      <span className="upload-note">Up to 10 MB · saved automatically</span>
    </section>
  );
}

function HostedRuntimeCard({
  busy,
  onStart
}: {
  busy: boolean;
  onStart: (input: CreateHostedRuntimeReviewInput) => void;
}) {
  const titleId = useId();
  const [expanded, setExpanded] = useState(false);
  const [appName, setAppName] = useState('');
  const [runtimeUrls, setRuntimeUrls] = useState('');

  if (!expanded) {
    return (
      <section className="runtime-start-card entry-card" aria-labelledby={titleId}>
        <div className="runtime-start-icon" aria-hidden="true">↗</div>
        <div>
          <span className="eyebrow">Hosted JavaScript</span>
          <h2 id={titleId}>Review production scripts</h2>
          <p>
            Use this path for a Data Client or another app whose code runs from public URLs.
          </p>
        </div>
        <button
          className="button button-secondary"
          disabled={busy}
          onClick={() => setExpanded(true)}
        >
          Enter script URLs
        </button>
      </section>
    );
  }

  return (
    <section className="runtime-start-card runtime-start-form" aria-labelledby={titleId}>
      <div>
        <span className="eyebrow">Hosted JavaScript</span>
        <h2 id={titleId}>Add production scripts</h2>
        <p>
          Add every JavaScript URL that runs in the same test, in execution order. You will pin
          the exact file contents before Webflow runs the browser test.
        </p>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          onStart({
            appName: appName.trim(),
            runtimeUrls: runtimeUrls
              .split(/\r?\n/)
              .map((value) => value.trim())
              .filter(Boolean)
          });
        }}
      >
        <label>
          App name
          <input
            aria-label="App name"
            required
            maxLength={120}
            value={appName}
            onChange={(event) => setAppName(event.target.value)}
            placeholder="Your app name"
          />
        </label>
        <label>
          Production JavaScript URLs
          <textarea
            aria-label="Hosted runtime URLs"
            required
            rows={4}
            value={runtimeUrls}
            onChange={(event) => setRuntimeUrls(event.target.value)}
            placeholder={'https://cdn.example.com/runtime-v1.js\nhttps://cdn.example.com/child-v1.js'}
          />
          <small>Enter one public HTTPS URL per line. Do not include credentials.</small>
        </label>
        <div className="runtime-start-actions">
          <button
            className="button button-tertiary"
            type="button"
            onClick={() => setExpanded(false)}
          >
            Cancel
          </button>
          <button className="button button-primary" disabled={busy} type="submit">
            {busy ? 'Saving scripts…' : 'Continue'}
          </button>
        </div>
      </form>
    </section>
  );
}

function History({
  items,
  busy,
  onSelect
}: {
  items: ReviewSummary[];
  busy: boolean;
  onSelect: (id: string) => void;
}) {
  if (items.length === 0) return null;
  return (
    <section className="history" aria-labelledby="history-title">
      <div className="section-heading">
        <h2 id="history-title">Your review runs</h2>
        <span>{items.length}</span>
      </div>
      <div className="history-list">
        {items.map((item) => {
          const runtimePending = item.coverage.some(
            (coverage) =>
              coverage.surface === 'production_runtime' &&
              coverage.status === 'needs_verification'
          );
          const status = item.readiness === 'changes_required'
            ? 'changes_required'
            : runtimePending
              ? 'needs_verification'
              : 'ready';
          const statusLabel = status === 'changes_required'
            ? 'Changes needed'
            : status === 'needs_verification'
              ? 'Runtime test needed'
              : 'Ready for review';
          return (
            <button
              className="history-row"
              key={item.id}
              disabled={busy}
              onClick={() => onSelect(item.id)}
            >
              <span>
                <strong>{item.name}</strong>
                <small>
                  {item.reviewType === 'runtime_manifest'
                    ? 'Runtime manifest'
                    : `Revision ${item.latestSequence}`} · {formatDate(item.updatedAt)}
                </small>
              </span>
              <span className={`readiness-status ${status}`}>
                <span className={`readiness-dot ${status}`} aria-hidden="true" />
                {statusLabel}
              </span>
            </button>
          );
        })}
      </div>
    </section>
  );
}

function Coverage({
  review,
  testPackages
}: {
  review: StoredReview;
  testPackages: RuntimeTestPackageView[];
}) {
  const observed = testPackages.find(
    (testPackage) =>
      testPackage.reviewVersionId === review.latestVersion.id &&
      testPackage.observation?.trust === 'webflow_observed'
  )?.observation?.evidence;
  const coverage = review.latestVersion.result.coverage.map((item) => {
    if (item.surface !== 'production_runtime' || !observed) return item;
    return {
      ...item,
      status: 'reviewed' as const,
      label: 'Production runtime observed',
      detail: observed.securityStatus === 'passed'
        ? 'Webflow captured the published runtime and its pinned security checks passed.'
        : 'Webflow captured the published runtime. Security blockers remain in the result below.'
    };
  });

  return (
    <section className="coverage-grid" aria-label="Review coverage">
      {coverage.map((item) => (
        <article className={`coverage-card ${item.status}`} key={item.surface}>
          <div className="coverage-mark" aria-hidden="true">
            {item.status === 'reviewed' ? '✓' : '!'}
          </div>
          <div>
            <h3>{item.label}</h3>
            <p>{item.detail}</p>
          </div>
        </article>
      ))}
    </section>
  );
}

function GuidanceCard({ item }: { item: ReviewGuidance }) {
  return (
    <details className={`finding-card ${item.label.toLowerCase().replaceAll(' ', '-')}`}>
      <summary>
        <span className="finding-state">{statusLabel(item)}</span>
        <span className="finding-title">
          <strong>{item.title}</strong>
          <small>{item.evidence.length} evidence location{item.evidence.length === 1 ? '' : 's'}</small>
        </span>
        <span className="chevron" aria-hidden="true">⌄</span>
      </summary>
      <div className="finding-body">
        <p>{item.explanation}</p>
        <div className="next-move">
          <span>Next move</span>
          <p>{item.nextMove}</p>
        </div>
        {item.evidence.map((evidence, index) => (
          <div className="evidence" key={`${evidence.filePath}:${evidence.line}:${index}`}>
            <code>{evidence.filePath}:{evidence.line}</code>
            <pre>{evidence.snippet}</pre>
          </div>
        ))}
      </div>
    </details>
  );
}

function Comparison({ comparison }: { comparison: ReviewComparison }) {
  return (
    <section className="comparison" aria-label="Revision progress">
      <div><strong>{comparison.resolved.length}</strong><span>Resolved</span></div>
      <div><strong>{comparison.remaining.length}</strong><span>Remaining</span></div>
      <div><strong>{comparison.added.length}</strong><span>New</span></div>
    </section>
  );
}

function RuntimeObservationCard({
  review,
  testPackages,
  busy,
  runtimeError,
  authenticatedSiteId,
  onPrepare,
  onRun,
  onRefresh
}: {
  review: StoredReview;
  testPackages: RuntimeTestPackageView[];
  busy: boolean;
  runtimeError: string | null;
  authenticatedSiteId: string | null;
  onPrepare: (input: RuntimeTestPackageInput) => void;
  onRun: (testPackageId: string) => void;
  onRefresh: () => void;
}) {
  const latest = testPackages.find(
    (testPackage) => testPackage.reviewVersionId === review.latestVersion.id
  ) ?? null;
  const previous = testPackages.find(
    (testPackage) => testPackage.reviewVersionId !== review.latestVersion.id
  ) ?? null;
  const discoveredArtifactUrl =
    review.latestVersion.result.runtime.references.find((value) => !value.includes('{')) ?? '';
  const discoveredArtifacts = review.latestVersion.result.runtime.references
    .filter((value) => !value.includes('{'))
    .map((url) => ({ url, sha256: '', integrity: '', loadMode: 'document' as const }));
  const dialogTitle = useId();
  const [confirm, setConfirm] = useState(false);
  const [targetUrl, setTargetUrl] = useState('');
  const [sandboxInstallationId, setSandboxInstallationId] = useState(
    authenticatedSiteId ?? ''
  );
  const [runtimeArtifacts, setRuntimeArtifacts] = useState<
    RuntimeTestPackageInput['runtimeArtifacts']
  >(discoveredArtifacts.length > 0
    ? discoveredArtifacts
    : [{ url: discoveredArtifactUrl, sha256: '', integrity: '', loadMode: 'document' }]);
  const [readySelector, setReadySelector] = useState('[data-runtime-ready]');
  const [proxyMode, setProxyMode] = useState<'probe' | 'none_declared'>('probe');
  const [proxyTemplate, setProxyTemplate] = useState('');
  const [showNewPackage, setShowNewPackage] = useState(false);
  const [inputError, setInputError] = useState<string | null>(null);
  const cardRef = useRef<HTMLElement>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const setupButtonRef = useRef<HTMLButtonElement>(null);
  const cancelConfirmationRef = useRef<HTMLButtonElement>(null);
  const actionableError = inputError;
  const trustLabel = latest?.observation?.trust === 'webflow_observed'
    ? 'Webflow observed'
    : latest
      ? 'Partner supplied'
      : 'Not prepared';
  const canRequestRun =
    !latest?.observation ||
    latest.observation.status === 'complete' ||
    latest.observation.status === 'failed' ||
    latest.observation.status === 'expired' ||
    latest.observation.status === 'revoked';
  const observedIssues = latest ? runtimeIssues(latest) : [];
  const runtimeOnly = review.latestVersion.result.artifact.kind === 'runtime_manifest';

  useEffect(() => {
    setShowNewPackage(false);
  }, [latest?.id]);

  const fillFromPackage = (source: RuntimeTestPackageView | null) => {
    setInputError(null);
    setTargetUrl(source?.target.url ?? '');
    setSandboxInstallationId(authenticatedSiteId ?? source?.sandboxInstallationId ?? '');
    setRuntimeArtifacts(
      source?.runtimeArtifacts.length
        ? source.runtimeArtifacts.map((artifact) => ({
            ...artifact,
            loadMode: artifact.loadMode ?? 'document'
          }))
        : discoveredArtifacts.length > 0
          ? discoveredArtifacts
          : [{ url: discoveredArtifactUrl, sha256: '', integrity: '', loadMode: 'document' }]
    );
    setReadySelector(source?.lifecycle.readySelector ?? '[data-runtime-ready]');
    setProxyMode(source?.negativeProxyProbe.mode === 'none_declared' ? 'none_declared' : 'probe');
    setProxyTemplate(
      source?.negativeProxyProbe.mode === 'none_declared'
        ? ''
        : source?.negativeProxyProbe.urlTemplate ?? ''
    );
  };

  useEffect(() => {
    if (latest) return;
    fillFromPackage(previous);
  }, [review.latestVersion.id, previous?.id]);

  useEffect(() => {
    if (authenticatedSiteId) setSandboxInstallationId(authenticatedSiteId);
  }, [authenticatedSiteId]);

  useEffect(() => {
    setInputError(runtimeError);
  }, [runtimeError]);

  useEffect(() => {
    if (!actionableError || !errorRef.current) return;
    errorRef.current.focus({ preventScroll: true });
    errorRef.current.scrollIntoView?.({ behavior: 'smooth', block: 'center' });
  }, [actionableError]);

  useEffect(() => {
    if (confirm) cancelConfirmationRef.current?.focus();
  }, [confirm]);

  const closeConfirmation = () => {
    setConfirm(false);
    setupButtonRef.current?.focus();
  };

  const submit = () => {
    onPrepare({
      targetUrl,
      sandboxInstallationId,
      sandboxOwnershipConfirmed: true,
      license: {
        mode: 'installation_allowlist',
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
      },
      runtimeArtifacts,
      negativeProxyProbe:
        proxyMode === 'none_declared'
          ? { mode: 'none_declared', declaration: 'no_proxy_surface' }
          : { mode: 'probe', method: 'GET', urlTemplate: proxyTemplate },
      lifecycle: {
        readySelector
      }
    });
  };

  return (
    <section
      ref={cardRef}
      className="runtime-card observation-card"
      aria-labelledby="observation-title"
      tabIndex={-1}
    >
      <div className="runtime-heading">
        <div>
          <span className="eyebrow">Webflow browser test</span>
          <h2 id="observation-title">Test the published runtime</h2>
        </div>
        <span
          className={`manual-pill ${latest?.observation?.trust ? 'approved' : ''}`}
          aria-label={`Current evidence: ${trustLabel}`}
        >
          {trustLabel}
        </span>
      </div>
      <p>
        Webflow opens the published test site in a fresh browser and records what the runtime
        loads. The result helps a reviewer; it does not approve or reject the app.
      </p>
      {actionableError ? (
        <div ref={errorRef} className="error-banner" role="alert" tabIndex={-1}>
          {actionableError}
        </div>
      ) : null}

      {latest && !showNewPackage ? (
        <div className="observation-status" role="status">
          <div className="checkpoint-row">
            <span className="checkpoint-number">1</span>
            <div>
              <strong>Test setup saved</strong>
              <p>{latest.target.url}</p>
              <small>
                Bound to {runtimeOnly ? 'runtime manifest' : 'bundle'}{' '}
                {latest.bundleSha256.slice(0, 12)}…
              </small>
            </div>
          </div>
          {latest.observation?.trust === 'webflow_observed' && latest.observation.evidence ? (
            <>
              <div className="checkpoint-row complete">
                <span className="checkpoint-number">2</span>
                <div>
                  <strong>Webflow captured the result</strong>
                  <p>
                    {latest.observation.evidence.runtimeFiles.length} declared runtime{' '}
                    {latest.observation.evidence.runtimeFiles.length === 1 ? 'file' : 'files'} observed
                    {' · '}{latest.observation.evidence.artifactCount} evidence{' '}
                    {latest.observation.evidence.artifactCount === 1 ? 'artifact' : 'artifacts'}
                  </p>
                </div>
              </div>
              <div className="observation-results">
                <div className={latest.observation.evidence.securityStatus === 'passed' ? 'pass' : 'fail'}>
                  <strong>
                    {latest.observation.evidence.securityStatus === 'passed'
                      ? 'Runtime security passed'
                      : `${observedIssues.length} ${observedIssues.length === 1 ? 'check needs' : 'checks need'} attention`}
                  </strong>
                  <span>
                    {latest.observation.evidence.securityStatus === 'passed'
                      ? 'Published code matched its reviewed hash and SRI requirements.'
                      : 'Fix each item, publish the test site, then run the test again.'}
                  </span>
                </div>
                <div
                  className={
                    latest.observation.evidence.negativeProxyOutcome === 'blocked'
                      ? 'pass'
                      : latest.observation.evidence.negativeProxyOutcome === 'not_applicable'
                        ? 'neutral'
                        : 'fail'
                  }
                >
                  <strong>
                    {latest.observation.evidence.negativeProxyOutcome === 'blocked'
                      ? 'Proxy canary blocked'
                      : latest.observation.evidence.negativeProxyOutcome === 'not_applicable'
                        ? 'Proxy check not applicable'
                      : latest.observation.evidence.negativeProxyOutcome === 'exposed'
                        ? 'Proxy canary exposed'
                        : 'Proxy canary inconclusive'}
                  </strong>
                  <span>
                    {latest.observation.evidence.negativeProxyOutcome === 'not_applicable'
                      ? 'Developer declared no proxy or fetch-through surface. A reviewer can verify this declaration.'
                      : 'This is observed evidence, not an approval decision.'}
                  </span>
                </div>
              </div>
              {observedIssues.length > 0 ? (
                <section className="runtime-issues" aria-labelledby="runtime-issues-title">
                  <div className="runtime-issues-heading">
                    <h3 id="runtime-issues-title">What to fix</h3>
                    <span>{observedIssues.length}</span>
                  </div>
                  <ol>
                    {observedIssues.map((issue) => (
                      <li key={issue.title}>
                        <div className="runtime-issue-number" aria-hidden="true" />
                        <div>
                          <strong>{issue.title}</strong>
                          <p>{issue.detail}</p>
                          {issue.urls && issue.urls.length > 0 ? (
                            <ul className="runtime-issue-files">
                              {issue.urls.map((url) => (
                                <li key={url}><code>{runtimeFileName(url) ?? url}</code></li>
                              ))}
                            </ul>
                          ) : null}
                          <div className="runtime-issue-action">
                            <span>Next step</span>
                            <p>{issue.nextMove}</p>
                          </div>
                        </div>
                      </li>
                    ))}
                  </ol>
                </section>
              ) : null}
              <details
                className="runtime-file-results"
                open={latest.observation.evidence.securityStatus === 'blocked' || undefined}
              >
                <summary>Runtime file results</summary>
                <ul>
                  {latest.observation.evidence.runtimeFiles.map((runtimeFile, index) => {
                    const name = runtimeFileName(runtimeFile.url) ?? `Runtime file ${index + 1}`;
                    return (
                      <li
                        key={runtimeFile.url}
                        aria-label={`Runtime file result: ${name}`}
                      >
                        <div className="runtime-result-heading">
                          <strong>{name}</strong>
                          <code>{runtimeFile.url}</code>
                        </div>
                        <div className="runtime-result-checks">
                          <span className={runtimeFile.loadedByPage ? 'pass' : 'fail'}>
                            {runtimeFile.loadedByPage ? 'Loaded' : 'Not loaded'}
                          </span>
                          <span className={runtimeFile.hashMatched ? 'pass' : 'fail'}>
                            {runtimeFile.hashMatched ? 'Hash matched' : 'Hash mismatch'}
                          </span>
                          <span className={runtimeFile.integrityMatched ? 'pass' : 'fail'}>
                            {runtimeFile.loadMode === 'runtime_child'
                              ? runtimeFile.integrityMatched
                                ? 'Pinned parent verified'
                                : 'Pinned parent not verified'
                              : runtimeFile.integrityMatched
                                ? 'SRI matched'
                                : 'SRI mismatch'}
                          </span>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              </details>
              <details className="artifact-details">
                <summary>Evidence artifact details</summary>
                <ul>
                  {latest.observation.evidence.artifacts.map((artifact) => (
                    <li key={`${artifact.kind}:${artifact.sha256}`}>
                      <span>{artifact.kind.replaceAll('_', ' ')}</span>
                      <code>{artifact.sha256.slice(0, 12)}… · {artifact.bytes} bytes</code>
                    </li>
                  ))}
                </ul>
              </details>
            </>
          ) : latest.observation ? (
            <div className="checkpoint-row active">
              <span className="checkpoint-number">2</span>
              <div>
                <strong>Webflow test {latest.observation.status}</strong>
                <p>Webflow is running the test in a fresh browser.</p>
              </div>
            </div>
          ) : (
            <div className="checkpoint-row pending">
              <div>
                <strong>Ready to test</strong>
                <p>Run the test after the scripts are published on this test site.</p>
              </div>
            </div>
          )}
          {canRequestRun ? (
            <button
              className="button button-primary"
              disabled={busy}
              onClick={() => onRun(latest.id)}
            >
              {busy
                ? 'Starting Webflow test…'
                : latest.observation
                  ? 'Run Webflow test again'
                  : 'Run Webflow test'}
            </button>
          ) : null}
          <button className="button button-secondary" disabled={busy} onClick={onRefresh}>
            Refresh results
          </button>
          <button
            className="button button-tertiary"
            disabled={busy}
            onClick={() => {
              fillFromPackage(latest);
              setShowNewPackage(true);
            }}
          >
            Edit test setup
          </button>
        </div>
      ) : (
        <form
          className="observation-form"
          onSubmit={(event) => {
            event.preventDefault();
            const duplicateIndex = runtimeArtifacts.findIndex(
              (_, index) => duplicateRuntimePosition(runtimeArtifacts, index) !== null
            );
            if (duplicateIndex >= 0) {
              const previousIndex = duplicateRuntimePosition(runtimeArtifacts, duplicateIndex)!;
              setInputError(
                `Runtime file ${duplicateIndex + 1} duplicates runtime file ${previousIndex + 1}. Use each immutable URL once.`
              );
              return;
            }
            setInputError(null);
            setConfirm(true);
          }}
        >
          {previous ? (
            <div className="prefill-note" role="status">
              <strong>Previous setup loaded</strong>
              <p>
                We reused the last test site, script pins, ready signal, and proxy check. Review
                each value before continuing; Webflow will test every script again.
              </p>
            </div>
          ) : null}
          <fieldset>
            <legend><span>1</span> Use a dedicated test site</legend>
            <label>
              Published Webflow test URL
              <input aria-label="Published Webflow test URL" required type="url" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="https://app-review-sandbox.webflow.io" />
              <small>
                Use the published test page, not its Designer URL. Keep customer data and
                production credentials out of this site.
              </small>
            </label>
            <label>
              Webflow installation or site ID
              <input
                aria-label="Webflow installation or site ID"
                required
                readOnly
                value={sandboxInstallationId}
                placeholder="Open this extension from the dedicated test site"
              />
              <small>
                Preflight fills this from the site open in Designer so the test cannot be attached
                to a different site.
              </small>
            </label>
          </fieldset>
          <fieldset>
            <legend><span>2</span> Pin each production script</legend>
            <p className="runtime-set-intro">
              List every JavaScript file that runs in this test. Each one needs its exact SHA-256;
              Preflight calculates the matching SRI value.
            </p>
            <details className="runtime-guide">
              <summary>How to find and pin runtime files</summary>
              <div className="runtime-guide-body">
                <section>
                  <h3>1. Find every runtime file</h3>
                  <p>
                    A runtime is JavaScript that your app loads on the published site, outside
                    the uploaded app bundle. Start with the script in your install instructions.
                  </p>
                  <ol>
                    <li>Open the published test page in a new browser tab.</li>
                    <li>Open Developer Tools, choose Network, and filter for JavaScript.</li>
                    <li>Reload the page and exercise the app once.</li>
                    <li>
                      Record the entry script, then include every child script it creates as a
                      separate runtime file.
                    </li>
                  </ol>
                  <p>
                    Region, plan, or release alternatives belong in separate test packages when
                    they do not execute together.
                  </p>
                </section>
                <section>
                  <h3>2. Download the exact bytes</h3>
                  <p>
                    Fetch the same URL used by the published page. The referrer matters for some
                    runtime hosts. Replace both example values before running these commands.
                  </p>
                  <pre><code>{`TEST_URL="https://your-test-site.webflow.io"
RUNTIME_URL="https://cdn.example.com/runtime.js"

curl --fail --silent --show-error --location \\
  --referer "$TEST_URL/" \\
  "$RUNTIME_URL" \\
  --output /tmp/reviewed-runtime.js

shasum -a 256 /tmp/reviewed-runtime.js

printf 'sha256-'
openssl dgst -sha256 -binary /tmp/reviewed-runtime.js \\
  | openssl base64 -A`}</code></pre>
                  <p>
                    If the download is blocked, do not hash an error page. Confirm the URL,
                    publish state, test-site allowlist, and vendor access rules first.
                  </p>
                </section>
                <section>
                  <h3>3. Understand the two pins</h3>
                  <dl>
                    <div>
                      <dt>SHA-256</dt>
                      <dd>
                        SHA-256 is the 64-character fingerprint of the downloaded file. Paste the
                        lowercase value printed before the temporary filename.
                      </dd>
                    </div>
                    <div>
                      <dt>SRI</dt>
                      <dd>
                        SRI is the same fingerprint encoded for a script tag. It starts with
                        <code>sha256-</code> and lets the browser reject different bytes.
                      </dd>
                    </div>
                  </dl>
                  <p>
                    For a page-loaded file, put the SRI value in the published script's{' '}
                    <code>integrity</code> attribute and add{' '}
                    <code>crossorigin=&quot;anonymous&quot;</code> only when the script response allows
                    cross-origin reads with an <code>Access-Control-Allow-Origin</code> header. If
                    the vendor does not send that header, browser SRI will block the script. Keep
                    the test page working without the SRI attributes, keep the calculated pin in
                    this package, and run the test. The result will correctly report missing
                    browser-enforced SRI as a blocker. Ask the vendor to add CORS before expecting
                    that check to pass. For a vendor-created child file, select “Loaded by another
                    pinned runtime.” Webflow will require the child bytes to match their pin and
                    prove that another pinned runtime initiated the request.
                  </p>
                </section>
              </div>
            </details>
            {runtimeArtifacts.map((artifact, index) => {
              const number = index + 1;
              const suffix = index === 0 ? '' : ` — file ${number}`;
              const fileName = runtimeFileName(artifact.url);
              const duplicateIndex = duplicateRuntimePosition(runtimeArtifacts, index);
              const update = (
                field: 'url' | 'sha256',
                value: string
              ) => {
                setInputError(null);
                setRuntimeArtifacts((current) =>
                  current.map((item, itemIndex) =>
                    itemIndex === index
                      ? field === 'sha256'
                        ? { ...item, sha256: value, integrity: sriFromSha256(value) }
                        : { ...item, [field]: value }
                      : item
                  )
                );
              };
              return (
                <section className="runtime-file" key={index}>
                  <div className="runtime-file-heading">
                    <h3>Runtime file {number}</h3>
                    {fileName ? <code className="runtime-file-name">{fileName}</code> : null}
                    {index > 0 ? (
                      <button
                        className="button button-tertiary"
                        type="button"
                        aria-label={`Remove runtime file ${number}`}
                        onClick={() => {
                          setRuntimeArtifacts((current) =>
                            current.filter((_, itemIndex) => itemIndex !== index)
                          );
                        }}
                      >
                        Remove
                      </button>
                    ) : null}
                  </div>
                  <label>
                    {`Versioned runtime URL${suffix}`}
                    <input
                      aria-label={`Versioned runtime URL${suffix}`}
                      required
                      type="url"
                      value={artifact.url}
                      aria-invalid={duplicateIndex !== null || undefined}
                      onChange={(event) => update('url', event.target.value)}
                    />
                    <small>
                      Use the exact JavaScript request from the published test page. The URL should
                      keep serving the same bytes after review.
                    </small>
                    {duplicateIndex !== null ? (
                      <small className="field-error">
                        Duplicates runtime file {duplicateIndex + 1}.
                      </small>
                    ) : null}
                  </label>
                  <fieldset className="runtime-load-choice">
                    <legend>{`How runtime file ${number} loads`}</legend>
                    <label>
                      <input
                        type="radio"
                        name={`runtime-load-mode-${index}`}
                        value="document"
                        checked={(artifact.loadMode ?? 'document') === 'document'}
                        onChange={() => {
                          setInputError(null);
                          setRuntimeArtifacts((current) =>
                            current.map((item, itemIndex) =>
                              itemIndex === index ? { ...item, loadMode: 'document' } : item
                            )
                          );
                        }}
                      />
                      Loaded directly by the published page
                    </label>
                    <label>
                      <input
                        type="radio"
                        name={`runtime-load-mode-${index}`}
                        value="runtime_child"
                        checked={artifact.loadMode === 'runtime_child'}
                        onChange={() => {
                          setInputError(null);
                          setRuntimeArtifacts((current) =>
                            current.map((item, itemIndex) =>
                              itemIndex === index ? { ...item, loadMode: 'runtime_child' } : item
                            )
                          );
                        }}
                      />
                      Loaded by another pinned runtime
                    </label>
                    <small>
                      Page-loaded files must carry this SRI in the DOM. Child files must be
                      requested by another pinned runtime and match their own SHA-256.
                    </small>
                  </fieldset>
                  <label>
                    {`SHA-256${suffix}`}
                    <input aria-label={`SHA-256${suffix}`} required pattern="[a-f0-9]{64}" value={artifact.sha256} onChange={(event) => update('sha256', event.target.value)} placeholder="64 lowercase hex characters" />
                    <small>
                      Paste the lowercase SHA-256 of the downloaded JavaScript bytes—not the zip
                      bundle and not a browser error response.
                    </small>
                  </label>
                  <label>
                    {`Script integrity (SRI)${suffix}`}
                    <input
                      required
                      readOnly
                      aria-label={`Script integrity (SRI)${suffix}`}
                      value={artifact.integrity}
                      placeholder="Calculated from SHA-256"
                    />
                    <small>
                      This app calculates SRI from the SHA-256 above. For a page-loaded file,
                      publish this exact value in the script's <code>integrity</code> attribute.
                      For a child file, it remains the human-readable form of the verified pin.
                    </small>
                  </label>
                </section>
              );
            })}
            <details className="runtime-set-settings" open={runtimeArtifacts.length > 1 || undefined}>
              <summary>More runtime files</summary>
              <p>
                Add a file only when it must execute in this same test. Use another test package
                for region, plan, or build variants that do not run together.
              </p>
              <button
                className="button button-secondary"
                type="button"
                onClick={() => {
                  setRuntimeArtifacts((current) =>
                    [...current, {
                      url: '',
                      sha256: '',
                      integrity: '',
                      loadMode: 'runtime_child'
                    }]
                  );
                }}
              >
                Add another runtime file
              </button>
            </details>
          </fieldset>
          <fieldset className="proxy-choice proxy-choice-primary">
            <legend>Does your app proxy or fetch another URL for customers?</legend>
            <p className="field-intro">
              Choose the option that matches your app. This lets us test a real proxy when one
              exists, without asking you to invent a test for a feature you do not have.
            </p>
            <label>
              <input
                type="radio"
                name="proxy-mode"
                value="probe"
                checked={proxyMode === 'probe'}
                onChange={() => setProxyMode('probe')}
              />
              Yes — test my real proxy endpoint
            </label>
            <label>
              <input
                type="radio"
                name="proxy-mode"
                value="none_declared"
                checked={proxyMode === 'none_declared'}
                onChange={() => {
                  setProxyMode('none_declared');
                  setProxyTemplate('');
                }}
              />
              No — this app has no proxy or fetch-through surface
            </label>
            {proxyMode === 'probe' ? (
              <label>
                Proxy probe URL template
                <input aria-label="Proxy probe URL template" required value={proxyTemplate} onChange={(event) => setProxyTemplate(event.target.value)} placeholder="https://api.example.com/proxy?url={canaryUrl}" />
                <small>
                  Use your app's real proxy or fetch-through endpoint and include{' '}
                  <code>{'{canaryUrl}'}</code> exactly once. If you are unsure whether your app
                  has one, choose “No” and flag it for the human reviewer.
                </small>
              </label>
            ) : (
              <div className="proxy-declaration" role="status">
                <strong>Proxy check: not applicable</strong>
                <p>
                  The package records your declaration for the reviewer. Webflow will not run a
                  proxy test or treat this declaration as proof.
                </p>
              </div>
            )}
          </fieldset>
          <details className="advanced-settings">
            <summary>Ready signal</summary>
            <label>
              Ready selector
              <input aria-label="Ready selector" required value={readySelector} onChange={(event) => setReadySelector(event.target.value)} />
              <small>
                Use a stable element or data attribute that appears only after every runtime file
                is usable. Check it on the published page with{' '}
                <code>document.querySelector('your-selector')</code>; the result must be an
                element. A JavaScript flag such as <code>window.vendor.ready</code> is not a CSS
                selector—have the runtime's ready event add a data attribute first.
              </small>
            </label>
          </details>
          <button ref={setupButtonRef} className="button button-primary" disabled={busy} type="submit">
            Review test setup
          </button>
          <small>Do not use a customer site or enter passwords, session exports, or license secrets.</small>
        </form>
      )}

      <details className="trust-details">
        <summary>What the evidence labels mean</summary>
        <dl>
          <div><dt>Partner supplied</dt><dd>The developer entered these settings. They are not evidence.</dd></div>
          <div><dt>Webflow observed</dt><dd>Webflow captured this result in a controlled browser.</dd></div>
          <div><dt>Human verified</dt><dd>A reviewer checked the evidence and conclusion.</dd></div>
        </dl>
      </details>

      {confirm ? (
        <div
          className="dialog-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby={dialogTitle}
          onKeyDown={(event) => {
            if (event.key === 'Escape') closeConfirmation();
          }}
        >
          <div className="dialog-card">
            <span className="eyebrow">Before you continue</span>
            <h2 id={dialogTitle}>Confirm test access</h2>
            <p>
              Use a dedicated Webflow test site with no customer data. Allow this site to run the
              app for the next 24 hours. Webflow—not this browser—will run the test.
            </p>
            <p>
              {runtimeArtifacts.length} runtime {runtimeArtifacts.length === 1 ? 'file' : 'files'} will
              be tested together.
            </p>
            <ul>
              <li>Each production script is pinned to the bytes you reviewed</li>
              <li>Webflow captures the result in a fresh browser</li>
              <li>A human reviewer makes the final decision</li>
            </ul>
            <div className="dialog-actions">
              <button ref={cancelConfirmationRef} className="button button-secondary" onClick={closeConfirmation}>Cancel</button>
              <button
                className="button button-primary"
                onClick={() => {
                  setConfirm(false);
                  submit();
                }}
              >
                Save test setup
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}

function ReviewDetail({
  review,
  comparison,
  runtimeTestPackages,
  busy,
  runtimeError,
  authenticatedSiteId,
  onRevision,
  onPrepareRuntimePackage,
  onRunRuntimeObservation,
  onRefreshRuntimePackages,
  reviewerHandoff,
  reviewerMode,
  onCreateReviewerHandoff,
  onBack
}: {
  review: StoredReview;
  comparison: ReviewComparison | null;
  runtimeTestPackages: RuntimeTestPackageView[];
  busy: boolean;
  runtimeError: string | null;
  authenticatedSiteId: string | null;
  onRevision: (file: File) => void;
  onPrepareRuntimePackage: (input: RuntimeTestPackageInput) => void;
  onRunRuntimeObservation: (testPackageId: string) => void;
  onRefreshRuntimePackages: () => void;
  reviewerHandoff: ReviewerHandoff | null;
  reviewerMode: boolean;
  onCreateReviewerHandoff: (testPackageId: string) => void;
  onBack: () => void;
}) {
  const result = review.latestVersion.result;
  const runtimeOnly = result.artifact.kind === 'runtime_manifest';
  const revisionId = useId();
  const blockerText = result.summary.securityBlockers === 1 ? 'blocker' : 'blockers';
  const readinessMessage = runtimeOnly
    ? 'Script list saved. Set up a Webflow test to observe the published runtime.'
    : result.summary.securityBlockers > 0
    ? `Fix ${result.summary.securityBlockers} ${blockerText} before review.`
    : result.runtime.status === 'discovered_unverified'
      ? 'Bundle scan finished. Test the production runtime next.'
      : 'Preflight checks complete. Send the evidence to a human reviewer.';

  return (
    <main className="review-view">
      <button className="back-button" onClick={onBack}>← All runs</button>
      <header className="review-header">
        <div className="eyebrow">
          {runtimeOnly ? 'Data Client runtime' : `Revision ${review.latestVersion.sequence}`}
        </div>
        <h2>{result.artifactScope.appName ?? review.name}</h2>
        <p>
          {readinessMessage}
        </p>
        <div className="saved-state"><span>✓</span> Saved</div>
      </header>

      {comparison ? <Comparison comparison={comparison} /> : null}
      <Coverage review={review} testPackages={runtimeTestPackages} />

      {!runtimeOnly ? <section className="summary-grid" aria-label="Finding summary">
        <div><strong>{result.summary.securityBlockers}</strong><span>Security blockers</span></div>
        <div><strong>{result.summary.requiredUpdates}</strong><span>Required updates</span></div>
        <div><strong>{result.summary.suggestedUpdates}</strong><span>Suggested updates</span></div>
      </section> : null}

      {!runtimeOnly || result.guidance.length > 0 ? (
        <section className="findings" aria-labelledby="findings-title">
          <div className="section-heading">
            <h2 id="findings-title">Review feedback</h2>
            <span>{result.guidance.length}</span>
          </div>
          {result.guidance.length > 0 ? (
            result.guidance.map((item) => <GuidanceCard item={item} key={item.id} />)
          ) : (
            <div className="success-card">
              <strong>Ready for human review</strong>
              <p>
                The bundle scan found no remaining deterministic issues. A reviewer still makes
                the Marketplace decision.
              </p>
            </div>
          )}
        </section>
      ) : null}

      <RuntimeObservationCard
        review={review}
        testPackages={runtimeTestPackages}
        busy={busy}
        runtimeError={runtimeError}
        authenticatedSiteId={authenticatedSiteId}
        onPrepare={onPrepareRuntimePackage}
        onRun={onRunRuntimeObservation}
        onRefresh={onRefreshRuntimePackages}
      />

      {reviewerMode && runtimeTestPackages[0]?.status === 'ready' ? (
        <section className="revision-card">
          <div>
            <span className="eyebrow">Reviewer workspace</span>
            <h2>Inspect and replay this exact package</h2>
            <p>Open the server-owned review surface to compare prior observations and request an independent runtime replay.</p>
          </div>
          {reviewerHandoff ? (
            <a
              className="button button-primary"
              href={reviewerHandoff.url}
              target="_blank"
              rel="noreferrer noopener"
            >
              Open reviewer workspace
            </a>
          ) : (
            <button
              className="button button-primary"
              disabled={busy}
              onClick={() => onCreateReviewerHandoff(runtimeTestPackages[0]!.id)}
            >
              {busy ? 'Preparing…' : 'Create reviewer workspace'}
            </button>
          )}
        </section>
      ) : null}

      {!runtimeOnly ? <section className="revision-card">
        <div>
          <span className="eyebrow">Next move</span>
          <h2>Upload a revised bundle</h2>
          <p>We will compare it with this checkpoint and show exactly what changed.</p>
        </div>
        <label className="button button-primary" htmlFor={revisionId}>
          {busy ? 'Comparing…' : 'Upload revision'}
        </label>
        <input
          id={revisionId}
          className="visually-hidden"
          type="file"
          accept=".zip,application/zip"
          disabled={busy}
          onChange={(event) => {
            const file = event.currentTarget.files?.[0];
            if (file) onRevision(file);
            event.currentTarget.value = '';
          }}
        />
      </section> : null}
    </main>
  );
}

export function App({ api }: { api: PreflightApi }) {
  const [history, setHistory] = useState<ReviewSummary[]>([]);
  const [review, setReview] = useState<StoredReview | null>(null);
  const [comparison, setComparison] = useState<ReviewComparison | null>(null);
  const [runtimeTestPackages, setRuntimeTestPackages] = useState<RuntimeTestPackageView[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [runtimeError, setRuntimeError] = useState<string | null>(null);
  const [identity, setIdentity] = useState<PreflightIdentity | null>(null);
  const [reviewerHandoff, setReviewerHandoff] = useState<ReviewerHandoff | null>(null);

  const refreshHistory = async () => {
    const items = await api.listReviews();
    setHistory(items);
    return items;
  };

  const refreshRuntimePackages = async (reviewId: string) => {
    const items = await api.listRuntimeTestPackages(reviewId);
    setRuntimeTestPackages(items);
    return items;
  };

  useEffect(() => {
    (async () => {
      const items = await refreshHistory();
      const selectedId = rememberedReviewId();
      if (!selectedId) return;
      if (!items.some((item) => item.id === selectedId)) {
        rememberReview(null);
        return;
      }
      try {
        const [selectedReview] = await Promise.all([
          api.getReview(selectedId),
          refreshRuntimePackages(selectedId)
        ]);
        setReview(selectedReview);
      } catch {
        rememberReview(null);
      }
    })().catch((cause: unknown) => {
      setError(cause instanceof Error ? cause.message : 'Saved runs are unavailable.');
    });
  }, []);

  useEffect(() => {
    api.getIdentity().then(setIdentity).catch((cause: unknown) => {
      setError(cause instanceof Error ? cause.message : 'Webflow identity is unavailable.');
    });
  }, []);

  const run = async (
    action: () => Promise<void>,
    onError: (message: string) => void = setError
  ) => {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : 'That step could not be completed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="app-shell">
      {error ? <div className="error-banner" role="alert">{error}</div> : null}

      {review ? (
        <ReviewDetail
          review={review}
          comparison={comparison}
          runtimeTestPackages={runtimeTestPackages}
          busy={busy}
          runtimeError={runtimeError}
          authenticatedSiteId={identity?.siteId ?? null}
          reviewerMode={identity?.companionRole === 'reviewer'}
          reviewerHandoff={reviewerHandoff}
          onBack={() => {
            setReview(null);
            setComparison(null);
            setRuntimeTestPackages([]);
            setReviewerHandoff(null);
            rememberReview(null);
          }}
          onRevision={(file) => run(async () => {
            const revised = await api.addRevision(review.id, file);
            setReview(revised.review);
            setComparison(revised.comparison);
            setReviewerHandoff(null);
            await refreshRuntimePackages(review.id);
            await refreshHistory();
          })}
          onPrepareRuntimePackage={(input) => {
            setRuntimeError(null);
            void run(async () => {
              const prepared = await api.createRuntimeTestPackage(review.id, input);
              setRuntimeTestPackages([prepared]);
            }, setRuntimeError);
          }}
          onRunRuntimeObservation={(testPackageId) => {
            setRuntimeError(null);
            void run(async () => {
              await api.requestRuntimeObservationRun(testPackageId);
              await refreshRuntimePackages(review.id);
            }, setRuntimeError);
          }}
          onRefreshRuntimePackages={() => run(async () => {
            await refreshRuntimePackages(review.id);
          })}
          onCreateReviewerHandoff={(testPackageId) => run(async () => {
            const handoff = await api.createReviewerHandoff(
              review.id,
              review.latestVersion.id,
              testPackageId
            );
            setReviewerHandoff(handoff);
          })}
        />
      ) : (
        <main className="start-view">
          <div className="intro">
            <div className="intro-meta">
              <span className="eyebrow">Review run</span>
              {identity ? (
                <div className="identity-state">
                  <span className="connection-dot" aria-hidden="true" />
                  <strong>Connected to this Webflow site</strong>
                  {identity.companionRole === 'reviewer' ? (
                    <span className="connection-role">Reviewer</span>
                  ) : null}
                </div>
              ) : null}
            </div>
            <h2>Start a preflight</h2>
            <p>Choose what the app ships. Preflight will collect evidence and show the next useful step.</p>
          </div>
          <div className="start-options">
            <UploadCard
              busy={busy}
              onFile={(file) => run(async () => {
                const created = await api.createReview(file);
                setReview(created);
                setComparison(null);
                setRuntimeTestPackages([]);
                setReviewerHandoff(null);
                rememberReview(created.id);
                await refreshHistory();
              })}
            />
            <HostedRuntimeCard
              busy={busy}
              onStart={(input) => run(async () => {
                const created = await api.createRuntimeReview(input);
                setReview(created);
                setComparison(null);
                setRuntimeTestPackages([]);
                setReviewerHandoff(null);
                rememberReview(created.id);
                await refreshHistory();
              })}
            />
          </div>
          <History
            items={history}
            busy={busy}
            onSelect={(id) => run(async () => {
              const [selectedReview] = await Promise.all([
                api.getReview(id),
                refreshRuntimePackages(id)
              ]);
              setReview(selectedReview);
              setComparison(null);
              setReviewerHandoff(null);
              rememberReview(id);
            })}
          />
          <p className="privacy-note">
            Your bundle and script list stay private. Preflight may use anonymized patterns only after a person approves them.
          </p>
        </main>
      )}
    </div>
  );
}
