# Webflow App Review Preflight

App Review Preflight is a native Webflow Designer Extension for Marketplace developers. It turns an uploaded app bundle into deterministic, scope-aware feedback, or starts directly from an immutable hosted-runtime manifest for Data Client apps that do not ship a bundle. Both paths support separately approved production-runtime evidence.

Operators should use the [App Review Preflight Operator Runbook](./OPERATOR_RUNBOOK.md) for the three-run validation loop, state decisions, failure routing, and evidence receipts.

It is a preflight and evidence system. It does not approve or reject an app.

The native Designer Extension is the developer surface for bundle feedback, immutable version history, Runtime Test Package preparation, and trusted-result readback. Reviewers use the web app to inspect submissions across developers and request independent replays. The actual production-runtime browser remains Webflow-controlled in E2B; neither interface can upload observed evidence, promote partner input to `Webflow observed`, or make an official decision.

For the Consent Pro pilot, authorization happens outside the Designer Extension. Authorization, configuration, and publication are unscored prerequisites. Uninstall cleanup is also unscored while the Custom Code API cannot reliably complete that lifecycle. The only security result comes from Webflow-controlled execution of the pinned production runtime; no user-controlled browser can issue or manufacture it.

## Hybrid App boundary

The Hybrid App has two intentional user surfaces over one evidence system:

- **Designer Extension — developer surface.** A developer uploads the exact submission bundle, prepares a dedicated site-bound Runtime Test Package, requests validation, and reads the resulting blockers. Developer access remains owner-scoped.
- **Reviewer web app — internal review surface.** An authenticated reviewer searches submissions across owners, opens any immutable revision, compares prior observations, and requests an independent replay of the exact package. Reviewer access is cross-owner, audited, and unavailable to developer identities.
- **Worker, D1, R2, and E2B — authority surface.** The Worker owns immutable bindings and audit events; R2 stores private artifacts; D1 stores versions and predicates; a server-side coordinator issues one-time E2B jobs. Neither user interface receives the coordinator token or uploads `Webflow observed` evidence.

The reviewer web app is the reason this is a Hybrid App. A separate browser extension is not part of the required architecture. Historical companion records and endpoints may remain readable during migration, but they do not appear in the active validation flow or contribute to the security result.

Reviewer reruns must preserve the original review-version ID, bundle SHA-256, published target, installation ID, complete pinned runtime set, ready selector, and negative proxy probe. A replay creates a new immutable observation linked to that package; it never overwrites an earlier result. If any required binding is stale or missing, the rerun stays blocked until a new package is prepared.

When a developer uploads a revision, the Designer Extension pre-fills the new Runtime Test Package from the most recent package for that review: the dedicated test URL, every runtime pin, selector, and proxy probe. The installation ID always comes from the Webflow site currently authenticated in Designer, so a prior package cannot silently bind a revision to another site. The form marks reused values as prior test input and asks the developer to review them. A prior package or Webflow observation never transfers to the new bundle; the new version starts unprepared and receives its own immutable evidence only after another Webflow-controlled run.

## Package boundaries

- `src/`: deterministic bundle review contract, artifact-scope detection, runtime-reference discovery, and plain-language guidance.
- `worker/`: Cloudflare Worker API with dedicated D1 metadata and private R2 bundle storage.
- `extension/`: native large right-panel Webflow Designer Extension.
- `runner/`: Webflow-controlled Playwright/E2B runtime observation runner.
- `../webflow-app-review-runtime-template/`: immutable E2B template with the runner, pinned Playwright, Chromium, and OS dependencies baked at build time.
- `migrations/`: dedicated Preflight D1 schema.

Raw partner bundles and canonical hosted-runtime manifests remain in private, owner-scoped R2 keys. They do not enter App Governance. Cross-app pattern candidates contain rule IDs, counts, dates, and generic guidance only; producing a governance handoff requires a separate authorized human approval and still performs no external write.

## Governance precision requirements

The governance backlog defines runtime integrity as the P0 rule: code that executes on a customer site must be reviewed, registered, and integrity-pinned regardless of whether it arrived through an App bundle, the Custom Code API, or a pasted loader. Preflight therefore keeps the executed-byte hash, DOM SRI, child-script inventory, source-map availability, and negative proxy result visible as separate predicates rather than collapsing them into one generic pass.

Findings must also preserve provenance. Each evidence location should identify developer-owned code or a declared third-party dependency when that can be proven. The default remains "if it is in your bundle, you own it"; a dependency finding may be reclassified only by a versioned, reviewer-owned library policy with the matching package/version and supporting evidence. A heuristic match or developer declaration alone cannot allowlist or close a blocker. This distinction improves routing and feedback without lowering the review bar.

The reviewer surface must keep bundle/source visibility, source-map gaps, iframe-only blind spots, DOM access to credential fields, and uninstall responsibility explicit. For the Consent Pro pilot, the unresolved Custom Code API uninstall limitation remains documented but unscored; it does not weaken the runtime-integrity predicates.

## Review flow

1. The extension gets a short-lived Webflow ID token. A bundle review uploads the exact zip; a Data Client review sends the app name and every exact public HTTPS runtime URL used by the same execution scenario without manufacturing a placeholder bundle. One or two files is typical, while providers that require more can declare them in order.
2. For a bundle, the Worker hashes and stores the original bytes and runs deterministic rules. For a Data Client, it creates and stores a canonical hosted-runtime manifest whose SHA-256 is bound to the review version. Both paths return artifact and production-runtime coverage separately.
3. Revisions create immutable versions and return resolved, remaining, and new rule IDs.
4. A developer prepares a version-bound Runtime Test Package in the Designer Extension. Hosted-runtime reviews prefill all declared URLs; bundle reviews prefill any discovered references. A reviewer may inspect or replay the same package from the reviewer web app. The package records the dedicated published target, installation allowlist, one to eight runtime files with individual SHA-256/SRI pins, ready selector, and negative proxy probe as test input—not evidence. Every file in one package must execute in the same scenario; mutually exclusive variants use separate packages.
5. The developer can request a fresh run for their own ready package from the Designer Extension. The Worker verifies ownership and package validity, creates the exact immutable E2B template build through E2B's control plane, and sends the one-time runner capability only to that sandbox's restricted `/run` route. Neither the Designer Extension nor the developer browser receives the capability or E2B credential.
6. Developers read the result in the Designer Extension; reviewers read the same immutable predicates, blockers, and artifact receipts in the web app. Their role changes access and authorization, not the security result.

## Complete runtime observation

Licensed and account-gated behavior uses a different trust model from the public runtime fetch:

1. The partner prepares a Runtime Test Package tied to the current review version and bundle SHA. It names a dedicated published Webflow test site, a one-hour installation allowlist, one to eight immutable runtime URLs whose individual SHA-256 and SRI values resolve to the same bytes, one runtime-ready selector, and one bounded proxy-canary template.
2. The package is labeled `Partner supplied`. It is test input, not evidence. The partner may request one fresh run for their own ready package, but cannot read its capability, upload review evidence, or change review state.
3. The Worker creates a 15-minute observation job and an E2B sandbox from the configured immutable `<template-name>:<build-id>` reference. Public sandbox traffic is disabled. The Worker uses E2B's per-sandbox traffic token to call the template's one-shot `/run` route, which places the capability in the baked runner process only; the Worker stores only its SHA-256 hash and the Designer Extension receives a safe status summary.
4. E2B opens a fresh Chromium context, proves it reached the published origin, instruments runtime-created script elements before page code executes, enforces the exact host and request budgets, masks form controls, and captures scripts, executed hashes, DOM SRI, source maps, sanitized network and console metadata, structural DOM/storage state, screenshots, and the Webflow-owned negative proxy canary.
5. The runner uploads a strict multipart manifest and artifact set. The Worker revalidates every binding, redaction receipt, type, size, and digest before writing immutable R2 objects and D1 metadata. A successful upload consumes the capability; replay fails closed.
6. The extension displays the earned `Webflow observed` result. It remains evidence only and cannot approve, reject, close a deterministic finding, or write to governance.

A partner-run browser cannot produce trusted review evidence because the partner controls both the subject and the collector. Webflow-controlled execution fixes that provenance problem, but no finite run can prove a third-party backend will never serve conditional behavior. Runtime bytes must therefore be included in the review or use immutable versioned delivery with a pinned hash/SRI. Mutable post-approval delivery remains a security blocker; random coordinator nonces, timing, and repeat runs are defense-in-depth.

## Local operation

Bootstrap the worktree, then build the domain package:

```bash
pnpm bootstrap:worktree
pnpm --filter @create-something/webflow-app-review-preflight build
```

Initialize local D1 and start the Worker with a local-only test identity:

```bash
cd packages/webflow-app-review-preflight/worker
pnpm exec wrangler d1 migrations apply webflow-app-review-preflight --local --config wrangler.jsonc
pnpm exec wrangler dev --config wrangler.jsonc --port 8787 \
  --var PREFLIGHT_DEV_TOKEN:test-token \
  --var E2B_COORDINATOR_TOKEN=coordinator-test-token \
  --var RUNTIME_CANARY_URL=http://127.0.0.1:4174/webflow-runtime-canary
```

Build and serve the extension:

```bash
cd packages/webflow-app-review-preflight/extension
pnpm build
python3 -m http.server 1337 --directory public
```

For the real Designer surface, use `pnpm serve` and add the displayed development extension through Webflow Designer. Production promotion must set `globalThis.PREFLIGHT_API_BASE` to the approved Worker origin in the extension shell; the bundle fails closed when that value is absent outside localhost.

Production authentication uses the registered Hybrid App's OAuth installation. Configure `WEBFLOW_CLIENT_ID`, `WEBFLOW_CLIENT_SECRET`, `WEBFLOW_OAUTH_REDIRECT_URI`, and a base64-encoded 32-byte `WEBFLOW_TOKEN_ENCRYPTION_KEY` as server-only Worker configuration. Open `/v1/oauth/webflow/start` to begin the state-bound installation flow. The callback exchanges the single-use code, encrypts the resulting app token before D1 storage, and never sends that token to the browser. The Worker then uses the token to resolve short-lived values from `webflow.getIdToken()`. `WEBFLOW_APP_ACCESS_TOKEN` remains an optional managed-secret fallback for controlled rotation and rollback.

Run the owned-fixture lifecycle after building the runner and starting the local Worker:

```bash
pnpm --filter @create-something/webflow-app-review-runtime-runner build
node packages/webflow-app-review-preflight/runner/fixtures/server.mjs

PREFLIGHT_BUNDLE_PATH=/path/to/app-bundle.zip \
RUNTIME_EVIDENCE_OUTPUT=.codex/partner-runtime-evidence/evidence/browser \
node packages/webflow-app-review-preflight/runner/scripts/run-local-integration.mjs
```

The integration fixture supports explicit negative receipts. Start its server with `RUNTIME_FIXTURE_DYNAMIC=1` to prove runtime-created loaders are blocked, or `RUNTIME_FIXTURE_TAMPERED=1` to prove changed bytes and a missing ready signal are blocked; set `RUNTIME_EXPECT_SECURITY_STATUS=blocked` on the integration command. Every run writes `receipt.json` beside its immutable artifacts.

The integration script uses fixed local development identities only. Production uses separately managed Webflow identity, coordinator authorization, and per-job capabilities; do not reuse local tokens.

### Developer-requested E2B launch

The **Run test now** button never starts a browser from the developer's computer. It asks the Worker to create a fresh job for the signed-in developer's own ready package. The Worker calls E2B's documented sandbox-create API using server-only `E2B_API_KEY` and the immutable reference in `E2B_RUNTIME_TEMPLATE_ID`. Mutable names and tags fail before network access.

E2B returns a per-sandbox restricted-traffic token. The Worker uses it once to send this body to the baked `/run` service:

```json
{
  "observationJobId": "job-id",
  "apiBaseUrl": "https://preflight.example.workers.dev",
  "capability": "one-time-secret"
}
```

The template service accepts the exact production Preflight origin, validates a bounded UUID/capability body, rejects replays, never logs or returns the capability, and starts the already-baked runner without a shell. Its process boundary is equivalent to:

```bash
RUNTIME_OBSERVATION_CAPABILITY="$capability" \
webflow-app-review-runtime --api-base "$apiBaseUrl" --job "$observationJobId"
```

`E2B_API_KEY` is a production secret; the immutable build reference is reviewed configuration. If either is absent, mutable, unreachable, or the template rejects the job, the Worker marks that job failed and returns only a safe launch-stage error. A partially created sandbox is deleted immediately, with its 15-minute TTL as the final cleanup boundary. The service never presents a failed launch as Webflow-observed evidence. A result remains evidence only and cannot approve, reject, or update governance policy.

## Submission receipt verify contract

`POST /v1/submission-receipts/verify` is unauthenticated: the receipt code (`wfpre_` plus 32 hex characters) is the secret. Request body:

```json
{ "code": "wfpre_...", "clientId": "<64 hex characters>", "bind": true }
```

- `clientId` and `bind` are optional. `clientId` is honoured only as a 64-character hex string (any case, stored lowercase); anything else is treated as absent.
- When `bind` is exactly `true`, a valid `clientId` is present, and the receipt has no bound client ID, the call binds it with one conditional `UPDATE` and re-reads the row, so concurrent first calls leave exactly one winner. A bound client ID is never changed or returned.
- Unknown, malformed, or dangling codes return `404 {"valid":false}`; a malformed body returns `400`.

Success (`200`) returns reconciliation metadata only, with no findings, evidence, artifact bytes, or bound client ID:

```json
{
  "valid": true,
  "receipt": {
    "reviewId": "...",
    "appName": "Name from webflow.json, or null",
    "bundleSha256": "...",
    "sourceMapArtifactSha256": null,
    "readiness": "ready | needs_review | changes_required",
    "sourceMapStatus": "matched",
    "runtimeSecurityStatus": "passed | blocked | none",
    "installUrl": null,
    "createdAt": "...",
    "sourceMapsInBundle": false,
    "clientIdBound": true,
    "clientIdConflict": false,
    "runtimeAdvisory": { "observationRan": false, "cspReplay": "not_run", "staticFindingCount": 0, "mutableRuntimeUrlCount": 0 },
    "bootTest": "not_run"
  }
}
```

- `appName` is the `name` field of the bundle manifest (`webflow.json`), so it is the name the manifest carries. It is `null` when the manifest is missing, unparseable, or has no string `name`.
- `sourceMapsInBundle` is `true` when the production bundle ZIP itself contains `.map` files (read from the stored review's `sourceMapSummary.exposedSourceMapFiles`; reviews stored without it read as `false`). The review guidance tells the developer to move the maps into the private review ZIP. The flag is informational and never changes `readiness`.
- `clientIdBound` is `true` when a client ID is bound to the receipt after this call. `clientIdConflict` is `true` when the receipt is bound to a different client ID than the one in this request; a request without a valid `clientId` always reports `false`.
- `runtimeAdvisory` summarizes the advisory published-site checks for this version: whether an observation ran, the strict-CSP replay status (`clean`, `violations`, `not_run`), the total of static-scan matches, and the count of declared runtime URLs with no version or content hash. It is `null` only when the summary could not be read. `bootTest` is the status of the latest Designer Extension boot test (`passed`, `failed`, `error`, `not_run`). Both are advisory and never change `readiness`.
- A receipt is a reference, not an approval; the reviewer replay remains the verification.

## Designer Extension boot test

Static rules do not run the bundle. The boot test does: it catches a panel that opens blank, a bundled script that the Content-Security-Policy blocks, and a file that `index.html` references but the ZIP does not contain. It is advisory evidence, off by default behind `BOOT_TEST_ENABLED`, and it never changes `readiness`, a static finding, or a runtime security status.

1. The review owner calls `POST /v1/reviews/:reviewId/boot-tests` for the latest version. The Worker allows one active job per review version, writes a contract with a random nonce, a 15-minute expiry, and the extension host policy, and stores only the SHA-256 of a one-time capability.
2. The Worker starts a fresh E2B sandbox with the same launcher as a runtime observation and sends `jobKind: "boot_test"` to the template's `/run` route. The sandbox receives no account credential or token beyond the job capability.
3. The runner reads the contract (`GET /v1/boot-test-jobs/:id`) and downloads that version's exact bundle (`GET /v1/boot-test-jobs/:id/bundle`). Both routes accept only the job capability while the job runs. The runner checks the bundle SHA-256 against the contract.
4. The runner serves the bundle from a static server on `127.0.0.1` with the policy on every response, stubs `window.webflow`, and opens `index.html` in headless Chromium. The browser can reach only that server: a route handler aborts every other origin (other loopback ports included), WebSockets close before they connect, and the browser's proxy is a local socket that drops every connection.
5. The runner uploads one JSON result (`POST /v1/boot-test-jobs/:id/result`). The Worker checks every binding, field, cap, and label, rejects internally inconsistent or secret-shaped results, stores the result as `webflow_observed`, consumes the job, and terminates the sandbox.

`status` is `failed` only for `bundled_script_blocked_by_csp`, `bundled_file_missing`, or `blank_panel` (no visible text and no rendered element after the settle time). Blocked external requests and uncaught errors are informational. `error` means the test itself could not run. `GET /v1/reviews/:reviewId/boot-tests` lists results; `bootTestSummaryForVersion` in `worker/src/boot-tests.ts` returns the latest status for one version.

## Security boundaries

- Zip uploads are limited to 10 MB, 50 MB uncompressed, and 2,000 files, and must pass deterministic archive processing before D1 writes.
- Evidence snippets are bounded; full immutable bytes stay in R2.
- CORS uses an explicit origin allowlist.
- Production users are owner-scoped through resolved Webflow identity.
- OAuth callbacks require a matching secure, HttpOnly browser state cookie and a one-time server-side state record. App tokens are AES-GCM encrypted before D1 storage and never returned in browser responses or logs.
- Runtime jobs accept only public HTTPS targets, reject templates and private/local hosts, and allow at most eight targets, twenty requests, ten seconds per request, and sixty seconds total.
- Runtime evidence contains response metadata and object keys only—no response bodies, credentials, cookies, tokens, official decisions, or governance writes.
- E2B, Webflow app, pattern coordinator, and governance approver credentials are separate server-side boundaries.
- Runtime Test Packages accept only a named Webflow sandbox, a short installation allowlist, pinned artifacts with matching SHA-256/SRI bytes, one bounded runtime-ready selector, and one proxy template whose host is already in the job allowlist.
- Observation jobs use hashed, expiring, one-time capabilities. A package owner can request a fresh job for their own ready package, but cannot fetch its capability, contract, or evidence-upload route; partner identity cannot submit evidence.
- Evidence intake is limited to 128 KB of manifest data, 10 MB total artifacts, a fixed file/type allowlist, per-file limits, strict SHA-256 validation, and secret-shaped metadata rejection before R2 writes.
- The runner records no headers, cookies, response/request bodies, form values, or storage values. Query values and console personal/secret-shaped text are redacted, and form controls are masked in screenshots.
- Production sandbox and canary URLs must be HTTPS and on Webflow-controlled origins. Development HTTP/private targets are accepted only when the Worker itself runs outside production.
- Mutable runtime delivery, hash/SRI mismatch, undeclared runtime-created scripts, unreviewed child scripts, source-map gaps, and proxy exposure remain evidence-backed runtime findings (the Marketplace Guidelines list these published-site practices as recommended practices, not review gates) or manual-review inputs. A dynamically inserted file is treated as declared only when its URL is in the package, the observation itself proves it was runtime-created (not loaded by the page document, initiated by another pinned runtime), and its executed bytes match its pinned SHA-256; the partner-supplied load mode never substitutes a weaker check for a page-loaded script. A "no proxy surface" declaration is unverified test input: it always leaves a mandatory manual-review blocker on the proxy check and can never produce an automated pass. Cleanup is recorded only for legacy compatibility and is not scored. Observation does not downgrade security findings.
- Development bypass tokens (`PREFLIGHT_DEV_TOKEN`, `PREFLIGHT_REVIEWER_DEV_TOKEN`) work only when `ENVIRONMENT` is exactly `development`; any other value fails closed as production. The Worker refuses to serve at all if those tokens are bound while `ALLOWED_ORIGINS` contains a non-localhost origin.
- Companion write paths (`/v1/companion-pairings/redeem`, companion run creation/replay/completion, and mission evidence) are retired in every environment; historical companion runs stay readable. Reviewer handoff links render an interstitial on GET and consume the one-time code only on an explicit POST, minting the session exclusively as an HttpOnly cookie — no readable bearer is ever issued.

## Verification

```bash
pnpm --filter @create-something/webflow-app-review-preflight test
pnpm --filter @create-something/webflow-app-review-preflight check
pnpm --filter @create-something/webflow-app-review-preflight build
pnpm --filter @create-something/webflow-app-review-preflight-worker test
pnpm --filter @create-something/webflow-app-review-preflight-worker check
pnpm --filter @create-something/webflow-app-review-preflight-worker build
pnpm --filter @create-something/webflow-app-review-preflight-extension test
pnpm --filter @create-something/webflow-app-review-preflight-extension check
pnpm --filter @create-something/webflow-app-review-preflight-extension bundle
pnpm --filter @create-something/webflow-app-review-runtime-runner test
pnpm --filter @create-something/webflow-app-review-runtime-runner check
pnpm --filter @create-something/webflow-app-review-runtime-runner build
```

## Deployment and rollback

This package is additive. Production promotion requires creating a dedicated D1 database and private R2 bucket, replacing the placeholder D1 ID, configuring approved origins and server-only secrets, deploying the Worker, and installing the bundled extension. None of those actions are part of local verification.

### Production deploy checklist (Worker)

Always deploy the production configuration explicitly — a bare `wrangler deploy` in `worker/` would ship the development config (`wrangler.jsonc`, `ENVIRONMENT: "development"`), which enables dev-token auth bypass and disables HTTPS/origin/site-ownership enforcement:

```bash
cd packages/webflow-app-review-preflight/worker
pnpm exec wrangler d1 migrations apply webflow-app-review-preflight --remote --config wrangler.production.jsonc
pnpm run deploy   # pinned to --config wrangler.production.jsonc ("run" is required: bare `pnpm deploy` is a pnpm built-in)
```

Before the first deploy (and after any rotation), set the out-of-band configuration:

1. **Secrets** (`wrangler secret put <NAME> --config wrangler.production.jsonc`): `E2B_API_KEY`, `E2B_COORDINATOR_TOKEN`, `WEBFLOW_CLIENT_ID`, `WEBFLOW_CLIENT_SECRET`, `WEBFLOW_TOKEN_ENCRYPTION_KEY`, `PATTERN_COORDINATOR_TOKEN`, `GOVERNANCE_APPROVER_TOKEN`.
2. **`REVIEWER_USER_IDS`** — comma-separated Webflow user IDs (secret or dashboard variable). Without it every identity is classified as a developer, `/v1/reviews/:id/reviewer-handoffs` returns 403 with an explicit "No reviewers are configured" message, and the reviewer web app is unreachable.
3. **`RUNTIME_CANARY_URL`** — an HTTPS URL on a Webflow-controlled origin (`webflow.com` / `webflow.io`; enforced by URL validation). Without it every probe-mode runtime package fails with a 503 configuration error naming this variable.
4. **Never** bind `PREFLIGHT_DEV_TOKEN` or `PREFLIGHT_REVIEWER_DEV_TOKEN` in production: the Worker refuses to serve while they are present alongside non-localhost `ALLOWED_ORIGINS`.

Rollback uses Cloudflare's Worker version rollback; D1 migrations are forward-only (see `migrations/README.md`).

Rollback is removal-first: disable the Designer Extension, stop observation-job issuance, stop routing traffic to the Worker, and retain the dedicated D1/R2 evidence under the owning retention policy. Revoke outstanding jobs or let their 15-minute capabilities expire; do not delete evidence outside the approved retention process. Because no existing governance schema or review endpoint is replaced, rollback does not require reverting another production system.
