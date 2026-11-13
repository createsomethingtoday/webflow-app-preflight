# Webflow App Review Runtime Template

This package builds the E2B sandbox used by App Review Preflight runtime observations.

The template's build recipe pins the Node base-image digest and the Playwright package version, installs Chromium and its OS dependencies during the E2B build, and copies the reviewed runner into `/app`. A prestarted one-shot HTTP service accepts only `POST /run` for the production Preflight origin. The job capability is passed only to the runner process and is never returned or logged by the service.

### What is and isn't reproducible

- **Immutable:** the built artifact, referenced by `immutableTemplateRef` (`<template-name>:<build-id>`). Production must pin exactly this — never a name or mutable tag.
- **Pinned recipe inputs:** the base-image digest and the requested `playwright@<version>`.
- **Captured, not reproducible:** the browser and OS layers. There is no lockfile, so the transitive npm tree floats; `npx playwright install --with-deps chromium` runs `apt` against moving Debian repos and downloads an unchecksummed browser from the Playwright CDN. The build receipt records the **resolved** facts (Chromium revision, resolved `playwright-core` version, and a SHA-256 of `dpkg -l`) under `resolved`, so two builds can be compared after the fact — but they are not guaranteed to reproduce byte-for-byte.

### Job kinds

The `/run` body is exactly `{ observationJobId, apiBaseUrl, capability }` for a runtime observation. A Designer Extension boot test adds `jobKind: "boot_test"`, and the service starts the same baked runner with `--kind boot-test`. Any other key or value is rejected with `400`. A template built before this change rejects boot test launches, so rebuild it before you turn on `BOOT_TEST_ENABLED`.

### Launch authentication

The service enforces an in-sandbox backstop when the Worker injects a per-sandbox launch secret as the `APP_REVIEW_RUNTIME_LAUNCH_SECRET` environment variable at sandbox create time. When set, `POST /run` must present it in the `x-webflow-runtime-launch-secret` header (constant-time compared); requests without it get `401`. When the variable is absent, no in-sandbox authentication is enforced and E2B's per-sandbox token is the only control.

No package install, browser download, runner upload, E2B credential, Webflow credential, or shared dispatcher token exists in the runtime launch path.

```bash
pnpm test
pnpm check
pnpm build

E2B_API_KEY=... pnpm build:e2b -- --receipt /absolute/path/to/receipt.json
```

`pnpm build:e2b` builds the workspace packages first, because the runner inlines `bundle-scanner-core`.

## Check a built template

Run these from the package directories after every template build. Each one starts a real sandbox from the immutable reference in the build receipt and then ends it.

```bash
# Launch handshake through the production launcher (from packages/webflow-app-review-preflight/worker).
E2B_API_KEY=... node scripts/probe-e2b-runtime.mjs \
  --template-receipt /absolute/path/to/receipt.json --receipt /absolute/path/to/probe.json
E2B_API_KEY=... node scripts/probe-e2b-runtime.mjs --kind boot-test \
  --template-receipt /absolute/path/to/receipt.json --receipt /absolute/path/to/probe-boot.json

# Boot test smoke and runtime observation smoke (from this package).
E2B_API_KEY=... node scripts/smoke-boot-test.mjs \
  --template-receipt /absolute/path/to/receipt.json --receipt /absolute/path/to/boot-smoke.json
E2B_API_KEY=... node scripts/smoke-observation.mjs \
  --template-receipt /absolute/path/to/receipt.json --receipt /absolute/path/to/observation-smoke.json
```

The boot test smoke runs the baked runner in boot-test mode against four fixture bundles: one that renders, one with a missing file, one that opens blank, and one whose own policy blocks its script. A stand-in for the Worker API runs inside the same sandbox on `127.0.0.1`, so the smoke needs no deployed Worker. It exits non-zero unless every fixture gives the expected result. It is an operator check of the template, not evidence about any developer bundle.

The runtime observation smoke runs one complete observation of a fixture page that is served inside the same sandbox. The fixture's runtime script marks itself ready, creates an inline script, and calls `eval`. The smoke passes only when the evidence is uploaded with the right bindings, the runtime hash matches, the static scan reports the `eval`, and the strict-CSP replay reports a violation from the runtime. The runner refuses loopback targets unless `RUNTIME_ALLOW_PRIVATE_HOSTS=1`; the smoke sets that for its own runner process only, and the template server never sets it.

A template with the boot test and the advisory runner checks stays compatible with a Worker that predates them: the runner reads no new contract field, and the Worker ignores the extra advisory fields in the evidence. Swap the template first, then deploy the Worker.
