# Webflow App Review Runtime Template

This package builds the E2B sandbox used by App Review Preflight runtime observations.

The template's build recipe pins the Node base-image digest and the Playwright package version, installs Chromium and its OS dependencies during the E2B build, and copies the reviewed runner into `/app`. A prestarted one-shot HTTP service accepts only `POST /run` for the production Preflight origin. The job capability is passed only to the runner process and is never returned or logged by the service.

### What is and isn't reproducible

- **Immutable:** the built artifact, referenced by `immutableTemplateRef` (`<template-name>:<build-id>`). Production must pin exactly this — never a name or mutable tag.
- **Pinned recipe inputs:** the base-image digest and the requested `playwright@<version>`.
- **Captured, not reproducible:** the browser and OS layers. There is no lockfile, so the transitive npm tree floats; `npx playwright install --with-deps chromium` runs `apt` against moving Debian repos and downloads an unchecksummed browser from the Playwright CDN. The build receipt records the **resolved** facts (Chromium revision, resolved `playwright-core` version, and a SHA-256 of `dpkg -l`) under `resolved`, so two builds can be compared after the fact — but they are not guaranteed to reproduce byte-for-byte.

### Launch authentication

The service enforces an in-sandbox backstop when the Worker injects a per-sandbox launch secret as the `APP_REVIEW_RUNTIME_LAUNCH_SECRET` environment variable at sandbox create time. When set, `POST /run` must present it in the `x-webflow-runtime-launch-secret` header (constant-time compared); requests without it get `401`. When the variable is absent, no in-sandbox authentication is enforced and E2B's per-sandbox token is the only control.

No package install, browser download, runner upload, E2B credential, Webflow credential, or shared dispatcher token exists in the runtime launch path.

```bash
pnpm test
pnpm check
pnpm build

E2B_API_KEY=... pnpm build:e2b -- --receipt /absolute/path/to/receipt.json
```
