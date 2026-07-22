# Webflow App Preflight

Webflow App Preflight reviews an uploaded app bundle and validates its production runtime in a server-owned browser.

It has two user surfaces:

- a Webflow Designer Extension for developers
- a reviewer web workspace for independent replay

The Worker stores immutable review versions and evidence. E2B runs each production-runtime observation in a fresh sandbox. Neither user surface can upload `webflow_observed` evidence or make an official Marketplace decision.

## Start here

- [Production runtime guide - Markdown](./docs/WEBFLOW_RUNTIME_VALIDATION_GUIDE.md) - junior-friendly walkthrough with a worked example
- [Production runtime guide - PDF](./output/pdf/webflow-runtime-validation-guide.pdf) - Webflow-branded print and handoff edition
- [Maintainer runbook](./packages/webflow-app-review-preflight/OPERATOR_RUNBOOK.md) - detailed operating and service procedures
- [Architecture and security boundaries](./packages/webflow-app-review-preflight/README.md)
- [Designer Extension guide](./packages/webflow-app-review-preflight/extension/README.md)
- [E2B runtime template](./packages/webflow-app-review-runtime-template/README.md)

## Repository map

| Path                                              | Purpose                                                                     |
| ------------------------------------------------- | --------------------------------------------------------------------------- |
| `packages/bundle-scanner-core`                    | Deterministic zip inventory and bundle rules                                |
| `packages/webflow-app-review-preflight`           | Review contract, types, policies, and documentation                         |
| `packages/webflow-app-review-preflight/extension` | Native Webflow Designer Extension                                           |
| `packages/webflow-app-review-preflight/worker`    | Cloudflare Worker, D1 metadata, R2 artifacts, OAuth, and reviewer workspace |
| `packages/webflow-app-review-preflight/runner`    | Playwright runtime observer and evidence collector                          |
| `packages/webflow-app-review-runtime-template`    | Immutable E2B template for the runner                                       |

## Local setup

Requirements:

- Node.js 20 or newer
- pnpm 9.15
- a Webflow developer account for Designer Extension testing
- Cloudflare credentials only when deploying the Worker
- an E2B API key only when building or probing a runtime template

Install and validate:

```bash
corepack enable
pnpm install
pnpm check
pnpm test
pnpm build
```

Start the local Worker:

```bash
cd packages/webflow-app-review-preflight/worker
pnpm exec wrangler d1 migrations apply webflow-app-review-preflight --local --config wrangler.jsonc
pnpm dev
```

In another terminal, start the Designer Extension:

```bash
pnpm dev:extension
```

## Build the production surfaces

Build the immutable E2B template and save its receipt outside the repository:

```bash
E2B_API_KEY=... pnpm build:e2b -- --receipt /absolute/path/to/e2b-receipt.json
```

Set the returned immutable template reference as `E2B_RUNTIME_TEMPLATE_ID`. Do not use a mutable template name or tag.

Build the Designer Extension for your Worker origin:

```bash
PREFLIGHT_API_BASE=https://preflight.example.workers.dev pnpm bundle:extension
```

The Webflow CLI writes the uploadable extension archive to the extension package. That archive is ignored by Git.

## Secrets and deployment configuration

This repository contains no production secret values. Copy `.env.example` only as a naming reference. Store Worker secrets with your deployment platform rather than in a committed env file.

Before deploying:

1. create a dedicated D1 database and private R2 bucket
2. replace placeholder resource IDs in the Worker configuration
3. set explicit allowed origins
4. configure Webflow OAuth and token encryption
5. set the immutable E2B template reference and server-only E2B key
6. keep developer, reviewer, coordinator, and governance identities separate

The included production configuration records the CREATE SOMETHING pilot deployment. Forks should create their own resources and configuration before deployment.

## Trust boundary

Preflight is an evidence system, not an approval system.

- partner settings remain `partner_supplied`
- only the server-owned runner can produce `webflow_observed` evidence
- one active observation job is allowed per package
- every started E2B sandbox must be verified as terminated
- reviewer replay uses the same immutable package without overwriting prior jobs
- the job contract sets the official decision to `null`

## Source import

The first standalone version was imported from CREATE SOMETHING monorepo commit `0f8fd9f4ec10c6514c53648229fb687728adbaa0`.

## License

[MIT](./LICENSE)
