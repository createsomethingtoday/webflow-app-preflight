# Runtime lane → advisory: implementation plan (gated on openapi-internal #964)

The scope alignment makes published-site behavior a set of recommended practices rather than
review gates. The static scanner in this repo runs on Designer-surface code and keeps its gates
(this branch adds the retained-gate checks). The **hosted-runtime lane** — E2B observation of
published runtimes with the SRI, runtime-created-script, fingerprinting, and proxy-canary
predicates — observes exactly the surface that stops gating. This plan reclassifies its
*presentation* without weakening its *evidence*.

## Principle

The evidence pipeline stays intact. Reviewer replay, `reproduced_pass`/`reproduced_block`, and
`webflow_observed` evidence remain the trusted record of what a published runtime actually does —
reviewers still want the facts, and the receipts contract already frames itself as "reference,
not an approval." What changes is severity language: a runtime observation is a **recommended
practice finding**, not a submission blocker, for all apps. This supersedes the 8/10 partner
split (blocker for non-partners, flag for partners): flag-only for everyone.

## Seams (identified 8/19)

1. **`worker/src/submission-receipts.ts:28`** — `runtimeSecurityStatus: 'passed' | 'blocked' |
   'none'` stays factual and unchanged; consumers change how they read it.
2. **Extension UI** (`UploadCard` / runtime results views) — copy that presents runtime failures
   as submission blockers becomes "recommended practices for published-site code" with a link to
   the guidelines subsection. No structural change to `RuntimeTestPackageView` fixtures.
3. **Reviewer web workspace** — same copy shift; the reviewer replay flow is unchanged.
4. **Docs** (`docs/runtime-validation-guide`) — reframe the worked examples' outcomes.

## Test gotchas (from prior sessions)

Worker tests assert full predicate objects with `toEqual` and count blockers
(`reviews.test.ts`); extension `App.test.tsx` fixtures type-check against
`RuntimeTestPackageView`. Adding required fields breaks both — this plan deliberately adds none.
Copy-level changes need `pnpm check` (extension fixtures), not just `pnpm test`.

## When

Ship in the same window as openapi-internal #964 and the `webflow-app-preflight` SKILL.md
sync — the tool, the skill, and the docs must flip together. Until then the current gating
matches the published docs, which is correct.
