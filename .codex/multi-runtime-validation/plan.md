# CRE-1381 execution plan

## Current state

- Goal phase: operator-readiness hardening resumed after the initial multi-runtime milestone. Formal registry activation remains unavailable because this task retains the unfinished, paused CRE-1264 production-pilot goal. That prior goal is preserved rather than falsely completed or replaced.
- Canonical repository: `/Users/micahjohnson/Code/webflow-app-preflight`.
- Branch: `codex/CRE-1381-multi-runtime-sets` from clean `origin/main`.
- Linear: CRE-1381, In Progress, assigned to Micah Johnson.
- Related but separate gate: CRE-1264 remains the blocked production-pilot issue.
- Existing contract: one to eight unique runtime artifact pins; all pins must load and match SHA-256 and SRI.
- Existing UI gap: the form stores, prefills, and submits only the first runtime artifact.
- Existing execution gap: page-world runtime-created scripts can be classified as blockers even when their URL is already declared and pinned.

## Phase 1 — Define the vertical slices

- [x] Confirm the standalone repository is clean and authoritative.
- [x] Create and claim CRE-1381.
- [x] Create the delivery branch.
- [x] Red-team scope against variant explosion, weakened pinning, stale saved packages, and undeclared child scripts.
- [x] Attempt formal durable-goal activation; preserve the prior paused CRE-1264 registry goal when the goal service rejects a second unfinished goal.

## Phase 2 — Runtime-set form, test first

- [x] Add a failing extension test for one default runtime, advanced add/remove, two-file submit, the eight-file limit, and all-file prefill.
- [x] Replace scalar runtime form state with an ordered runtime-artifact collection.
- [x] Add accessible per-file labels and concise scenario guidance.
- [x] Keep the common one-file path visually primary.
- [x] Run the focused extension tests and refactor only after green (4 focused flows passed).

## Phase 3 — Declared dynamic dependencies, test first

- [x] Add runner regression coverage proving a dynamically inserted declared pin is not classified as an additional runtime-created script. The initial test was already green at the trusted-execution layer.
- [x] Preserve the existing failing behavior for an undeclared dynamic child.
- [x] Align the page-world inventory explicitly by filtering the declared pinned URL set.
- [x] Add Worker evaluation coverage proving every declared file must load and match hash and SRI, plus API coverage for unique multi-file packages and duplicate rejection.
- [x] Run focused runner and Worker tests (declared/undeclared runner cases and multi-pin Worker package/evidence path passed).

## Phase 4 — Operator documentation

- [x] Update the operator runbook with the one-file/runtime-set/separate-package decision rule.
- [x] Explain dynamic dependencies, security expectations, failure interpretation, and revision workflow for a young junior in the field.
- [x] Update package and extension README surfaces where the public contract needs discovery.
- [x] Check formatting and terminology against the app labels.

## Phase 5 — Verification

- [x] Verify Node 22.21.1, pnpm 9.15.0, Webflow CLI 1.23.0, TypeScript 5.9.3, `webflow.json`, lockfile, and package resolution.
- [x] Run focused tests for each slice.
- [x] Run complete `pnpm test` (120 tests), `pnpm check`, `pnpm build`, and `pnpm format:check` once; repeat final gates after diff cleanup.
- [x] Build and verify the production Designer Extension bundle.
- [x] Exercise the rendered runtime-set flow against local Worker/D1: add two pins, observe mismatched-SRI rejection, persist the corrected two-pin package, reopen both pins from server state, and remove the second editable pin.
- [x] Capture `output/playwright/multi-runtime-form.png` and `output/playwright/multi-runtime-prefill.png` locally; `.playwright-cli/` and `output/` are ignored as verification artifacts.
- [x] Final production bundle receipt: `packages/webflow-app-review-preflight/extension/bundle.zip`, 180,010 bytes, SHA-256 `a3dc612ec3d509aee49ac35ee5ad53a45ec47f3355cef6e693d6031dfe3a4208`.
- [x] Copy the verified upload artifact to `/Users/micahjohnson/Downloads/webflow-app-preflight-CRE-1381-multi-runtime.zip`; `unzip -t` passed and the digest remained unchanged.

## Phase 6 — Delivery and evidence

- [x] Review the exact diff; remove default-Prettier churn and Webflow CLI-only manifest normalization. Keep the rebuilt production `public/bundle.js` as the expected generated artifact.
- [x] Commit the verified CRE-1381 scope as `eb17b21`.
- [x] Push `codex/CRE-1381-multi-runtime-sets`.
- [x] Open draft pull request <https://github.com/createsomethingtoday/webflow-app-preflight/pull/1> against `main` with invariant, tests, approval boundaries, and rollback.
- [x] Record exact commit, PR, local checks, successful CI run `29862809657`, UI proof, bundle digest, and rollback in CRE-1381.
- [ ] Mark CRE-1381 done only when no required implementation or review artifact remains.
- [x] Mark the initial repo-local milestone complete. User steering subsequently reopened the same goal for operator-readiness hardening; the thread-level registry remains reserved by the earlier paused CRE-1264 goal and was not overwritten.

## Phase 7: Make multi-runtime failures actionable

Status: complete

Implementation
- [x] Add one failing public-interface test for runtime-package preparation errors remaining inside the runtime card with preserved editable state.
- [x] Add one failing test for file-numbered Worker validation errors, then identify duplicate, malformed, and mismatched pins by runtime file.
- [x] Add one failing form test for SHA-derived SRI, inline duplicate detection, URL-derived labels, and confirmation file count.
- [x] Implement each slice minimally and refactor only while its focused tests stay green.

Verification
- [x] Focused extension and Worker tests pass without weakening existing server validation.
- [x] Error focus, field values, and file-numbered messages are observable through the public UI/API interfaces.

Exit criteria
- [x] A junior operator can find and repair the failing runtime without searching the page or manually converting the same digest twice.

## Phase 8: Make multi-runtime evidence reviewable

Status: complete

Implementation
- [x] Add per-runtime observed outcomes to the sanitized observation summary.
- [x] Render loaded, executed-hash, and DOM-SRI status for each declared runtime.
- [x] Separate runtime-file count from evidence-artifact count in the completion checkpoint.

Verification
- [x] Worker tests prove the summary is sanitized, complete, and aligned with aggregate predicates.
- [x] Extension tests prove a mixed two-file result names the failing runtime and each outcome.

Exit criteria
- [x] The aggregate verdict and every per-file row describe the same observation without exposing raw script contents or credentials.

## Phase 9: Verify, bundle, and merge

Status: in progress

Implementation
- [x] Rebuild the production extension bundle and replace the Downloads handoff with the verified archive.
- [ ] Update PR 1 and CRE-1381 with the final evidence and rollback receipt.
- [ ] Mark PR 1 ready, merge after required checks pass, and leave deployment/upload boundaries unchanged.

Verification
- [x] Run focused red/green tests, complete `pnpm test` (122 tests), `pnpm check`, `pnpm build`, `pnpm format:check`, and `git diff --check`.
- [x] Exercise duplicate/error recovery, confirmation, Webflow-observed per-file results, reload/prefill, and narrow viewport on the rendered local Worker/D1 surface.
- [ ] Record screenshots, final bundle size/SHA-256, clean working tree, successful CI, and merged-main readback. Local screenshots and the 181,263-byte bundle SHA-256 `90f7f79381dab093741dec96ee9e3986951efca7c3f07498ed4c4a896ac5f743` are recorded; CI and merged-main readback remain.

Exit criteria
- [ ] PR 1 is merged, CRE-1381 is complete with exact evidence, the final bundle is in Downloads, and no Worker/E2B/Designer deployment occurred.

## Approval boundaries

- Worker deployment: not authorized by this goal.
- E2B template rebuild/deployment: not authorized by this goal.
- Designer Extension upload or publication: not authorized by this goal.
- Production pilot approval: remains in CRE-1264.
