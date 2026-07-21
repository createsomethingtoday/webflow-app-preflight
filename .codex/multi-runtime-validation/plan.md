# CRE-1381 execution plan

## Current state

- Goal phase: durable artifacts active. Formal registry activation was attempted and rejected because this task retains the unfinished, paused CRE-1264 production-pilot goal. That prior goal is preserved rather than falsely completed or replaced.
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
- [ ] Commit the verified CRE-1381 scope.
- [ ] Push `codex/CRE-1381-multi-runtime-sets`.
- [ ] Open a pull request against `main` with invariant, tests, approval boundaries, and rollback.
- [ ] Record exact commit, PR, checks, UI proof, bundle digest, and rollback in CRE-1381.
- [ ] Mark CRE-1381 done only when no required implementation or review artifact remains.
- [ ] Mark the Ultragoal complete only after the objective and completion proof are satisfied.

## Approval boundaries

- Worker deployment: not authorized by this goal.
- E2B template rebuild/deployment: not authorized by this goal.
- Designer Extension upload or publication: not authorized by this goal.
- Production pilot approval: remains in CRE-1264.
