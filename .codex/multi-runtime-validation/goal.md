# Multi-runtime validation goal

## Objective

Complete CRE-1381 by making Webflow App Preflight safely validate one production execution scenario that contains more than one reviewed runtime file.

The operator experience starts with one runtime file. An advanced action can add up to eight files to the same runtime set. Every file in the set is verified independently during the same Webflow-owned E2B observation. Mutually exclusive builds, regions, plans, or other variants are separate test packages because they do not execute in the same scenario.

## System invariant

One runtime test package represents one executable scenario:

- all declared runtime files must load during that run;
- every declared file must match its pinned SHA-256 and SRI value;
- a dynamically inserted file is acceptable only when it is declared in the package and satisfies those same checks;
- any undeclared runtime-created script remains a security blocker;
- partner-supplied settings never become Webflow-observed evidence by themselves.

## Acceptance outcomes

1. The Designer Extension shows one runtime file by default and exposes an advanced `Add another runtime file` action.
2. The operator can add and remove runtime files without losing the first file, cannot exceed the server contract of eight, and submits the complete ordered set.
3. A saved package containing multiple files repopulates all files, not only the first.
4. The UI explains in plain language that files in one set must execute together and that variants need separate packages.
5. Server tests prove a package with multiple unique pins is accepted while duplicate or malformed pins remain rejected.
6. Runner and Worker tests prove a declared dynamically inserted file is not treated as undeclared, while an undeclared child script still blocks the run.
7. The Worker still requires every declared file to be loaded, hash-matched, and SRI-matched before security can pass.
8. Operator documentation teaches a young junior in the field when to use one file, a runtime set, or separate packages.
9. Package tests, type checks, production builds, formatting checks, and the Designer Extension bundle all pass.
10. A real rendered UI flow proves the add, remove, prefill, and submit behavior. If authenticated Designer upload is not available without a consequential external change, the exact bundle and a short manual verification handoff are produced instead.
11. The completed change is committed on `codex/CRE-1381-multi-runtime-sets`, pushed, opened for review, and recorded in Linear with verification and rollback evidence.
12. Runtime-package preparation failures stay inside the runtime card, preserve the editable package, identify the affected runtime file when possible, and move focus to the actionable error.
13. A valid lowercase SHA-256 deterministically supplies its matching `sha256-...` SRI value in the form; duplicate URLs and malformed pins are rejected before confirmation while the Worker retains the same authoritative checks.
14. A completed Webflow observation exposes and renders each declared runtime file's loaded, executed-hash, and DOM-SRI outcomes rather than only aggregate booleans.
15. The operator sees runtime-file count separately from evidence-artifact count, URL-derived file labels, and the runtime-file count in the confirmation checkpoint.
16. The hardened flow is verified at a Designer-sized viewport, bundled, copied to Downloads with a new digest, committed, CI-green, and merged through PR 1 before CRE-1381 closes.

## Non-goals

- Do not combine mutually exclusive runtime variants into one package.
- Do not introduce a general dependency graph or execution-order language before a concrete need requires it.
- Do not weaken SHA-256, SRI, published-target, runtime-ready, proxy-canary, or evidence-trust predicates.
- Do not deploy the Worker, rebuild the E2B template, or upload the Designer Extension without the owning production promotion authority.
- Do not alter or close CRE-1264; its live-pilot evidence remains independently gated.

## Primary verifier

The primary verifier is a rendered operator flow using the built extension UI and local Worker/D1 at a Designer-sized viewport: begin with one runtime file, add a second, enter valid hashes, observe derived SRI values and URL-derived labels, reject a duplicate or invalid pin without losing the form, confirm the package count, submit, and inspect per-file observation results. Reload and prefill the saved package. Automated component, runner, and Worker tests support this proof but do not replace the rendered flow.

## Completion proof

- failing tests are captured before implementation for each public behavior;
- focused and full test/check/build outputs are clean;
- the production extension bundle is verified and its SHA-256 recorded;
- rendered-flow screenshots or trace evidence show the multi-runtime interaction;
- the rendered error path keeps focus and editable state in the runtime card, while the completed state names every runtime and shows its three verification outcomes;
- Git commit, push, pull request, and Linear evidence identify the exact revision;
- the final branch head is CI-green and PR 1 is merged without deploying the Worker, E2B template, or Designer bundle;
- rollback is the revert of the CRE-1381 merge and restoration of the previously approved Designer bundle.

## Blocker criteria

Stop and report a blocker only when the same external condition prevents progress on three consecutive goal turns and no safe local or reviewable route remains. Authenticated deployment or Designer upload is an approval boundary, not evidence that the implementation itself is blocked.

## Prior milestone receipt

This receipt proves the initial multi-runtime slice. User steering reopened the repo-local goal for the operator-readiness outcomes above, so this bundle is not the final upload artifact.

- Implementation commit: `eb17b21` on `codex/CRE-1381-multi-runtime-sets`.
- Draft review: <https://github.com/createsomethingtoday/webflow-app-preflight/pull/1>.
- Independent CI: run `29862809657` passed formatting, typecheck, tests, and build.
- Local validation: 120 tests, typecheck, build, formatting, and the rendered two-runtime Worker/D1 flow passed.
- Upload artifact: `/Users/micahjohnson/Downloads/webflow-app-preflight-CRE-1381-multi-runtime.zip`, 180,010 bytes, SHA-256 `a3dc612ec3d509aee49ac35ee5ad53a45ec47f3355cef6e693d6031dfe3a4208`.
- Linear evidence: CRE-1381 comment `e2b1c4b9-6a6a-4039-a211-7f907ebb4112`.
- Approval boundary retained: the operator owns Designer upload; CRE-1264 owns the independent production pilot.

## Operator-readiness verification receipt

- Focused red/green coverage proves in-card error recovery, file-numbered Worker validation, SHA-derived SRI, duplicate rejection, per-file observation results, and singular/plural count copy.
- Complete local verification: 122 tests, type checks, builds, formatting, and `git diff --check` passed.
- Rendered Worker/D1 proof passed at 900×780 and 390×844 for duplicate recovery, two-file confirmation, Webflow-observed per-file results, reload, and two-file prefill.
- Local screenshots: `output/playwright/runtime-duplicate-error-900.png`, `output/playwright/runtime-confirmation-900.png`, `output/playwright/runtime-results-900.png`, and `output/playwright/runtime-results-390.png` (ignored verification artifacts).
- Final upload artifact: `/Users/micahjohnson/Downloads/webflow-app-preflight-CRE-1381-multi-runtime.zip`, 181,263 bytes, SHA-256 `90f7f79381dab093741dec96ee9e3986951efca7c3f07498ed4c4a896ac5f743`; `unzip -t` passed.
- Review head `8e7bcf8` passed GitHub Actions run `29867169000`, and PR 1 is ready for review. Merge and merged-main readback remain. No Worker, E2B template, or Designer Extension deployment occurred.
