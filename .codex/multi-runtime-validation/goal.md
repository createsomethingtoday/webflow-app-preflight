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

## Non-goals

- Do not combine mutually exclusive runtime variants into one package.
- Do not introduce a general dependency graph or execution-order language before a concrete need requires it.
- Do not weaken SHA-256, SRI, published-target, runtime-ready, proxy-canary, or evidence-trust predicates.
- Do not deploy the Worker, rebuild the E2B template, or upload the Designer Extension without the owning production promotion authority.
- Do not alter or close CRE-1264; its live-pilot evidence remains independently gated.

## Primary verifier

The primary verifier is a rendered operator flow using the built extension UI: begin with one runtime file, add a second, fill both pins, remove/re-add when relevant, submit, and inspect the resulting API payload. Automated component, runner, and Worker tests support this proof but do not replace the rendered flow.

## Completion proof

- failing tests are captured before implementation for each public behavior;
- focused and full test/check/build outputs are clean;
- the production extension bundle is verified and its SHA-256 recorded;
- rendered-flow screenshots or trace evidence show the multi-runtime interaction;
- Git commit, push, pull request, and Linear evidence identify the exact revision;
- rollback is the revert of the CRE-1381 commit and restoration of the previous single-file form.

## Blocker criteria

Stop and report a blocker only when the same external condition prevents progress on three consecutive goal turns and no safe local or reviewable route remains. Authenticated deployment or Designer upload is an approval boundary, not evidence that the implementation itself is blocked.
