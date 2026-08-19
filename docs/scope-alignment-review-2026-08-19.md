# Preflight review vs the 8/18 scope alignment (openapi-internal #964)

Reviewed 2026-08-19 against `main` (1561504), `fix/preflight-review-hardening` (3f3ddb7), the
live worker, and Adam Lehman's 8/18 disposition. Verdict: **yes, the app needs updating** — on
two axes, one of which has nothing to do with the scope change.

## Finding 0 — CORRECTED 8/19: false alarm, receipts are live

The original version of this review reported the receipts feature as undeployed because
`POST /v1/submission-receipts/verify` returned HTTP 404. That probe read only the status code.
The route's designed semantics return **404 with `{"valid":false}`** for an unknown receipt code
(worker `src/index.ts`), which is exactly what an all-zeros probe should receive from a healthy
deployment. Verified 8/19: the endpoint responds with the JSON body, migrations 0009 and 0010 are
applied to the production D1, and the receipts/source-map work reached `main` inside the #6
squash plus #7. Nothing to deploy. (A briefly opened duplicate PR #8 from the stale
`fix/preflight-review-hardening` branch was closed unmerged.)

Lesson recorded: probing a JSON API means reading the body, not just the status code.

## Finding 1: the scope change splits the app's two lanes differently

**The static scanner mostly survives.** It runs on the uploaded bundle, which is
Designer-surface code — in scope under the new review model. Most of the 18 rules map directly
onto guidelines sections that #964 keeps as gates:

| Scanner rule | Surviving guideline | Status |
|---|---|---|
| Dynamic Code Execution, Dynamic Script Injection, Obfuscated Source | Designer Extensions technical 5, 6, 9 | Gate, keep |
| Unsafe HTML Injection, Unauthorized Host DOM Access | DE technical 2 | Gate, keep |
| Hardcoded API Secrets, Insecure Token Storage | Token security 1–2 | Gate, keep |
| Insecure Protocols, Non-Production Endpoints | Transport security 1–2 | Gate, keep (and strengthen — see Finding 2) |
| Hardware Access, Prohibited Popups | User interaction | Gate, keep |

**The hosted-runtime lane flips to advisory for everyone.** The E2B published-runtime
validation — SRI predicates, `noRuntimeCreatedScripts`, fingerprinting detection, the proxy
canary — validates exactly the published-site surface that #964 moves to recommended practices.
This supersedes the 8/10 partner split (runtime findings block non-partners, flag partners): the
split collapses to **flag-only for all apps**. Rules the app treats as AUTO_REJECT that the
disposition explicitly waived on published runtimes: Fingerprinting & Session Replay
(FingerprintJS was waived by name), Dynamic Script Injection (the mutable loader), Forced
Redirect, Insecure postMessage.

**The structural gap: no surface attribution.** Findings carry severity but not *which surface
the file belongs to*. For a hybrid app whose bundle includes both the extension and its
published-site scripts (exactly the North shape), the same regex hit must be a gate on the DE
file and a recommendation on the injected script. The scanner needs per-file surface
classification (DE entry from `webflow.json` vs custom-code scripts) with severity resolved per
surface, and the verdict/report copy needs a two-tier output: "will be rejected" vs
"recommended practices."

## Finding 2: retained gates the app should check but doesn't

From the disposition's fail list and the new artifacts docs — all in scope, all
developer-detectable:

1. **Webflow token in a GET URL** (North finding 6): regex-able in compiled bundles — token-ish
   parameters in query strings on sign-in/auth routes.
2. **Debug/bypass residue and dev identities** (North findings 17–18, now documented in
   submission artifacts): debug routes, onboarding-bypass flags, staging identities in
   `webflow.json`, CLI state files. The existing Non-Production Endpoints rule is
   MEDIUM/ACTION_REQUIRED and its known gap (HTTPS staging origins pass) is exactly what these
   need — elevate and extend.
3. **Manifest + lockfile presence** for compiled bundles (new artifacts requirement): a
   structural check plus a receipt metadata field.
4. **Mutate-on-open** (North finding 8, User interaction rule 3): Designer API write calls
   reachable from extension mount rather than a user gesture — heuristic statically, precise as
   an E2B DE-run predicate.
5. (Later, optional) a developer-side **endpoint-rule self-probe** mirroring how review verifies
   the consolidated backend rule: hostile-origin CORS probe + forged-identifier rejection
   against declared backend endpoints.

## Sequencing

- **With #964's merge**: the scope-model changes (surface attribution, runtime lane to advisory,
  severity reclass, verdict copy) — the tool must mirror the published docs the moment they
  change, since the announcement's promise is "the docs are the standard."
- **Same window**: the `webflow-app-preflight` SKILL.md twin (already on the post-#964 sync
  list) — the skill and the app must agree with each other and with the docs.
