# App Review Preflight Designer Extension

Native Webflow large right-panel UI for uploading an app bundle or starting from a Data Client's hosted production scripts, understanding deterministic feedback, preparing a reproducible Runtime Test Package, reading Webflow-controlled runtime evidence, uploading a bundle revision, and reopening automatically saved review history.

Data Client and hosted apps do not need a placeholder zip. Choose **Test production runtime**, name the app, and enter every exact public HTTPS JavaScript URL that executes in the same scenario, in execution order. One or two files is typical, but the manifest can include more when the provider requires them. Preflight saves an immutable runtime manifest, prefills every declared file into the existing pinning form, and keeps the manifest labeled as partner-supplied input until the Webflow-controlled observation completes. Runtime-only reviews do not expose bundle revision actions.

One Runtime Test Package represents one execution scenario. The form starts with one runtime file and can add up to eight files that must execute together. Each file keeps its own immutable URL and SHA-256; the form derives the matching SRI and the server verifies both encodings. Completed observations report loaded, hash-matched, and SRI-matched status for every file. Region, plan, build, or release variants that do not execute together use separate packages.

```bash
pnpm build
pnpm test
pnpm check
pnpm serve
pnpm bundle
```

`pnpm serve` uses the Webflow CLI for Designer development. The standalone local workflow serves `public/` on `http://localhost:1337` and talks to the local Worker on port `8787`.

There is no Share or explicit Save action. Bundle versions and hosted-runtime manifests persist through the Worker automatically, while the last selected review ID is kept only as local extension navigation state.

The complete behavior-test flow labels partner configuration as `Partner supplied`. It becomes `Webflow observed` only after a separately authorized E2B job completes and the Worker validates the evidence manifest and immutable artifacts. The extension never receives the job capability, uploads browser evidence, or changes an official review decision.
