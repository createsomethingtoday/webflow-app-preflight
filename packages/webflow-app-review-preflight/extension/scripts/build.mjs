import { build } from "esbuild";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { productionApiBase } from "./production-config.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const production = process.env.PREFLIGHT_BUILD_MODE === "production";
const externalApiBase = process.env.PREFLIGHT_API_BASE?.replace(/\/$/, "");

// Production builds are hard-pinned to the production API origin. The
// PREFLIGHT_API_BASE override exists for local development only; letting it
// win in production mode would allow a build whose sole API origin is an
// attacker-controlled host. Fail loudly rather than silently ignoring it.
if (
  production &&
  externalApiBase !== undefined &&
  externalApiBase !== productionApiBase
) {
  throw new Error(
    `Production Designer Extension builds are pinned to ${productionApiBase}. ` +
      `Refusing to build with PREFLIGHT_API_BASE="${process.env.PREFLIGHT_API_BASE}". ` +
      "Unset PREFLIGHT_API_BASE; the override is development-only.",
  );
}

const apiBase = production ? productionApiBase : (externalApiBase ?? "");
const runtimeBoundary = resolve(
  root,
  production ? "src/production-runtime.ts" : "src/development-runtime.ts",
);

await build({
  entryPoints: [resolve(root, "src/main.tsx")],
  bundle: true,
  format: "iife",
  target: "es2020",
  outfile: resolve(root, "public/bundle.js"),
  // Production builds must be minified and must resolve React to its production
  // build. Without the NODE_ENV define, React's development build is bundled and
  // ships ~56 hardcoded reactjs.org warning URLs, which Marketplace security
  // scanning flags as undisclosed external connections.
  minify: production,
  // Minifying without a source map would remove the readable source that review
  // depends on, so the two travel together.
  sourcemap: production ? true : "inline",
  plugins: [
    {
      name: "development-runtime-boundary",
      setup(build) {
        build.onResolve({ filter: /^\.\/development-runtime$/ }, () => ({
          path: runtimeBoundary,
        }));
      },
    },
  ],
  define: {
    __PREFLIGHT_API_BASE__: JSON.stringify(apiBase),
    "process.env.NODE_ENV": JSON.stringify(
      production ? "production" : "development",
    ),
  },
});
