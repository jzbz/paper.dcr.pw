// Bundles the dcr-ts-backed engine (src/dcr-engine.mjs) into a single browser
// IIFE at src/engine.bundle.js, which build.js then inlines into index.html.
//
// esbuild leaves `/* @__PURE__ */` / `@__NO_SIDE_EFFECTS__` tree-shaking hints
// in non-minified output. They are inert once bundled (nothing re-bundles the
// inlined script), but their `__TOKEN__` shape collides with build.js's
// placeholder guard, so we strip just those annotations and then assert that no
// `__X__` token survives.
import { build } from "esbuild";
import { writeFileSync } from "node:fs";

const result = await build({
  entryPoints: ["src/dcr-engine.mjs"],
  bundle: true,
  format: "iife",
  target: "es2020",
  legalComments: "inline", // keep @noble / @scure license notices
  write: false,
});

let code = result.outputFiles[0].text;
code = code.replace(/@__PURE__/g, "").replace(/@__NO_SIDE_EFFECTS__/g, "");

const leftover = code.match(/__[A-Z0-9_]+__/g);
if (leftover) {
  throw new Error(`bundle still contains placeholder-like tokens: ${[...new Set(leftover)].join(", ")}`);
}

writeFileSync("src/engine.bundle.js", code);
console.log(`wrote src/engine.bundle.js (${(Buffer.byteLength(code) / 1024).toFixed(0)} KB)`);
