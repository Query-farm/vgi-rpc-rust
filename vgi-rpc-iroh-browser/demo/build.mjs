#!/usr/bin/env node
import { createRequire } from "node:module";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, parse, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repository = join(here, "..", "..");
const haybarn =
  process.env.HAYBARN_WASM ??
  join(homedir(), "Development", "haybarn", "haybarn-wasm");
const engineRoot = process.env.VGI_ENGINE_ROOT ?? haybarn;
const generatedBindings =
  process.env.IROH_BINDINGS ?? join(repository, "target", "browser-bindings");
const engineVersion = process.env.VGI_ENGINE_VERSION_DIR ?? "v1.5.5";
const extension =
  process.env.VGI_EXT_WASM ??
  join(
    engineRoot,
    "extensions",
    engineVersion,
    "wasm_threads",
    "vgi.duckdb_extension.wasm",
  );
const defaultOutput = join(here, "dist");
const output = resolve(process.env.DEMO_DIST ?? defaultOutput);
const outputMarker = ".vgi-iroh-browser-demo-output";
const enginePackageRoot = existsSync(
  join(engineRoot, "dist", "duckdb-browser.mjs"),
)
  ? engineRoot
  : join(engineRoot, "packages", "duckdb-wasm");
const engineWasmCandidates = [
  join(enginePackageRoot, "src", "bindings", "duckdb-coi.wasm"),
  join(enginePackageRoot, "dist", "duckdb-coi.wasm"),
];
const haybarnDist = join(enginePackageRoot, "dist");
const engineWasm = engineWasmCandidates.find(existsSync);
const generatedJavaScript = join(generatedBindings, "vgi_rpc_iroh_browser.js");
const generatedWasm = join(generatedBindings, "vgi_rpc_iroh_browser_bg.wasm");
const haybarnVgi = join(haybarnDist, "duckdb-browser-vgi.mjs");

const prerequisites = new Map([
  ["Haybarn browser module", join(haybarnDist, "duckdb-browser.mjs")],
  ["Haybarn COI worker", join(haybarnDist, "duckdb-browser-coi.worker.js")],
  [
    "Haybarn pthread worker",
    join(haybarnDist, "duckdb-browser-coi.pthread.worker.js"),
  ],
  ["Haybarn VGI bridge", haybarnVgi],
  ["generated Iroh bindings", generatedJavaScript],
  ["generated Iroh WebAssembly", generatedWasm],
  ["VGI loadable extension", extension],
]);
for (const [label, path] of prerequisites) {
  if (!existsSync(path)) {
    throw new Error(`${label} is missing: ${path}`);
  }
}
if (!engineWasm) {
  throw new Error(
    `Haybarn COI WebAssembly is missing; checked ${engineWasmCandidates.join(", ")}`,
  );
}

let esbuild;
try {
  esbuild = createRequire(join(haybarn, "package.json"))("esbuild");
} catch (error) {
  throw new Error(
    `esbuild is not installed in ${haybarn}; install the Haybarn workspace dependencies`,
    { cause: error },
  );
}

const forbiddenOutputs = new Set([
  parse(output).root,
  resolve(homedir()),
  resolve(repository),
  resolve(here),
  resolve(haybarn),
  resolve(engineRoot),
]);
if (forbiddenOutputs.has(output)) {
  throw new Error(`refusing unsafe DEMO_DIST: ${output}`);
}
if (existsSync(output)) {
  const metadata = lstatSync(output);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`DEMO_DIST must be a real directory: ${output}`);
  }
  if (
    output !== resolve(defaultOutput) &&
    !existsSync(join(output, outputMarker))
  ) {
    throw new Error(
      `refusing to replace unmarked DEMO_DIST: ${output}; choose a new directory`,
    );
  }
}
rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
writeFileSync(join(output, outputMarker), "VGI Iroh browser demo output\n");
copyFileSync(join(here, "index.html"), join(output, "index.html"));
for (const file of [
  "duckdb-browser-coi.worker.js",
  "duckdb-browser-coi.pthread.worker.js",
]) {
  copyFileSync(join(haybarnDist, file), join(output, file));
}
copyFileSync(engineWasm, join(output, "duckdb-coi.wasm"));
copyFileSync(generatedWasm, join(output, "vgi_rpc_iroh_browser_bg.wasm"));
copyFileSync(extension, join(output, "vgi.duckdb_extension.wasm"));

const common = {
  bundle: true,
  format: "esm",
  platform: "browser",
  sourcemap: true,
  target: ["es2022"],
  nodePaths: [join(haybarn, "node_modules")],
  logLevel: "info",
};
await esbuild.build({
  ...common,
  entryPoints: [join(here, "main.ts")],
  outfile: join(output, "main.js"),
  alias: {
    "demo-haybarn": join(haybarnDist, "duckdb-browser.mjs"),
    "demo-haybarn-vgi": haybarnVgi,
  },
});
await esbuild.build({
  ...common,
  entryPoints: [join(here, "adapter-entry.ts")],
  outfile: join(output, "adapter-worker.js"),
  alias: {
    "demo-iroh-bindings": generatedJavaScript,
  },
});

console.log(`Browser demo built in ${output}`);
console.log(`VGI extension ABI version: ${engineVersion}`);
