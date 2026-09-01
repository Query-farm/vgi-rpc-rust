# Haybarn `httpi://` browser demo

This page exercises the complete browser path:

```text
Haybarn/VGI -> SharedArrayBuffer -> adapter Worker
             -> vgi-rpc-iroh-browser.wasm -> iroh-http/2
             -> vgi-iroh-bridge -> ordinary VGI HTTP worker
```

It uses the generated wasm-bindgen package, the production
`installIrohVgiAdapter` pump, and Haybarn's production
`installVgiWebWorkerBridge`. The page accepts one bridge EndpointId, authorizes
only that exact peer, loads the VGI extension, executes
`ATTACH 'example' AS remote (TYPE vgi, LOCATION 'httpi://<EndpointId>')`, and
runs a SELECT against the attached catalog. Before the user query, it calls the
VGI example worker's `whoami` function and fails unless the authenticated
principal ends in the browser endpoint's own EndpointId.

## Prerequisites

- A built Haybarn WASM checkout, including its COI engine and VGI page bridge.
- A VGI loadable WASM extension compatible with that engine.
- Homebrew LLVM on macOS (Apple clang has no WebAssembly backend), or LLVM clang
  and `llvm-ar` on Linux.
- `wasm-bindgen-cli` 0.2.121, matching this workspace's lockfile.
- A `vgi-rust` checkout containing the example worker's explicit
  `--http-iroh-demo` mode.

The repository launcher builds and owns the VGI example worker, bridge, browser
bindings, and asset server:

```sh
python3 vgi-rpc-iroh-browser/demo/launch.py
```

It supplies the EndpointId in the page URL and runs the demo automatically.
`Ctrl-C` gracefully stops both native children. For manual operation, start the
worker and bridge separately, retaining each readiness line:

```sh
cargo run --manifest-path "$HOME/Development/vgi-rust/Cargo.toml" \
  -p vgi-example-worker -- --http-iroh-demo
cargo run -p vgi-iroh-bridge -- \
  --ephemeral \
  --http-upstream http://127.0.0.1:<worker-port>
```

`--ephemeral` is development-only. Use `--secret-key-file` for a stable bridge
identity.

For the automated Chrome assertion, add `--verify`. It exits non-zero unless
the page is cross-origin isolated, ATTACH and SELECT succeed, and the worker's
authenticated Iroh principal matches the browser EndpointId.

## Build and run

From the repository root:

```sh
CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang \
AR_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/llvm-ar \
cargo build -p vgi-rpc-iroh-browser \
  --target wasm32-unknown-unknown --locked

wasm-bindgen --target web --out-dir target/browser-bindings \
  target/wasm32-unknown-unknown/debug/vgi_rpc_iroh_browser.wasm

cd vgi-rpc-iroh-browser/demo
HAYBARN_WASM="$HOME/Development/haybarn/haybarn-wasm" \
VGI_EXT_WASM=/absolute/path/to/vgi.duckdb_extension.wasm \
VGI_ENGINE_VERSION_DIR=v1.5.5 \
npm run build

npm run serve
```

Open <http://127.0.0.1:8787/>, paste the bridge's lowercase 64-hex EndpointId,
and run the query. The EndpointId can also be supplied in the URL:

```text
http://127.0.0.1:8787/?endpoint=<64-lowercase-hex>
```

Add `&autorun=1` to start without pressing the button.

Environment overrides understood by `build.mjs`:

| Variable                 | Default                                           |
| ------------------------ | ------------------------------------------------- |
| `HAYBARN_WASM`           | `~/Development/haybarn/haybarn-wasm`              |
| `VGI_ENGINE_ROOT`        | same as `HAYBARN_WASM`                             |
| `IROH_BINDINGS`          | repository `target/browser-bindings`              |
| `VGI_EXT_WASM`           | the extension under the Haybarn version directory |
| `VGI_ENGINE_VERSION_DIR` | `v1.5.5`                                          |
| `DEMO_DIST`              | `demo/dist`                                       |

`serve.mjs` sets COOP, COEP, and CORP headers. A generic static server without
those headers will not expose `SharedArrayBuffer`, and the demo intentionally
fails before starting Haybarn.

## Security boundary

The Haybarn resolver allows only the exact `httpi://` EndpointId entered in the
form. The Iroh adapter authenticates that peer cryptographically. The bridge
still forwards identity evidence rather than an authorization decision: the
HTTP worker must independently configure its trusted bridge boundary and
authorization policy.

The included worker mode is development-only. It trusts the loopback address,
so another process in the same network namespace could forge the forwarded
header, and `peer_identity_primary("iroh")` accepts any cryptographically valid
Iroh EndpointId rather than enforcing an application caller allowlist. A
deployment must isolate the bridge-to-worker listener, trust only the bridge's
exact private address, and apply its own EndpointId authorization policy.
