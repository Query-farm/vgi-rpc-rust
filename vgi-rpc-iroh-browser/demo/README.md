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
`ATTACH 'example' AS remote (TYPE vgi, LOCATION 'httpi://<EndpointId>')`, and runs a SELECT against
the attached catalog.

## Prerequisites

- A built Haybarn WASM checkout, including its COI engine and VGI page bridge.
- A VGI loadable WASM extension compatible with that engine.
- Homebrew LLVM on macOS (Apple clang has no WebAssembly backend), or LLVM clang
  and `llvm-ar` on Linux.
- `wasm-bindgen-cli` 0.2.121, matching this workspace's lockfile.
- A reachable `vgi-iroh-bridge --http-upstream ...` in front of a VGI HTTP
  worker. The worker used by the default SELECT exposes `count_to`.

Start the bridge, retaining the first stdout line as the EndpointId:

```sh
cargo run -p vgi-iroh-bridge -- \
  --ephemeral \
  --http-upstream http://127.0.0.1:9401
```

`--ephemeral` is development-only. Use `--secret-key-file` for a stable bridge
identity.

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

Environment overrides understood by `build.mjs`:

| Variable                 | Default                                           |
| ------------------------ | ------------------------------------------------- |
| `HAYBARN_WASM`           | `~/Development/haybarn/haybarn-wasm`              |
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
