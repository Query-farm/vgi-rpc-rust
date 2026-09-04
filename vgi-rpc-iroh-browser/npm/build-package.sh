#!/usr/bin/env bash
set -euo pipefail

package_root=$(cd "$(dirname "$0")" && pwd)
repository_root=$(cd "$package_root/../.." && pwd)
wasm_input=${1:-$repository_root/target/wasm32-unknown-unknown/release/vgi_rpc_iroh_browser.wasm}

rm -rf "$package_root/dist" "$package_root/src/wasm"
rm -f "$package_root/src/transport.ts" "$package_root/src/adapter-worker.ts"
mkdir -p "$package_root/src/wasm"
cp "$repository_root/vgi-rpc-iroh-browser/js/index.ts" "$package_root/src/transport.ts"
cp "$repository_root/vgi-rpc-iroh-browser/js/adapter-worker.ts" "$package_root/src/adapter-worker.ts"
cp "$repository_root/LICENSE" "$package_root/LICENSE"
cp "$repository_root/NOTICE" "$package_root/NOTICE"

wasm-bindgen --target web --out-dir "$package_root/src/wasm" "$wasm_input"
(cd "$package_root" && npm run build)
mkdir -p "$package_root/dist/wasm"
cp "$package_root/src/wasm/"* "$package_root/dist/wasm/"

test -f "$package_root/dist/index.js"
test -f "$package_root/dist/index.d.ts"
test -f "$package_root/dist/adapter-worker.js"
test -f "$package_root/dist/wasm/vgi_rpc_iroh_browser.js"
test -f "$package_root/dist/wasm/vgi_rpc_iroh_browser_bg.wasm"
