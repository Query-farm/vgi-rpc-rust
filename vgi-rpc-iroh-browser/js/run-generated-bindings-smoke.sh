#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
port=$((20000 + RANDOM % 20000))
log_file=$(mktemp)
output_file=$(mktemp)
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -f "$log_file" "$output_file"
}
trap cleanup EXIT

python3 -m http.server "$port" --bind 127.0.0.1 --directory "$repo_root" >"$log_file" 2>&1 &
server_pid=$!

smoke_url="http://127.0.0.1:$port/vgi-rpc-iroh-browser/js/generated-bindings-smoke.html"
ready=false
for _ in {1..100}; do
  if curl --fail --silent "$smoke_url" >/dev/null; then
    ready=true
    break
  fi
  sleep 0.05
done
if [[ "$ready" != true ]]; then
  cat "$log_file" >&2
  echo "browser smoke HTTP server did not become ready" >&2
  exit 1
fi

chrome=${CHROME_BIN:-}
if [[ -z "$chrome" ]]; then
  if command -v google-chrome >/dev/null 2>&1; then
    chrome=$(command -v google-chrome)
  elif [[ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]]; then
    chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
  else
    echo "Chrome not found; set CHROME_BIN" >&2
    exit 1
  fi
fi

"$chrome" --headless --disable-gpu --no-sandbox --virtual-time-budget=5000 \
  --dump-dom "$smoke_url" \
  >"$output_file"
cat "$output_file"
grep -q '<body>PASS</body>' "$output_file"
