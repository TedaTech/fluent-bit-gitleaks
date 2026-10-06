#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
want=$(sed -n 's/^ARG WAMR_VERSION=//p' "$root/Dockerfile")
fb=$(sed 's/.*://' "$root/test/fluent-bit-image")
got=$(curl -fsSL ${GH_TOKEN:+-H "Authorization: Bearer $GH_TOKEN"} "https://api.github.com/repos/fluent/fluent-bit/contents/lib?ref=v$fb" | python3 -c "import json,sys;print(next(e['name'] for e in json.load(sys.stdin) if e['name'].startswith('wasm-micro-runtime-WAMR-'))[len('wasm-micro-runtime-WAMR-'):])")
[ "$got" = "$want" ] || { echo "fluent-bit $fb bundles WAMR $got, Dockerfile pins $want" >&2; exit 1; }
echo "fluent-bit $fb bundles WAMR $want" >&2
echo "$want"
