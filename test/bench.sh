#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
image=${FLUENT_BIT_IMAGE:-$(cat "$here/fluent-bit-image")}
dist=${DIST:-$here/../dist}
n=${N:-20000}
port=${PORT:-2020}
mode=$([ -n "${BASELINE:-}" ] && echo baseline || echo wasm)
work=$(mktemp -d "$here/.work.XXXX")
trap 'docker rm -f fbg-bench >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
python3 "$here/gen.py" "$n" > "$work/in.jsonl"
mkdir -p "$work/out"
filter=$here/filter.conf
[ "$mode" = baseline ] && { : > "$work/none.conf"; filter=$work/none.conf; }
docker run -d --name fbg-bench -p "$port:2020" \
  -v "$dist:/wasm:ro" -v "$here:/bench:ro" -v "$filter:/bench/filter.conf:ro" \
  -v "$work:/data:ro" -v "$work/out:/out" \
  "$image" /fluent-bit/bin/fluent-bit -c /bench/bench.conf >/dev/null
running() {
  [ "$(docker inspect -f '{{.State.Running}}' fbg-bench)" = true ] || { docker logs fbg-bench 2>&1 | tail; exit 1; }
}
metric() {
  curl -sf -m 2 "localhost:$port/api/v1/metrics" | python3 -c "import json,sys;m=json.load(sys.stdin)['$1'];print(next(iter(m.values()))['$2'])" 2>/dev/null || echo 0
}
sample_peak() {
  local m
  m=$(docker stats --no-stream --format '{{.MemUsage}}' fbg-bench | awk '{print $1}')
  python3 -c "import re;v,u=re.match(r'([\d.]+)(\w+)','$m').groups();print(max($(cat "$work/peak" 2>/dev/null || echo 0),float(v)*{'B':2**-20,'kB':2**-10,'KiB':2**-10,'MiB':1,'MB':1,'GiB':1024,'GB':1024}[u]))" > "$work/peak.new"
  mv "$work/peak.new" "$work/peak"
}
until [ "$(metric input records)" -gt 0 ]; do running; done
start=$(date +%s.%N)
# docker stats --no-stream blocks ~2s; sampling it in the completion poll
# rounded the measured duration up to that tick.
while :; do sample_peak; done &
sampler=$!
until [ "$(metric output proc_records)" -ge "$n" ]; do running; sleep 0.05; done
end=$(date +%s.%N)
kill "$sampler" 2>/dev/null || true
wait "$sampler" 2>/dev/null || true
sample_peak
docker stop fbg-bench >/dev/null
peak=$(cat "$work/peak")
rate=$(python3 -c "import sys;s,e,n=map(float,sys.argv[1:]);print(int(n/(e-s)))" "$start" "$end" "$n")
python3 -c "import sys;print(f'{sys.argv[1]}: {sys.argv[2]} records, {sys.argv[3]} rec/s, peak mem {float(sys.argv[4]):.0f} MiB')" \
  "$mode" "$n" "$rate" "$peak"
[ "$mode" = baseline ] && exit 0
(cd "$here/.." && go run . < "$work/in.jsonl") > "$work/want.jsonl"
python3 - "$work/want.jsonl" "$work/out/out.jsonl" <<'PY'
import json, sys
want, got = (sorted(json.loads(l)["log"] for l in open(p)) for p in sys.argv[1:])
missing = [l for l in want if "REDACTED" in l and l not in got]
print(f"redacted {sum('REDACTED' in l for l in got)} records, native gitleaks {sum('REDACTED' in l for l in want)}")
if want != got or missing:
    sys.exit(f"wasm output differs from native gitleaks, e.g. {missing[:3]}")
PY
[ "$rate" -ge "${MIN_RATE:-0}" ] || { echo "$rate rec/s is below MIN_RATE=$MIN_RATE" >&2; exit 1; }
