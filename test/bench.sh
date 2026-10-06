#!/usr/bin/env bash
set -euo pipefail
image=${FLUENT_BIT_IMAGE:-cr.fluentbit.io/fluent/fluent-bit:5.1.3}
n=${N:-20000}
port=${PORT:-2020}
mode=$([ -n "${BASELINE:-}" ] && echo baseline || echo wasm)
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "$here/.work.XXXX")
trap 'docker rm -f fbg-bench >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
python3 "$here/gen.py" "$n" > "$work/in.jsonl"
mkdir -p "$work/out"
filter=$here/${FILTER_CONF:-filter.conf}
[ "$mode" = baseline ] && { : > "$work/none.conf"; filter=$work/none.conf; }
docker run -d --name fbg-bench -p "$port:2020" \
  -v "$here/..:/wasm:ro" -v "$here:/bench:ro" -v "$filter:/bench/filter.conf:ro" \
  -v "$work:/data:ro" -v "$work/out:/out" \
  "$image" /fluent-bit/bin/fluent-bit -c /bench/bench.conf >/dev/null
running() {
  [ "$(docker inspect -f '{{.State.Running}}' fbg-bench)" = true ] || { docker logs fbg-bench 2>&1 | tail; exit 1; }
}
metric() {
  curl -sf -m 2 "localhost:$port/api/v1/metrics" | python3 -c "import json,sys;m=json.load(sys.stdin)['$1'];print(next(iter(m.values()))['$2'])" 2>/dev/null || echo 0
}
until [ "$(metric input records)" -gt 0 ]; do running; done
start=$(date +%s.%N)
peak=0
until [ "$(metric output proc_records)" -ge "$n" ]; do
  running
  m=$(docker stats --no-stream --format '{{.MemUsage}}' fbg-bench | awk '{print $1}')
  peak=$(python3 -c "import re;v,u=re.match(r'([\d.]+)(\w+)','$m').groups();print(max($peak,float(v)*{'B':2**-20,'kB':2**-10,'KiB':2**-10,'MiB':1,'MB':1,'GiB':1024,'GB':1024}[u]))")
done
end=$(date +%s.%N)
docker stop fbg-bench >/dev/null
python3 -c "import sys;s,e,n,p=map(float,sys.argv[2:]);print(f'{sys.argv[1]}: {int(n)} records in {e-s:.1f}s = {n/(e-s):.0f} rec/s, peak mem {p:.0f} MiB')" \
  "$mode" "$start" "$end" "$n" "$peak"
[ "$mode" = baseline ] && exit 0
want=$(cd "$here/.." && go run . < "$work/in.jsonl" | grep -c REDACTED)
got=$(grep -c REDACTED "$work/out/out.jsonl")
echo "redacted $got/$want records native gitleaks redacts"
[ "$got" = "$want" ]
