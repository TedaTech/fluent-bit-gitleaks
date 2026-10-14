# fluent-bit-gitleaks

A [fluent-bit](https://fluentbit.io) WASM filter that redacts secrets and
personal data from log records using
[gitleaks](https://github.com/gitleaks/gitleaks)' detector and default rule
set — keyword prefilter, entropy checks and allowlists included — plus
[alcatraz](https://github.com/hoophq/alcatraz)' email and IP recognizers for
personal data.

Every string field of a record is scanned; each finding is replaced with
`REDACTED:<rule-id>`. A record the filter cannot decode is replaced with
`{"log":"REDACTED:scrub-error"}` rather than passed through.

Secret rules apply to every record. PII masking (`pii-email`, `pii-ipv4`,
`pii-ipv6`) applies only to records whose tag starts with `kube.` or
`events.` — tenant-facing container logs and Kubernetes events. Node and audit
logs keep their addresses: infra debugging needs node and peer IPs, and the
audit trail's source IPs are the security-forensics record, protected by access
control and retention instead of masking.

```
{"log":"connecting with api_key=q8Rf2LxW9mTz4KcVb7NpYs3H"}
{"log":"connecting with api_key=REDACTED:generic-api-key"}
```

## Requirements

- fluent-bit **≥ 4.2.0**. Earlier releases re-instantiate the module for every
  chunk (≤ 4.0) or leak the per-record buffers (4.1), and 3.x passes records
  through unfiltered when the module fails to load.
- The `.aot` file must match the WAMR version bundled in your fluent-bit. Image
  tags carry it: `vX.Y.Z-wamr2.4.1` fits fluent-bit 4.2 – 5.1.

## Image

`ghcr.io/tedatech/fluent-bit-gitleaks:<version>-wamr<wamr>` is a `scratch`
image for `linux/amd64` and `linux/arm64`:

| Path | |
|---|---|
| `/fluent-bit-gitleaks.aot` | AOT-compiled for the image's architecture — use this |
| `/fluent-bit-gitleaks.wasm` | portable module; the WAMR interpreter runs it ~12× slower |
| `/LICENSE`, `/THIRD_PARTY_NOTICES` | this project's and every embedded dependency's license |

Mount it into the fluent-bit pod as a Kubernetes
[image volume](https://kubernetes.io/docs/concepts/storage/volumes/#image):

```yaml
volumes:
  - name: gitleaks
    image:
      reference: ghcr.io/tedatech/fluent-bit-gitleaks:v0.1.0-wamr2.4.1
containers:
  - name: fluent-bit
    volumeMounts:
      - name: gitleaks
        mountPath: /fluent-bit/wasm
        readOnly: true
```

## fluent-bit configuration

```ini
[FILTER]
    Name             wasm
    Match            kube.*
    WASM_Path        /fluent-bit/wasm/fluent-bit-gitleaks.aot
    Function_Name    scrub
    Accessible_Paths /fluent-bit/wasm
    Wasm_Stack_Size  8M
    Wasm_Heap_Size   8M
```

Place it before any `rewrite_tag` so re-emitted records are not scanned twice.

## Rules

`gitleaks.toml` extends gitleaks' default rules (pinned by the gitleaks version
in `go.mod`) with `kv-pair-secret` — protobuf-text key/value pairs such as
`secrets:{key:"secret-key" value:"…"}`, raw or JSON-escaped, a shape the
default rules miss.

Personal data is detected by alcatraz's Presidio-derived email and IP
recognizers (pinned by the alcatraz version in `go.mod`), not by hand-written
rules. Detected IPs are masked only when `net/netip` classifies them as public
(global unicast and not private): RFC1918, loopback, link-local, multicast,
broadcast, `0.0.0.0` and IPv6 ULA all pass through. Full-form IPv6 addresses
are masked as `pii-ipv6`; a four-part version string (`1.2.3.4-rc1`) matches
by accepted design — a lost version string costs less than a shipped client
IP.

## Performance

`test/bench.sh` runs fluent-bit over a generated mix (5% leaks, 25% keyword
hits) and checks the output redacts exactly what native gitleaks redacts.

| | rec/s (one core) | peak RSS |
|---|---|---|
| no filter | — | 33 MiB |
| `.wasm` (interpreted) | 433 | 175 MiB |
| `.aot` | 5,380 | 150 MiB |

Measured locally on fluent-bit 5.1.3, Apple M-series, `linux/arm64`. CI reruns
the bench on `linux/amd64` runners; their numbers vary with the runner.

## Development

```sh
go test ./...                                                          # rules, native
docker buildx build --platform linux/amd64 --output type=local,dest=dist .
test/bench.sh                                                          # fluent-bit + dist/
```

The WASM build needs two shims: `hack/termenv_wasip1.go` (termenv has no
`wasip1` build) and `internal/argv` (WAMR passes an empty `argv`, which pflag's
`init` indexes).

## License

MIT. The compiled filter embeds gitleaks (MIT), its dependencies and the Go
runtime; the image carries their licenses in `/THIRD_PARTY_NOTICES`.
