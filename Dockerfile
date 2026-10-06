# syntax=docker/dockerfile:1
# check=skip=FromPlatformFlagConstDisallowed
FROM --platform=$BUILDPLATFORM golang:1.27 AS wasm
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go mod vendor \
 && cp hack/termenv_wasip1.go vendor/github.com/muesli/termenv/ \
 && GOOS=wasip1 GOARCH=wasm go build -mod=vendor -trimpath -buildmode=c-shared -o /out/fluent-bit-gitleaks.wasm . \
 && { printf -- '--- Go ---\n\n'; cat "$(go env GOROOT)/LICENSE"; \
      find vendor -type f \( -iname 'LICENSE*' -o -iname 'NOTICE*' -o -iname 'COPYING*' \) | sort | while read -r f; do \
        printf -- '\n--- %s ---\n\n' "${f#vendor/}"; cat "$f"; done; } > /out/THIRD_PARTY_NOTICES

FROM --platform=linux/amd64 ubuntu:22.04 AS aot
ARG WAMR_VERSION=2.4.1
ARG TARGETARCH
ADD --checksum=sha256:fb0c656f98613bdd9df7e67b653c6afc9ff8f090785dfe8edf56ceaeb7e9bacd \
    https://github.com/bytecodealliance/wasm-micro-runtime/releases/download/WAMR-${WAMR_VERSION}/wamrc-${WAMR_VERSION}-x86_64-ubuntu-22.04.tar.gz /tmp/wamrc.tgz
RUN tar -xzf /tmp/wamrc.tgz -C /usr/local/bin
COPY --from=wasm /out/ /out/
RUN wamrc --target=$([ "$TARGETARCH" = arm64 ] && echo aarch64 || echo x86_64) \
      -o /out/fluent-bit-gitleaks.aot /out/fluent-bit-gitleaks.wasm

FROM scratch
LABEL org.opencontainers.image.source=https://github.com/TedaTech/fluent-bit-gitleaks
LABEL org.opencontainers.image.licenses=MIT
COPY --from=aot /out/ /
COPY LICENSE /
