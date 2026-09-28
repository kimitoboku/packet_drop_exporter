FROM golang:1.27-bookworm AS build

ARG VERSION=dev

ENV CGO_ENABLED=0 \
    GOFLAGS=-trimpath

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        clang \
        llvm \
        libbpf-dev \
        linux-libc-dev \
        make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go generate ./internal/bpf \
    && go test ./... \
    && go vet ./... \
    && go run ./cmd/license-bundle \
    && mkdir -p /out \
    && go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/packet-drop-exporter ./cmd/packet-drop-exporter

FROM build AS test

ENV CGO_ENABLED=1

CMD ["go", "test", "-race", "./..."]

FROM debian:bookworm-slim AS exporter

LABEL org.opencontainers.image.title="packet-drop-exporter" \
      org.opencontainers.image.description="Prometheus exporter for Linux skb drop reasons using eBPF" \
      org.opencontainers.image.source="https://github.com/kimitoboku/packet_drop_exporter" \
      org.opencontainers.image.licenses="MIT"

RUN useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin exporter
COPY --from=build /out/packet-drop-exporter /usr/local/bin/packet-drop-exporter
COPY --from=build /src/LICENSE /usr/share/doc/packet-drop-exporter/LICENSE
COPY --from=build /src/THIRD_PARTY_NOTICES.md /usr/share/doc/packet-drop-exporter/THIRD_PARTY_NOTICES.md
COPY --from=build /src/third_party_licenses /usr/share/doc/packet-drop-exporter/third_party_licenses

USER exporter
ENTRYPOINT ["/usr/local/bin/packet-drop-exporter"]
