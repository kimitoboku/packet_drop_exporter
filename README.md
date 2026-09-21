# packet-drop-exporter

[![CI](https://github.com/kimitoboku/packet_drop_exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/kimitoboku/packet_drop_exporter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/kimitoboku/packet_drop_exporter)](go.mod)

`packet-drop-exporter` is a Linux Prometheus exporter that uses eBPF to aggregate `sk_buff` drops observed at `tp_btf/kfree_skb`. It reports cumulative packet and byte counters by kernel drop reason, drop location, and L3 protocol without forwarding every event to user space.

> [!IMPORTANT]
> The project is experimental and has not reached a stable release. It has been verified on the Docker Desktop Linux VM kernel, but the planned distribution-kernel matrix, a full 24-hour soak, real CPU hotplug, and packet-path performance comparisons are not complete. See [Verification Status](#verification-status).

## Features

- CO-RE eBPF program attached to the typed `kfree_skb` BTF tracepoint.
- Per-CPU in-kernel aggregation with fixed map capacity.
- Drop reasons resolved from the running kernel's BTF instead of a compiled-in enum table.
- Kernel locations resolved through `/proc/kallsyms`, with atomic refresh after `/proc/modules` changes.
- Immutable user-space snapshots, keeping Prometheus scrapes independent from BPF map traversal.
- Optional network namespace and interface dimensions.
- Health, readiness, exporter self-metrics, Prometheus rules, and a Grafana dashboard.
- Linux amd64/arm64 release and OCI image automation with runtime dependency licenses, SBOM, provenance, checksums, and keyless signatures.

The exporter does not read packet payloads, IP addresses, ports, process IDs, cgroups, or container identifiers. Raw kernel addresses are not exposed as metric labels or normal log fields.

## How It Works

```text
Linux network stack
        │
        │ tp_btf/kfree_skb
        ▼
eBPF collector
        │ per-CPU packet/byte counters
        ▼
BPF maps
        │ periodic collection
        ▼
Immutable Go snapshot ─── /metrics ─── Prometheus
        │
        ├── drop reason resolver (kernel BTF)
        └── location resolver (/proc/kallsyms)
```

The primary map uses a fixed capacity rather than LRU eviction. If a new series cannot be inserted, existing counters continue to update and `packet_drop_exporter_map_update_failures_total` increases.

## Requirements

The exporter targets Linux amd64 and arm64. Support is determined by startup feature checks, not only by a kernel version number. The running kernel must provide:

- BPF syscalls and the required map types.
- BTF at `/sys/kernel/btf/vmlinux`.
- A drop-reason-aware `tp_btf/kfree_skb` hook.
- CO-RE-compatible fields used from `sk_buff` and `net_device`.

Runtime permissions normally include `CAP_BPF`, `CAP_PERFMON`, and sufficient memlock. Some kernels or distributions also require `CAP_SYS_ADMIN` for BPF operations and `CAP_SYSLOG` to expose kallsyms addresses. The supplied Docker integration profile is intentionally privileged; the systemd deployment is preferred when tighter capability control is required.

## Quick Start

### Build and Test with Docker

Docker is the reproducible development environment and is also required when developing on macOS.

```sh
docker compose run --build --rm test
```

This generates the BPF bindings inside Debian Bookworm, then runs unit tests, race tests, static analysis, and the Go build.

### Run Against a Linux Kernel

Run the privileged integration profile on a Linux host:

```sh
docker compose --profile integration up --build exporter
```

In another terminal:

```sh
curl --fail http://127.0.0.1:9435/-/ready
curl --fail http://127.0.0.1:9435/metrics
```

On Docker Desktop, its host-network container may not be reachable from the macOS loopback. Probe it from the same network namespace instead:

```sh
docker run --rm \
  --network container:packet_drop_exporter-exporter-1 \
  curlimages/curl:8.10.1 \
  -fsS http://127.0.0.1:9435/-/ready
```

Success on Docker Desktop validates its Linux VM kernel only; it is not evidence for the eventual target host kernel matrix.

### Build and Install Natively

On Debian or Ubuntu, install the build dependencies and compile:

```sh
sudo apt-get update
sudo apt-get install --yes clang llvm libbpf-dev linux-libc-dev make
make build
sudo install -Dm0755 bin/packet-drop-exporter /usr/local/bin/packet-drop-exporter
sudo install -Dm0644 config.example.yaml /etc/packet-drop-exporter/config.yaml
sudo install -Dm0644 packet-drop-exporter.service.example /etc/systemd/system/packet-drop-exporter.service
sudo systemctl daemon-reload
sudo systemctl enable --now packet-drop-exporter
```

Review the capability set in the example unit before production use. Requirements vary by kernel and distribution.

### Published Container Image

After the first tagged release, the release workflow publishes `linux/amd64` and `linux/arm64` images to:

```text
ghcr.io/kimitoboku/packet_drop_exporter
```

Project and runtime dependency license texts are installed under `/usr/share/doc/packet-drop-exporter` in the image.

The equivalent direct invocation is intentionally explicit about its host access:

```sh
docker run --rm \
  --user 0 \
  --privileged \
  --pid host \
  --network host \
  --security-opt apparmor=unconfined \
  --volume /sys/kernel/btf:/sys/kernel/btf:ro \
  --volume /sys/kernel/debug:/sys/kernel/debug \
  ghcr.io/kimitoboku/packet_drop_exporter:latest \
  --web.listen-address=127.0.0.1:9435
```

## Configuration

The complete example is in [config.example.yaml](config.example.yaml).

```yaml
listen_address: "127.0.0.1:9435"
metrics_path: "/metrics"
collection_interval: "5s"

bpf:
  max_entries: 8192
  reason: true
  location: true
  protocol: true
  interface: false

symbolizer:
  kallsyms_path: "/proc/kallsyms"
  modules_path: "/proc/modules"
  module_refresh_interval: "60s"

logging:
  level: "info"
  format: "json"
```

`bpf.reason` is mandatory in v1 because disabling it would change the meaning of the product metrics. Enabling `bpf.interface` adds `netns` and `ifindex` to the map key and metric labels, potentially increasing cardinality significantly.

CLI flags override file values:

```text
--config.file
--web.listen-address
--web.metrics-path
--collector.interval
--bpf.max-entries
--bpf.dimension-location
--bpf.dimension-protocol
--bpf.dimension-interface
--symbolizer.kallsyms-path
--symbolizer.modules-path
--symbolizer.module-refresh-interval
--log.level
--log.format
--version
```

## Metrics and Endpoints

The default primary metrics are:

| Metric | Type | Description |
| --- | --- | --- |
| `linux_skb_drops_total` | counter | Number of observed skb drops. |
| `linux_skb_drop_bytes_total` | counter | Bytes associated with observed skb drops. |

Default labels are `reason`, `location`, and `protocol`. When the interface dimension is enabled, `netns` and `ifindex` are added. Counters reset when the exporter restarts; Prometheus `rate()` and `increase()` handle this as a normal counter reset.

Exporter self-metrics use the `packet_drop_exporter_` prefix and cover attachment/readiness, map capacity and estimated memory, BPF event statistics, collection freshness, resolver availability, and failure counters.

| Path | Meaning |
| --- | --- |
| `/metrics` | Prometheus metrics. |
| `/-/healthy` | The process is alive. |
| `/-/ready` | BPF is attached and at least one valid snapshot exists. |

Monitoring assets are provided in:

- [Prometheus recording and alerting rules](deploy/prometheus/packet-drop-exporter.rules.yaml)
- [Grafana dashboard](deploy/grafana/packet-drop-exporter.json)

## Observation Scope and Limitations

This exporter observes drops that reach `kfree_skb`. It is not a complete source for every packet loss mechanism. In particular, it does not fully observe:

- NIC hardware or driver RX-ring drops.
- `/proc/net/softnet_stat` drops.
- qdisc drops that never reach `kfree_skb`.
- `XDP_DROP`, especially hardware-offloaded XDP.
- Discards performed by user-space applications.

Use NIC statistics, node_exporter, qdisc telemetry, and XDP-program counters alongside this exporter when those layers matter.

If kallsyms is unavailable because of permissions or `kptr_restrict`, collection continues with `location="unknown"`, readiness remains enabled, and `packet_drop_exporter_symbolizer_available` is set to `0`.

## Development and Testing

Common commands:

```sh
make test                    # Generate BPF bindings and run unit tests
make race                    # Run the Go race detector
make vet                     # Run go vet
make benchmark               # Benchmark 8192-entry snapshot construction
make licenses                # Collect runtime dependency licenses
make docker-test             # Reproduce tests in Linux/Docker
make docker-integration-test # Privileged map-full and kallsyms checks
make docker-integration      # Run the exporter against the current Linux kernel
make docker-soak             # Run the 24-hour readiness/metrics soak
```

Override the soak duration for a quick orchestration check:

```sh
SOAK_SECONDS=300 SOAK_INTERVAL_SECONDS=5 make docker-soak
```

Generated `internal/bpf/drop_bpf*.go` and object files are intentionally ignored. Regenerate them with `go generate ./internal/bpf`; do not edit generated files manually.

After changing Go runtime dependencies, run `make licenses` and review the generated manifest before opening a pull request. The generated directory is ignored because CI, image builds, and release automation recreate it from `go.mod` and the actual exporter dependency graph.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow, [docs/implementation-plan.md](docs/implementation-plan.md) for design decisions, and [docs/verification.md](docs/verification.md) for recorded evidence and explicit verification boundaries.

## Verification Status

The current implementation has passed:

- Go unit, race, and vet checks on the development host.
- Docker-based Linux generation, tests, vet, and build.
- Privileged attachment, real UDP `NO_SOCKET` reproduction, map-full accounting, and unavailable-kallsyms behavior on the Docker Desktop Linux VM kernel.
- A short run through the same Compose path used by the 24-hour soak.
- Prometheus rule, Grafana JSON, Compose, and GoReleaser configuration validation.

The following evidence is still required before claiming production readiness:

- Multiple upstream LTS and distribution kernels.
- Real CPU add/remove testing.
- Attached-versus-unattached packet throughput and CPU measurements.
- A complete 24-hour soak.
- An actual tagged release with downloaded artifact and signature verification.

## Releases and Signature Verification

Tags matching `v*` trigger release automation for Linux amd64/arm64 archives and a multi-architecture OCI image. Archives include an SBOM, [third-party notices](THIRD_PARTY_NOTICES.md), and the license files for runtime Go modules. They are covered by `checksums.txt`; the checksum file is signed using keyless cosign.

For a release tag such as `v0.1.0`, verify the checksum bundle before using an archive:

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/kimitoboku/packet_drop_exporter/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt

sha256sum --ignore-missing --check checksums.txt
```

No release artifacts exist until the first tag is published.

## Contributing and Security

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and follow the [Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request.

Please do not report vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md) instead.

Repository documentation is maintained in English. Discussions may use whichever language participants prefer, but durable decisions and verification evidence should be recorded in English.

## License

Copyright (c) 2026 Kento Kawakami.

Released under the [MIT License](LICENSE).
