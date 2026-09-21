# Verification Record

## 2026-09-21: Initial Implementation

### Automated Tests

The following commands passed:

```text
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go test -race ./...
GOTOOLCHAIN=local go vet ./...
git diff --check
docker compose run --build --rm test
```

The Docker `build` stage also runs clang, libbpf-header checks, the Go build, and BPF bytecode generation on Debian Bookworm. The `test` stage runs the race test with `CGO_ENABLED=1`.

### Linux Real-Kernel Smoke Test

The following was run on the Docker Desktop Linux VM:

```text
docker compose --profile integration up --build exporter
```

The following was verified:

- The `skb_drop_reason` enum was resolved from `/sys/kernel/btf/vmlinux`.
- The embedded CO-RE object loaded and attached to `tp_btf/kfree_skb`.
- `/metrics` and `/-/ready` responded with `packet_drop_exporter_ready 1` and `packet_drop_exporter_bpf_attached 1`.
- `linux_skb_drops_total` exposed `reason`, `location`, and `protocol` labels.
- After sending five packets to the unused UDP port `54321`, `reason="NO_SOCKET"` and `location="__udp4_lib_rcv"` were observed.
- `packet_drop_exporter_events_seen_total` and `packet_drop_exporter_events_exported_total` increased from the map aggregates.

This is a single-kernel check on the Docker Desktop VM. It does not prove support across the target Linux kernel matrix, CPU hotplug, map-full conditions, kallsyms restrictions, or 24-hour continuous operation. On a native Linux host, run the same compose service and retain results for each target kernel.

## 2026-09-21: Production Hardening Infrastructure

### Automated and Privileged Tests

The following commands passed after adding symbol refresh, possible-CPU re-evaluation, corrected memory estimation, release automation, and monitoring assets:

```text
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go test -race ./...
GOTOOLCHAIN=local go vet ./...
docker compose run --build --rm test
docker compose --profile integration-test run --build --rm integration-test
SOAK_SECONDS=3 SOAK_INTERVAL_SECONDS=1 docker compose --profile integration --profile soak up --build --abort-on-container-exit --exit-code-from soak-probe exporter soak-probe
```

The privileged integration suite verified both of the following on the Docker Desktop Linux VM kernel:

- A one-entry per-CPU hash map was pre-filled, a real UDP no-listener drop was generated, and `map_update_failures` increased.
- BPF attachment and map collection continued with `/dev/null` as kallsyms, while the snapshot reported the symbolizer as unavailable.

The three-second soak used the same Compose path as the default 24-hour run and continuously checked `/-/ready` and `packet_drop_exporter_ready`. This validates orchestration only; it is not 24-hour stability evidence.

### Snapshot Benchmark

The 8192-entry immutable-snapshot benchmark was run in the Debian Linux test container on arm64:

```text
BenchmarkBuildSnapshot8192Entries-8  1386  814449 ns/op  786453 B/op  1 allocs/op
```

This measures user-space snapshot construction only. It does not establish the packet-path throughput target or compare attached versus unattached kernel CPU cost.

### Release and Monitoring Configuration

The following checks passed:

- Grafana dashboard JSON parsed with `jq`.
- Prometheus v2.53.0 `promtool check rules` accepted all nine recording and alerting rules.
- Compose rendered successfully with the integration, integration-test, and soak profiles.
- GoReleaser v2.18.2 accepted `.goreleaser.yaml` in a temporary initialized Git repository.
- All repository YAML files parsed successfully.

The GitHub workflows and keyless signing configuration have not been executed by a tagged release. Distribution-kernel coverage, real CPU hotplug, packet-path benchmarks, a tagged release with signature verification, and the full 24-hour soak remain unverified external tasks.

## 2026-09-21: OSS Publication Readiness

The public README and community files were checked against the current implementation and verification record. The following repository-level checks passed:

```text
rg --files --hidden -g '!.git/**'
rg -n -i 'password|secret|token|api[_-]?key|private[_-]?key|BEGIN .*PRIVATE' --hidden -g '!.git/**' -g '!go.sum' .
jq empty deploy/grafana/packet-drop-exporter.json
docker compose --profile integration --profile integration-test --profile soak config
git diff --check
```

The sensitive-pattern scan found the expected `${{ secrets.GITHUB_TOKEN }}` expressions in the release workflow and words such as `secret` in policy/documentation text. A focused scan found no private-key blocks, common provider token formats, or literal credential assignments. No embedded credentials, packet payloads, or raw kernel addresses were found in repository content.

README statements retain the existing boundaries: the project is experimental, the Docker Desktop result is one VM kernel rather than a distribution matrix, the short soak is not 24-hour evidence, and release/signature verification remains pending until an actual tag is published.

Runtime dependency licensing is checked with `go run ./cmd/license-bundle`. The command derives modules from the exporter dependency graph, copies their top-level license and notice files into `third_party_licenses/`, and fails if any runtime module has no matching file. CI and GoReleaser run the same command, and release archives include the generated bundle plus `THIRD_PARTY_NOTICES.md`.

The Docker build runs the same collector and installs the project license, third-party notice, and generated dependency license files under `/usr/share/doc/packet-drop-exporter` in the final image.

The final publication-readiness pass completed successfully with:

```text
go test ./...
go test -race ./...
go vet ./...
make licenses
docker compose run --build --rm test
docker compose build exporter
ruby YAML and local Markdown-link validation
jq empty deploy/grafana/packet-drop-exporter.json
docker compose --profile integration --profile integration-test --profile soak config
```

The built exporter image was inspected to confirm its OCI license label is `MIT` and that the project license, third-party notice, and generated dependency manifest are present. GoReleaser v2.18.2 accepted the final configuration in a temporary initialized Git repository, and `git diff --check` passed there. The workspace itself remains uncommitted, so no real GitHub Actions run, published package, or hosted security-reporting flow has been verified.
