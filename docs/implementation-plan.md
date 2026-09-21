# Linux Packet Drop Exporter Design

## 1. Overview

Implement a resident exporter that continuously observes discarded `sk_buff` objects in the Linux kernel network stack and exposes cumulative values to Prometheus by drop reason and location.

This design attaches an eBPF program to the BTF tracepoint corresponding to `skb:kfree_skb` and aggregates events in a per-CPU map in the kernel. A user-space process reads the map periodically and creates an immutable snapshot for Prometheus.

The working name is `packet-drop-exporter`.

```text
Linux network stack
        │
        │ kfree_skb tracepoint
        ▼
eBPF collector
        │
        │ per-CPU counters
        ▼
BPF map
        │
        │ periodic collection
        ▼
Go exporter ────── /metrics ────── Prometheus
        │
        ├── reason resolver (BTF)
        ├── symbol resolver (/proc/kallsyms)
        └── immutable metric snapshot
```

## 2. Objectives

### 2.1 Functional Objectives

- Continuously observe skb drops in the Linux network stack.
- Aggregate drops by reason, kernel function, and L3 protocol.
- Optionally add network namespace and ifindex as aggregation dimensions.
- Expose the results as Prometheus counters.
- Use CO-RE to absorb structure-layout differences between kernel versions and distributions.
- Make exporter failures such as map exhaustion, symbol-resolution failures, and unsupported kernels observable.
- Provide a distribution model for user-space binaries on amd64 and arm64.

### 2.2 Operational Objectives

- Do not forward events one at a time to user space during normal operation.
- Do not lose observed events because of user-space processing capacity during a drop burst.
- Limit the number of generated Prometheus series through configuration and the map limit.
- Do not include packet payloads, IP addresses, or ports in normal metrics.
- Make counter resets caused by an exporter restart behave as normal Prometheus counter resets.

## 3. Non-Goals

The initial version excludes the following:

- Lossless storage of each individual drop event.
- A replacement for tcpdump or pcap.
- Continuous aggregation by five-tuple, socket, process, cgroup, or Pod.
- Complete centralized observation of every drop, including NIC hardware, driver RX ring, qdisc, softnet, and XDP_DROP drops.
- Automatic determination of whether a drop affected an end user.
- A `pwru`-like feature that traces the entire kernel stack per packet.
- Automatic explanation of the root cause.

The exporter's central responsibility is to convert skb drops observable at the `kfree_skb` tracepoint into low-overhead time-series metrics.

## 4. Observation Scope

### 4.1 Drops Observed in v1

v1 attaches to `tp_btf/kfree_skb` and obtains the following from the tracepoint:

- `struct sk_buff *skb`
- `location`, identifying the call site that dropped the packet
- `reason`, corresponding to `enum skb_drop_reason`
- `skb->protocol`
- `skb->len`
- Optionally, `skb->dev->ifindex`
- Optionally, the inum of the network namespace containing `skb->dev`

Normal consumption reported as `SKB_CONSUMED` is not added to drop counters.

### 4.2 What This Hook Cannot Observe

The following cannot be observed completely using `kfree_skb` alone.

| Area | v1 handling |
| --- | --- |
| NIC hardware drop | Out of scope; consider ethtool integration in the future. |
| driver RX ring overflow | Out of scope; consider driver-stats integration in the future. |
| Drops in `/proc/net/softnet_stat` | Out of scope; use this with node_exporter. |
| qdisc drop | Only drops that reach `kfree_skb` are visible; a qdisc collector is future work. |
| `XDP_DROP` | Generally invisible; the relevant XDP program must provide its own counter. |
| Hardware-offloaded XDP drop | Invisible. |
| Discards inside a user-space application | Out of scope. |

Therefore, metric names must not imply all packet drops; they must make it explicit that they represent skb drops.

## 5. Supported Environment

### 5.1 Required Capabilities

Do not determine support from kernel version numbers alone. Probe the following at startup:

- The BPF syscall is available.
- BTF for the running kernel is available at `/sys/kernel/btf/vmlinux`.
- The exporter can attach to the `kfree_skb` BTF tracepoint.
- The tracepoint arguments include a drop reason.
- The required map types are available.
- CO-RE can resolve the required fields of `struct sk_buff`, `struct net_device`, and related structures.

Upstream support for drop reasons was introduced around Linux 5.17, but distribution backports make feature detection of actual capabilities necessary.

### 5.2 Support Policy

- Official v1 support covers kernels that provide BTF and a drop-reason-aware `kfree_skb` hook.
- Do not reject a kernel based on its version alone.
- v1 does not provide a compatibility mode for older kernels without drop reasons.
- On an unsupported environment, fail startup with an explicit reason.
- Official targets are `amd64` and `arm64`.

Do not use a partial location-only fallback, because it would change metric semantics between hosts in the fleet.

## 6. Overall Architecture

### 6.1 Components

| Component | Responsibility |
| --- | --- |
| eBPF collector | Extract drop events, filter them, and aggregate them per CPU. |
| BPF loader | Probe features, perform CO-RE relocation, attach programs, and manage map lifecycles. |
| Map collector | Read BPF maps periodically and sum values across CPUs. |
| Reason resolver | Convert numeric reasons from the running kernel into display names. |
| Symbol resolver | Convert the `location` address into a kernel symbol. |
| Interface metadata resolver | Optionally resolve supporting netns/ifindex metadata. |
| Snapshot store | Atomically replace the completed metric snapshot. |
| Prometheus collector | Generate `/metrics` from the snapshot. |
| Health server | Expose liveness, readiness, and version information. |

### 6.2 Data Flow

1. The kernel drops an skb and executes the `kfree_skb` tracepoint.
2. The eBPF program excludes `reason == SKB_CONSUMED`.
3. It stores only enabled dimensions in `drop_key`.
4. It increments the packets/bytes counters in `BPF_MAP_TYPE_PERCPU_HASH`.
5. The user-space collector walks the map at the configured interval.
6. It sums counters across CPUs.
7. It resolves reason and location to strings.
8. It builds an immutable snapshot and replaces the published snapshot through `atomic.Pointer`.
9. Prometheus scrapes read only the completed snapshot.

The scrape request itself never walks the BPF map. This separates concurrent scrapes from multiple Prometheus servers, scrape timeouts, and partial output during map traversal.

## 7. eBPF Design

### 7.1 Attachment Method

Build the CO-RE-enabled C program with `bpf2go` and embed it in the Go binary.

The first choice is a typed BTF tracepoint.

```c
SEC("tp_btf/kfree_skb")
int BPF_PROG(observe_kfree_skb,
             struct sk_buff *skb,
             void *location,
             enum skb_drop_reason reason)
```

Reasons:

- Receive `struct sk_buff *` as a typed argument.
- Avoid defining the tracepoint's serialized context layout manually.
- Use CO-RE to absorb kernel-structure field-offset differences.
- Keep the observed kernel interface explicit compared with a kprobe.

### 7.2 Map Key

```c
struct drop_key {
    __u64 location;
    __u32 reason;
    __u32 netns_inum;
    __u32 ifindex;
    __u16 protocol;
    __u16 reserved;
};
```

Always store zero for a disabled dimension. The BPF program reads a read-only configuration map to determine which dimensions are enabled.

### 7.3 Map Value

```c
struct drop_value {
    __u64 packets;
    __u64 bytes;
};
```

Use `BPF_MAP_TYPE_PERCPU_HASH` as the map type. Each CPU has its own value, so the packet path does not need atomic operations.

The recommended initial values are:

```text
max_entries = 8192
preallocate = enabled
```

As a rough estimate, the values alone require `8192 × 16 bytes × CPU count`. This is about 32 MiB on 256 CPUs, before adding keys and map-management memory. On large hosts, report the estimate in the startup log and self metrics.

### 7.4 Behavior When the Map Is Full

Do not affect packet processing when insertion of a new key fails.

- Increment `map_update_failures` in a per-CPU stats map.
- Continue incrementing existing keys.
- Keep readiness enabled, but expose the degraded state through a self metric.
- Operationally, alert when even one failure occurs.

Do not use an LRU map for normal metrics, because entry eviction would make Prometheus counters move backward.

### 7.5 In-Kernel Processing

The following is conceptual code.

```c
SEC("tp_btf/kfree_skb")
int BPF_PROG(observe_kfree_skb,
             struct sk_buff *skb,
             void *location,
             enum skb_drop_reason reason)
{
    struct drop_key key = {};
    struct drop_value zero = {};
    struct drop_value *value;

    stats_inc(EVENTS_SEEN);

    if (reason == SKB_CONSUMED) {
        stats_inc(EVENTS_CONSUMED);
        return 0;
    }

    key.reason = (__u32)reason;

    if (cfg.dimension_location)
        key.location = (__u64)location;

    if (cfg.dimension_protocol)
        key.protocol = BPF_CORE_READ(skb, protocol);

    if (cfg.dimension_interface) {
        struct net_device *dev = BPF_CORE_READ(skb, dev);

        if (dev) {
            key.ifindex = BPF_CORE_READ(dev, ifindex);
            key.netns_inum = read_netns_inum(dev);
        }
    }

    value = bpf_map_lookup_elem(&drops, &key);
    if (!value) {
        if (bpf_map_update_elem(&drops, &key, &zero, BPF_NOEXIST)) {
            stats_inc(MAP_UPDATE_FAILURES);
            return 0;
        }
        value = bpf_map_lookup_elem(&drops, &key);
    }

    if (value) {
        value->packets++;
        value->bytes += BPF_CORE_READ(skb, len);
    }

    return 0;
}
```

The implementation assumes that the first lookup and insert are unlikely to contend on the same CPU, while always checking return values. To limit verifier work, perform the netns lookup only when the interface dimension is enabled.

### 7.6 eBPF-Side Self Stats

Use a fixed-size `BPF_MAP_TYPE_PERCPU_ARRAY` and retain at least the following:

- observed tracepoint events
- ignored `SKB_CONSUMED` events
- exported drop events
- map insert failures
- skb field read failures
- interface metadata read failures

## 8. Dimensions and Cardinality

### 8.1 Default Dimensions

The default dimensions are:

```text
reason + location + protocol
```

Add `netns` and `ifindex` to the key and labels only when explicitly enabled.

### 8.2 Forbidden Labels

Do not use the following as labels in normal metrics:

- source/destination IP address
- source/destination port
- skb address
- PID/TID
- process name
- cgroup ID
- container ID or Pod UID
- the kernel address itself
- symbol offset

These would create high cardinality, expose personal or communication information, and cause series churn after every kernel restart.

### 8.3 Location Normalization

Resolve kernel addresses to symbols in user space and remove the offset by default.

```text
ffffffff8193a201
    ↓
tcp_v4_rcv+0x191
    ↓
location="tcp_v4_rcv"
```

An offset may be shown for diagnostics when distinguishing drop sites within one function, but it must not be included in a Prometheus label.

Do not put an unresolved address into a label; aggregate it as `location="unknown"`. Expose the unresolved count as a self metric.

### 8.4 Series Limit

The BPF map's `max_entries` is the physical upper bound for the number of series. Log the dimension configuration and limit at startup, and expose the following:

```prometheus
packet_drop_exporter_bpf_map_entries 317
packet_drop_exporter_bpf_map_max_entries 8192
```

When the interface dimension is enabled, operators must account for the number of netns objects and interfaces per host when setting the limit.

## 9. Drop Reason Resolution

### 9.1 General Policy

Do not hard-code drop-reason values or enum ordering into the exporter. Read the corresponding enum information from the running kernel's BTF and build the resolver table at startup.

Reasons:

- The drop-reason enum may be extended or changed between kernels.
- Distribution kernels may backport the feature.
- The exporter should not need to be rebuilt for every kernel update.

### 9.2 Unknown Reasons

Normalize an unresolvable reason to the following form:

```text
UNKNOWN_123
```

Do not stop observation when an unknown reason occurs. Also increment:

```prometheus
packet_drop_exporter_reason_resolution_failures_total
```

Support subsystem-specific reasons incrementally, within the limits of safe resolution from the running kernel's BTF. If v1 cannot resolve a subsystem reason, do not translate it to an incorrect name; fall back to `UNKNOWN_*` with the numeric value.

## 10. Kernel Symbol Resolution

### 10.1 Input

Read `/proc/kallsyms` at startup and build a symbol table ordered by address. Binary-search for the symbol immediately preceding an address to obtain its function name.

### 10.2 KASLR

Because KASLR changes addresses after every reboot, use the address in the BPF map key but expose only the symbol name to Prometheus.

### 10.3 Modules

To handle kernel module load and unload, use the following strategy:

- Check a `/proc/modules` fingerprint at a fixed interval and reload kallsyms only when it changes.
- If the resolver is unavailable, retry at every refresh interval so a temporary mount or permission problem can recover without a restart.
- Parse a complete replacement table and publish it atomically; retain the previous table after a failed refresh.

This keeps steady-state overhead low while preserving recovery and consistency.

### 10.4 When Symbols Cannot Be Retrieved

If addresses cannot be obtained because of `kptr_restrict` or insufficient capabilities, continue BPF collection.

- Aggregate locations as `unknown`.
- Keep readiness enabled.
- Set `packet_drop_exporter_symbolizer_available` to 0.
- State the required permissions in the startup log.

## 11. Prometheus Metrics Design

### 11.1 Primary Metrics

```prometheus
# TYPE linux_skb_drops_total counter
linux_skb_drops_total{
  reason="NO_SOCKET",
  location="tcp_v4_rcv",
  protocol="ipv4"
} 1842

# TYPE linux_skb_drop_bytes_total counter
linux_skb_drop_bytes_total{
  reason="NO_SOCKET",
  location="tcp_v4_rcv",
  protocol="ipv4"
} 156570
```

Add the following labels only when the interface dimension is enabled.

```prometheus
linux_skb_drops_total{
  reason="IP_RPFILTER",
  location="ip_rcv_core",
  protocol="ipv4",
  netns="4026531840",
  ifindex="2"
} 37
```

Normalize known EtherTypes such as `ipv4`, `ipv6`, and `arp`; format unknown values as `0xNNNN`. The value range is limited to 16 bits, so cardinality remains bounded by the map limit.

### 11.2 Self Metrics

Provide at least the following:

```text
packet_drop_exporter_build_info
packet_drop_exporter_ready
packet_drop_exporter_bpf_attached
packet_drop_exporter_bpf_map_entries
packet_drop_exporter_bpf_map_max_entries
packet_drop_exporter_bpf_map_estimated_bytes
packet_drop_exporter_events_seen_total
packet_drop_exporter_events_consumed_total
packet_drop_exporter_events_exported_total
packet_drop_exporter_map_update_failures_total
packet_drop_exporter_skb_read_failures_total
packet_drop_exporter_interface_read_failures_total
packet_drop_exporter_symbol_resolution_failures_total
packet_drop_exporter_reason_resolution_failures_total
packet_drop_exporter_collection_failures_total
packet_drop_exporter_symbol_refresh_failures_total
packet_drop_exporter_collection_duration_seconds
packet_drop_exporter_last_successful_collection_timestamp_seconds
packet_drop_exporter_snapshot_age_seconds
packet_drop_exporter_symbolizer_available
```

Also expose the Go runtime and process collectors.

### 11.3 Counter Reset

Without a pinned BPF map, counters return to zero when the exporter restarts. Prometheus `rate()` and `increase()` handle this as a normal counter reset, so this is considered correct behavior.

Map pinning is a future option and is not required for v1. If pinning is implemented, store a map schema version and do not reuse a map whose key/value layout does not match.

## 12. User-Space Implementation

### 12.1 Language and Main Libraries

Use Go.

- eBPF loader: `github.com/cilium/ebpf`
- BPF code generation: `bpf2go`
- Prometheus: `github.com/prometheus/client_golang`
- configuration: Prefer the Go standard library and add a YAML library if needed.
- logging: `log/slog`

`cilium/ebpf` is pure Go, supports long-running processes, and provides APIs for BTF, links, feature probes, and ring buffers.

### 12.2 Proposed Package Layout

```text
cmd/packet-drop-exporter/
    main.go

internal/bpf/
    drop.bpf.c
    drop.go
    generate.go

internal/loader/
    loader.go
    features.go

internal/collector/
    map_reader.go
    snapshot.go
    prometheus.go

internal/reason/
    resolver.go
    btf.go

internal/symbol/
    kallsyms.go
    resolver.go

internal/netmeta/
    resolver.go

internal/config/
    config.go

internal/server/
    server.go
    health.go
```

### 12.3 Snapshot Model

Run map collection in a goroutine independent of scrapes.

```go
type Snapshot struct {
    CollectedAt time.Time
    Drops       []DropMetric
    Self        SelfMetrics
}

type Store struct {
    current atomic.Pointer[Snapshot]
}
```

Build a new `Snapshot` completely before storing it. The Prometheus collector loads the store once at the beginning of a scrape and returns only that snapshot.

### 12.4 Collection Interval

Use five seconds by default.

- BPF counters are updated continuously.
- Values visible to Prometheus may be delayed by up to five seconds.
- Keep the previous snapshot when collection fails.
- Expose snapshot age as a metric so that collection stoppage can be detected.

## 13. Configuration

Example configuration:

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

Keep `reason` permanently enabled to preserve the product semantics; configuration must not be able to disable it. Because changing dimensions changes the meaning of the BPF map key, accept dimension changes only at startup in v1 and exclude them from SIGHUP reload.

The main CLI options are:

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

## 14. HTTP Interface

| Path | Purpose |
| --- | --- |
| `/metrics` | Prometheus metrics |
| `/-/healthy` | Return 200 while the process is alive. |
| `/-/ready` | Return 200 when BPF is attached and a valid snapshot exists. |

Even if diagnostic endpoints are added, do not return packet contents or raw kernel addresses by default.

Bind the HTTP server to loopback by default. External exposure must be explicit and should normally be handled by a Prometheus agent, a node-local proxy, or access control within the host network.

## 15. Permissions and Security

### 15.1 Required Permissions

On newer kernels, use the following in principle:

- `CAP_BPF`
- `CAP_PERFMON`
- `CAP_SYSLOG` where kallsyms address retrieval requires it
- `CAP_SYS_ADMIN` on older kernels or with certain distribution settings

Reserve memlock through systemd's `LimitMEMLOCK=` or the container runtime configuration. Validate the capabilities actually needed through startup feature probes and do not request excessive permissions.

### 15.2 Security Policy

- Do not copy packet payloads into user space.
- Do not read IP addresses or ports.
- Do not expose raw kernel addresses in metrics or normal logs.
- Bind the HTTP server to loopback by default.
- Do not provide a feature that loads arbitrary external BPF objects outside the configuration.
- Embed BPF bytecode in release artifacts and version it with the corresponding source.
- Include an SBOM with release binaries and container images.

## 16. Startup and Shutdown

### 16.1 Startup Order

1. Parse and validate the configuration.
2. Probe kernel features.
3. Read BTF and build the reason resolver.
4. Read kallsyms and build the symbol resolver.
5. Record the map memory estimate and cardinality limit.
6. Load the BPF object.
7. Attach to `kfree_skb`.
8. Collect the first map snapshot.
9. Enable readiness.
10. Start the HTTP server.

Do not open the HTTP server before attachment, so a process that is still starting cannot become a scrape target.

### 16.2 Graceful Shutdown

1. Set readiness to false.
2. Close the HTTP listener and wait for running scrapes for a bounded period.
3. Stop the collection goroutine.
4. Detach the BPF link.
5. Close the map and object.

## 17. Failure Modes

| Condition | Behavior |
| --- | --- |
| Missing BTF | Fail startup. |
| No drop-reason-aware hook | Fail startup. |
| BPF verifier rejection | Summarize the verifier log and fail startup. |
| Attachment failure | Fail startup. |
| Cannot read kallsyms | Aggregate locations as `unknown` and expose a degraded metric. |
| Cannot resolve a reason | Continue with `UNKNOWN_N`. |
| Map is full | Drop new series and increment the failure counter. |
| Map iteration failure | Keep the previous snapshot. |
| Collection stops | Detect it with a snapshot-age alert. |
| Module load/unload | Reload the symbol table. |
| CPU hotplug | Re-evaluate possible CPUs and reinitialize after collection failure. |

## 18. Observability and Alerts

For the exporter itself, consider at least the following alert candidates:

```promql
packet_drop_exporter_ready == 0
```

```promql
rate(packet_drop_exporter_map_update_failures_total[5m]) > 0
```

```promql
time() - packet_drop_exporter_last_successful_collection_timestamp_seconds > 30
```

```promql
packet_drop_exporter_bpf_map_entries
  / packet_drop_exporter_bpf_map_max_entries > 0.8
```

Because drops can occur during normal operation, do not alert universally on `linux_skb_drops_total > 0`. Combine reason/location baselines and growth rates with other metrics that show communication impact.

Example PromQL for investigation:

```promql
topk(
  20,
  sum by (reason, location) (
    rate(linux_skb_drops_total[5m])
  )
)
```

## 19. Performance Design

### 19.1 Fast Path

Per-packet processing is limited to the following:

- Tracepoint invocation
- A small number of CO-RE field reads
- Conditional branches
- per-CPU hash lookup
- Two `u64` increments

Do not use a ring buffer, collect stack traces, parse packet headers, or send user-space notifications in normal mode.

### 19.2 Benchmark Metrics

Compare the following with and without the attachment:

- packets per second
- CPU cycles per packet
- softirq CPU usage
- exporter userspace CPU
- BPF map memory
- drop reason/location accuracy
- map update failure

Use relative values under representative workloads as acceptance criteria rather than fixed nanosecond values.

- Target less than 3% throughput degradation at the target packet rate.
- Keep the additional packet-path impact of map collection within measurement error.
- Ensure that the user-space collector does not cause scrape timeouts with an interval of five seconds and 8192 entries.
- A 100% drop burst must not have a ring-buffer-overflow failure mode.

## 20. Test Strategy

### 20.1 Unit Tests

- configuration validation
- Conversion from a drop key to Prometheus labels
- EtherType stringification
- Kallsyms parsing and nearest-symbol lookup
- Reason-table generation from a BTF enum
- Unknown-reason/location fallback
- Summation of per-CPU values
- Concurrent reads and writes of the immutable snapshot
- Counter-reset handling

### 20.2 BPF Tests

- verifier load test
- Exclusion of `SKB_CONSUMED`
- Key generation with dimensions enabled and disabled
- Safety when `skb->dev == NULL`
- Failure counter behavior when the map is full
- Packets/bytes counter increments

Use `BPF_PROG_TEST_RUN` where possible, and verify tracepoint paths that cannot use it with VM integration tests.

### 20.3 Integration Tests

Run the following on VMs with multiple kernels:

- Connect to a TCP port without a listener.
- Send to a UDP port without a listener.
- Checksum-error packets.
- Drops caused by `rp_filter`.
- IPv4 and IPv6 packets.
- Drops using a network namespace and veth pair.
- Interface dimension enabled and disabled.
- Load and unload symbols from a kernel module.
- Inaccessible kallsyms.
- Reaching the map limit.
- Exporter restart.
- Add and remove CPUs in an environment that supports CPU hotplug.

The CI matrix must include, at minimum, multiple upstream LTS kernel generations and major distribution kernels. Store feature-probe results with test results rather than only version numbers.

The repository provides a privileged integration test that pre-fills a one-entry map and verifies `map_update_failures`, plus a pipeline check using unavailable kallsyms. These tests run on the current Docker host kernel; they do not replace the required multi-kernel matrix.

### 20.4 Load Tests

- High-pps drops of 64-byte packets.
- High-bandwidth drops of 1500-byte packets.
- Concentration on a single key.
- High cardinality across many reasons, locations, and interfaces.
- Per-CPU map memory and collection time for a 256-CPU-class host.

## 21. Distribution

### 21.1 Artifacts

- Linux amd64 static Go binary
- Linux arm64 static Go binary
- OCI image
- systemd unit example
- example configuration
- Grafana dashboard
- Prometheus recording/alerting rule example
- SBOM
- Checksums and signatures

### 21.2 systemd Operation

For observing the entire host network stack, recommend a systemd service first. Also provide a container distribution, but host PID/network namespaces, BTF, tracefs, kallsyms, and capabilities are more complex to handle there.

The systemd unit must explicitly set the following:

```text
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYSLOG
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYSLOG
LimitMEMLOCK=infinity
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
```

If `CAP_SYS_ADMIN` is required for a target distribution or kernel, provide a separate unit example rather than adding it by default.

## 22. Implementation Phases

### Phase 0: Technical Proof of Concept

- Build a minimal program that attaches to `tp_btf/kfree_skb`.
- Aggregate reason/location/protocol in a per-CPU map.
- Read the map from Go and print it to standard output.
- Verify drop-reason correctness on a single kernel.

Completion criteria:

- Reproduce an intended reason such as `NO_SOCKET`.
- Resolve locations to kernel symbols.
- Aggregate without forwarding per-packet events to user space.

### Phase 1: MVP

- Prometheus `/metrics`
- immutable snapshot
- reason resolver
- symbol resolver
- self metrics
- health/readiness
- systemd unit
- unit/integration tests

Completion criteria:

- Run continuously for 24 hours.
- Detect a full map and symbol-resolution failures.
- Preserve the same metric semantics across the target kernel matrix.

### Phase 2: Production Hardening

- Expand the distribution-kernel matrix.
- Refresh module symbols.
- Support CPU hotplug.
- Estimate map memory.
- Add benchmarks and performance-regression CI.
- OCI image, SBOM, and signatures.
- Grafana dashboard and alert rules.

### Phase 3: Extensions

- optional map pinning
- qdisc/rtnetlink/ethtool/softnet collector
- CNI-oriented netns metadata integration.
- A short-lived diagnostic mode that must be explicitly enabled.
- OpenTelemetry metrics support.

Because generic observation of XDP_DROP uses a different approach, design it as a separate collector rather than forcing it into the skb drop collector.

## 23. Major Design Decisions

| Decision | Choice | Reason |
| --- | --- | --- |
| Language | Go | cilium/ebpf, the Prometheus ecosystem, and ease of distribution. |
| Attachment | BTF tracepoint | Typed skb access and CO-RE compatibility. |
| Event transport | None | Avoid ring-buffer overflow at high drop rates. |
| Aggregation map | Per-CPU hash | No atomic operations on the fast path. |
| Map capacity | Fixed limit | Control series count and memory. |
| LRU | Not used | Eviction would move counters backward. |
| Reason resolution | Running-kernel BTF | Follow enum changes and backports. |
| Location label | Symbol name only | Handle KASLR, kernel updates, and cardinality. |
| Map reads | Periodic collection | Separate scrape latency from BPF map traversal. |
| Snapshot | Immutable atomic swap | Do not expose partial updates to scrapes. |
| IP/port labels | Not used | Protect cardinality and communication information. |
| Old-kernel fallback | Not used | Keep metric semantics consistent between hosts. |

## 24. Open Questions and Decisions

1. **Open:** Whether `tp_btf/kfree_skb` has a signature that can be attached in the same way on every target distribution kernel. It is verified only on the current Docker Desktop VM kernel.
2. **Partially resolved:** Core reasons are loaded from running-kernel BTF. Subsystem-specific values that are not safely resolvable remain `UNKNOWN_N`; broader kernel coverage is still required.
3. **Partially resolved:** The current CO-RE view reads the network namespace inum through `net_device.nd_net.net` and is verified on one kernel. Distribution coverage remains open.
4. **Open:** Per-CPU hash allocator footprint and map-iteration time on a real 256-CPU environment. The exporter now reports a lower-bound key/value estimate, and the 8192-entry user-space snapshot path has a benchmark.
5. **Open:** Distribution differences in the minimum capability required to read `/proc/kallsyms`.
6. **Resolved:** Poll `/proc/modules` at a configured interval, reload kallsyms after a fingerprint change, and retry every interval while the resolver is unavailable.
7. **Resolved:** Include both packet and byte counters in the primary metrics by default.

## 25. References

- [nhorman/dropwatch](https://github.com/nhorman/dropwatch)
- [Linux kernel: `dropreason-core.h`](https://github.com/torvalds/linux/blob/master/include/net/dropreason-core.h)
- [Linux kernel BPF selftest: `kfree_skb.c`](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/kfree_skb.c)
- [cilium/ebpf](https://github.com/cilium/ebpf)
- [Prometheus metric and label naming](https://prometheus.io/docs/practices/naming/)
- [How to retrieve packet drop reasons in the Linux kernel](https://developers.redhat.com/articles/2023/07/19/how-retrieve-packet-drop-reasons-linux-kernel)
- [Inspektor Gadget `trace_tcpdrop`](https://www.inspektor-gadget.io/docs/main/gadgets/trace_tcpdrop/)

## 26. Implementation Progress

### 2026-09-21: From Phase 0 to the Phase 1 Skeleton

Implementation started with the following additions:

- `Dockerfile` and `compose.yaml` with the Linux toolchain, clang, libbpf headers, and BPF bytecode generation.
- A minimal CO-RE `tp_btf/kfree_skb` program, per-CPU hash/array maps, a map reader, and a privileged integration service intended for `CAP_BPF` and related capabilities.
- An `skb_drop_reason` enum resolver based on running-kernel BTF and a nearest-symbol resolver based on `/proc/kallsyms`.
- Per-CPU counter summation, an immutable atomic snapshot, Prometheus `/metrics`, liveness/readiness, and self metrics.
- YAML configuration, CLI overrides, configuration validation, a systemd unit example, unit tests, and race tests.

Attachment and metric scraping were verified on the Docker Desktop Linux VM, and `NO_SOCKET` was reproduced by sending to an unused UDP port. Details are recorded in `docs/verification.md`.

### 2026-09-21: Production Hardening Infrastructure

The next implementation unit added:

- Atomic kallsyms replacement after `/proc/modules` changes, periodic recovery while symbolization is unavailable, and a refresh-failure counter.
- Re-evaluation of `ebpf.PossibleCPU()` before each per-CPU map read, preventing stale slice sizing after CPU-topology changes.
- A corrected lower-bound map-memory estimate that counts one key plus one value per possible CPU for every entry.
- Privileged Linux integration tests for map-full accounting and continued collection with unavailable kallsyms.
- An 8192-entry immutable-snapshot benchmark, CI execution of tests/vet/benchmark/image build, and a self-hosted kernel integration workflow.
- A 24-hour-by-default soak profile, Prometheus recording/alerting rules, and a Grafana dashboard.
- GoReleaser configuration for Linux amd64/arm64 archives, archive SBOMs, checksums, and keyless checksum signing. The release workflow also publishes and signs a multi-architecture OCI image with SBOM and provenance attestations.

Verified in this workspace: unit tests, the privileged map-full/unavailable-kallsyms integration suite, a short soak using the same 24-hour path, Prometheus rule syntax, Grafana JSON, Compose configuration, and GoReleaser configuration.

Still requiring external or extended evidence: the distribution/kernel matrix, real CPU add/remove testing, packet-path throughput and CPU-overhead comparison, an actual tagged release/signature verification, and a full 24-hour soak. Do not mark these complete until those runs are recorded in `docs/verification.md`.

### 2026-09-21: OSS Publication Readiness

The repository was organized for public collaboration without changing runtime behavior:

- Replaced the development-oriented README with a public project overview, feature and architecture summary, installation paths, privilege requirements, configuration, metrics, limitations, verification boundaries, release verification, and contribution/security links.
- Added an MIT license with copyright assigned to Kento Kawakami.
- Added contribution, security, and conduct policies, structured bug/feature issue forms, a pull request checklist, and Dependabot configuration for Go modules, GitHub Actions, and Docker.
- Included the project license, contribution guide, third-party notices, and generated runtime dependency license bundle in release archives.
- Added a standard-library-only license collector and CI check so a release fails when a runtime Go module has no discoverable top-level license or notice file.
- Added OCI license metadata and installed the project and runtime dependency license texts in the published image.
- Scanned the repository for common credential and private-key patterns. Matches were limited to expected GitHub Actions token expressions and policy/documentation text; no credential values or private keys were present.

The repository still has no commit or configured remote in this workspace. Publication, enabling GitHub private vulnerability reporting, repository metadata/topics, branch protection, and the first tagged release remain hosting-side tasks.
