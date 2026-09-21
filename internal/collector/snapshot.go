package collector

import (
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/kimitoboku/packet_drop_exporter/internal/bpf"
	"github.com/kimitoboku/packet_drop_exporter/internal/reason"
	"github.com/kimitoboku/packet_drop_exporter/internal/symbol"
)

type DropMetric struct {
	Reason   string
	Location string
	Protocol string
	Netns    string
	Ifindex  string
	Packets  uint64
	Bytes    uint64
}

type SelfMetrics struct {
	MapEntries                uint64
	MapMaxEntries             uint64
	MapEstimatedBytes         uint64
	EventsSeen                uint64
	EventsConsumed            uint64
	EventsExported            uint64
	MapUpdateFailures         uint64
	SKBReadFailures           uint64
	InterfaceReadFailures     uint64
	SymbolResolutionFailures  uint64
	ReasonResolutionFailures  uint64
	CollectionDurationSeconds float64
	LastSuccessfulCollection  time.Time
	CollectedAt               time.Time
	SymbolizerAvailable       bool
}

type Snapshot struct {
	Drops []DropMetric
	Self  SelfMetrics
}

// ResolutionStats keeps *_failures_total monotonic across immutable
// snapshots. A resolver failure is counted once per failed lookup, including
// repeated collections of an unresolved map entry.
type ResolutionStats struct {
	symbolFailures atomic.Uint64
	reasonFailures atomic.Uint64
}

func NewResolutionStats() *ResolutionStats {
	return &ResolutionStats{}
}

// Store publishes only complete snapshots. The pointed-to values are never
// mutated after Store, so concurrent Prometheus scrapes see one consistent
// collection result.
type Store struct {
	current atomic.Pointer[Snapshot]
}

func NewStore() *Store {
	store := &Store{}
	store.current.Store(&Snapshot{Drops: []DropMetric{}})
	return store
}

func (s *Store) Load() *Snapshot {
	return s.current.Load()
}

func (s *Store) Store(snapshot Snapshot) {
	snapshot.Drops = append([]DropMetric(nil), snapshot.Drops...)
	s.current.Store(&snapshot)
}

// BuildSnapshot converts raw map entries into public labels and copies the
// resulting data into a new immutable snapshot.
func BuildSnapshot(raw bpf.RawSnapshot, collectedAt time.Time, reasons *reason.Resolver, symbols *symbol.Resolver, interfaceDimension bool) Snapshot {
	return buildSnapshot(raw, collectedAt, reasons, symbols, interfaceDimension, nil)
}

// BuildSnapshotWithStats is the production variant which accumulates resolver
// failures for the lifetime of the exporter process.
func BuildSnapshotWithStats(raw bpf.RawSnapshot, collectedAt time.Time, reasons *reason.Resolver, symbols *symbol.Resolver, interfaceDimension bool, resolutionStats *ResolutionStats) Snapshot {
	return buildSnapshot(raw, collectedAt, reasons, symbols, interfaceDimension, resolutionStats)
}

func buildSnapshot(raw bpf.RawSnapshot, collectedAt time.Time, reasons *reason.Resolver, symbols *symbol.Resolver, interfaceDimension bool, resolutionStats *ResolutionStats) Snapshot {
	drops := make([]DropMetric, 0, len(raw.Samples))
	var reasonFailures uint64
	var symbolFailures uint64
	for _, sample := range raw.Samples {
		reasonName, knownReason := reasons.Resolve(sample.Key.Reason)
		if !knownReason {
			reasonFailures++
		}
		location := symbols.Resolve(sample.Key.Location)
		if sample.Key.Location != 0 && location == "unknown" {
			symbolFailures++
		}
		metric := DropMetric{
			Reason:   reasonName,
			Location: location,
			Protocol: ProtocolName(sample.Key.Protocol),
			Packets:  sample.Value.Packets,
			Bytes:    sample.Value.Bytes,
		}
		if interfaceDimension {
			metric.Netns = strconv.FormatUint(uint64(sample.Key.NetnsInum), 10)
			metric.Ifindex = strconv.FormatUint(uint64(sample.Key.Ifindex), 10)
		}
		drops = append(drops, metric)
	}
	if resolutionStats != nil {
		if reasonFailures > 0 {
			resolutionStats.reasonFailures.Add(reasonFailures)
		}
		if symbolFailures > 0 {
			resolutionStats.symbolFailures.Add(symbolFailures)
		}
		reasonFailures = resolutionStats.reasonFailures.Load()
		symbolFailures = resolutionStats.symbolFailures.Load()
	}

	return Snapshot{
		Drops: drops,
		Self: SelfMetrics{
			MapEntries:               uint64(len(raw.Samples)),
			MapMaxEntries:            raw.MapMaxEntries,
			MapEstimatedBytes:        estimateMapBytes(raw),
			EventsSeen:               raw.Stats.EventsSeen,
			EventsConsumed:           raw.Stats.EventsConsumed,
			EventsExported:           raw.Stats.EventsExported,
			MapUpdateFailures:        raw.Stats.MapUpdateFailures,
			SKBReadFailures:          raw.Stats.SKBReadFailures,
			InterfaceReadFailures:    raw.Stats.InterfaceReadFailures,
			SymbolResolutionFailures: symbolFailures,
			ReasonResolutionFailures: reasonFailures,
			LastSuccessfulCollection: collectedAt,
			CollectedAt:              collectedAt,
			SymbolizerAvailable:      symbols.Available(),
		},
	}
}

func estimateMapBytes(raw bpf.RawSnapshot) uint64 {
	if raw.MapMaxEntries == 0 || raw.PossibleCPUs == 0 {
		return 0
	}
	// This is a lower-bound estimate for key/value storage, not the kernel's
	// allocator footprint. Map metadata and hash buckets are intentionally not
	// presented as exact bytes.
	const keyBytes = 24
	const valueBytes = 16
	return raw.MapMaxEntries * (keyBytes + uint64(raw.PossibleCPUs)*valueBytes)
}

func ProtocolName(protocol uint16) string {
	switch protocol {
	case 0x0800:
		return "ipv4"
	case 0x86dd:
		return "ipv6"
	case 0x0806:
		return "arp"
	case 0x8847:
		return "mpls_unicast"
	case 0x8848:
		return "mpls_multicast"
	default:
		return fmt.Sprintf("0x%04x", protocol)
	}
}
