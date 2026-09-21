package collector

import (
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"

	"github.com/kimitoboku/packet_drop_exporter/internal/bpf"
	"github.com/kimitoboku/packet_drop_exporter/internal/reason"
	"github.com/kimitoboku/packet_drop_exporter/internal/symbol"
)

func TestProtocolName(t *testing.T) {
	cases := map[uint16]string{
		0x0800: "ipv4",
		0x86dd: "ipv6",
		0x0806: "arp",
		0xbeef: "0xbeef",
	}
	for protocol, want := range cases {
		if got := ProtocolName(protocol); got != want {
			t.Errorf("ProtocolName(0x%x) = %q, want %q", protocol, got, want)
		}
	}
}

func TestBuildSnapshotResolvesLabelsAndCopiesData(t *testing.T) {
	collectedAt := time.Unix(100, 0)
	reasons := reason.New([]btf.EnumValue{{Name: "SKB_DROP_REASON_NO_SOCKET", Value: 2}})
	symbols := symbol.New([]symbol.Entry{{Address: 0x1000, Name: "tcp_v4_rcv"}})
	raw := bpf.RawSnapshot{
		PossibleCPUs:  2,
		MapMaxEntries: 64,
		Samples: []bpf.Sample{
			{Key: bpf.Key{Reason: 2, Location: 0x1010, Protocol: 0x0800, NetnsInum: 7, Ifindex: 2}, Value: bpf.Value{Packets: 3, Bytes: 1500}},
			{Key: bpf.Key{Reason: 99, Location: 0x0999, Protocol: 0xbeef}, Value: bpf.Value{Packets: 1}},
		},
		Stats: bpf.Stats{
			EventsSeen:            10,
			EventsConsumed:        4,
			EventsExported:        4,
			MapUpdateFailures:     1,
			SKBReadFailures:       2,
			InterfaceReadFailures: 3,
		},
	}
	snapshot := BuildSnapshot(raw, collectedAt, reasons, symbols, true)
	if len(snapshot.Drops) != 2 {
		t.Fatalf("got %d drops", len(snapshot.Drops))
	}
	if got := snapshot.Drops[0]; got.Reason != "NO_SOCKET" || got.Location != "tcp_v4_rcv" || got.Protocol != "ipv4" || got.Netns != "7" || got.Ifindex != "2" {
		t.Fatalf("resolved drop = %+v", got)
	}
	if got := snapshot.Drops[1]; got.Reason != "UNKNOWN_99" || got.Location != "unknown" || got.Protocol != "0xbeef" {
		t.Fatalf("fallback drop = %+v", got)
	}
	if snapshot.Self.MapEntries != 2 || snapshot.Self.MapEstimatedBytes != 3584 {
		t.Fatalf("map self metrics = %+v", snapshot.Self)
	}
	if snapshot.Self.ReasonResolutionFailures != 1 || snapshot.Self.SymbolResolutionFailures != 1 {
		t.Fatalf("resolution failures = %+v", snapshot.Self)
	}

	store := NewStore()
	store.Store(snapshot)
	// Store copies the slice before publishing it, so a caller retaining and
	// mutating the source snapshot cannot change the published value.
	snapshot.Drops[0].Reason = "changed before second store"
	if got := store.Load().Drops[0].Reason; got != "NO_SOCKET" {
		t.Fatalf("published snapshot changed through source mutation: %q", got)
	}
}

func TestEstimateMapBytesCountsOneKeyAndPerCPUValuesPerEntry(t *testing.T) {
	raw := bpf.RawSnapshot{MapMaxEntries: 8192, PossibleCPUs: 256}
	const want = uint64(8192 * (24 + 256*16))
	if got := estimateMapBytes(raw); got != want {
		t.Fatalf("estimateMapBytes() = %d, want %d", got, want)
	}
}

func TestBuildSnapshotOmitsInterfaceLabelsWhenDisabled(t *testing.T) {
	raw := bpf.RawSnapshot{
		Samples: []bpf.Sample{{Key: bpf.Key{Reason: 1, NetnsInum: 42, Ifindex: 9}, Value: bpf.Value{Packets: 1}}},
	}
	snapshot := BuildSnapshot(raw, time.Now(), nil, nil, false)
	if snapshot.Drops[0].Netns != "" || snapshot.Drops[0].Ifindex != "" {
		t.Fatalf("interface labels should be omitted: %+v", snapshot.Drops[0])
	}
}

func TestBuildSnapshotWithStatsAccumulatesResolutionFailures(t *testing.T) {
	raw := bpf.RawSnapshot{
		Samples: []bpf.Sample{{Key: bpf.Key{Reason: 99, Location: 0x1000}}},
	}
	stats := NewResolutionStats()
	first := BuildSnapshotWithStats(raw, time.Now(), nil, nil, false, stats)
	second := BuildSnapshotWithStats(raw, time.Now(), nil, nil, false, stats)
	if first.Self.ReasonResolutionFailures != 1 || first.Self.SymbolResolutionFailures != 1 {
		t.Fatalf("first resolution counters = %+v", first.Self)
	}
	if second.Self.ReasonResolutionFailures != 2 || second.Self.SymbolResolutionFailures != 2 {
		t.Fatalf("second resolution counters = %+v", second.Self)
	}
}
