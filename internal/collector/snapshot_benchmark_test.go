package collector

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"

	"github.com/kimitoboku/packet_drop_exporter/internal/bpf"
	"github.com/kimitoboku/packet_drop_exporter/internal/reason"
	"github.com/kimitoboku/packet_drop_exporter/internal/symbol"
)

var benchmarkSnapshot Snapshot

func BenchmarkBuildSnapshot8192Entries(b *testing.B) {
	raw := bpf.RawSnapshot{
		Samples:       make([]bpf.Sample, 8192),
		MapMaxEntries: 8192,
		PossibleCPUs:  256,
	}
	symbols := make([]symbol.Entry, 8192)
	for index := range raw.Samples {
		address := uint64(0x100000 + index*0x20)
		raw.Samples[index] = bpf.Sample{
			Key: bpf.Key{
				Location:  address,
				Reason:    uint32(index % 8),
				Protocol:  0x0800,
				NetnsInum: uint32(index % 64),
				Ifindex:   uint32(index%32 + 1),
			},
			Value: bpf.Value{Packets: uint64(index + 1), Bytes: uint64(index+1) * 128},
		}
		symbols[index] = symbol.Entry{Address: address, Name: fmt.Sprintf("drop_site_%d", index)}
	}
	reasonValues := make([]btf.EnumValue, 8)
	for index := range reasonValues {
		reasonValues[index] = btf.EnumValue{
			Name:  fmt.Sprintf("SKB_DROP_REASON_BENCHMARK_%d", index),
			Value: uint64(index),
		}
	}
	reasons := reason.New(reasonValues)
	resolver := symbol.New(symbols)
	collectedAt := time.Unix(1, 0)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		benchmarkSnapshot = BuildSnapshot(raw, collectedAt, reasons, resolver, true)
	}
}
