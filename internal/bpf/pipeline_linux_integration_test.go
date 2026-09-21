//go:build linux && integration

package bpf_test

import (
	"testing"
	"time"

	"github.com/kimitoboku/packet_drop_exporter/internal/bpf"
	"github.com/kimitoboku/packet_drop_exporter/internal/collector"
	"github.com/kimitoboku/packet_drop_exporter/internal/reason"
	"github.com/kimitoboku/packet_drop_exporter/internal/symbol"
)

func TestUnavailableKallsymsKeepsCollectionOperational(t *testing.T) {
	source, err := bpf.Open(bpf.LoaderConfig{MaxEntries: 8, DimensionLocation: true, DimensionProtocol: true})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	reasons, err := reason.LoadKernel()
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := symbol.Load("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	if symbols.Available() {
		t.Fatal("empty kallsyms source unexpectedly available")
	}

	raw, err := source.Collect()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := collector.BuildSnapshot(raw, time.Now(), reasons, symbols, false)
	if snapshot.Self.SymbolizerAvailable {
		t.Fatal("snapshot unexpectedly reports symbolizer availability")
	}
}
