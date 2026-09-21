package collector

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"

	"github.com/kimitoboku/packet_drop_exporter/internal/bpf"
	"github.com/kimitoboku/packet_drop_exporter/internal/reason"
	"github.com/kimitoboku/packet_drop_exporter/internal/symbol"
)

func TestMetricsCollectorExportsCountersAndSelfMetrics(t *testing.T) {
	store := NewStore()
	store.Store(BuildSnapshot(
		bpf.RawSnapshot{
			MapMaxEntries: 8,
			PossibleCPUs:  1,
			Samples: []bpf.Sample{{
				Key:   bpf.Key{Reason: 2, Location: 0x1000, Protocol: 0x0800},
				Value: bpf.Value{Packets: 4, Bytes: 512},
			}},
			Stats: bpf.Stats{EventsSeen: 5, EventsExported: 4},
		},
		time.Unix(200, 0),
		reason.New(nil),
		symbol.New([]symbol.Entry{{Address: 0x1000, Name: "dropper"}}),
		false,
	))
	runtimeState := &Runtime{}
	runtimeState.SetAttached(true)
	runtimeState.SetReady(true)
	registry := prometheus.NewRegistry()
	registry.MustRegister(NewMetricsCollector(store, runtimeState, "test", false))

	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	encoded := new(strings.Builder)
	encoder := expfmt.NewEncoder(encoded, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, family := range metricFamilies {
		if err := encoder.Encode(family); err != nil {
			t.Fatal(err)
		}
	}
	output := encoded.String()
	for _, expected := range []string{
		"linux_skb_drops_total",
		"linux_skb_drop_bytes_total",
		"packet_drop_exporter_ready",
		"packet_drop_exporter_bpf_attached",
		"reason=\"UNKNOWN_2\"",
		"location=\"dropper\"",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("metrics output does not contain %q:\n%s", expected, output)
		}
	}
}

func TestMetricsCollectorCanOmitDisabledDimensions(t *testing.T) {
	store := NewStore()
	store.Store(BuildSnapshot(
		bpf.RawSnapshot{Samples: []bpf.Sample{{Key: bpf.Key{Reason: 1}, Value: bpf.Value{Packets: 1}}}},
		time.Now(), nil, nil, false,
	))
	runtimeState := &Runtime{}
	registry := prometheus.NewRegistry()
	registry.MustRegister(NewMetricsCollectorWithDimensions(store, runtimeState, "test", MetricDimensions{}))
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	encoded := new(strings.Builder)
	encoder := expfmt.NewEncoder(encoded, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, family := range families {
		if err := encoder.Encode(family); err != nil {
			t.Fatal(err)
		}
	}
	output := encoded.String()
	if strings.Contains(output, "location=\"") || strings.Contains(output, "protocol=\"") {
		t.Fatalf("disabled dimensions were exported: %s", output)
	}
}
