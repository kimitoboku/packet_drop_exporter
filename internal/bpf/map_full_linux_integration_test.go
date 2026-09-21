//go:build linux && integration

package bpf

import (
	"math"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestMapFullIncrementsFailureCounter(t *testing.T) {
	collector, err := Open(LoaderConfig{
		MaxEntries:        1,
		DimensionLocation: true,
		DimensionProtocol: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()

	key := dropDropKey{Location: math.MaxUint64, Reason: math.MaxUint32, Protocol: math.MaxUint16}
	values := make([]dropDropValue, collector.possibleCPUs)
	values[0].Packets = 1
	if err := collector.objects.Drops.Update(&key, values, ebpf.UpdateNoExist); err != nil {
		t.Fatalf("prefill drops map: %v", err)
	}

	connection, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := connection.Write([]byte("map-full-integration-test")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
		snapshot, err := collector.Collect()
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Stats.MapUpdateFailures > 0 {
			return
		}
	}
	t.Fatal("map update failure counter did not increase")
}
