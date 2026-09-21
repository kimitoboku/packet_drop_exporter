//go:build linux

package bpf

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const defaultMaxEntries = 8192

// Collector owns the loaded BPF objects and attached tp_btf link.
type Collector struct {
	objects      dropObjects
	link         link.Link
	possibleCPUs int
	maxEntries   uint32
	closeOnce    sync.Once
}

// Open probes the kernel, loads the embedded CO-RE object, and attaches it to
// the typed kfree_skb BTF tracepoint.
func Open(cfg LoaderConfig) (*Collector, error) {
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = defaultMaxEntries
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return nil, fmt.Errorf("kernel BTF (/sys/kernel/btf/vmlinux) is unavailable: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("read possible CPU count: %w", err)
	}

	spec, err := loadDrop()
	if err != nil {
		return nil, fmt.Errorf("load embedded BPF object: %w", err)
	}
	mapSpec, ok := spec.Maps["drops"]
	if !ok {
		return nil, errors.New("embedded BPF object has no drops map")
	}
	mapSpec.MaxEntries = cfg.MaxEntries

	var objects dropObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("load BPF object: %w", err)
	}

	configKey := uint32(0)
	configValue := dropConfigValue{
		DimensionReason:    1,
		DimensionLocation:  boolByte(cfg.DimensionLocation),
		DimensionProtocol:  boolByte(cfg.DimensionProtocol),
		DimensionInterface: boolByte(cfg.DimensionInterface),
	}
	if err := objects.Config.Update(&configKey, &configValue, ebpf.UpdateAny); err != nil {
		_ = objects.Close()
		return nil, fmt.Errorf("write BPF configuration: %w", err)
	}

	attached, err := link.AttachTracing(link.TracingOptions{
		Program:    objects.ObserveKfreeSkb,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		_ = objects.Close()
		return nil, fmt.Errorf("attach tp_btf/kfree_skb: %w", err)
	}

	return &Collector{
		objects:      objects,
		link:         attached,
		possibleCPUs: possibleCPUs,
		maxEntries:   cfg.MaxEntries,
	}, nil
}

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

// Collect reads the complete map into a userspace snapshot. The per-CPU
// values are summed here; the packet path never sends individual events to
// userspace.
func (c *Collector) Collect() (RawSnapshot, error) {
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return RawSnapshot{}, fmt.Errorf("refresh possible CPU count: %w", err)
	}
	if possibleCPUs <= 0 {
		return RawSnapshot{}, fmt.Errorf("refresh possible CPU count: got %d", possibleCPUs)
	}
	c.possibleCPUs = possibleCPUs

	values := make([]dropDropValue, possibleCPUs)
	iterator := c.objects.Drops.Iterate()
	samples := make([]Sample, 0)
	var key dropDropKey
	for iterator.Next(&key, values) {
		var value Value
		for _, cpuValue := range values {
			value.Packets += cpuValue.Packets
			value.Bytes += cpuValue.Bytes
		}
		samples = append(samples, Sample{
			Key: Key{
				Location:  key.Location,
				Reason:    key.Reason,
				NetnsInum: key.NetnsInum,
				Ifindex:   key.Ifindex,
				Protocol:  key.Protocol,
				Reserved:  key.Reserved,
			},
			Value: value,
		})
	}
	if err := iterator.Err(); err != nil {
		return RawSnapshot{}, fmt.Errorf("iterate drops map: %w", err)
	}

	statsKey := uint32(0)
	statsValues := make([]dropStatsValue, possibleCPUs)
	if err := c.objects.Stats.Lookup(&statsKey, statsValues); err != nil {
		return RawSnapshot{}, fmt.Errorf("read BPF stats: %w", err)
	}
	var aggregate Stats
	for _, cpuValue := range statsValues {
		aggregate.EventsSeen += cpuValue.EventsSeen
		aggregate.EventsConsumed += cpuValue.EventsConsumed
		aggregate.EventsExported += cpuValue.EventsExported
		aggregate.MapUpdateFailures += cpuValue.MapUpdateFailures
		aggregate.SKBReadFailures += cpuValue.SkbReadFailures
		aggregate.InterfaceReadFailures += cpuValue.InterfaceReadFailures
	}

	return RawSnapshot{
		Samples:       samples,
		Stats:         aggregate,
		MapMaxEntries: uint64(c.maxEntries),
		PossibleCPUs:  uint32(c.possibleCPUs),
	}, nil
}

// Close detaches the tracepoint and closes all BPF file descriptors.
func (c *Collector) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.link != nil {
			err = c.link.Close()
		}
		if closeErr := c.objects.Close(); err == nil {
			err = closeErr
		}
	})
	return err
}
