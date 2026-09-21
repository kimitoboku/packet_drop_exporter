package bpf

// LoaderConfig controls the BPF program and its map dimensions.
type LoaderConfig struct {
	MaxEntries         uint32
	DimensionLocation  bool
	DimensionProtocol  bool
	DimensionInterface bool
}

// Key is the userspace representation of the BPF map key.
type Key struct {
	Location  uint64
	Reason    uint32
	NetnsInum uint32
	Ifindex   uint32
	Protocol  uint16
	Reserved  uint16
}

// Value is the userspace representation of a per-CPU BPF map value after
// CPU values have been summed.
type Value struct {
	Packets uint64
	Bytes   uint64
}

// Stats is the aggregate of the per-CPU BPF self-observation counters.
type Stats struct {
	EventsSeen            uint64
	EventsConsumed        uint64
	EventsExported        uint64
	MapUpdateFailures     uint64
	SKBReadFailures       uint64
	InterfaceReadFailures uint64
}

// Sample is one map entry with per-CPU values already summed.
type Sample struct {
	Key   Key
	Value Value
}

// RawSnapshot contains data collected from BPF maps at one point in time.
type RawSnapshot struct {
	Samples       []Sample
	Stats         Stats
	MapMaxEntries uint64
	PossibleCPUs  uint32
}
