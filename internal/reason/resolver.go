package reason

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// Resolver maps the running kernel's skb_drop_reason values to stable metric
// names without compiling an enum table into the exporter.
type Resolver struct {
	names map[uint32]string
}

// LoadKernel reads the enum from the running kernel BTF.
func LoadKernel() (*Resolver, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("load kernel BTF for drop reasons: %w", err)
	}
	var enum *btf.Enum
	if err := spec.TypeByName("skb_drop_reason", &enum); err != nil {
		return nil, fmt.Errorf("find enum skb_drop_reason in kernel BTF: %w", err)
	}
	return New(enum.Values), nil
}

// New builds a resolver from BTF enum values. It is intentionally independent
// from the kernel loader so enum fallback behavior can be unit tested.
func New(values []btf.EnumValue) *Resolver {
	names := make(map[uint32]string, len(values))
	for _, value := range values {
		names[uint32(value.Value)] = normalize(value.Name)
	}
	return &Resolver{names: names}
}

// Resolve returns UNKNOWN_N for an enum value not present in the running
// kernel's BTF. The boolean reports whether the lookup was exact.
func (r *Resolver) Resolve(value uint32) (string, bool) {
	if r != nil {
		if name, ok := r.names[value]; ok {
			return name, true
		}
	}
	return fmt.Sprintf("UNKNOWN_%d", value), false
}

func normalize(name string) string {
	name = strings.TrimPrefix(name, "SKB_DROP_REASON_")
	name = strings.TrimPrefix(name, "SKB_")
	return name
}
