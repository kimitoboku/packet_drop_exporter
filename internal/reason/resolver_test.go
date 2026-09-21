package reason

import (
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestResolverNormalizesKernelNamesAndFallsBack(t *testing.T) {
	resolver := New([]btf.EnumValue{
		{Name: "SKB_DROP_REASON_NO_SOCKET", Value: 2},
		{Name: "SKB_CONSUMED", Value: 1},
	})

	if got, known := resolver.Resolve(2); !known || got != "NO_SOCKET" {
		t.Fatalf("known reason = %q, %v", got, known)
	}
	if got, known := resolver.Resolve(1); !known || got != "CONSUMED" {
		t.Fatalf("consumed reason = %q, %v", got, known)
	}
	if got, known := resolver.Resolve(123); known || got != "UNKNOWN_123" {
		t.Fatalf("unknown reason = %q, %v", got, known)
	}
}

func TestNilResolverFallsBack(t *testing.T) {
	var resolver *Resolver
	if got, known := resolver.Resolve(7); known || got != "UNKNOWN_7" {
		t.Fatalf("nil resolver = %q, %v", got, known)
	}
}
