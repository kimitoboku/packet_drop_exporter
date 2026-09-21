//go:build !linux

package bpf

import "errors"

// Collector is a placeholder on non-Linux hosts so package-level unit tests
// and documentation tooling can still compile.
type Collector struct{}

// Open reports the platform limitation instead of pretending that BPF was
// attached.
func Open(LoaderConfig) (*Collector, error) {
	return nil, errors.New("tp_btf/kfree_skb requires Linux")
}

func (c *Collector) Collect() (RawSnapshot, error) {
	return RawSnapshot{}, errors.New("tp_btf/kfree_skb requires Linux")
}

func (c *Collector) Close() error { return nil }
