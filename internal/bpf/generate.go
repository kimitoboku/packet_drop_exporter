package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -cc clang -type drop_key -type drop_value -type config_value -type stats_value drop drop.bpf.c -- -I. -O2 -g
