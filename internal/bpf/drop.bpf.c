//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct drop_key {
	__u64 location;
	__u32 reason;
	__u32 netns_inum;
	__u32 ifindex;
	__u16 protocol;
	__u16 reserved;
};

struct drop_value {
	__u64 packets;
	__u64 bytes;
};

struct config_value {
	__u8 dimension_reason;
	__u8 dimension_location;
	__u8 dimension_protocol;
	__u8 dimension_interface;
};

struct stats_value {
	__u64 events_seen;
	__u64 events_consumed;
	__u64 events_exported;
	__u64 map_update_failures;
	__u64 skb_read_failures;
	__u64 interface_read_failures;
};

enum stats_key {
	STAT_EVENTS = 0,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct drop_key);
	__type(value, struct drop_value);
} drops SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config_value);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stats_value);
} stats SEC(".maps");

static __always_inline struct stats_value *stats_get(void)
{
	__u32 key = STAT_EVENTS;

	return bpf_map_lookup_elem(&stats, &key);
}

static __always_inline void stats_inc_events(void)
{
	struct stats_value *value = stats_get();

	if (value)
		value->events_seen++;
}

SEC("tp_btf/kfree_skb")
int BPF_PROG(observe_kfree_skb,
		     struct sk_buff *skb,
		     void *location,
		     enum skb_drop_reason reason)
{
	__u32 config_key = 0;
	struct config_value defaults = {
		.dimension_reason = 1,
		.dimension_location = 1,
		.dimension_protocol = 1,
	};
	struct config_value *cfg;
	struct drop_key key = {};
	struct drop_value zero = {};
	struct drop_value *value;
	struct stats_value *stats_value;

	stats_inc_events();

	stats_value = stats_get();
	if (reason == SKB_CONSUMED) {
		if (stats_value)
			stats_value->events_consumed++;
		return 0;
	}

	if (!skb) {
		if (stats_value)
			stats_value->skb_read_failures++;
		return 0;
	}

	cfg = bpf_map_lookup_elem(&config, &config_key);
	if (!cfg)
		cfg = &defaults;

	/* reason is intentionally always part of the identity in v1. */
	key.reason = (__u32)reason;
	if (cfg->dimension_location)
		key.location = (__u64)location;

	if (cfg->dimension_protocol)
		key.protocol = bpf_ntohs(BPF_CORE_READ(skb, protocol));

	if (cfg->dimension_interface) {
		struct net_device *dev = BPF_CORE_READ(skb, dev);

		if (dev) {
			struct net *net;

			key.ifindex = BPF_CORE_READ(dev, ifindex);
			net = BPF_CORE_READ(dev, nd_net.net);
			if (net)
				key.netns_inum = BPF_CORE_READ(net, ns.inum);
			else if (stats_value)
				stats_value->interface_read_failures++;
		} else if (stats_value) {
			stats_value->interface_read_failures++;
		}
	}

	value = bpf_map_lookup_elem(&drops, &key);
	if (!value) {
		if (bpf_map_update_elem(&drops, &key, &zero, BPF_NOEXIST)) {
			if (stats_value)
				stats_value->map_update_failures++;
			return 0;
		}
		value = bpf_map_lookup_elem(&drops, &key);
	}

	if (!value) {
		if (stats_value)
			stats_value->map_update_failures++;
		return 0;
	}

	value->packets++;
	value->bytes += BPF_CORE_READ(skb, len);
	if (stats_value)
		stats_value->events_exported++;

	return 0;
}
