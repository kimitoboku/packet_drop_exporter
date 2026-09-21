/*
 * This is the deliberately small CO-RE type view used by drop.bpf.c.
 *
 * CO-RE uses type and member names to relocate field accesses against the
 * running kernel's BTF. Keeping only the fields used by the fast path makes
 * the source portable and avoids checking in a distribution-specific full
 * vmlinux.h. The integration container still probes the running kernel BTF
 * before loading the object.
 */
#ifndef PACKET_DROP_EXPORTER_VMLINUX_H
#define PACKET_DROP_EXPORTER_VMLINUX_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
};

#define BPF_NOEXIST 1

struct ns_common {
	__u32 inum;
};

struct net {
	struct ns_common ns;
};

typedef struct {
	struct net *net;
} possible_net_t;

struct net_device {
	int ifindex;
	possible_net_t nd_net;
};

struct sk_buff {
	__u32 len;
	__be16 protocol;
	struct net_device *dev;
};

enum skb_drop_reason {
	SKB_NOT_DROPPED_YET = 0,
	SKB_CONSUMED = 1,
};

#endif
