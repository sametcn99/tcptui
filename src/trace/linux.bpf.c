// A CO-RE state observer. This program never changes or drops network traffic.
// Small flavored types describe just the kernel fields used by the probe.
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

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 27
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define TCP_ESTABLISHED 1

struct ns_common___tcptui {
    unsigned int inum;
} __attribute__((preserve_access_index));

struct net___tcptui {
    struct ns_common___tcptui ns;
} __attribute__((preserve_access_index));

typedef struct {
    struct net___tcptui *net;
} possible_net_t___tcptui;

struct in6_addr___tcptui {
    union {
        __u8 u6_addr8[16];
    } in6_u;
} __attribute__((preserve_access_index));

struct sock_common___tcptui {
    __u16 skc_family;
    __be32 skc_rcv_saddr;
    __be32 skc_daddr;
    __u16 skc_num;
    __be16 skc_dport;
    possible_net_t___tcptui skc_net;
    struct in6_addr___tcptui skc_v6_rcv_saddr;
    struct in6_addr___tcptui skc_v6_daddr;
} __attribute__((preserve_access_index));

struct sock___tcptui {
    struct sock_common___tcptui __sk_common;
    __u16 sk_protocol;
} __attribute__((preserve_access_index));

struct event {
    __u64 cookie;
    __u64 monotonic_ns;
    __u8 local[16];
    __u8 remote[16];
    __u16 local_port;
    __u16 remote_port;
    __u16 family;
    __u8 connected;
    __u8 reserved;
};

const volatile __u32 netns = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} LOST SEC(".maps");

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(observe_state, struct sock___tcptui *sk, int old_state, int new_state)
{
    if ((old_state == TCP_ESTABLISHED) == (new_state == TCP_ESTABLISHED))
        return 0;

    if (BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum) != netns ||
        BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
        return 0;

    struct event value = {};
    value.family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (value.family == AF_INET) {
        BPF_CORE_READ_INTO((__be32 *)value.local, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO((__be32 *)value.remote, sk, __sk_common.skc_daddr);
    } else if (value.family == AF_INET6) {
        if (!bpf_core_field_exists(sk->__sk_common.skc_v6_daddr))
            return 0;
        BPF_CORE_READ_INTO(&value.local, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&value.remote, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    } else {
        return 0;
    }

    value.local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    value.remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (!value.local_port || !value.remote_port)
        return 0;
    value.cookie = bpf_get_socket_cookie(sk);
    value.monotonic_ns = bpf_ktime_get_ns();
    value.connected = new_state == TCP_ESTABLISHED;

    if (bpf_ringbuf_output(&EVENTS, &value, sizeof(value), 0) != 0) {
        __u32 index = 0;
        __u64 *lost = bpf_map_lookup_elem(&LOST, &index);
        if (lost)
            __sync_fetch_and_add(lost, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
