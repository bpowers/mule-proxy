// Copyright 2022 Bobby Powers. All rights reserved.
// Use of this source code is governed by the ISC License
// that can be found in the LICENSE file, or GPL version 2.

// +build ignore

#include <stdint.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_CONN_ENTRIES 128

// only supports 3 args, due to eBPF limitations
#define printk(fmt, ...)                                       \
  ({                                                           \
    static const char ____fmt[] = fmt;                         \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })

// TODO: ipv6 support
struct socket_key {
  __u32 local_ip;
  __u32 local_port;
  __u32 remote_ip;
  __u32 remote_port;
};

void socket_key_init(struct socket_key *key, const struct __sk_buff *skb) {
  key->local_ip = skb->local_ip4;
  key->local_port = skb->local_port;
  key->remote_ip = skb->remote_ip4;
  // sk_buff's local_port is native-endian (little), but remote port is network (big)
  key->remote_port = bpf_ntohl(skb->remote_port);
}

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __type(key, struct socket_key);
  __type(value, sizeof(int));
  __uint(max_entries, MAX_CONN_ENTRIES);
} frontend_conns SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __type(key, struct socket_key);
  __type(value, sizeof(int));
  __uint(max_entries, MAX_CONN_ENTRIES);
} backend_conns SEC(".maps");

SEC("sk_skb/stream_verdict")
int mule_frontend_verdict(struct __sk_buff *skb) {
  struct socket_key key;
  socket_key_init(&key, skb);
  // flags is 0, because skb is an ingress packet, but we want to redirect
  // it to the egress path on the other side
  return bpf_sk_redirect_hash(skb, &backend_conns, &key, 0);
}

SEC("sk_skb/stream_verdict")
int mule_backend_verdict(struct __sk_buff *skb) {
  struct socket_key key;
  socket_key_init(&key, skb);
  // flags is 0, because skb is an ingress packet, but we want to redirect
  // it to the egress path on the other side
  return bpf_sk_redirect_hash(skb, &frontend_conns, &key, 0);
}

char __license[] SEC("license") = "Dual ISC/GPL";
