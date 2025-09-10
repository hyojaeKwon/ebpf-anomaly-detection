// file: xflow_kern.c
// CO-RE: vmlinux.h + bpf_helpers.h + bpf_endian.h
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* EtherType/Protocol 상수 */
#define ETH_P_IP  0x0800
#define L4_TCP    6
#define L4_UDP    17

/* ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);          // 0:hit, 1:parsed_ok, 2:parsed_fail, 3:ring_submit
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* 유저 공간과 동일 레이아웃 */
struct net_event {
    __u64 ts_ns;
    __u32 ifindex;
    __u32 pkt_len;
    __u32 saddr;   // be32
    __u32 daddr;   // be32
    __u16 sport;   // be16
    __u16 dport;   // be16
    __u8  dir;     // 0=in, 1=out
    __u8  l4;      // 6=TCP, 17=UDP
    __u16 _pad;    // align
};

/* (옵션) 특정 포트만 수집 */
// #define FILTER_PORT 9000

/* 임시로 parse결과와 상관없이 추가하기 */
static __always_inline void bump(__u32 k){
    __u64 *v = bpf_map_lookup_elem(&stats, &k);   
    if (v){
        __sync_fetch_and_add(v, 1);
    }
}

/* 안전하게 오프셋에서 값 읽기 */
static __always_inline int load_u8(const struct __sk_buff *skb, int off, __u8 *dst) {
    return bpf_skb_load_bytes(skb, off, dst, sizeof(*dst));
}
static __always_inline int load_u16(const struct __sk_buff *skb, int off, __u16 *dst) {
    return bpf_skb_load_bytes(skb, off, dst, sizeof(*dst));
}
static __always_inline int load_u32(const struct __sk_buff *skb, int off, __u32 *dst) {
    return bpf_skb_load_bytes(skb, off, dst, sizeof(*dst));
}

/* L2/L3/L4 파싱을 skb_load_bytes로만 수행 (포인터 접근 없음) */
static __always_inline int parse_ipv4_tcpudp(struct __sk_buff *skb, struct net_event *ev) {
    /* ---- L2: EtherType (offset 12) ---- */
    __u16 eth_proto = 0;
    if (load_u16(skb, 12, &eth_proto) < 0)
        return 0;
    eth_proto = bpf_ntohs(eth_proto);
    if (eth_proto != ETH_P_IP)
        return 0;

    /* ---- L3: IPv4 header 시작(off=14) ----
       첫 바이트: version(상위4비트)/ihl(하위4비트) */
    __u8 vihl = 0;
    if (load_u8(skb, 14, &vihl) < 0)
        return 0;
    __u8 version = vihl >> 4;
    __u8 ihl     = (vihl & 0x0F) * 4;  // 바이트 단위
    if (version != 4 || ihl < 20)
        return 0;

    /* protocol: IP 헤더 내 offset 9 → frame 기준 14+9=23 */
    __u8 proto = 0;
    if (load_u8(skb, 14 + 9, &proto) < 0)
        return 0;

    /* saddr: IP 헤더 내 offset 12 → frame 기준 26 */
    if (load_u32(skb, 14 + 12, &ev->saddr) < 0)
        return 0;
    /* daddr: IP 헤더 내 offset 16 → frame 기준 30 */
    if (load_u32(skb, 14 + 16, &ev->daddr) < 0)
        return 0;

    /* L4 시작 오프셋 */
    int l4off = 14 + ihl;

    if (proto == L4_TCP) {
        __u16 sport = 0, dport = 0;
        if (load_u16(skb, l4off + 0, &sport) < 0) return 0;
        if (load_u16(skb, l4off + 2, &dport) < 0) return 0;
        ev->l4    = L4_TCP;
        ev->sport = sport;  // 그대로 be16
        ev->dport = dport;  // 그대로 be16
        return 1;
    } else if (proto == L4_UDP) {
        __u16 sport = 0, dport = 0;
        if (load_u16(skb, l4off + 0, &sport) < 0) return 0;
        if (load_u16(skb, l4off + 2, &dport) < 0) return 0;
        ev->l4    = L4_UDP;
        ev->sport = sport;
        ev->dport = dport;
        return 1;
    }

    return 0;
}

static __always_inline int handle_pkt(struct __sk_buff *skb, __u8 dir) {
    bump(0);
    struct net_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return BPF_OK;

    ev->ts_ns   = bpf_ktime_get_ns();
    ev->ifindex = skb->ifindex;
    ev->pkt_len = skb->len;
    ev->dir     = dir;
    ev->l4      = 0;
    ev->sport   = 0;
    ev->dport   = 0;
    ev->_pad    = 0;

    if (!parse_ipv4_tcpudp(skb, ev)) {
        bump(2);
        bpf_ringbuf_discard(ev, 0);
        return BPF_OK;
    }
    bump(1);

#ifdef FILTER_PORT
    if (ev->dport != bpf_htons(FILTER_PORT) && ev->sport != bpf_htons(FILTER_PORT)) {
        bpf_ringbuf_discard(ev, 0);
        return BPF_OK;
    }
#endif
    bump(3);
    bpf_ringbuf_submit(ev, 0);
    return BPF_OK;
}

SEC("tcx/ingress")
int handle_ingress(struct __sk_buff *skb) {
    return handle_pkt(skb, 0);
}

SEC("tcx/egress")
int handle_egress(struct __sk_buff *skb) {
    return handle_pkt(skb, 1);
}

char _license[] SEC("license") = "GPL";