#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define TC_ACT_OK 0
#define L4_TCP    6
#define L4_UDP    17

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct netEvent {
    __u64 ts_ns;
    __u32 pkt_len;
    __u32 saddr;   // be32
    __u32 daddr;   // be32
    __u16 sport;   // be16
    __u16 dport;   // be16
    __u8  protocol;      // 6=TCP, 17=UDP
    // __u16 _pad;    // align    
};

static __always_inline int load_u8(const struct __sk_buff *skb, int off, __u8 *dst) {
    return bpf_skb_load_bytes(skb, off, dst, sizeof(*dst));
}
static __always_inline int load_u16(const struct __sk_buff *skb, int off, __u16 *dst) {
    return bpf_skb_load_bytes(skb, off, dst, sizeof(*dst));
}
static __always_inline int load_u32(const struct __sk_buff *skb, int off, __u32 *dst) {
    return bpf_skb_load_bytes(skb, off, dst, sizeof(*dst));
}

static __always_inline int parse_ipv4(struct __sk_buff *skb, struct netEvent *ev){

    // ipv4 헤더 길이는 가변적임(옵션 유무) -> l4위치 동적 계산
    __u8 vihl = 0;
    if (load_u8(skb, 14, &vihl) < 0)
        return 0;

    __u8 version = vihl >> 4;
    __u8 ihl     = (vihl & 0x0F) * 4;  // 바이트 단위
    if (version != 4 || ihl < 20)
        return 0;

    __u8 protocol = 0;
    if(load_u8(skb, 23, &protocol) < 0){
        return 0;
    }
    
    if(load_u32(skb, 26, &ev->saddr) < 0){
        return 0;
    }
    if(load_u32(skb, 26, &ev->daddr) < 0){
        return 0;   
    }

    int l4offset = 14 + ihl;
    if(protocol == L4_TCP){
        __u16 sport = 0, dport = 0;
        if(load_u16(skb, l4offset, &sport) < 0 ) return 0;
        if(load_u16(skb, l4offset + 2, &dport) < 0 ) return 0;
        ev->protocol = L4_TCP;
        ev->sport = sport;
        ev->dport = dport;
        return 1;
    } else if (protocol == L4_UDP){
        __u16 sport = 0, dport = 0;
        if(load_u16(skb, l4offset, &sport) < 0 ) return 0;
        if(load_u16(skb, l4offset + 2, &dport) < 0 ) return 0;
        ev->protocol = L4_UDP;
        ev->sport = sport;
        ev->dport = dport;
        return 1;
    } 
    return 0;
}

SEC("tcx/ingress")
int ingress_custom_ebpf(struct __sk_buff *skb)
{
    __u16 proto;
    // __u32 nhoff = ETH_HLEN;

    // IPv4가 아니면 모으지 않음
    if(load_u16(skb, 12, &proto) < 0) return TC_ACT_OK;
    proto = __bpf_ntohs(proto);
    if (proto != ETH_P_IP) return TC_ACT_OK;

    // 자리 할당
    struct netEvent *net_ev = bpf_ringbuf_reserve(&events, sizeof(*net_ev), 0);
    if(!net_ev) return TC_ACT_OK;

    net_ev->ts_ns   = bpf_ktime_get_ns();
    net_ev->pkt_len = skb->len;
    net_ev->protocol= 0;
    net_ev->sport   = 0;
    net_ev->dport   = 0;

    // 파싱 -> 에러 시 자리 반납 및 기록
    if(!parse_ipv4(skb, net_ev)){
        bpf_ringbuf_discard(net_ev, 0);
        bpf_printk("event dropped by parse error");
        return TC_ACT_OK;
    }

    // ringbuf에 등록
    bpf_ringbuf_submit(net_ev, 0);
    return TC_ACT_OK;
}


char __license[] SEC("license") = "GPL";