#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define TC_ACT_OK 0

SEC("tcx/ingress")
int ingress_custom_ebpf(struct __sk_buff *skb)
{
    __u16 proto, tot_len;
    __u8 ihl_ver, ttl;
    __u32 nhoff = ETH_HLEN;

    if (bpf_skb_load_bytes(skb, 12, &proto, 2) < 0) return TC_ACT_OK;
    proto = __bpf_ntohs(proto);
    if (proto != ETH_P_IP) return TC_ACT_OK;

    if (bpf_skb_load_bytes(skb, nhoff + 0, &ihl_ver, 1) < 0) return TC_ACT_OK;
    __u8 ihl = (ihl_ver & 0x0f) * 4;
    if (ihl < sizeof(struct iphdr)) return TC_ACT_OK;

    if (bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tot_len, 2) < 0) return TC_ACT_OK;
    tot_len = __bpf_ntohs(tot_len);

    if (bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, ttl), &ttl, 1) < 0) return TC_ACT_OK;

    bpf_printk("Got IP packet: tot_len=%d ttl=%d\n", tot_len, ttl);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";