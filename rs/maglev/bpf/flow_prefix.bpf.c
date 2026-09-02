#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include "vendor/bpf_compat.h"

#ifndef VIP_HOST
#define VIP_HOST 0x0a000164u /* 10.0.1.100 */
#endif

#define META_MAGIC 0xA5

struct flow_meta {
	__u8   magic;
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__u8   proto;
	__u8   pad[2];
} __attribute__((packed));
_Static_assert(sizeof(struct flow_meta) == 16, "flow_meta must be 16 bytes");

struct l4_ports {
	__be16 sport;
	__be16 dport;
};

#ifdef PASSTHROUGH
volatile __u64 parse_sink;
#endif

SEC("xdp")
int xdp_flow_prefix(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = data + sizeof(*eth);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;
	if (iph->version != 4 || iph->ihl < 5)
		return XDP_PASS;
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return XDP_PASS;
	if (iph->daddr != bpf_htonl(VIP_HOST))
		return XDP_PASS;
	/* Non-first fragments carry no L4 header: leave them alone. */
	if (iph->frag_off & bpf_htons(0x1FFF))
		return XDP_PASS;

	__u64 l4_off = sizeof(*eth) + (__u64)iph->ihl * 4;
	struct l4_ports *pp = data + l4_off;
	if ((void *)(pp + 1) > data_end)
		return XDP_PASS;

	__be32 saddr = iph->saddr;
	__be32 daddr = iph->daddr;
	__be16 sport = pp->sport;
	__be16 dport = pp->dport;
	__u8 proto = iph->protocol;

#ifdef PASSTHROUGH
	parse_sink += (__u64)saddr + daddr + sport + dport + proto;
	return XDP_PASS;
#else
	if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct flow_meta)))
		return XDP_PASS; /* no headroom: deliver unprefixed */

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	struct flow_meta *m = data;
	if ((void *)(m + 1) > data_end)
		return XDP_ABORTED;

	m->magic = META_MAGIC;
	m->saddr = saddr;
	m->daddr = daddr;
	m->sport = sport;
	m->dport = dport;
	m->proto = proto;
	m->pad[0] = 0;
	m->pad[1] = 0;
	return XDP_PASS;
#endif
}

char _license[] SEC("license") = "GPL";
