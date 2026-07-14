/*
 * Stateless source-NAT NF: hash the flow 5-tuple to an entry in an external
 * address/port pool and rewrite the packet's source IP and L4 port.
 *
 * Header fields are read in place through pointer casts (benchmark traffic
 * is plain eth+ip+l4: no VLAN or IP options, headers at fixed offsets). The
 * IP/L4 checksums are intentionally not recomputed (the traffic generator
 * counts packets without validating checksums).
 */
#include <rte_eal.h>
#include <rte_jhash.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <string.h>

#ifndef NF_NAT_POOL
#define NF_NAT_POOL 4096
#endif

static uint16_t g_ext_port[NF_NAT_POOL];
#if defined(NF_IPV6)
static uint8_t g_ext_ip6[NF_NAT_POOL][16];
#else
static uint32_t g_ext_ip[NF_NAT_POOL];
#endif

void nf_setup(void) {
    for (uint32_t i = 0; i < NF_NAT_POOL; ++i)
        g_ext_port[i] = rte_cpu_to_be_16((uint16_t)(10000 + (i & 0x7fff)));
#if defined(NF_IPV6)
    /* External pool: 2001:db8::/32 (documentation space). */
    uint8_t base[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,0,0,0,1};
    for (uint32_t i = 0; i < NF_NAT_POOL; ++i) {
        memcpy(g_ext_ip6[i], base, 16);
        uint32_t *low = (uint32_t *)&g_ext_ip6[i][12];
        *low = rte_cpu_to_be_32(rte_be_to_cpu_32(*low) + i);
    }
#else
    /* External pool: 100.64.0.0/10 (CGNAT space). */
    uint32_t base = RTE_IPV4(100, 64, 0, 1);
    for (uint32_t i = 0; i < NF_NAT_POOL; ++i)
        g_ext_ip[i] = rte_cpu_to_be_32(base + i);
#endif
}

static __rte_always_inline void nf_app(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
#if defined(NF_IPV6)
    struct rte_ipv6_hdr *iph = (struct rte_ipv6_hdr *)(eth + 1);
    /* src/dst port share offsets in UDP and TCP: one cast covers both. */
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(iph + 1);
    const uint32_t l4 = ((uint32_t)udp->src_port << 16) | udp->dst_port;
    /* src_addr and dst_addr are adjacent: hash the 32 address bytes at once. */
    const uint32_t h = rte_jhash(iph->src_addr, 32, 0) ^ l4 ^ (uint32_t)iph->proto;
    const uint32_t idx = h & (NF_NAT_POOL - 1);
    rte_memcpy(iph->src_addr, g_ext_ip6[idx], 16);  // rewrite source IP
    udp->src_port = g_ext_port[idx];                // rewrite L4 source port
#else
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(eth + 1);
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(iph + 1);
    const uint32_t l4 = ((uint32_t)udp->src_port << 16) | udp->dst_port;
    const uint32_t h = rte_jhash_3words(iph->src_addr, iph->dst_addr,
                                        l4 ^ (uint32_t)iph->next_proto_id, 0);
    const uint32_t idx = h & (NF_NAT_POOL - 1);
    iph->src_addr = g_ext_ip[idx];                  // rewrite source IP
    udp->src_port = g_ext_port[idx];                // rewrite L4 source port
#endif
}

#include "nf_main.h"
