/*
 * L3 forwarder NF: longest-prefix-match on the destination IP -> next hop,
 * then rewrite the destination MAC with the next hop's address.
 *
 * Header fields are read in place through pointer casts (benchmark traffic
 * is plain eth+ip: no VLAN or IP options, headers at fixed offsets).
 */
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <sched.h>
#include <cstdlib>
#if defined(NF_IPV6)
#include <rte_lpm6.h>
#else
#include <rte_lpm.h>
#endif

#ifndef NF_NB_ROUTES
#define NF_NB_ROUTES 16
#endif

/* Next-hop MAC table, indexed by the LPM next-hop id.
 *
 * WARNING: forwarding to fabricated MACs (02:00:00:00:00:NN) that no device
 * owns makes any intervening switch FLOOD every frame (unknown unicast). On a
 * switched testbed set NF_NEXTHOP_MAC to a MAC the switch knows (e.g. the
 * traffic generator's port MAC); the LPM lookup still runs — only the egress
 * MAC is fixed. */
static struct rte_ether_addr g_nexthop_mac[NF_NB_ROUTES];
static void init_nexthop_macs(void) {
    struct rte_ether_addr nh;
    const char *env = getenv("NF_NEXTHOP_MAC");
    bool have = (env && rte_ether_unformat_addr(env, &nh) == 0);
    for (uint32_t i = 0; i < NF_NB_ROUTES; ++i) {
        if (have) { rte_ether_addr_copy(&nh, &g_nexthop_mac[i]); continue; }
        for (int b = 0; b < 6; ++b) g_nexthop_mac[i].addr_bytes[b] = 0x02;
        g_nexthop_mac[i].addr_bytes[5] = (uint8_t)i;
    }
}

#if defined(NF_IPV6)
static __thread struct rte_lpm6 *g_lpm6 = nullptr;

void nf_setup(void) {
    int lcore = sched_getcpu();
    char name[64];
    snprintf(name, sizeof(name), "l3fwd_lpm6_%03d", lcore);
    struct rte_lpm6_config cfg;
    cfg.max_rules = 1024;
    cfg.number_tbl8s = 4096;
    cfg.flags = 0;
    g_lpm6 = rte_lpm6_create(name, rte_socket_id(), &cfg);
    if (g_lpm6 == nullptr) rte_exit(EXIT_FAILURE, "l3fwd: lpm6 create failed\n");
    init_nexthop_macs();
    /* fd00:0:0:<i>::/64 -> next hop i. */
    for (uint32_t i = 0; i < NF_NB_ROUTES; ++i) {
        uint8_t net[16] = {0xfd,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
        net[7] = (uint8_t)i;
        if (rte_lpm6_add(g_lpm6, net, 64, i) < 0)
            rte_exit(EXIT_FAILURE, "l3fwd: lpm6 add failed\n");
    }
    uint8_t any[16] = {0};
    rte_lpm6_add(g_lpm6, any, 0, 0);  // default route
}

static __rte_always_inline void nf_app(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *iph = (struct rte_ipv6_hdr *)(eth + 1);
    uint32_t next_hop = 0;
    if (rte_lpm6_lookup(g_lpm6, iph->dst_addr, &next_hop) != 0)
        next_hop = 0;
    rte_ether_addr_copy(&g_nexthop_mac[next_hop & (NF_NB_ROUTES - 1)], &eth->dst_addr);
}

#else  /* IPv4 */
static __thread struct rte_lpm *g_lpm = nullptr;

void nf_setup(void) {
    int lcore = sched_getcpu();
    char name[64];
    snprintf(name, sizeof(name), "l3fwd_lpm_%03d", lcore);
    struct rte_lpm_config cfg;
    cfg.max_rules = 1024;
    cfg.number_tbl8s = 256;
    cfg.flags = 0;
    g_lpm = rte_lpm_create(name, rte_socket_id(), &cfg);
    if (g_lpm == nullptr) rte_exit(EXIT_FAILURE, "l3fwd: lpm create failed\n");
    init_nexthop_macs();
    /* 10.0.<i>.0/24 -> next hop i. */
    for (uint32_t i = 0; i < NF_NB_ROUTES; ++i) {
        uint32_t net = RTE_IPV4(10, 0, i, 0);
        if (rte_lpm_add(g_lpm, net, 24, i) < 0)
            rte_exit(EXIT_FAILURE, "l3fwd: lpm add failed\n");
    }
    rte_lpm_add(g_lpm, 0, 0, 0);  // default route
}

static __rte_always_inline void nf_app(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(eth + 1);
    uint32_t next_hop = 0;
    uint32_t dip = iph->dst_addr;
    if (rte_lpm_lookup(g_lpm, rte_be_to_cpu_32(dip), &next_hop) != 0)
        next_hop = 0;
    rte_ether_addr_copy(&g_nexthop_mac[next_hop & (NF_NB_ROUTES - 1)], &eth->dst_addr);
}
#endif

#include "nf_main.h"
