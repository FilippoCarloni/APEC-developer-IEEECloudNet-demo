/*
 * ACL/firewall NF: classify the 5-tuple against an ordered rule set (linear
 * first-match, the classic firewall ladder) and tally permit/deny in
 * per-lcore counters. Packets are still forwarded: the verdict is counted,
 * not enforced — enforcing it would just skip the TX of denied packets and
 * is an easy extension in the runtime loop.
 *
 * Header fields are read in place through pointer casts (benchmark traffic
 * is plain eth+ip+l4: no VLAN or IP options, headers at fixed offsets).
 */
#include <rte_eal.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <string.h>

#ifndef NF_NB_RULES
#define NF_NB_RULES 64
#endif

static __thread uint64_t g_permit = 0, g_deny = 0;

#if defined(NF_IPV6)
/* IPv6 rules: a source /prefix match (the firewall ladder over 128-bit src). */
struct acl_rule6 {
    uint8_t  sip[16];
    uint8_t  prefix_len;  // bytes of sip to compare
    uint16_t sport_lo, sport_hi;
    uint16_t dport_lo, dport_hi;
    uint8_t  proto, proto_mask;
    uint8_t  permit;
};
static acl_rule6 g_rules[NF_NB_RULES];

void nf_setup(void) {
    for (uint32_t i = 0; i < NF_NB_RULES - 1; ++i) {
        memset(&g_rules[i], 0, sizeof(acl_rule6));
        uint8_t pref[16] = {0xfd,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
        pref[7] = (uint8_t)i;
        memcpy(g_rules[i].sip, pref, 16);
        g_rules[i].prefix_len = 8;            // /64
        g_rules[i].sport_hi = 0xFFFF; g_rules[i].dport_hi = 0xFFFF;
        g_rules[i].permit = 0;
    }
    acl_rule6 &last = g_rules[NF_NB_RULES - 1];
    memset(&last, 0, sizeof(acl_rule6));
    last.prefix_len = 0; last.sport_hi = 0xFFFF; last.dport_hi = 0xFFFF; last.permit = 1;
}

static __rte_always_inline uint8_t classify(const struct rte_ipv6_hdr *iph,
                                            const struct rte_udp_hdr *udp) {
    const uint16_t sp = rte_be_to_cpu_16(udp->src_port);
    const uint16_t dp = rte_be_to_cpu_16(udp->dst_port);
    for (uint32_t i = 0; i < NF_NB_RULES; ++i) {
        const acl_rule6 &r = g_rules[i];
        if (r.prefix_len && memcmp(iph->src_addr, r.sip, r.prefix_len) != 0) continue;
        if (sp < r.sport_lo || sp > r.sport_hi) continue;
        if (dp < r.dport_lo || dp > r.dport_hi) continue;
        if ((iph->proto & r.proto_mask) != r.proto) continue;
        return r.permit;
    }
    return 0;
}

static __rte_always_inline void nf_app(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *iph = (struct rte_ipv6_hdr *)(eth + 1);
    /* src/dst port share offsets in UDP and TCP: one cast covers both. */
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(iph + 1);
    if (classify(iph, udp)) g_permit++; else g_deny++;
}

#else  /* IPv4 */
struct acl_rule {
    uint32_t sip, sip_mask;
    uint32_t dip, dip_mask;
    uint16_t sport_lo, sport_hi;
    uint16_t dport_lo, dport_hi;
    uint8_t  proto, proto_mask;
    uint8_t  permit;  // 1 = permit, 0 = deny
};
static acl_rule g_rules[NF_NB_RULES];

void nf_setup(void) {
    /* Synthetic rule ladder: deny a spread of /24 sources, last rule permits
     * all. Representative of a real firewall's linear match cost. */
    for (uint32_t i = 0; i < NF_NB_RULES - 1; ++i) {
        g_rules[i].sip = rte_cpu_to_be_32(RTE_IPV4(10, 0, i, 0));
        g_rules[i].sip_mask = rte_cpu_to_be_32(0xFFFFFF00);
        g_rules[i].dip = 0; g_rules[i].dip_mask = 0;
        g_rules[i].sport_lo = 0; g_rules[i].sport_hi = 0xFFFF;
        g_rules[i].dport_lo = 0; g_rules[i].dport_hi = 0xFFFF;
        g_rules[i].proto = 0; g_rules[i].proto_mask = 0;
        g_rules[i].permit = 0;
    }
    acl_rule &last = g_rules[NF_NB_RULES - 1];
    last.sip = 0; last.sip_mask = 0; last.dip = 0; last.dip_mask = 0;
    last.sport_lo = 0; last.sport_hi = 0xFFFF;
    last.dport_lo = 0; last.dport_hi = 0xFFFF;
    last.proto = 0; last.proto_mask = 0; last.permit = 1;
}

static __rte_always_inline uint8_t classify(const struct rte_ipv4_hdr *iph,
                                            const struct rte_udp_hdr *udp) {
    const uint16_t sp = rte_be_to_cpu_16(udp->src_port);
    const uint16_t dp = rte_be_to_cpu_16(udp->dst_port);
    for (uint32_t i = 0; i < NF_NB_RULES; ++i) {
        const acl_rule &r = g_rules[i];
        if ((iph->src_addr & r.sip_mask) != r.sip) continue;
        if ((iph->dst_addr & r.dip_mask) != r.dip) continue;
        if (sp < r.sport_lo || sp > r.sport_hi) continue;
        if (dp < r.dport_lo || dp > r.dport_hi) continue;
        if ((iph->next_proto_id & r.proto_mask) != r.proto) continue;
        return r.permit;  // first match wins
    }
    return 0;
}

static __rte_always_inline void nf_app(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(eth + 1);
    /* src/dst port share offsets in UDP and TCP: one cast covers both. */
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(iph + 1);
    if (classify(iph, udp)) g_permit++; else g_deny++;
}
#endif

#include "nf_main.h"
