/*
 * Maglev load balancer NF (Eisenbud et al., NSDI '16): hash the 5-tuple,
 * map it to a backend through the Maglev consistent-hash table (permutations
 * + populate, with a per-bucket connection cache), and rewrite the packet's
 * destination IP with the selected backend address. The table is
 * address-family-agnostic: it maps a hash to a backend index; the IPv4/IPv6
 * split is only the key it hashes and the address it writes (NF_IPV6).
 *
 * Header fields are read in place through pointer casts (benchmark traffic
 * is plain eth+ip+l4: no VLAN or IP options, headers at fixed offsets).
 */
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_jhash.h>
#include <rte_fbk_hash.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_mbuf.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <array>
#include <vector>
#include <utility>

#ifndef NF_NB_BACKENDS
#define NF_NB_BACKENDS 1024
#endif

/* Family-agnostic consistent-hash table over backend indices [0, N). */
class MaglevTable {
public:
    explicit MaglevTable(uint32_t nb_backends)
        : nb_backends_(nb_backends), permutations_(nb_backends) {
        for (uint32_t i = 0; i < kSize; ++i) hash_table_[i] = 0xffff;
    }
    ~MaglevTable() { if (ht_) rte_fbk_hash_free(ht_); }

    /* backend_seed[i] = {h1, h2} derived from backend i's address. */
    int setup(const std::vector<std::pair<uint32_t, uint32_t>> &backend_seed) {
        struct rte_fbk_hash_params hp;
        char name[64];
        int lcore = sched_getcpu();
        if (lcore < 0) return errno;
        snprintf(name, sizeof(name), "maglev_ht_%03d", lcore);
        hp.name = name; hp.entries = 1024; hp.entries_per_bucket = kEntriesPerBucket;
        hp.socket_id = rte_socket_id(); hp.hash_func = NULL; hp.init_val = 0;
        ht_ = rte_fbk_hash_create(&hp);
        if (ht_ == NULL) return rte_errno;
        generate_permutations(backend_seed);
        populate();
        return 0;
    }

    __rte_always_inline uint16_t pick(uint32_t hash) {
        uint32_t bucket = rte_fbk_hash_get_bucket(ht_, hash);
        for (uint16_t i = 0; i < kEntriesPerBucket; i++) {
            if (!ht_->t[bucket + i].entry.is_entry) {
                union rte_fbk_hash_entry ne;
                ne.whole_entry = ((uint64_t)hash << 32) |
                                 ((uint64_t)hash_table_[hash % kSize] << 16) | 1ULL;
                ht_->t[bucket + i].whole_entry = ne.whole_entry;
                ht_->t[bucket].entry.is_entry = (i << 1) | 1;
                ht_->used_entries++;
                return ne.entry.value;
            }
            if (ht_->t[bucket + i].entry.key == hash)
                return ht_->t[bucket + i].entry.value;
        }
        union rte_fbk_hash_entry ne;
        ne.whole_entry = ((uint64_t)hash << 32) |
                         ((uint64_t)hash_table_[hash % kSize] << 16) | 1ULL;
        uint32_t eid = ((ht_->t[bucket].entry.is_entry >> 1) + 1) & (kEntriesPerBucket - 1);
        ht_->t[bucket + eid].whole_entry = ne.whole_entry;
        ht_->t[bucket].entry.is_entry = ((uint16_t)eid << 1) | 1;
        return ne.entry.value;
    }

private:
    static constexpr uint32_t kSize = 65537;  // prime
    static constexpr uint32_t kEntriesPerBucket = 4;

    void generate_permutations(const std::vector<std::pair<uint32_t, uint32_t>> &seed) {
        std::vector<uint32_t> off(nb_backends_), skip(nb_backends_);
        for (uint32_t i = 0; i < nb_backends_; ++i) {
            off[i] = seed[i].first % kSize;
            skip[i] = (seed[i].second % (kSize - 1)) + 1;
        }
        for (uint32_t i = 0; i < nb_backends_; ++i)
            for (uint32_t j = 0; j < kSize; ++j)
                permutations_[i][j] = (off[i] + j * skip[i]) % kSize;
    }
    void populate() {
        std::vector<uint32_t> next(nb_backends_, 0);
        uint32_t n = 0;
        while (true) {
            for (uint32_t i = 0; i < nb_backends_; ++i) {
                uint32_t c = permutations_[i][next[i]];
                while (hash_table_[c] != 0xffff) c = permutations_[i][++next[i]];
                hash_table_[c] = i;
                ++next[i];
                if (++n == kSize) return;
            }
        }
    }

    const uint32_t nb_backends_;
    std::array<uint16_t, kSize> hash_table_;
    std::vector<std::array<uint32_t, kSize>> permutations_;
    struct rte_fbk_hash_table *ht_ = nullptr;
};

static __thread MaglevTable *g_tbl = nullptr;
#if defined(NF_IPV6)
static __thread uint8_t (*g_bk6)[16] = nullptr;  // backend IPv6 addresses
#else
static __thread uint32_t *g_bk4 = nullptr;        // backend IPv4 addresses (be32)
#endif

void nf_setup(void) {
    g_tbl = new MaglevTable(NF_NB_BACKENDS);
    std::vector<std::pair<uint32_t, uint32_t>> seed(NF_NB_BACKENDS);

#if defined(NF_IPV6)
    g_bk6 = (uint8_t (*)[16])rte_malloc("bk6", NF_NB_BACKENDS * 16, 0);
    uint8_t base[16] = {0xfd,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1};
    for (uint32_t i = 0; i < NF_NB_BACKENDS; ++i) {
        memcpy(g_bk6[i], base, 16);
        uint32_t *low = (uint32_t *)&g_bk6[i][12];
        *low = rte_cpu_to_be_32(rte_be_to_cpu_32(*low) + i);
        uint32_t h1 = 0, h2 = 1;
        rte_jhash_32b_2hashes((const uint32_t *)g_bk6[i], 4, &h1, &h2);
        seed[i] = {h1, h2};
    }
#else
    g_bk4 = (uint32_t *)rte_malloc("bk4", NF_NB_BACKENDS * sizeof(uint32_t), 0);
    uint32_t base = RTE_IPV4(10, 0, 0, 1);
    for (uint32_t i = 0; i < NF_NB_BACKENDS; ++i) {
        g_bk4[i] = rte_cpu_to_be_32(base + i);
        uint32_t h1 = 0, h2 = 1;
        rte_jhash_32b_2hashes(&g_bk4[i], 1, &h1, &h2);
        seed[i] = {h1, h2};
    }
#endif
    if (g_tbl->setup(seed))
        rte_exit(EXIT_FAILURE, "maglev setup failed\n");
}

static __rte_always_inline void nf_app(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
#if defined(NF_IPV6)
    struct rte_ipv6_hdr *iph = (struct rte_ipv6_hdr *)(eth + 1);
    /* src/dst port share offsets in UDP and TCP: one cast covers both. */
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(iph + 1);
    const uint32_t l4 = ((uint32_t)udp->src_port << 16) | udp->dst_port;
    /* src_addr and dst_addr are adjacent: hash the 32 address bytes at once. */
    uint32_t h = rte_jhash(iph->src_addr, 32, 0) ^ l4 ^ (uint32_t)iph->proto;
    uint16_t b = g_tbl->pick(h);
    rte_memcpy(iph->dst_addr, g_bk6[b], 16);  // rewrite destination IP -> backend
#else
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(eth + 1);
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(iph + 1);
    const uint32_t l4 = ((uint32_t)udp->src_port << 16) | udp->dst_port;
    uint32_t h = rte_jhash_3words(iph->src_addr, iph->dst_addr,
                                  l4 ^ (uint32_t)iph->next_proto_id, 0);
    uint16_t b = g_tbl->pick(h);
    iph->dst_addr = g_bk4[b];                 // rewrite destination IP -> backend
#endif
}

#include "nf_main.h"
