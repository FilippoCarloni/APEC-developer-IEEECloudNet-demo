/*
 * Shared DPDK run-to-completion runtime for all NFs.
 *
 * Include LAST from an NF translation unit, after it has defined nf_setup
 * and nf_app. Provides main(): EAL init, mempool, RSS port setup, one worker
 * per lcore that runs nf_setup() and then the RX -> nf_app -> TX loop, and
 * an end-of-run PORT_STATS line.
 */
#ifndef NF_MAIN_H
#define NF_MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#ifndef NF_RX_RING_SIZE
#define NF_RX_RING_SIZE 512
#endif
#ifndef NF_TX_RING_SIZE
#define NF_TX_RING_SIZE 512
#endif
#define NF_MBUF_CACHE_SIZE 250
#define NF_BURST_SIZE 32

/* Swap src/dst MACs so frames flow back to the generator on a back-to-back
 * or switched loopback link. */
static __rte_always_inline void nf_macswap(struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ether_addr tmp;
    rte_ether_addr_copy(&eth->dst_addr, &tmp);
    rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
    rte_ether_addr_copy(&tmp, &eth->src_addr);
}

static __rte_always_inline void nf_process(struct rte_mbuf *m)
{
    nf_macswap(m);
    nf_app(m);
}

static volatile bool nf_force_quit;
static void nf_signal_handler(int signum) { (void)signum; nf_force_quit = true; }

static int nf_lcore_main(__rte_unused void *arg)
{
    const uint16_t port = 0;
    const uint16_t queue_id = (uint16_t)rte_lcore_index(rte_lcore_id());
    struct rte_mbuf *pkts[NF_BURST_SIZE];
    uint64_t pkts_processed = 0;

    pid_t tid = (pid_t)syscall(SYS_gettid);
    printf("NF running on lcore %u (queue %u) (TID=%d)\n",
           rte_lcore_id(), queue_id, tid);

    /* Per-lcore NF state (hash tables, rule sets, ...). */
    nf_setup();

    while (!nf_force_quit) {
        const uint16_t nb_rx = rte_eth_rx_burst(port, queue_id, pkts, NF_BURST_SIZE);
        if (unlikely(nb_rx == 0)) continue;

        for (uint16_t i = 0; i < nb_rx; i++)
            nf_process(pkts[i]);

        pkts_processed += nb_rx;

        const uint16_t nb_tx = rte_eth_tx_burst(port, queue_id, pkts, nb_rx);
        if (unlikely(nb_tx < nb_rx)) {
            for (uint16_t b = nb_tx; b < nb_rx; b++)
                rte_pktmbuf_free(pkts[b]);
        }
    }

    printf("LCORE %u (TID=%d): pkts_processed=%lu\n",
           rte_lcore_id(), tid, (unsigned long)pkts_processed);
    return 0;
}

static int nf_port_init(uint16_t port, struct rte_mempool *pool, uint16_t nb_queues)
{
    struct rte_eth_dev_info dev_info;
    if (rte_eth_dev_info_get(port, &dev_info) < 0) return -1;

    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.mq_mode = (nb_queues > 1) ? RTE_ETH_MQ_RX_RSS : RTE_ETH_MQ_RX_NONE;
    port_conf.rxmode.offloads = 0;
    port_conf.txmode.mq_mode  = RTE_ETH_MQ_TX_NONE;
    port_conf.txmode.offloads = 0;
    port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
    port_conf.rx_adv_conf.rss_conf.rss_hf =
        (RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP) &
        dev_info.flow_type_rss_offloads;

    if (rte_eth_dev_configure(port, nb_queues, nb_queues, &port_conf) < 0) return -1;

    for (uint16_t q = 0; q < nb_queues; q++) {
        if (rte_eth_rx_queue_setup(port, q, NF_RX_RING_SIZE,
                                   rte_eth_dev_socket_id(port), NULL, pool) < 0)
            return -1;
        if (rte_eth_tx_queue_setup(port, q, NF_TX_RING_SIZE,
                                   rte_eth_dev_socket_id(port), NULL) < 0)
            return -1;
    }

    if (rte_eth_dev_start(port) < 0) return -1;
    rte_eth_promiscuous_enable(port);
    return 0;
}

int main(int argc, char *argv[])
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");

    signal(SIGINT, nf_signal_handler);
    signal(SIGTERM, nf_signal_handler);

    const uint16_t port = 0;
    unsigned nb_lcores = rte_lcore_count();
    printf("NF starting on %u lcore(s)/queue(s)\n", nb_lcores);

    struct rte_mempool *pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", 8192 * nb_lcores, NF_MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (pool == NULL) rte_exit(EXIT_FAILURE, "mempool create failed\n");

    if (nf_port_init(port, pool, (uint16_t)nb_lcores) < 0)
        rte_exit(EXIT_FAILURE, "port init failed\n");

    rte_eal_mp_remote_launch(nf_lcore_main, NULL, CALL_MAIN);

    unsigned lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id)
        rte_eal_wait_lcore(lcore_id);

    struct rte_eth_stats stats;
    if (rte_eth_stats_get(port, &stats) == 0) {
        uint64_t offered = stats.ipackets + stats.imissed;
        double drop_pct = offered ? (100.0 * (double)stats.imissed / (double)offered) : 0.0;
        printf("PORT_STATS: ipackets=%lu imissed=%lu ierrors=%lu opackets=%lu oerrors=%lu drop_pct=%.4f\n",
               (unsigned long)stats.ipackets, (unsigned long)stats.imissed,
               (unsigned long)stats.ierrors, (unsigned long)stats.opackets,
               (unsigned long)stats.oerrors, drop_pct);
    }

    rte_eth_dev_stop(port);
    rte_eth_dev_close(port);
    printf("NF terminated.\n");
    return 0;
}

#endif /* NF_MAIN_H */
