# APEC Developer Demo — Network Function Library

Reference implementations of the four network functions (NFs) used in the
**APEC developer-workflow demonstration** (see [`DEMO.md`](DEMO.md)).

Each NF is a small, self-contained DPDK application in the usual optimized
style: the per-packet logic (`nf_app()`) reads and rewrites header fields in
place through zero-copy pointer casts, and `common/nf_main.h` provides the
shared run-to-completion runtime (`main()`, RSS, per-lcore workers, MAC-swap
forwarding).

## The NFs

| NF | Fields read | Logic | Packet rewrite |
|---|---|---|---|
| [`l3fwd`](l3fwd/) | destination IP | longest-prefix match → next hop | destination MAC |
| [`acl`](acl/) | 5-tuple | ordered rule set, linear first-match | none (permit/deny counters) |
| [`maglev`](maglev/) | 5-tuple | Maglev consistent hashing (NSDI '16) → backend | destination IP |
| [`nat`](nat/) | 5-tuple | stateless source-NAT over an address/port pool | source IP + L4 port |

All four support IPv4 (default) and IPv6 (`L3=ipv6`, 128-bit addresses).

## Building

Requirements: Linux, a C++11 compiler, and DPDK ≥ 22.11 discoverable via
`pkg-config libdpdk`.

```bash
make            # builds all four NFs (IPv4)
make -C nat     # build one NF
make -C nat L3=ipv6   # IPv6 variant -> nat/nat_v6
```

## Running

Each binary is a standard DPDK application: one RX/TX queue pair per lcore
(RSS), MAC-swap forwarding back to the sender, and a `PORT_STATS` summary on
exit.

```bash
# example: NAT on 2 cores, one NIC port
sudo ./nat/nat -l 0-1 -a <PCI_ADDR>

# l3fwd on a switched testbed: point the next hop at a known MAC
sudo NF_NEXTHOP_MAC=aa:bb:cc:dd:ee:ff ./l3fwd/l3fwd -l 0 -a <PCI_ADDR>
```

Traffic can be generated with [TRex](https://trex-tgn.cisco.com) or any
line-rate generator on a back-to-back link. The NFs expect plain
`eth / IPv4|IPv6 / UDP|TCP` frames (no VLAN or IP options: headers sit at
fixed offsets).

> **Note (l3fwd):** without `NF_NEXTHOP_MAC`, frames are forwarded to
> fabricated locally administered MACs; on a switched network this causes
> unknown-unicast flooding. Use a back-to-back link or set the variable.

## License

[MIT License](LICENSE).
