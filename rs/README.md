# APEC Developer Demo — Network Function Library (Rust, raw sockets)

Rust port of the four C/DPDK network functions in the parent directory
(see [`../README.md`](../README.md)): the same NF logic and the same
run-to-completion runtime shape, but running over **AF_PACKET raw sockets**
instead of DPDK — the plain-userspace executor, with no kernel-bypass
dependencies.

## Layout

| Crate | Mirrors | Contents |
|---|---|---|
| [`nf-runtime`](nf-runtime/) | `common/nf_main.h` | the `Nf` trait + generic `run()` loop (RX → MAC-swap → `Nf::app` → TX), AF_PACKET plumbing, header views, `rte_jhash` port |
| [`l3fwd`](l3fwd/) | `l3fwd/l3fwd.cpp` | LPM on destination IP → next hop, rewrite destination MAC |
| [`acl`](acl/) | `acl/acl.cpp` | ordered rule set, linear first-match, permit/deny counters |
| [`maglev`](maglev/) | `maglev/maglev.cpp` | Maglev consistent hashing → backend, rewrite destination IP |
| [`nat`](nat/) | `nat/nat.cpp` | stateless source-NAT over an address/port pool, rewrite source IP + L4 port |

## How the runtime maps to the DPDK original

- **Sockets instead of queues.** Each worker thread owns one raw packet
  socket (`socket2` creates it; `libc` supplies the AF_PACKET-specific
  options). All sockets join one `PACKET_FANOUT_HASH` group, so the kernel
  spreads flows across workers by 5-tuple hash — the raw-socket equivalent
  of the RSS multi-queue setup.
- **Bursts survive.** The loop uses `recvmmsg`/`sendmmsg` with the same
  burst size (32) as the C runtime's `rte_eth_rx_burst`/`tx_burst`.
- **Same NF interface.** `Nf::setup()` builds per-worker state on the worker
  thread (as `nf_setup()` did per lcore), `Nf::app()` gets a raw pointer to
  the frame and rewrites headers in place. `run::<N>()` is generic, so the
  per-packet call inlines into the loop like the C single-translation-unit
  build.
- **Sockets are promiscuous** and set `PACKET_IGNORE_OUTGOING` (kernel
  ≥ 4.20) — without it, every transmitted frame would be received again and
  the MAC-swap forwarding would loop forever. For the same reason, don't run
  the NFs on `lo`.
- Unlike DPDK there is no zero-copy: every frame crosses the kernel/user
  boundary twice. That is the point of this executor — it is the baseline
  the accelerated layers are compared against.

## NF-logic notes (unchanged from the DPDK port)

- `rte_jhash` is ported bit-exactly (unit-tested against values computed
  with the DPDK headers), so flow→pool/backend mappings match the C NFs.
- `rte_lpm` is replaced by a Rust DIR-24-8 table with the same lookup cost;
  `rte_lpm6` by a deepest-first linear match (equivalent at this demo's 17
  routes). The maglev table is verified slot-for-slot against the C++
  implementation, including its connection cache (same crc32c bucket
  function as the `rte_fbk_hash` it replaces).
- `acl` prints its per-worker permit/deny counters at shutdown (the C
  version only keeps them in memory).
- IPv6 variants are a cargo feature instead of a `-DNF_IPV6` rebuild, and
  replace the IPv4 binary in `target/` rather than getting a `_v6` suffix.

## Building

Requirements: Linux and Rust (stable). No DPDK needed.

```bash
cargo build --release                          # all four NFs (IPv4)
cargo build --release -p nat                   # one NF
cargo build --release -p nat --features ipv6   # IPv6 variant (same binary name)
cargo test                                     # hash/LPM/maglev/NF parity tests
```

Binaries land in `target/release/{l3fwd,acl,maglev,nat}`.

## Running

`<NF> <IFACE> [NB_WORKERS]` — needs `CAP_NET_RAW` (root, or a user netns):

```bash
# example: NAT with 2 workers on enp1s0
sudo ./target/release/nat enp1s0 2

# l3fwd on a switched testbed: point the next hop at a known MAC
sudo NF_NEXTHOP_MAC=aa:bb:cc:dd:ee:ff ./target/release/l3fwd enp1s0 1

# smoke test without hardware or privileges: veth pair in a user netns
unshare -r -n bash -c '
  ip link add nfva type veth peer name nfvb
  ip link set nfva up; ip link set nfvb up
  ./target/release/nat nfva 1 &
  # inject frames on nfvb, then: kill -INT %1
'
```

MAC-swap forwarding and the `PORT_STATS` summary on exit work as in the C
demo. The NFs expect plain `eth / IPv4|IPv6 / UDP|TCP` frames (no VLAN or IP
options: headers sit at fixed offsets), and `l3fwd` floods switched networks
unless `NF_NEXTHOP_MAC` is set — see the notes in
[`../README.md`](../README.md).

## License

[Apache License 2.0](../LICENSE).
