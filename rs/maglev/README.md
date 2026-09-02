# maglev — XDP five-tuple prefix PoC

A proof-of-concept that moves packet parsing out of userspace. XDP intercepts VIP traffic, extracts the 5‑tuple once, and slaps a 16‑byte metadata label in front of the frame. The Rust load balancer on the other side gets a zero‑copy, typed read—no parsing Ethernet/IP/TCP headers ever again.

```
[PACKET] -> XDP (prepend meta) -> AF_PACKET -> Rust LB
```

It’s **selective**: only IPv4 TCP/UDP headed to `10.0.1.100` gets the treatment. ARP, SSH, ICMP (ping!) pass through untouched, so your SSH session stays alive.

---

The kernel and userspace share a strict 16‑byte layout (`struct flow_meta` in C, `FlowMeta` in Rust). Network byte order, no padding, enforced by static asserts on both sides. The first byte is a **magic marker**—if userspace doesn’t see it, the frame is ignored as “no_meta”.

---

## Project layout (short version)

- `bpf/` – XDP program (`flow_prefix.bpf.c`)
- `src/` – Rust receiver, Maglev table, checksum fixes, flow structs
- `examples/tui/` – live dashboard (twin of the original C `maglev_tui.c`)
- `scripts/` – setup, attach, teardown, and a full demo
- `benches/` – microbenchmarks comparing typed read vs. full header parse

---

## Quick start

```bash
cargo build --release --examples
./scripts/build_bpf.sh        # compiles bpf/build/flow_prefix.bpf.o
sudo ./scripts/demo.sh        # spins up netns, attaches XDP, fires traffic
sudo ./scripts/teardown.sh    # clean up
```

If you prefer to run piecewise:

```bash
sudo ./scripts/setup.sh
sudo ./scripts/attach.sh prefix generic

# Terminal 1: Receiver
sudo target/release/maglev -i veth-host

# Terminal 2: Sender (client netns)
sudo ip netns exec maglev-client target/release/examples/sender --dest 10.0.1.100 --flows 64 --count 200000

# Terminal 3: Live dashboard
sudo target/release/examples/tui -i veth-host
```

Want to see the internal `[meta | frame]` format?  
`sudo tcpdump -XX -i veth-host -Q in 'ether[0] = 0xa5'`

---


## Limitations & next steps

- **IPv4 only**: VLANs, tunnels, and fragments slip through unprefixed.
- **Tap, not redirect**: the receiver rewrites `daddr` and checksums in its own copy, but the kernel still sees and drops the original. No real TX to backends.
- **VIP is hardcoded**: in the BPF object (`VIP_HOST=0x0a000164`). A production version would use a BPF map.

**What’s next?** Swap `bpf_xdp_adjust_head` for `bpf_xdp_adjust_meta`, and AF_PACKET for AF_XDP. The same `[meta | frame]` layout and the same `FlowMeta` contract fit perfectly into the umem—just zero syscalls and a pristine original frame. That’s the real target.