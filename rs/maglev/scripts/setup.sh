#!/usr/bin/env bash
# Create the veth topology:
#   [netns maglev-client] veth-client 10.0.0.2/24 <--> veth-host 10.0.0.1/24 [root ns]
# The client routes the VIP subnet 10.0.1.0/24 via 10.0.0.1.
set -euo pipefail
NS=${NS:-maglev-client}
HOST_IF=${HOST_IF:-veth-host}
CLIENT_IF=${CLIENT_IF:-veth-client}

ip netns add "$NS"
ip link add "$HOST_IF" type veth peer name "$CLIENT_IF" netns "$NS"
ip addr add 10.0.0.1/24 dev "$HOST_IF"
ip link set "$HOST_IF" up
ip -n "$NS" addr add 10.0.0.2/24 dev "$CLIENT_IF"
ip -n "$NS" link set "$CLIENT_IF" up
ip -n "$NS" link set lo up
ip -n "$NS" route add 10.0.1.0/24 via 10.0.0.1

# Predictable frames: no merged super-packets, checksums computed in software.
for k in gro gso tso tx rx; do
    ethtool -K "$HOST_IF" "$k" off >/dev/null 2>&1 || true
    ip netns exec "$NS" ethtool -K "$CLIENT_IF" "$k" off >/dev/null 2>&1 || true
done
# Less noise on the packet tap.
sysctl -qw "net.ipv6.conf.$HOST_IF.disable_ipv6=1" 2>/dev/null || true
ip netns exec "$NS" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true

echo "setup done: [$NS] $CLIENT_IF 10.0.0.2 <-> $HOST_IF 10.0.0.1 (VIP route 10.0.1.0/24)"
