#!/usr/bin/env bash
set -euo pipefail
HOST_IF=${HOST_IF:-veth-host}
ip link set dev "$HOST_IF" xdpgeneric off 2>/dev/null || true
ip link set dev "$HOST_IF" xdp off 2>/dev/null || true
echo "detached XDP from $HOST_IF"
