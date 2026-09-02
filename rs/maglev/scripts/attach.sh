#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
VARIANT=${1:-prefix}
MODE=${2:-generic}
HOST_IF=${HOST_IF:-veth-host}

case "$VARIANT" in
prefix) OBJ=bpf/build/flow_prefix.bpf.o ;;
pass) OBJ=bpf/build/flow_pass.bpf.o ;;
*)
    echo "variant must be prefix|pass" >&2
    exit 1
    ;;
esac
case "$MODE" in
generic) FLAG=xdpgeneric ;;
native) FLAG=xdp ;;
*)
    echo "mode must be generic|native" >&2
    exit 1
    ;;
esac
[ -f "$OBJ" ] || scripts/build_bpf.sh

ip link set dev "$HOST_IF" xdpgeneric off 2>/dev/null || true
ip link set dev "$HOST_IF" xdp off 2>/dev/null || true
ip link set dev "$HOST_IF" "$FLAG" obj "$OBJ" sec xdp
echo "attached $OBJ to $HOST_IF ($FLAG)"
