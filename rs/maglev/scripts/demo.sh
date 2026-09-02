#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "$(id -u)" -ne 0 ]; then
    echo "demo.sh must run as root (netns + XDP + AF_PACKET)" >&2
    exit 1
fi

NS=${NS:-maglev-client}
HOST_IF=${HOST_IF:-veth-host}
VIP=${VIP:-10.0.1.100}
COUNT=${COUNT:-200000}
FLOWS=${FLOWS:-64}

[ -x target/release/maglev ] || cargo build --release
[ -x target/release/examples/sender ] || cargo build --release --examples
[ -f bpf/build/flow_prefix.bpf.o ] || scripts/build_bpf.sh

scripts/teardown.sh >/dev/null 2>&1 || true
scripts/setup.sh
scripts/attach.sh prefix generic

echo
echo "== 1. control path still works: ping straight through the XDP program =="
ip netns exec "$NS" ping -c 2 -i 0.3 10.0.0.1

echo
echo "== 2. wire proof of the internal format (frames whose first byte = 0xa5 magic) =="
LOG=$(mktemp)
PCAPLOG=$(mktemp)
TCPDUMP=""
if command -v tcpdump >/dev/null 2>&1; then
    timeout 15 tcpdump -c 2 -XX -i "$HOST_IF" -Q in "ether[0] = 0xa5" >"$PCAPLOG" 2>/dev/null &
    TCPDUMP=$!
    sleep 0.5
else
    echo "(tcpdump not installed, skipping)"
fi

echo
echo "== 3. receiver (typed fast path) + sender: $COUNT UDP packets, $FLOWS flows -> $VIP =="
target/release/maglev -i "$HOST_IF" >"$LOG" 2>&1 &
RECV=$!
sleep 0.7
ip netns exec "$NS" target/release/examples/sender --dest "$VIP" --flows "$FLOWS" --count "$COUNT"
sleep 1.5
kill -INT "$RECV" 2>/dev/null || true
wait "$RECV" 2>/dev/null || true
if [ -n "$TCPDUMP" ]; then
    wait "$TCPDUMP" 2>/dev/null || true
fi

echo
echo "---- receiver output ----"
cat "$LOG"
if [ -n "$TCPDUMP" ] && [ -s "$PCAPLOG" ]; then
    echo
    echo "---- tcpdump: the prefixed frames as the wire tap sees them ----"
    head -n 30 "$PCAPLOG"
fi
rm -f "$LOG" "$PCAPLOG"

echo
echo "environment left up; scripts/teardown.sh removes it"
