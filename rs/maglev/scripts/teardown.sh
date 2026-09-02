#!/usr/bin/env bash
NS=${NS:-maglev-client}
HOST_IF=${HOST_IF:-veth-host}
ip netns del "$NS" 2>/dev/null || true
ip link del "$HOST_IF" 2>/dev/null || true
echo "teardown done"
