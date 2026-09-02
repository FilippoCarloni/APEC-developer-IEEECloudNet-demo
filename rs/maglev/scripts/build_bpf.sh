#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bpf/build
VIP_HOST=${VIP_HOST:-0x0a000164} # 10.0.1.100
clang -O2 -g -Wall -target bpf -DVIP_HOST="$VIP_HOST" \
    -c bpf/flow_prefix.bpf.c -o bpf/build/flow_prefix.bpf.o
clang -O2 -g -Wall -target bpf -DVIP_HOST="$VIP_HOST" -DPASSTHROUGH \
    -c bpf/flow_prefix.bpf.c -o bpf/build/flow_pass.bpf.o
echo "built bpf/build/flow_prefix.bpf.o (prefixer) and bpf/build/flow_pass.bpf.o (parse-only passthrough)"
