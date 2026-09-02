#pragma once

#include <linux/types.h>
#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))

static long (*bpf_xdp_adjust_head)(struct xdp_md *ctx, int delta) =
	(void *)BPF_FUNC_xdp_adjust_head;
static long (*bpf_xdp_adjust_meta)(struct xdp_md *ctx, int delta) =
	(void *)BPF_FUNC_xdp_adjust_meta;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#else
#define bpf_htons(x) (x)
#define bpf_htonl(x) (x)
#endif
