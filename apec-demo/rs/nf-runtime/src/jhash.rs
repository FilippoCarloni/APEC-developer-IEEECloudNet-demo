//! Port of DPDK's `rte_jhash.h` (Bob Jenkins' lookup3), bit-exact with the
//! C functions on little-endian targets — verified against values computed
//! with the DPDK headers (see the tests below).
//!
//! Only the variants the NFs use are ported: `rte_jhash` over bytes,
//! `rte_jhash_3words`, and `rte_jhash_32b_2hashes` (as `jhash_2hashes`).

const GOLDEN_RATIO: u32 = 0xdeadbeef;

#[inline(always)]
fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c); *a ^= c.rotate_left(4);  *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a); *b ^= a.rotate_left(6);  *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b); *c ^= b.rotate_left(8);  *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c); *a ^= c.rotate_left(16); *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a); *b ^= a.rotate_left(19); *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b); *c ^= b.rotate_left(4);  *b = b.wrapping_add(*a);
}

#[inline(always)]
fn final_mix(mut a: u32, mut b: u32, mut c: u32) -> (u32, u32) {
    c ^= b; c = c.wrapping_sub(b.rotate_left(14));
    a ^= c; a = a.wrapping_sub(c.rotate_left(11));
    b ^= a; b = b.wrapping_sub(a.rotate_left(25));
    c ^= b; c = c.wrapping_sub(b.rotate_left(16));
    a ^= c; a = a.wrapping_sub(c.rotate_left(4));
    b ^= a; b = b.wrapping_sub(a.rotate_left(14));
    c ^= b; c = c.wrapping_sub(b.rotate_left(24));
    (c, b)
}

#[inline(always)]
fn word(k: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([k[i], k[i + 1], k[i + 2], k[i + 3]])
}

/// `rte_jhash_2hashes` / `rte_jhash_32b_2hashes`: `pc`/`pb` are seeds in,
/// primary/secondary hash out.
///
/// The C tail cases mask the last partial word (`LOWERxb_MASK`); reading the
/// tail through a zero-padded 12-byte block produces the identical sums
/// without the C version's read-past-the-key.
pub fn jhash_2hashes(key: &[u8], pc: &mut u32, pb: &mut u32) {
    let mut len = key.len();
    let init = GOLDEN_RATIO.wrapping_add(key.len() as u32).wrapping_add(*pc);
    let (mut a, mut b) = (init, init);
    let mut c = init.wrapping_add(*pb);

    let mut k: &[u8] = key;
    while len > 12 {
        a = a.wrapping_add(word(k, 0));
        b = b.wrapping_add(word(k, 4));
        c = c.wrapping_add(word(k, 8));
        mix(&mut a, &mut b, &mut c);
        k = &k[12..];
        len -= 12;
    }

    if len == 0 {
        *pc = c;
        *pb = b;
        return;
    }

    let mut tail = [0u8; 12];
    tail[..len].copy_from_slice(&k[..len]);
    a = a.wrapping_add(word(&tail, 0));
    b = b.wrapping_add(word(&tail, 4));
    c = c.wrapping_add(word(&tail, 8));

    let (rc, rb) = final_mix(a, b, c);
    *pc = rc;
    *pb = rb;
}

/// `rte_jhash`: hash an arbitrary byte sequence.
#[inline(always)]
pub fn jhash(key: &[u8], initval: u32) -> u32 {
    let mut pc = initval;
    let mut pb = 0u32;
    jhash_2hashes(key, &mut pc, &mut pb);
    pc
}

/// `rte_jhash_3words`: optimized 3-word (12-byte) hash.
#[inline(always)]
pub fn jhash_3words(a: u32, b: u32, c: u32, initval: u32) -> u32 {
    let a = a.wrapping_add(12).wrapping_add(GOLDEN_RATIO).wrapping_add(initval);
    let b = b.wrapping_add(12).wrapping_add(GOLDEN_RATIO).wrapping_add(initval);
    let c = c.wrapping_add(12).wrapping_add(GOLDEN_RATIO).wrapping_add(initval);
    final_mix(a, b, c).0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected values computed with DPDK 24.11's rte_jhash.h on x86-64
    // (scratch program compiled against the installed headers).
    #[test]
    fn matches_rte_jhash_bytes() {
        let k32: Vec<u8> = (0..32u32).map(|i| (i * 7 + 3) as u8).collect();
        assert_eq!(jhash(&k32, 0), 0x89490b4a);
        assert_eq!(jhash(&k32, 0xabcd1234), 0xcabc2481);
        assert_eq!(jhash(&[1, 2, 3, 4, 5], 0), 0xf85554a4);
        assert_eq!(jhash(&[9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 255, 254], 77), 0xd800108c);
        assert_eq!(jhash(&[], 42), 0xdeadbf19);
    }

    #[test]
    fn matches_rte_jhash_3words() {
        assert_eq!(jhash_3words(0x0a000001, 0x0a000002, 0x12345678, 0), 0x5934720e);
        assert_eq!(jhash_3words(0, 0, 0, 0), 0x1b68e557);
    }

    #[test]
    fn matches_rte_jhash_32b_2hashes() {
        // be32(10.0.0.1) as stored in memory on a little-endian machine.
        let (mut h1, mut h2) = (0u32, 1u32);
        jhash_2hashes(&0x0100000au32.to_le_bytes(), &mut h1, &mut h2);
        assert_eq!((h1, h2), (0x119b72c4, 0xb5da3f7e));

        let mut k = [0u8; 16];
        k[..4].copy_from_slice(&0x20010db8u32.to_le_bytes());
        k[12..].copy_from_slice(&0x01000000u32.to_le_bytes());
        let (mut h1, mut h2) = (0u32, 1u32);
        jhash_2hashes(&k, &mut h1, &mut h2);
        assert_eq!((h1, h2), (0x5c658675, 0x4d645048));
    }
}
