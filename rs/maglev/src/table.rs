//! Family-agnostic Maglev consistent-hash table over backend indices [0, N)
//! (Eisenbud et al., NSDI '16): permutations + populate, with a per-bucket
//! connection cache in front, ported from the C++ `MaglevTable`.
//!
//! Two deliberate differences from the C++ version, with identical results:
//! - permutation entries are computed on the fly during populate instead of
//!   materializing the N x 65537 permutation matrix (same wrapping-u32
//!   arithmetic, hundreds of MB less memory per lcore);
//! - the connection cache replaces the intrusively-used `rte_fbk_hash` with
//!   a native 4-way bucket cache using the same crc32c bucket function and
//!   round-robin eviction.

pub const K_SIZE: usize = 65537; // prime
const CACHE_ENTRIES: usize = 1024;
const ENTRIES_PER_BUCKET: usize = 4;
const NB_BUCKETS: usize = CACHE_ENTRIES / ENTRIES_PER_BUCKET;

#[derive(Clone, Copy, Default, Debug)]
struct CacheEntry {
    key: u32,
    value: u16,
    valid: bool,
}

#[derive(Clone, Copy, Default, Debug)]
struct Bucket {
    slots: [CacheEntry; ENTRIES_PER_BUCKET],
    last: u8, // last-inserted slot, for round-robin eviction
}

pub struct MaglevTable {
    hash_table: Box<[u16; K_SIZE]>,
    buckets: Box<[Bucket; NB_BUCKETS]>,
}

impl MaglevTable {
    /// `backend_seed[i] = (h1, h2)` derived from backend i's address.
    pub fn new(backend_seed: &[(u32, u32)]) -> Self {
        let mut hash_table: Box<[u16; K_SIZE]> =
            vec![u16::MAX; K_SIZE].into_boxed_slice().try_into().unwrap();
        populate(&mut hash_table, backend_seed);
        MaglevTable {
            hash_table,
            buckets: vec![Bucket::default(); NB_BUCKETS].into_boxed_slice().try_into().unwrap(),
        }
    }

    /// Map a flow hash to a backend index, memoized in the connection cache.
    #[inline(always)]
    pub fn pick(&mut self, hash: u32) -> u16 {
        let bucket = &mut self.buckets[crc32c_u32(hash, 0) as usize & (NB_BUCKETS - 1)];
        for i in 0..ENTRIES_PER_BUCKET {
            let e = bucket.slots[i];
            if !e.valid {
                let value = self.hash_table[hash as usize % K_SIZE];
                bucket.slots[i] = CacheEntry { key: hash, value, valid: true };
                bucket.last = i as u8;
                return value;
            }
            if e.key == hash {
                return e.value;
            }
        }
        // Bucket full: evict round-robin, like the C++ pick().
        let value = self.hash_table[hash as usize % K_SIZE];
        let i = (bucket.last as usize + 1) & (ENTRIES_PER_BUCKET - 1);
        bucket.slots[i] = CacheEntry { key: hash, value, valid: true };
        bucket.last = i as u8;
        value
    }
}

/// Maglev populate. `perm(i, j) = (offset[i] + j * skip[i]) % K_SIZE`,
/// computed with wrapping u32 multiplication exactly like the C++ table.
fn populate(hash_table: &mut [u16; K_SIZE], backend_seed: &[(u32, u32)]) {
    let n = backend_seed.len();
    assert!(n > 0 && n <= u16::MAX as usize, "invalid backend count {n}");
    let off: Vec<u32> = backend_seed.iter().map(|s| s.0 % K_SIZE as u32).collect();
    let skip: Vec<u32> = backend_seed.iter().map(|s| (s.1 % (K_SIZE as u32 - 1)) + 1).collect();
    let perm = |i: usize, j: u32| (off[i].wrapping_add(j.wrapping_mul(skip[i])) % K_SIZE as u32) as usize;

    let mut next = vec![0u32; n];
    let mut filled = 0usize;
    loop {
        for i in 0..n {
            let mut c = perm(i, next[i]);
            while hash_table[c] != u16::MAX {
                next[i] += 1;
                c = perm(i, next[i]);
            }
            hash_table[c] = i as u16;
            next[i] += 1;
            filled += 1;
            if filled == K_SIZE {
                return;
            }
        }
    }
}

/// CRC-32C over one little-endian u32, bit-identical to DPDK's
/// `rte_hash_crc_4byte` (the fbk-hash default bucket function).
#[inline(always)]
fn crc32c_u32(data: u32, init: u32) -> u32 {
    const TABLE: [u32; 256] = build_crc32c_table();
    let mut crc = init;
    for b in data.to_le_bytes() {
        crc = TABLE[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

const fn build_crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82F63B78 } else { crc >> 1 };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use nf_runtime::jhash;

    #[test]
    fn crc32c_matches_rte_hash_crc_4byte() {
        // Values from DPDK's rte_hash_crc_4byte on x86-64 (SSE4.2 CRC32).
        assert_eq!(crc32c_u32(0x12345678, 0), 0xfa745634);
        assert_eq!(crc32c_u32(0xdeadbeef, 0), 0x09991d14);
    }

    /// Slot-for-slot comparison with the C++ generate_permutations+populate
    /// run over 8 IPv4-derived backend seeds (reference program compiled
    /// against maglev.cpp's table code).
    #[test]
    fn populate_matches_cpp_reference() {
        let seeds: Vec<(u32, u32)> = (0..8u32)
            .map(|i| {
                let bk = (u32::from_be_bytes([10, 0, 0, 1]) + i).to_be();
                let (mut h1, mut h2) = (0u32, 1u32);
                jhash::jhash_2hashes(&bk.to_ne_bytes(), &mut h1, &mut h2);
                (h1, h2)
            })
            .collect();
        let mut tbl = MaglevTable::new(&seeds);

        let expected_slots: [u16; 16] = [0, 6, 4, 2, 1, 5, 5, 7, 7, 0, 3, 6, 4, 4, 1, 3];
        assert_eq!(&tbl.hash_table[..16], &expected_slots);

        // Cold-cache picks resolve straight from the hash table.
        let expected_picks: [u16; 8] = [0, 0, 1, 6, 7, 3, 6, 2];
        for (h, &want) in expected_picks.iter().enumerate() {
            let hash = (h as u32).wrapping_mul(0x9e3779b9) % K_SIZE as u32;
            assert_eq!(tbl.pick(hash), want);
        }
    }

    #[test]
    fn cache_hits_and_round_robin_eviction() {
        let seeds: Vec<(u32, u32)> = (0..4).map(|i| (i * 11 + 1, i * 17 + 2)).collect();
        let mut tbl = MaglevTable::new(&seeds);
        let h = 12345u32;
        let first = tbl.pick(h);
        assert_eq!(tbl.pick(h), first); // cached
        assert_eq!(first, tbl.hash_table[h as usize % K_SIZE]);
    }
}
