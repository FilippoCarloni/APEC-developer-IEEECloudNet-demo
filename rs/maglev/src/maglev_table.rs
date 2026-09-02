use twox_hash::XxHash64;

use crate::backend::Backend;
use crate::hash::fnv1a64;

pub const LUT_SIZE: usize = 65537;

pub struct MaglevTable {
    pub backends: Vec<Backend>,
    lut: Vec<u16>,
}

pub fn hash_name(name: &str) -> (u64, u64) {
    let mut buf = name.as_bytes().to_vec();
    buf.push(0xff);
    (fnv1a64(&buf), XxHash64::oneshot(0, &buf))
}

impl MaglevTable {
    pub fn build(backends: Vec<Backend>) -> Self {
        let n = backends.len();
        assert!(n > 0 && n < LUT_SIZE, "bad backend count");
        let m = LUT_SIZE as u32;

        let mut perm = vec![vec![0u32; LUT_SIZE]; n];
        for (i, b) in backends.iter().enumerate() {
            let (fnv, xx) = hash_name(&b.name);
            let mut off = (xx % LUT_SIZE as u64) as u32;
            let skip = (fnv % (LUT_SIZE as u64 - 1) + 1) as u32;
            for slot in perm[i].iter_mut() {
                *slot = off;
                off += skip;
                if off >= m {
                    off -= m;
                }
            }
        }

        let mut lut = vec![u16::MAX; LUT_SIZE];
        let mut next = vec![0usize; n];
        let mut filled = 0;
        while filled < LUT_SIZE {
            for i in 0..n {
                if filled == LUT_SIZE {
                    break;
                }
                while lut[perm[i][next[i]] as usize] != u16::MAX {
                    next[i] += 1;
                }
                lut[perm[i][next[i]] as usize] = i as u16;
                next[i] += 1;
                filled += 1;
            }
        }
        Self { backends, lut }
    }

    #[inline]
    pub fn size(&self) -> usize {
        LUT_SIZE
    }

    #[inline]
    pub fn lookup_index(&self, flow_hash: u64) -> usize {
        self.lut[(flow_hash % LUT_SIZE as u64) as usize] as usize
    }

    #[inline]
    pub fn lookup(&self, flow_hash: u64) -> &Backend {
        &self.backends[self.lookup_index(flow_hash)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::five_tuple::FiveTuple;

    fn backends(names: &[&str]) -> Vec<Backend> {
        names
            .iter()
            .enumerate()
            .map(|(i, n)| Backend::new(n, [10, 0, 2, i as u8 + 1]))
            .collect()
    }

    #[test]
    fn matches_maglev_tui_c() {
        assert_eq!(hash_name("10.0.2.1"), (2783697993570190264, 11359228972548421684));

        let t = MaglevTable::build(backends(&["10.0.2.1", "10.0.2.2", "10.0.2.3"]));
        let head: Vec<usize> = (0..8).map(|i| t.lookup_index(i)).collect();
        assert_eq!(head, [0, 2, 1, 2, 1, 1, 0, 1]);
        assert_eq!(t.lookup_index(1000), 0);
        assert_eq!(t.lookup_index(65536), 1);

        let mut counts = [0usize; 3];
        for i in 0..LUT_SIZE {
            counts[t.lookup_index(i as u64)] += 1;
        }
        assert_eq!(counts, [21846, 21846, 21845]);

        let flow = FiveTuple {
            src_ip: u32::from_be_bytes([10, 0, 0, 2]),
            dst_ip: u32::from_be_bytes([10, 0, 1, 100]),
            src_port: 40000,
            dst_port: 8080,
            proto: 17,
        };
        assert_eq!(flow.hash(), 17500750975328167376);
        assert_eq!(t.lookup_index(flow.hash()), 0);
    }

    #[test]
    fn removal_causes_minimal_disruption() {
        let t1 = MaglevTable::build(backends(&["a", "b", "c", "d"]));
        let t2 = MaglevTable::build(backends(&["a", "b", "d"]));
        let mut moved = 0usize;
        let mut kept = 0usize;
        for i in 0..LUT_SIZE {
            let b1 = &t1.backends[t1.lookup_index(i as u64)].name;
            if b1 == "c" {
                continue; // had to move: its backend is gone
            }
            kept += 1;
            if b1 != &t2.backends[t2.lookup_index(i as u64)].name {
                moved += 1;
            }
        }
        let frac = moved as f64 / kept as f64;
        assert!(frac < 0.10, "too much disruption: {frac:.3}");
    }
}
