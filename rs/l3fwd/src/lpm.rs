//! Longest-prefix-match tables, replacing `rte_lpm`/`rte_lpm6`.
//!
//! IPv4 uses the same DIR-24-8 layout as `rte_lpm`: a 2^24-entry first-level
//! table indexed by the top 24 address bits, extended by 256-entry second
//! -level groups for prefixes deeper than /24 — lookups cost one load for the
//! common case, two for deep prefixes.
//!
//! IPv6 keeps the rules sorted deepest-first and scans linearly; with this
//! demo's route table (a handful of /64s plus a default) that costs about the
//! same as `rte_lpm6`'s multi-level walk and stays trivially verifiable.

/// Entry layout: bit 31 = valid, bit 30 = extended (tbl8 group in the
/// low bits), bits 24..30 = depth, bits 0..16 = next hop or tbl8 group.
#[cfg(any(not(feature = "ipv6"), test))]
const VALID: u32 = 1 << 31;
#[cfg(any(not(feature = "ipv6"), test))]
const EXT: u32 = 1 << 30;

#[cfg(any(not(feature = "ipv6"), test))]
#[inline]
fn entry(depth: u8, nh: u16) -> u32 {
    VALID | (depth as u32) << 24 | nh as u32
}

#[cfg(any(not(feature = "ipv6"), test))]
#[inline]
fn entry_depth(e: u32) -> u8 {
    ((e >> 24) & 0x3f) as u8
}

#[cfg(any(not(feature = "ipv6"), test))]
pub struct Lpm {
    tbl24: Vec<u32>,
    tbl8: Vec<u32>, // 256-entry groups
}

#[cfg(any(not(feature = "ipv6"), test))]
impl Lpm {
    pub fn new() -> Self {
        Lpm { tbl24: vec![0; 1 << 24], tbl8: Vec::new() }
    }

    /// Add `net/depth -> nh`. Deeper prefixes win regardless of insert order.
    pub fn add(&mut self, net: u32, depth: u8, nh: u16) {
        assert!(depth <= 32, "invalid IPv4 prefix depth {depth}");
        let masked = if depth == 0 { 0 } else { net & (u32::MAX << (32 - depth)) };

        if depth <= 24 {
            let first = (masked >> 8) as usize;
            let count = 1usize << (24 - depth);
            for slot in &mut self.tbl24[first..first + count] {
                if *slot & VALID == 0 || (*slot & EXT == 0 && entry_depth(*slot) <= depth) {
                    *slot = entry(depth, nh);
                } else if *slot & EXT != 0 {
                    let group = (*slot & 0xffff) as usize;
                    for e8 in &mut self.tbl8[group * 256..(group + 1) * 256] {
                        if *e8 & VALID == 0 || entry_depth(*e8) <= depth {
                            *e8 = entry(depth, nh);
                        }
                    }
                }
            }
            return;
        }

        // depth > 24: all covered addresses share one tbl24 slot.
        let slot = (masked >> 8) as usize;
        if self.tbl24[slot] & EXT == 0 {
            let group = self.tbl8.len() / 256;
            let fill = self.tbl24[slot]; // pre-existing shallower route (or 0)
            self.tbl8.extend(std::iter::repeat(fill).take(256));
            self.tbl24[slot] = VALID | EXT | group as u32;
        }
        let group = (self.tbl24[slot] & 0xffff) as usize;
        let low = (masked & 0xff) as usize;
        let count = 1usize << (32 - depth);
        for e8 in &mut self.tbl8[group * 256 + low..group * 256 + low + count] {
            if *e8 & VALID == 0 || entry_depth(*e8) <= depth {
                *e8 = entry(depth, nh);
            }
        }
    }

    /// Look up a host-order IPv4 address; `None` on no matching route.
    #[inline(always)]
    pub fn lookup(&self, ip: u32) -> Option<u16> {
        let e = unsafe { *self.tbl24.get_unchecked((ip >> 8) as usize) };
        if e & VALID == 0 {
            return None;
        }
        if e & EXT != 0 {
            let group = (e & 0xffff) as usize;
            let e8 = self.tbl8[group * 256 + (ip & 0xff) as usize];
            if e8 & VALID == 0 {
                return None;
            }
            return Some((e8 & 0xffff) as u16);
        }
        Some((e & 0xffff) as u16)
    }
}

#[cfg(any(feature = "ipv6", test))]
struct Route6 {
    net: [u8; 16],
    depth: u8,
    nh: u16,
}

#[cfg(any(feature = "ipv6", test))]
pub struct Lpm6 {
    routes: Vec<Route6>, // kept sorted deepest-first
}

#[cfg(any(feature = "ipv6", test))]
impl Lpm6 {
    pub fn new() -> Self {
        Lpm6 { routes: Vec::new() }
    }

    pub fn add(&mut self, net: [u8; 16], depth: u8, nh: u16) {
        assert!(depth <= 128, "invalid IPv6 prefix depth {depth}");
        self.routes.push(Route6 { net, depth, nh });
        self.routes.sort_by(|a, b| b.depth.cmp(&a.depth));
    }

    /// Longest-prefix match; `None` on no matching route.
    #[inline(always)]
    pub fn lookup(&self, addr: &[u8; 16]) -> Option<u16> {
        'route: for r in &self.routes {
            let full = (r.depth / 8) as usize;
            if addr[..full] != r.net[..full] {
                continue;
            }
            let rem = r.depth % 8;
            if rem != 0 {
                let mask = 0xffu8 << (8 - rem);
                if (addr[full] ^ r.net[full]) & mask != 0 {
                    continue 'route;
                }
            }
            return Some(r.nh);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lpm4_demo_routes() {
        let mut lpm = Lpm::new();
        for i in 0..16u16 {
            lpm.add(u32::from_be_bytes([10, 0, i as u8, 0]), 24, i);
        }
        lpm.add(0, 0, 0); // default route
        assert_eq!(lpm.lookup(u32::from_be_bytes([10, 0, 7, 33])), Some(7));
        assert_eq!(lpm.lookup(u32::from_be_bytes([10, 0, 15, 255])), Some(15));
        assert_eq!(lpm.lookup(u32::from_be_bytes([192, 168, 1, 1])), Some(0)); // default
    }

    #[test]
    fn lpm4_deep_prefixes_and_order_independence() {
        let mut lpm = Lpm::new();
        lpm.add(u32::from_be_bytes([10, 1, 2, 128]), 25, 9);
        lpm.add(u32::from_be_bytes([10, 1, 2, 200]), 32, 5); // host route
        lpm.add(u32::from_be_bytes([10, 1, 2, 0]), 24, 3); // shallower, added last
        assert_eq!(lpm.lookup(u32::from_be_bytes([10, 1, 2, 200])), Some(5));
        assert_eq!(lpm.lookup(u32::from_be_bytes([10, 1, 2, 129])), Some(9));
        assert_eq!(lpm.lookup(u32::from_be_bytes([10, 1, 2, 1])), Some(3));
        assert_eq!(lpm.lookup(u32::from_be_bytes([10, 1, 3, 1])), None);
    }

    #[test]
    fn lpm6_demo_routes() {
        let mut lpm = Lpm6::new();
        lpm.add([0; 16], 0, 0); // default route first: depth ordering must win
        for i in 0..16u16 {
            let mut net = [0u8; 16];
            net[0] = 0xfd;
            net[7] = i as u8;
            lpm.add(net, 64, i);
        }
        let mut a = [0u8; 16];
        a[0] = 0xfd;
        a[7] = 5;
        a[15] = 42;
        assert_eq!(lpm.lookup(&a), Some(5));
        a[0] = 0x20;
        assert_eq!(lpm.lookup(&a), Some(0)); // default
    }
}
