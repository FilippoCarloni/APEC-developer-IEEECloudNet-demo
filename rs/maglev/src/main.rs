//! Maglev load balancer NF (Eisenbud et al., NSDI '16): hash the 5-tuple,
//! map it to a backend through the Maglev consistent-hash table (permutations
//! + populate, with a per-bucket connection cache), and rewrite the packet's
//! destination IP with the selected backend address. The table is
//! address-family-agnostic: it maps a hash to a backend index; the IPv4/IPv6
//! split is only the key it hashes and the address it writes (`ipv6` feature).
//!
//! Header fields are read in place through the `hdr` views (benchmark traffic
//! is plain eth+ip+l4: no VLAN or IP options, headers at fixed offsets).

mod table;

use nf_runtime::{hdr, jhash, Nf};
use table::MaglevTable;

const NB_BACKENDS: usize = 1024;

struct Maglev {
    tbl: MaglevTable,
    #[cfg(not(feature = "ipv6"))]
    bk4: Box<[u32; NB_BACKENDS]>, // backend IPv4 addresses (be32)
    #[cfg(feature = "ipv6")]
    bk6: Box<[[u8; 16]; NB_BACKENDS]>, // backend IPv6 addresses
}

impl Nf for Maglev {
    fn setup() -> Self {
        let mut seed = vec![(0u32, 0u32); NB_BACKENDS];

        #[cfg(not(feature = "ipv6"))]
        {
            let base = u32::from_be_bytes([10, 0, 0, 1]);
            let mut bk4 = Box::new([0u32; NB_BACKENDS]);
            for (i, bk) in bk4.iter_mut().enumerate() {
                *bk = (base + i as u32).to_be();
                let (mut h1, mut h2) = (0u32, 1u32);
                jhash::jhash_2hashes(&bk.to_ne_bytes(), &mut h1, &mut h2);
                seed[i] = (h1, h2);
            }
            Maglev { tbl: MaglevTable::new(&seed), bk4 }
        }
        #[cfg(feature = "ipv6")]
        {
            let base: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            let mut bk6 = Box::new([[0u8; 16]; NB_BACKENDS]);
            for (i, bk) in bk6.iter_mut().enumerate() {
                *bk = base;
                let low = u32::from_be_bytes(bk[12..16].try_into().unwrap());
                bk[12..16].copy_from_slice(&(low + i as u32).to_be_bytes());
                let (mut h1, mut h2) = (0u32, 1u32);
                jhash::jhash_2hashes(bk, &mut h1, &mut h2);
                seed[i] = (h1, h2);
            }
            Maglev { tbl: MaglevTable::new(&seed), bk6 }
        }
    }

    #[cfg(not(feature = "ipv6"))]
    #[inline(always)]
    unsafe fn app(&mut self, pkt: *mut u8) {
        let iph = hdr::ipv4_hdr(pkt);
        let udp = hdr::udp_hdr_v4(pkt);
        let l4 = (((*udp).src_port as u32) << 16) | (*udp).dst_port as u32;
        let h = jhash::jhash_3words(
            (*iph).src_addr,
            (*iph).dst_addr,
            l4 ^ (*iph).next_proto_id as u32,
            0,
        );
        let b = self.tbl.pick(h);
        (*iph).dst_addr = *self.bk4.get_unchecked(b as usize); // rewrite destination IP -> backend
    }

    #[cfg(feature = "ipv6")]
    #[inline(always)]
    unsafe fn app(&mut self, pkt: *mut u8) {
        let iph = hdr::ipv6_hdr(pkt);
        let udp = hdr::udp_hdr_v6(pkt);
        let l4 = (((*udp).src_port as u32) << 16) | (*udp).dst_port as u32;
        /* src_addr and dst_addr are adjacent: hash the 32 address bytes at once. */
        let addrs = std::slice::from_raw_parts(std::ptr::addr_of!((*iph).src_addr).cast::<u8>(), 32);
        let h = jhash::jhash(addrs, 0) ^ l4 ^ (*iph).proto as u32;
        let b = self.tbl.pick(h);
        (*iph).dst_addr = *self.bk6.get_unchecked(b as usize); // rewrite destination IP -> backend
    }
}

fn main() {
    nf_runtime::run::<Maglev>()
}

#[cfg(all(test, not(feature = "ipv6")))]
mod tests {
    use super::*;

    /// Expected backend picks from running the C `nf_app` (maglev.cpp) on
    /// the same crafted eth/IPv4/UDP packets (harness against DPDK 24.11).
    #[test]
    fn backend_picks_match_c_nf_app() {
        let mut lb = Maglev::setup();
        let want_dst: [u32; 6] = [
            0x0a0003b4, 0x0a000281, 0x0a000363, 0x0a000240, 0x0a000082, 0x0a000384,
        ];
        for (t, want) in want_dst.into_iter().enumerate() {
            let mut b = [0u8; 64];
            b[23] = 17; // proto
            b[26..30].copy_from_slice(&[192, 168, t as u8, 2]);
            b[30..34].copy_from_slice(&[10, 0, (t * 3) as u8, 5]);
            b[34..36].copy_from_slice(&(5555 + t as u16).to_be_bytes());
            b[36..38].copy_from_slice(&80u16.to_be_bytes());
            unsafe { lb.app(b.as_mut_ptr()) };
            assert_eq!(b[30..34], want.to_be_bytes());
        }
    }
}
