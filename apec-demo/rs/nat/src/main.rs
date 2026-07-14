//! Stateless source-NAT NF: hash the flow 5-tuple to an entry in an external
//! address/port pool and rewrite the packet's source IP and L4 port.
//!
//! Header fields are read in place through the `hdr` views (benchmark traffic
//! is plain eth+ip+l4: no VLAN or IP options, headers at fixed offsets). The
//! IP/L4 checksums are intentionally not recomputed (the traffic generator
//! counts packets without validating checksums).

use nf_runtime::{hdr, jhash, Nf};

const NAT_POOL: usize = 4096;

struct Nat {
    /// L4 source ports, stored big-endian as written to the wire.
    ext_port: Box<[u16; NAT_POOL]>,
    #[cfg(not(feature = "ipv6"))]
    ext_ip: Box<[u32; NAT_POOL]>,
    #[cfg(feature = "ipv6")]
    ext_ip6: Box<[[u8; 16]; NAT_POOL]>,
}

impl Nf for Nat {
    fn setup() -> Self {
        let mut ext_port = Box::new([0u16; NAT_POOL]);
        for (i, p) in ext_port.iter_mut().enumerate() {
            *p = (10000 + (i & 0x7fff)) as u16;
            *p = p.to_be();
        }

        #[cfg(not(feature = "ipv6"))]
        {
            /* External pool: 100.64.0.0/10 (CGNAT space). */
            let base = u32::from_be_bytes([100, 64, 0, 1]);
            let mut ext_ip = Box::new([0u32; NAT_POOL]);
            for (i, ip) in ext_ip.iter_mut().enumerate() {
                *ip = (base + i as u32).to_be();
            }
            Nat { ext_port, ext_ip }
        }
        #[cfg(feature = "ipv6")]
        {
            /* External pool: 2001:db8::/32 (documentation space). */
            let base: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            let mut ext_ip6 = Box::new([[0u8; 16]; NAT_POOL]);
            for (i, ip) in ext_ip6.iter_mut().enumerate() {
                *ip = base;
                let low = u32::from_be_bytes(ip[12..16].try_into().unwrap());
                ip[12..16].copy_from_slice(&(low + i as u32).to_be_bytes());
            }
            Nat { ext_port, ext_ip6 }
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
        let idx = h as usize & (NAT_POOL - 1);
        (*iph).src_addr = *self.ext_ip.get_unchecked(idx); // rewrite source IP
        (*udp).src_port = *self.ext_port.get_unchecked(idx); // rewrite L4 source port
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
        let idx = h as usize & (NAT_POOL - 1);
        (*iph).src_addr = *self.ext_ip6.get_unchecked(idx); // rewrite source IP
        (*udp).src_port = *self.ext_port.get_unchecked(idx); // rewrite L4 source port
    }
}

fn main() {
    nf_runtime::run::<Nat>()
}

#[cfg(all(test, not(feature = "ipv6")))]
mod tests {
    use super::*;

    /// Expected rewrites from running the C `nf_app` (nat.cpp) on the same
    /// crafted eth/IPv4/UDP packets (harness against DPDK 24.11).
    #[test]
    fn rewrites_match_c_nf_app() {
        let mut nat = Nat::setup();
        let cases: [([u8; 4], u16, u32, u16); 3] = [
            ([192, 168, 1, 2], 5555, 0x64400891, 12192),
            ([10, 0, 3, 7], 5556, 0x64400aaf, 12734),
            ([172, 16, 0, 9], 5557, 0x64400905, 12308),
        ];
        for (src, sport, want_src, want_sport) in cases {
            let mut b = [0u8; 64];
            b[23] = 17; // proto
            b[26..30].copy_from_slice(&src);
            b[30..34].copy_from_slice(&[10, 0, 0, 5]);
            b[34..36].copy_from_slice(&sport.to_be_bytes());
            b[36..38].copy_from_slice(&80u16.to_be_bytes());
            unsafe { nat.app(b.as_mut_ptr()) };
            assert_eq!(b[26..30], want_src.to_be_bytes());
            assert_eq!(b[34..36], want_sport.to_be_bytes());
        }
    }
}
