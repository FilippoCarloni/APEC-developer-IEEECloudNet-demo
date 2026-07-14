//! L3 forwarder NF: longest-prefix-match on the destination IP -> next hop,
//! then rewrite the destination MAC with the next hop's address.
//!
//! Header fields are read in place through the `hdr` views (benchmark traffic
//! is plain eth+ip: no VLAN or IP options, headers at fixed offsets).

mod lpm;

use nf_runtime::{hdr, Nf};

const NB_ROUTES: usize = 16;

/// Next-hop MAC table, indexed by the LPM next-hop id.
///
/// WARNING: forwarding to fabricated MACs (02:02:02:02:02:NN) that no device
/// owns makes any intervening switch FLOOD every frame (unknown unicast). On
/// a switched testbed set NF_NEXTHOP_MAC to a MAC the switch knows (e.g. the
/// traffic generator's port MAC); the LPM lookup still runs — only the egress
/// MAC is fixed.
fn init_nexthop_macs() -> [[u8; 6]; NB_ROUTES] {
    let fixed = std::env::var("NF_NEXTHOP_MAC").ok().and_then(|s| parse_mac(&s));
    std::array::from_fn(|i| match fixed {
        Some(mac) => mac,
        None => [0x02, 0x02, 0x02, 0x02, 0x02, i as u8],
    })
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = s.split([':', '-']);
    for b in &mut mac {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

struct L3fwd {
    nexthop_mac: [[u8; 6]; NB_ROUTES],
    #[cfg(not(feature = "ipv6"))]
    lpm: lpm::Lpm,
    #[cfg(feature = "ipv6")]
    lpm: lpm::Lpm6,
}

impl Nf for L3fwd {
    fn setup() -> Self {
        let nexthop_mac = init_nexthop_macs();

        #[cfg(not(feature = "ipv6"))]
        {
            let mut lpm = lpm::Lpm::new();
            /* 10.0.<i>.0/24 -> next hop i. */
            for i in 0..NB_ROUTES as u16 {
                lpm.add(u32::from_be_bytes([10, 0, i as u8, 0]), 24, i);
            }
            lpm.add(0, 0, 0); // default route
            L3fwd { nexthop_mac, lpm }
        }
        #[cfg(feature = "ipv6")]
        {
            let mut lpm = lpm::Lpm6::new();
            /* fd00:0:0:<i>::/64 -> next hop i. */
            for i in 0..NB_ROUTES as u16 {
                let mut net = [0u8; 16];
                net[0] = 0xfd;
                net[7] = i as u8;
                lpm.add(net, 64, i);
            }
            lpm.add([0; 16], 0, 0); // default route
            L3fwd { nexthop_mac, lpm }
        }
    }

    #[cfg(not(feature = "ipv6"))]
    #[inline(always)]
    unsafe fn app(&mut self, pkt: *mut u8) {
        let eth = hdr::ether_hdr(pkt);
        let iph = hdr::ipv4_hdr(pkt);
        let dip = (*iph).dst_addr;
        let next_hop = self.lpm.lookup(u32::from_be(dip)).unwrap_or(0);
        (*eth).dst_addr = self.nexthop_mac[next_hop as usize & (NB_ROUTES - 1)];
    }

    #[cfg(feature = "ipv6")]
    #[inline(always)]
    unsafe fn app(&mut self, pkt: *mut u8) {
        let eth = hdr::ether_hdr(pkt);
        let iph = hdr::ipv6_hdr(pkt);
        let dst = std::ptr::addr_of!((*iph).dst_addr).read_unaligned();
        let next_hop = self.lpm.lookup(&dst).unwrap_or(0);
        (*eth).dst_addr = self.nexthop_mac[next_hop as usize & (NB_ROUTES - 1)];
    }
}

fn main() {
    nf_runtime::run::<L3fwd>()
}

#[cfg(all(test, not(feature = "ipv6")))]
mod tests {
    use super::*;

    /// Expected MAC rewrites from running the C `nf_app` (l3fwd.cpp) on the
    /// same crafted eth/IPv4/UDP packets (harness against DPDK 24.11).
    #[test]
    fn mac_rewrites_match_c_nf_app() {
        let mut fwd = L3fwd::setup();
        for t in 0..6u8 {
            let mut b = [0u8; 64];
            b[23] = 17; // proto
            b[26..30].copy_from_slice(&[192, 168, t, 2]);
            b[30..34].copy_from_slice(&[10, 0, t * 3, 5]);
            unsafe { fwd.app(b.as_mut_ptr()) };
            assert_eq!(b[..6], [0x02, 0x02, 0x02, 0x02, 0x02, t * 3]);
        }
    }

    #[test]
    fn parses_nexthop_mac() {
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff"), Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(parse_mac("02-00-00-00-00-10"), Some([2, 0, 0, 0, 0, 0x10]));
        assert_eq!(parse_mac("aa:bb:cc"), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff:00"), None);
        assert_eq!(parse_mac("zz:bb:cc:dd:ee:ff"), None);
    }
}
