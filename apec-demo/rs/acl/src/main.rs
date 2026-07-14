//! ACL/firewall NF: classify the 5-tuple against an ordered rule set (linear
//! first-match, the classic firewall ladder) and tally permit/deny in
//! per-lcore counters. Packets are still forwarded: the verdict is counted,
//! not enforced — enforcing it would just skip the TX of denied packets and
//! is an easy extension in the runtime loop.
//!
//! Header fields are read in place through the `hdr` views (benchmark traffic
//! is plain eth+ip+l4: no VLAN or IP options, headers at fixed offsets).

use nf_runtime::{hdr, Nf};

const NB_RULES: usize = 64;

#[cfg(not(feature = "ipv6"))]
#[derive(Clone, Copy, Default)]
struct AclRule {
    /// Address/mask fields hold raw big-endian words, compared as on the wire.
    sip: u32,
    sip_mask: u32,
    dip: u32,
    dip_mask: u32,
    sport_lo: u16,
    sport_hi: u16,
    dport_lo: u16,
    dport_hi: u16,
    proto: u8,
    proto_mask: u8,
    permit: bool,
}

#[cfg(feature = "ipv6")]
#[derive(Clone, Copy, Default)]
/// IPv6 rules: a source /prefix match (the firewall ladder over 128-bit src).
struct AclRule {
    sip: [u8; 16],
    prefix_len: u8, // bytes of sip to compare
    sport_lo: u16,
    sport_hi: u16,
    dport_lo: u16,
    dport_hi: u16,
    proto: u8,
    proto_mask: u8,
    permit: bool,
}

struct Acl {
    rules: Box<[AclRule; NB_RULES]>,
    permit: u64,
    deny: u64,
}

impl Acl {
    #[cfg(not(feature = "ipv6"))]
    #[inline(always)]
    fn classify(&self, sip: u32, dip: u32, sp: u16, dp: u16, proto: u8) -> bool {
        for r in self.rules.iter() {
            if (sip & r.sip_mask) != r.sip {
                continue;
            }
            if (dip & r.dip_mask) != r.dip {
                continue;
            }
            if sp < r.sport_lo || sp > r.sport_hi {
                continue;
            }
            if dp < r.dport_lo || dp > r.dport_hi {
                continue;
            }
            if (proto & r.proto_mask) != r.proto {
                continue;
            }
            return r.permit; // first match wins
        }
        false
    }

    #[cfg(feature = "ipv6")]
    #[inline(always)]
    fn classify(&self, sip: &[u8; 16], sp: u16, dp: u16, proto: u8) -> bool {
        for r in self.rules.iter() {
            let plen = r.prefix_len as usize;
            if plen != 0 && sip[..plen] != r.sip[..plen] {
                continue;
            }
            if sp < r.sport_lo || sp > r.sport_hi {
                continue;
            }
            if dp < r.dport_lo || dp > r.dport_hi {
                continue;
            }
            if (proto & r.proto_mask) != r.proto {
                continue;
            }
            return r.permit;
        }
        false
    }
}

impl Nf for Acl {
    fn setup() -> Self {
        let mut rules = Box::new([AclRule::default(); NB_RULES]);

        #[cfg(not(feature = "ipv6"))]
        {
            /* Synthetic rule ladder: deny a spread of /24 sources, last rule
             * permits all. Representative of a real firewall's linear match
             * cost. */
            for (i, r) in rules.iter_mut().take(NB_RULES - 1).enumerate() {
                r.sip = u32::from_be_bytes([10, 0, i as u8, 0]).to_be();
                r.sip_mask = 0xFFFFFF00u32.to_be();
                r.sport_hi = 0xFFFF;
                r.dport_hi = 0xFFFF;
                r.permit = false;
            }
        }
        #[cfg(feature = "ipv6")]
        {
            for (i, r) in rules.iter_mut().take(NB_RULES - 1).enumerate() {
                r.sip = [0xfd, 0, 0, 0, 0, 0, 0, i as u8, 0, 0, 0, 0, 0, 0, 0, 0];
                r.prefix_len = 8; // /64
                r.sport_hi = 0xFFFF;
                r.dport_hi = 0xFFFF;
                r.permit = false;
            }
        }

        let last = &mut rules[NB_RULES - 1];
        last.sport_hi = 0xFFFF;
        last.dport_hi = 0xFFFF;
        last.permit = true;

        Acl { rules, permit: 0, deny: 0 }
    }

    #[cfg(not(feature = "ipv6"))]
    #[inline(always)]
    unsafe fn app(&mut self, pkt: *mut u8) {
        let iph = hdr::ipv4_hdr(pkt);
        let udp = hdr::udp_hdr_v4(pkt);
        let sp = u16::from_be((*udp).src_port);
        let dp = u16::from_be((*udp).dst_port);
        if self.classify((*iph).src_addr, (*iph).dst_addr, sp, dp, (*iph).next_proto_id) {
            self.permit += 1;
        } else {
            self.deny += 1;
        }
    }

    #[cfg(feature = "ipv6")]
    #[inline(always)]
    unsafe fn app(&mut self, pkt: *mut u8) {
        let iph = hdr::ipv6_hdr(pkt);
        let udp = hdr::udp_hdr_v6(pkt);
        let sp = u16::from_be((*udp).src_port);
        let dp = u16::from_be((*udp).dst_port);
        let sip = std::ptr::addr_of!((*iph).src_addr).read_unaligned();
        if self.classify(&sip, sp, dp, (*iph).proto) {
            self.permit += 1;
        } else {
            self.deny += 1;
        }
    }

    fn teardown(&mut self) {
        println!(
            "WORKER {}: permit={} deny={}",
            nf_runtime::worker_id(),
            self.permit,
            self.deny
        );
    }
}

fn main() {
    nf_runtime::run::<Acl>()
}

#[cfg(all(test, not(feature = "ipv6")))]
mod tests {
    use super::*;

    /// Expected verdicts from running the C `nf_app` (acl.cpp) on the same
    /// crafted eth/IPv4/UDP packets (harness against DPDK 24.11):
    /// six sources outside the deny ladder, three inside, one outside.
    #[test]
    fn verdicts_match_c_nf_app() {
        let mut acl = Acl::setup();
        let mut run = |src: [u8; 4], sport: u16| {
            let mut b = [0u8; 64];
            b[23] = 17; // proto
            b[26..30].copy_from_slice(&src);
            b[30..34].copy_from_slice(&[10, 0, 0, 5]);
            b[34..36].copy_from_slice(&sport.to_be_bytes());
            b[36..38].copy_from_slice(&80u16.to_be_bytes());
            unsafe { acl.app(b.as_mut_ptr()) };
        };
        for t in 0..6u8 {
            run([192, 168, t, 2], 5555 + t as u16);
        }
        for t in 0..3u8 {
            run([10, 0, t, 9], 1000 + t as u16);
        }
        run([192, 168, 0, 9], 1003);
        assert_eq!((acl.permit, acl.deny), (7, 3));
    }
}
