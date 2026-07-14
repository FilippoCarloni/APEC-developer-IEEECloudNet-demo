//! Zero-copy header views over raw packet data, the Rust counterpart of the
//! C demo's pointer casts (`(struct rte_ipv4_hdr *)(eth + 1)`).
//!
//! Benchmark traffic is plain `eth / IPv4|IPv6 / UDP|TCP` — no VLAN, no IP
//! options — so every header sits at a fixed offset. Multi-byte fields hold
//! network byte order exactly as on the wire; `packed` makes every access an
//! unaligned load/store (the IP header starts at offset 14).

pub const ETHER_HDR_LEN: usize = 14;
pub const IPV4_HDR_LEN: usize = 20;
pub const IPV6_HDR_LEN: usize = 40;

#[repr(C, packed)]
pub struct EtherHdr {
    pub dst_addr: [u8; 6],
    pub src_addr: [u8; 6],
    pub ether_type: u16, // be16
}

#[repr(C, packed)]
pub struct Ipv4Hdr {
    pub version_ihl: u8,
    pub type_of_service: u8,
    pub total_length: u16,    // be16
    pub packet_id: u16,       // be16
    pub fragment_offset: u16, // be16
    pub time_to_live: u8,
    pub next_proto_id: u8,
    pub hdr_checksum: u16, // be16
    pub src_addr: u32,     // be32
    pub dst_addr: u32,     // be32
}

#[repr(C, packed)]
pub struct Ipv6Hdr {
    pub vtc_flow: u32,    // be32
    pub payload_len: u16, // be16
    pub proto: u8,
    pub hop_limits: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

/// src/dst port share offsets in UDP and TCP: one view covers both.
#[repr(C, packed)]
pub struct UdpHdr {
    pub src_port: u16,    // be16
    pub dst_port: u16,    // be16
    pub dgram_len: u16,   // be16
    pub dgram_cksum: u16, // be16
}

#[inline(always)]
pub unsafe fn ether_hdr(pkt: *mut u8) -> *mut EtherHdr {
    pkt.cast()
}

#[inline(always)]
pub unsafe fn ipv4_hdr(pkt: *mut u8) -> *mut Ipv4Hdr {
    pkt.add(ETHER_HDR_LEN).cast()
}

#[inline(always)]
pub unsafe fn ipv6_hdr(pkt: *mut u8) -> *mut Ipv6Hdr {
    pkt.add(ETHER_HDR_LEN).cast()
}

#[inline(always)]
pub unsafe fn udp_hdr_v4(pkt: *mut u8) -> *mut UdpHdr {
    pkt.add(ETHER_HDR_LEN + IPV4_HDR_LEN).cast()
}

#[inline(always)]
pub unsafe fn udp_hdr_v6(pkt: *mut u8) -> *mut UdpHdr {
    pkt.add(ETHER_HDR_LEN + IPV6_HDR_LEN).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn layouts_match_the_wire() {
        assert_eq!(size_of::<EtherHdr>(), 14);
        assert_eq!(size_of::<Ipv4Hdr>(), 20);
        assert_eq!(size_of::<Ipv6Hdr>(), 40);
        assert_eq!(size_of::<UdpHdr>(), 8);
        assert_eq!(offset_of!(Ipv4Hdr, src_addr), 12);
        assert_eq!(offset_of!(Ipv4Hdr, dst_addr), 16);
        assert_eq!(offset_of!(Ipv6Hdr, src_addr), 8);
        assert_eq!(offset_of!(Ipv6Hdr, dst_addr), 24);
    }
}
