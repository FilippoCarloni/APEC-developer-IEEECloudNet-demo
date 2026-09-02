use zerocopy::byteorder::network_endian::U16;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Ipv4Hdr {
    pub ver_ihl: u8,
    pub tos: u8,
    pub tot_len: U16,
    pub id: U16,
    pub frag_off: U16,
    pub ttl: u8,
    pub proto: u8,
    pub csum: U16,
    pub saddr: [u8; 4],
    pub daddr: [u8; 4],
}

impl Ipv4Hdr {
    #[inline]
    pub fn ihl_bytes(&self) -> usize {
        ((self.ver_ihl & 0x0f) as usize) * 4
    }
}
