use zerocopy::byteorder::network_endian::U16;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct EthHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: U16,
}

impl EthHdr {
    pub const ETH_P_IP: u16 = 0x0800;
}
