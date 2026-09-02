use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct L4Ports {
    pub sport: [u8; 2],
    pub dport: [u8; 2],
}
