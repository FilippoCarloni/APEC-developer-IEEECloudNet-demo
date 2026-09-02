use zerocopy::byteorder::network_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::five_tuple::FiveTuple;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy, Debug)]
#[repr(C)]
pub struct FlowMeta {
    pub magic: u8,
    pub saddr: U32,
    pub daddr: U32,
    pub sport: U16,
    pub dport: U16,
    pub proto: u8,
    pub pad: [u8; 2],
}

const _: () = assert!(core::mem::size_of::<FlowMeta>() == 16);
const _: () = assert!(core::mem::align_of::<FlowMeta>() == 1);

impl FlowMeta {
    pub const MAGIC: u8 = 0xA5;
    pub const SIZE: usize = core::mem::size_of::<Self>();

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    #[inline]
    pub fn five_tuple(&self) -> FiveTuple {
        FiveTuple {
            src_ip: self.saddr.get(),
            dst_ip: self.daddr.get(),
            src_port: self.sport.get(),
            dst_port: self.dport.get(),
            proto: self.proto,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::FromBytes as _;

    #[test]
    fn layout_roundtrip() {
        let bytes: [u8; 20] = [
            0xA5,
            10, 1, 0, 1,
            10, 0, 1, 100,
            0x9c, 0x40,
            0x1f, 0x90,
            17,
            0, 0,
            0xde, 0xad, 0xbe, 0xef,
        ];
        let (meta, rest) = FlowMeta::ref_from_prefix(&bytes[..]).unwrap();
        assert!(meta.is_valid());
        assert_eq!(rest, &[0xde, 0xad, 0xbe, 0xef]);
        let t = meta.five_tuple();
        assert_eq!(t.src_ip, u32::from_be_bytes([10, 1, 0, 1]));
        assert_eq!(t.dst_ip, u32::from_be_bytes([10, 0, 1, 100]));
        assert_eq!(t.src_port, 40000);
        assert_eq!(t.dst_port, 8080);
        assert_eq!(t.proto, 17);
    }

    #[test]
    fn unaligned_read_is_fine() {
        let mut buf = vec![0u8; 21];
        buf[1] = FlowMeta::MAGIC;
        let (meta, _) = FlowMeta::ref_from_prefix(&buf[1..]).unwrap();
        assert!(meta.is_valid());
    }
}
