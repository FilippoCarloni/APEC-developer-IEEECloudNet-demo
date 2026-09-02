use core::fmt;
use std::net::Ipv4Addr;

use zerocopy::FromBytes;

use crate::eth_hdr::EthHdr;
use crate::hash::fnv1a64;
use crate::ipv4_hdr::Ipv4Hdr;
use crate::l4_ports::L4Ports;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FiveTuple {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl FiveTuple {
    #[inline]
    pub fn from_frame(frame: &[u8]) -> Option<Self> {
        let (eth, rest) = EthHdr::ref_from_prefix(frame).ok()?;
        if eth.ethertype.get() != EthHdr::ETH_P_IP {
            return None;
        }
        let (ip, _) = Ipv4Hdr::ref_from_prefix(rest).ok()?;
        if ip.proto != 6 && ip.proto != 17 {
            return None;
        }
        let (ports, _) = L4Ports::ref_from_prefix(rest.get(ip.ihl_bytes()..)?).ok()?;
        Some(Self {
            src_ip: u32::from_be_bytes(ip.saddr),
            dst_ip: u32::from_be_bytes(ip.daddr),
            src_port: u16::from_be_bytes(ports.sport),
            dst_port: u16::from_be_bytes(ports.dport),
            proto: ip.proto,
        })
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; 13] {
        let mut b = [0u8; 13];
        b[0..4].copy_from_slice(&self.src_ip.to_ne_bytes());
        b[4..8].copy_from_slice(&self.dst_ip.to_ne_bytes());
        b[8..10].copy_from_slice(&self.src_port.to_ne_bytes());
        b[10..12].copy_from_slice(&self.dst_port.to_ne_bytes());
        b[12] = self.proto;
        b
    }

    #[inline]
    pub fn hash(&self) -> u64 {
        fnv1a64(&self.to_bytes())
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proto = match self.proto {
            6 => "TCP",
            17 => "UDP",
            _ => "?",
        };
        write!(
            f,
            "{}:{} -> {}:{}/{}",
            Ipv4Addr::from(self.src_ip),
            self.src_port,
            Ipv4Addr::from(self.dst_ip),
            self.dst_port,
            proto
        )
    }
}
