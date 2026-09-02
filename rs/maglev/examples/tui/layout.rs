use maglev::eth_hdr::EthHdr;
use maglev::ipv4_hdr::Ipv4Hdr;
use zerocopy::FromBytes;

#[derive(Clone, Copy)]
pub struct Layout {
    pub l3: usize,
    pub l4: usize,
    pub l4_end: usize,
    pub ip_end: usize,
}

impl Layout {
    pub fn of(frame: &[u8]) -> Option<Self> {
        let (eth, rest) = EthHdr::ref_from_prefix(frame).ok()?;
        if eth.ethertype.get() != EthHdr::ETH_P_IP {
            return None;
        }
        let (ip, _) = Ipv4Hdr::ref_from_prefix(rest).ok()?;
        let l3 = 14;
        let l4 = l3 + ip.ihl_bytes();
        let l4_hdr = match ip.proto {
            6 => frame.get(l4 + 12).map_or(20, |&b| ((b >> 4) as usize * 4).max(20)),
            17 | 1 => 8,
            _ => 0,
        };
        // IP total length bounds the real data; anything past it is
        // Ethernet padding, which must not be painted as protocol content.
        let ip_end = (l3 + ip.tot_len.get() as usize).min(frame.len());
        Some(Self { l3, l4, l4_end: (l4 + l4_hdr).min(ip_end), ip_end })
    }

    pub fn shifted(self, by: usize) -> Self {
        Self {
            l3: self.l3 + by,
            l4: self.l4 + by,
            l4_end: self.l4_end + by,
            ip_end: self.ip_end + by,
        }
    }
}
