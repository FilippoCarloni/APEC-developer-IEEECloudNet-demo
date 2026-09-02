use zerocopy::IntoBytes;
use zerocopy::byteorder::network_endian::{U16, U32};

use maglev::checksum;
use maglev::flow_meta::FlowMeta;

pub struct FrameSpec {
    pub saddr: [u8; 4],
    pub daddr: [u8; 4],
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub payload_len: usize,
    pub ip_opt_len: usize,
}

impl Default for FrameSpec {
    fn default() -> Self {
        Self {
            saddr: [10, 0, 0, 2],
            daddr: [10, 0, 1, 100],
            sport: 40000,
            dport: 8080,
            proto: 17,
            payload_len: 64,
            ip_opt_len: 0,
        }
    }
}

pub fn build_frame(s: &FrameSpec) -> Vec<u8> {
    assert!(s.ip_opt_len % 4 == 0 && s.ip_opt_len <= 40);
    assert!(s.proto == 6 || s.proto == 17);
    let l3 = 14;
    let ihl = 20 + s.ip_opt_len;
    let l4_hdr = if s.proto == 6 { 20 } else { 8 };
    let tot = ihl + l4_hdr + s.payload_len;
    let mut f = vec![0u8; l3 + tot];

    f[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    f[l3] = 0x40 | (ihl as u8 / 4);
    f[l3 + 2..l3 + 4].copy_from_slice(&(tot as u16).to_be_bytes());
    f[l3 + 4..l3 + 6].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    f[l3 + 8] = 64; // ttl
    f[l3 + 9] = s.proto;
    f[l3 + 12..l3 + 16].copy_from_slice(&s.saddr);
    f[l3 + 16..l3 + 20].copy_from_slice(&s.daddr);
    for i in 0..s.ip_opt_len {
        f[l3 + 20 + i] = 0x01; // NOP options
    }
    let ipc = checksum::ipv4_header_checksum(&f[l3..l3 + ihl]);
    f[l3 + 10..l3 + 12].copy_from_slice(&ipc.to_be_bytes());

    let l4 = l3 + ihl;
    f[l4..l4 + 2].copy_from_slice(&s.sport.to_be_bytes());
    f[l4 + 2..l4 + 4].copy_from_slice(&s.dport.to_be_bytes());
    let seg_len = l4_hdr + s.payload_len;
    if s.proto == 17 {
        f[l4 + 4..l4 + 6].copy_from_slice(&(seg_len as u16).to_be_bytes());
    } else {
        f[l4 + 12] = 0x50; // data offset 5
        f[l4 + 13] = 0x10; // ACK
        f[l4 + 14..l4 + 16].copy_from_slice(&0xffffu16.to_be_bytes());
    }
    for i in 0..s.payload_len {
        f[l4 + l4_hdr + i] = i as u8;
    }
    let coff = if s.proto == 6 { 16 } else { 6 };
    let mut c = checksum::l4_checksum(s.saddr, s.daddr, s.proto, &f[l4..]);
    if s.proto == 17 && c == 0 {
        c = 0xffff;
    }
    f[l4 + coff..l4 + coff + 2].copy_from_slice(&c.to_be_bytes());
    f
}

pub fn prefix_frame(frame: &[u8]) -> Vec<u8> {
    let t = maglev::five_tuple::FiveTuple::from_frame(frame).expect("frame must be parseable to prefix it");
    let meta = FlowMeta {
        magic: FlowMeta::MAGIC,
        saddr: U32::new(t.src_ip),
        daddr: U32::new(t.dst_ip),
        sport: U16::new(t.src_port),
        dport: U16::new(t.dst_port),
        proto: t.proto,
        pad: [0; 2],
    };
    let mut out = Vec::with_capacity(16 + frame.len());
    out.extend_from_slice(meta.as_bytes());
    out.extend_from_slice(frame);
    out
}
