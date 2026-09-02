#[path = "support/synth.rs"]
mod synth;

use maglev::checksum::{ipv4_header_checksum, l4_checksum, rewrite_daddr};
use maglev::flow_meta::FlowMeta;
use maglev::five_tuple::FiveTuple;
use synth::{FrameSpec, build_frame, prefix_frame};
use zerocopy::FromBytes;

#[test]
fn casts_plain_udp() {
    let f = build_frame(&FrameSpec::default());
    let t = FiveTuple::from_frame(&f).unwrap();
    assert_eq!(t.proto, 17);
    assert_eq!(t.src_ip, u32::from_be_bytes([10, 0, 0, 2]));
    assert_eq!(t.dst_ip, u32::from_be_bytes([10, 0, 1, 100]));
    assert_eq!(t.src_port, 40000);
    assert_eq!(t.dst_port, 8080);
}

#[test]
fn ihl_moves_the_ports_overlay() {
    let f = build_frame(&FrameSpec { ip_opt_len: 12, proto: 6, ..FrameSpec::default() });
    let t = FiveTuple::from_frame(&f).unwrap();
    assert_eq!(t.proto, 6);
    assert_eq!(t.dst_port, 8080);
}

#[test]
fn rejects_non_ip_and_short() {
    assert!(FiveTuple::from_frame(&[0u8; 10]).is_none());
    let mut f = build_frame(&FrameSpec::default());
    f[12] = 0x08;
    f[13] = 0x06; // ARP
    assert!(FiveTuple::from_frame(&f).is_none());
}

#[test]
fn typed_and_parsed_agree() {
    let f = build_frame(&FrameSpec::default());
    let pre = prefix_frame(&f);
    let (meta, rest) = FlowMeta::ref_from_prefix(&pre[..]).unwrap();
    assert_eq!(meta.five_tuple(), FiveTuple::from_frame(rest).unwrap());
    assert_eq!(meta.five_tuple().hash(), FiveTuple::from_frame(rest).unwrap().hash());
}

/// Verify both checksums of a frame by full recomputation.
fn check_frame(frame: &[u8]) {
    let t = FiveTuple::from_frame(frame).unwrap();
    let ihl = ((frame[14] & 0x0f) as usize) * 4;
    let hdr = &frame[14..14 + ihl];
    assert_eq!(
        u16::from_be_bytes([hdr[10], hdr[11]]),
        ipv4_header_checksum(hdr),
        "ip checksum mismatch"
    );

    let l4 = 14 + ihl;
    let mut seg = frame[l4..].to_vec();
    let coff = if t.proto == 6 { 16 } else { 6 };
    let stored = u16::from_be_bytes([seg[coff], seg[coff + 1]]);
    seg[coff] = 0;
    seg[coff + 1] = 0;
    let mut want = l4_checksum(t.src_ip.to_be_bytes(), t.dst_ip.to_be_bytes(), t.proto, &seg);
    if t.proto == 17 && want == 0 {
        want = 0xffff;
    }
    assert_eq!(stored, want, "l4 checksum mismatch");
}

#[test]
fn incremental_rewrite_matches_full_recompute() {
    for proto in [6u8, 17] {
        for opts in [0usize, 12] {
            let mut f = build_frame(&FrameSpec { proto, ip_opt_len: opts, ..FrameSpec::default() });
            check_frame(&f);
            assert!(rewrite_daddr(&mut f, 14, proto, [10, 0, 2, 7]));
            assert_eq!(&f[14 + 16..14 + 20], &[10, 0, 2, 7]);
            check_frame(&f);
        }
    }
}
