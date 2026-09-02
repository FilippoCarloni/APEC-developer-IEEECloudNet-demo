#[inline]
pub fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

#[inline]
pub fn sum_words(data: &[u8]) -> u32 {
    let mut s = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        s += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        s += (*last as u32) << 8;
    }
    s
}

pub fn ipv4_header_checksum(hdr: &[u8]) -> u16 {
    let mut s = 0u32;
    for (i, c) in hdr.chunks_exact(2).enumerate() {
        if i == 5 {
            continue;
        }
        s += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    !fold(s)
}

pub fn l4_checksum(saddr: [u8; 4], daddr: [u8; 4], proto: u8, segment: &[u8]) -> u16 {
    let mut s = sum_words(&saddr) + sum_words(&daddr);
    s += proto as u32;
    s += segment.len() as u32;
    s += sum_words(segment);
    !fold(s)
}

#[inline]
fn incr_update(csum: u16, old: u16, new: u16) -> u16 {
    let s = ((!csum) as u32) + ((!old) as u32) + (new as u32);
    !fold(s)
}

pub fn rewrite_daddr(frame: &mut [u8], l3_off: usize, l4_proto: u8, new_daddr: [u8; 4]) -> bool {
    if frame.len() < l3_off + 20 {
        return false;
    }
    let ihl = ((frame[l3_off] & 0x0f) as usize) * 4;
    if ihl < 20 || frame.len() < l3_off + ihl {
        return false;
    }

    let old: [u8; 4] = frame[l3_off + 16..l3_off + 20].try_into().unwrap();
    if old == new_daddr {
        return true;
    }
    let old_hi = u16::from_be_bytes([old[0], old[1]]);
    let old_lo = u16::from_be_bytes([old[2], old[3]]);
    let new_hi = u16::from_be_bytes([new_daddr[0], new_daddr[1]]);
    let new_lo = u16::from_be_bytes([new_daddr[2], new_daddr[3]]);

    let c = u16::from_be_bytes([frame[l3_off + 10], frame[l3_off + 11]]);
    let c = incr_update(incr_update(c, old_hi, new_hi), old_lo, new_lo);
    frame[l3_off + 10..l3_off + 12].copy_from_slice(&c.to_be_bytes());

    let l4 = l3_off + ihl;
    match l4_proto {
        6 => {
            if frame.len() < l4 + 18 {
                return false;
            }
            let c = u16::from_be_bytes([frame[l4 + 16], frame[l4 + 17]]);
            let c = incr_update(incr_update(c, old_hi, new_hi), old_lo, new_lo);
            frame[l4 + 16..l4 + 18].copy_from_slice(&c.to_be_bytes());
        }
        17 => {
            if frame.len() < l4 + 8 {
                return false;
            }
            let c = u16::from_be_bytes([frame[l4 + 6], frame[l4 + 7]]);
            if c != 0 {
                // 0 means "no checksum" in UDP
                let mut c = incr_update(incr_update(c, old_hi, new_hi), old_lo, new_lo);
                if c == 0 {
                    c = 0xffff; // RFC 768: a computed 0 is transmitted as all-ones
                }
                frame[l4 + 6..l4 + 8].copy_from_slice(&c.to_be_bytes());
            }
        }
        _ => {}
    }

    frame[l3_off + 16..l3_off + 20].copy_from_slice(&new_daddr);
    true
}
