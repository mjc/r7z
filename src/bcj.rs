//! x86 BCJ (Branch, Call, Jump) filter.
//!
//! Converts relative addresses in x86 CALL (0xE8) and JMP (0xE9) instructions
//! to absolute form (encode) or back to relative form (decode).  This improves
//! compression of executable code because nearby calls to the same target end up
//! with identical displacement bytes after the filter.
//!
//! The algorithm matches p7zip / LZMA SDK `Bra86.c` exactly.

/// Test whether the most-significant byte of a 4-byte displacement indicates
/// a near address (0x00 or 0xFF after biased addition).
#[inline]
fn test86_msb(b: u8) -> bool {
    (b.wrapping_add(1)) & 0xFE == 0
}

/// Lookup: prevMask value → number of relevant high bits to check.
const MASK_TO_BIT_NUMBER: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];

/// Apply the x86 BCJ filter in-place (matches LZMA SDK `Bra86.c`).
///
/// * `encoding` — `true` to convert relative → absolute (encode / pre-compress),
///   `false` to convert absolute → relative (decode / post-decompress).
/// * `data`     — mutable buffer; modified in-place.
/// * `ip`       — virtual instruction pointer base (usually 0 for 7z).
/// * `state`    — 3-bit overlap state carried across calls; initialise to 0.
///
/// Returns the number of bytes that were fully processed.  Trailing bytes
/// (fewer than 5) are left untouched and should be prepended to the next call.
pub fn bcj_x86_convert(data: &mut [u8], ip: u32, state: &mut u32, encoding: bool) -> usize {
    let size = data.len();
    if size < 5 {
        return 0;
    }

    let limit = size - 4;
    let ip = ip.wrapping_add(5); // p7zip pre-adds 5
    let mut buf_pos: usize = 0;
    let mut prev_pos_t: usize = usize::MAX; // (SizeT)0 - 1
    let mut prev_mask: u32 = *state & 0x7;

    loop {
        // Scan for E8 (CALL) or E9 (JMP) starting at buf_pos
        let found = data[buf_pos..limit]
            .iter()
            .position(|&b| (b & 0xFE) == 0xE8);
        buf_pos = match found {
            Some(offset) => buf_pos + offset,
            None => break,
        };

        // Distance since last candidate
        let prev_pos_t_new = buf_pos.wrapping_sub(prev_pos_t);
        prev_pos_t = prev_pos_t_new;
        if prev_pos_t > 3 {
            prev_mask = 0;
        } else {
            prev_mask = (prev_mask << (prev_pos_t.wrapping_sub(1) as u32)) & 0x7;
            if prev_mask != 0 {
                let check_byte_idx = buf_pos + 4 - MASK_TO_BIT_NUMBER[prev_mask as usize] as usize;
                if !test86_msb(data[check_byte_idx]) {
                    prev_pos_t = buf_pos;
                    prev_mask = ((prev_mask << 1) & 0x7) | 1;
                    buf_pos += 1;
                    continue;
                }
            }
        }
        prev_pos_t = buf_pos;

        if test86_msb(data[buf_pos + 4]) {
            // Read 4-byte displacement (LE) from p[1..5]
            let p = buf_pos;
            let mut src = u32::from(data[p + 1])
                | (u32::from(data[p + 2]) << 8)
                | (u32::from(data[p + 3]) << 16)
                | (u32::from(data[p + 4]) << 24);

            let dest;
            loop {
                let d = if encoding {
                    ip.wrapping_add(buf_pos as u32).wrapping_add(src)
                } else {
                    src.wrapping_sub(ip.wrapping_add(buf_pos as u32))
                };
                if prev_mask == 0 {
                    dest = d;
                    break;
                }
                let index = MASK_TO_BIT_NUMBER[prev_mask as usize] * 8;
                let b = (d >> (24 - index)) as u8;
                if !test86_msb(b) {
                    dest = d;
                    break;
                }
                src = d ^ ((1u32 << (32 - index)).wrapping_sub(1));
            }

            // Write back: MSB byte becomes 0x00 or 0xFF
            data[p + 4] = (!(((dest >> 24) & 1).wrapping_sub(1))) as u8;
            data[p + 3] = (dest >> 16) as u8;
            data[p + 2] = (dest >> 8) as u8;
            data[p + 1] = dest as u8;
            buf_pos += 5;
        } else {
            prev_mask = ((prev_mask << 1) & 0x7) | 1;
            buf_pos += 1;
        }
    }

    *state = prev_mask;
    buf_pos
}

/// Decode (post-decompress) x86 BCJ filter.
///
/// Convenience wrapper around [`bcj_x86_convert`] with `encoding = false`.
/// Processes the entire buffer in a single pass — suitable when the full
/// decompressed stream is available at once (the 7z case).
pub fn bcj_x86_decode(data: &mut [u8]) {
    let mut state = 0u32;
    bcj_x86_convert(data, 0, &mut state, false);
}

/// Encode (pre-compress) x86 BCJ filter.
///
/// Convenience wrapper around [`bcj_x86_convert`] with `encoding = true`.
pub fn bcj_x86_encode(data: &mut [u8]) {
    let mut state = 0u32;
    bcj_x86_convert(data, 0, &mut state, true);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test86_msb_check() {
        assert!(test86_msb(0x00));
        assert!(test86_msb(0xFF));
        assert!(!test86_msb(0x01));
        assert!(!test86_msb(0xFE));
        assert!(!test86_msb(0x80));
    }

    #[test]
    fn encode_decode_roundtrip() {
        // Build a small buffer with E8 CALL at position 10
        let mut original = vec![0x90u8; 64]; // NOP sled

        // Place a CALL instruction: E8 <4 bytes>
        // CALL to absolute address 0x00001000 from IP=10+5=15
        // relative displacement = 0x1000 - 15 = 0x0FF1
        original[10] = 0xE8;
        original[11] = 0xF1;
        original[12] = 0x0F;
        original[13] = 0x00;
        original[14] = 0x00; // MSB = 0x00, valid

        // Place a JMP at position 32
        // JMP to absolute 0x00002000 from IP=32+5=37
        // relative = 0x2000 - 37 = 0x1FDB
        original[32] = 0xE9;
        original[33] = 0xDB;
        original[34] = 0x1F;
        original[35] = 0x00;
        original[36] = 0x00; // MSB = 0x00

        let saved = original.clone();

        // Encode
        bcj_x86_encode(&mut original);
        // Data should be different (addresses converted to absolute)
        assert_ne!(&original[11..15], &saved[11..15]);
        assert_ne!(&original[33..37], &saved[33..37]);

        // Decode
        bcj_x86_decode(&mut original);
        // Should be back to the original
        assert_eq!(original, saved);
    }

    #[test]
    fn no_modification_without_e8_e9() {
        let mut data = vec![0x90u8; 32];
        let saved = data.clone();
        bcj_x86_encode(&mut data);
        assert_eq!(data, saved);
    }

    #[test]
    fn short_buffer_noop() {
        let mut data = vec![0xE8, 0x00, 0x00, 0x00]; // 4 bytes, too short
        let saved = data.clone();
        bcj_x86_encode(&mut data);
        assert_eq!(data, saved);
    }

    #[test]
    fn non_near_target_not_converted() {
        // E8 with MSB byte = 0x80 (not 0x00 or 0xFF) → should be skipped
        let mut data = vec![0x90u8; 16];
        data[5] = 0xE8;
        data[6] = 0x00;
        data[7] = 0x00;
        data[8] = 0x00;
        data[9] = 0x80; // MSB = 0x80, NOT a near target
        let saved = data.clone();
        bcj_x86_encode(&mut data);
        assert_eq!(data, saved);
    }

    #[test]
    fn multiple_calls_roundtrip() {
        let mut data = vec![0x90u8; 256];

        // Plant multiple CALL instructions at various positions
        for &pos in &[10u32, 30, 60, 100, 150, 200] {
            let p = pos as usize;
            if p + 5 <= data.len() {
                data[p] = 0xE8;
                data[p + 1] = (pos * 7) as u8;
                data[p + 2] = ((pos * 7) >> 8) as u8;
                data[p + 3] = 0x00;
                data[p + 4] = 0x00;
            }
        }

        let saved = data.clone();
        bcj_x86_encode(&mut data);
        assert_ne!(data, saved);
        bcj_x86_decode(&mut data);
        assert_eq!(data, saved);
    }

    #[test]
    fn encode_produces_absolute_addresses() {
        let mut data = vec![0x90u8; 16];
        // CALL at pos 0: relative displacement = 0x00000100
        data[0] = 0xE8;
        data[1] = 0x00;
        data[2] = 0x01;
        data[3] = 0x00;
        data[4] = 0x00;

        bcj_x86_encode(&mut data);

        // After encoding, displacement should be absolute:
        // ip = 0 + 5 = 5, absolute = 0x100 + 5 = 0x105
        let disp = u32::from_le_bytes([data[1], data[2], data[3], 0]);
        // The MSB byte (data[4]) gets special treatment
        assert_eq!(disp, 0x0105);
    }
}
