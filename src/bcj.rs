//! x86 BCJ (Branch, Call, Jump) filter.
//!
//! Converts relative addresses in x86 CALL (0xE8) and JMP (0xE9) instructions
//! to absolute form (encode) or back to relative form (decode).  This improves
//! compression of executable code because nearby calls to the same target end up
//! with identical displacement bytes after the filter.
//!
//! The algorithm matches p7zip / LZMA SDK `Bra86.c` exactly.

use std::io::{self, Read, Write};

#[derive(Clone, Copy, Debug)]
pub(crate) enum BranchFilter {
    Arm,
    ArmThumb,
    Ia64,
    Ppc,
    Sparc,
}

impl BranchFilter {
    fn convert(self, data: &mut [u8], ip: u32, encoding: bool) -> usize {
        match self {
            Self::Arm => arm_convert(data, ip, encoding),
            Self::ArmThumb => arm_thumb_convert(data, ip, encoding),
            Self::Ia64 => ia64_convert(data, ip, encoding),
            Self::Ppc => ppc_convert(data, ip, encoding),
            Self::Sparc => sparc_convert(data, ip, encoding),
        }
    }
}

#[inline]
fn get_u32_le(data: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
}

#[inline]
fn set_u32_le(data: &mut [u8], pos: usize, value: u32) {
    data[pos..pos + 4].copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn get_u32_be(data: &[u8], pos: usize) -> u32 {
    u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
}

#[inline]
fn set_u32_be(data: &mut [u8], pos: usize, value: u32) {
    data[pos..pos + 4].copy_from_slice(&value.to_be_bytes());
}

/// Test whether the most-significant byte of a 4-byte displacement indicates
/// a near address (0x00 or 0xFF after biased addition).
#[inline]
fn test86_msb(b: u8) -> bool {
    (b.wrapping_add(1)) & 0xFE == 0
}

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
#[allow(clippy::cast_possible_truncation)]
pub fn bcj_x86_convert(data: &mut [u8], ip: u32, state: &mut u32, encoding: bool) -> usize {
    let size = data.len();
    let mut pos: usize = 0;
    let mut mask: u32 = *state & 7;
    if size < 5 {
        return 0;
    }

    let limit = size - 4;
    let ip = ip.wrapping_add(5); // p7zip pre-adds 5

    loop {
        let start = pos;
        while pos < limit && (data[pos] & 0xFE) != 0xE8 {
            pos += 1;
        }

        let distance = pos - start;
        if pos >= limit {
            *state = if distance > 2 {
                0
            } else {
                mask >> u32::try_from(distance).unwrap_or(0)
            };
            return pos;
        }

        if distance > 2 {
            mask = 0;
        } else {
            mask >>= u32::try_from(distance).unwrap_or(0);
            if mask != 0 {
                let test_idx = pos + usize::try_from(mask >> 1).unwrap_or(0) + 1;
                if mask > 4 || mask == 3 || test86_msb(data[test_idx]) {
                    mask = (mask >> 1) | 4;
                    pos += 1;
                    continue;
                }
            }
        }

        if test86_msb(data[pos + 4]) {
            let p = pos;
            let mut value = u32::from(data[p + 4]) << 24
                | u32::from(data[p + 3]) << 16
                | u32::from(data[p + 2]) << 8
                | u32::from(data[p + 1]);
            let current = ip.wrapping_add(pos as u32);
            pos += 5;

            if encoding {
                value = value.wrapping_add(current);
            } else {
                value = value.wrapping_sub(current);
            }

            if mask != 0 {
                let shift = (mask & 6) << 2;
                if test86_msb((value >> shift) as u8) {
                    let adjust_mask = ((0x100u64 << shift) - 1) as u32;
                    value ^= adjust_mask;
                    if encoding {
                        value = value.wrapping_add(current);
                    } else {
                        value = value.wrapping_sub(current);
                    }
                }
                mask = 0;
            }

            data[p + 1] = value as u8;
            data[p + 2] = (value >> 8) as u8;
            data[p + 3] = (value >> 16) as u8;
            data[p + 4] = (0u8).wrapping_sub(((value >> 24) & 1) as u8);
        } else {
            mask = (mask >> 1) | 4;
            pos += 1;
        }
    }
}

pub(crate) struct BcjX86Reader<R> {
    inner: R,
    tail: Vec<u8>,
    pending: Vec<u8>,
    pending_pos: usize,
    state: u32,
    input_offset: u64,
    eof: bool,
}

pub(crate) struct BranchReader<R> {
    inner: R,
    filter: BranchFilter,
    tail: Vec<u8>,
    pending: Vec<u8>,
    pending_pos: usize,
    input_offset: u64,
    eof: bool,
}

pub(crate) struct BcjX86Writer<W> {
    inner: W,
    tail: Vec<u8>,
    state: u32,
    input_offset: u64,
}

impl<W: Write> BcjX86Writer<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            tail: Vec::with_capacity(4),
            state: 0,
            input_offset: 0,
        }
    }

    pub(crate) fn finish(mut self) -> io::Result<W> {
        if !self.tail.is_empty() {
            self.inner.write_all(&self.tail)?;
            self.tail.clear();
        }
        Ok(self.inner)
    }
}

impl<W: Write> Write for BcjX86Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut data = Vec::with_capacity(self.tail.len() + buf.len());
        data.extend_from_slice(&self.tail);
        data.extend_from_slice(buf);

        #[allow(clippy::cast_possible_truncation)]
        let processed = bcj_x86_convert(&mut data, self.input_offset as u32, &mut self.state, true);
        self.inner.write_all(&data[..processed])?;
        self.tail.clear();
        self.tail.extend_from_slice(&data[processed..]);
        self.input_offset = self.input_offset.wrapping_add(processed as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<R: Read> BcjX86Reader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            tail: Vec::with_capacity(4),
            pending: Vec::new(),
            pending_pos: 0,
            state: 0,
            input_offset: 0,
            eof: false,
        }
    }

    fn fill_pending(&mut self) -> io::Result<()> {
        self.pending.clear();
        self.pending_pos = 0;

        while self.pending.is_empty() && !self.eof {
            let mut chunk = [0u8; 8192];
            let n = self.inner.read(&mut chunk)?;

            if n == 0 {
                self.eof = true;
                self.pending.extend_from_slice(&self.tail);
                self.tail.clear();
                break;
            }

            let mut data = Vec::with_capacity(self.tail.len() + n);
            data.extend_from_slice(&self.tail);
            data.extend_from_slice(&chunk[..n]);

            #[allow(clippy::cast_possible_truncation)]
            let processed =
                bcj_x86_convert(&mut data, self.input_offset as u32, &mut self.state, false);
            self.pending.extend_from_slice(&data[..processed]);
            self.tail.clear();
            self.tail.extend_from_slice(&data[processed..]);
            self.input_offset = self.input_offset.wrapping_add(processed as u64);
        }
        Ok(())
    }
}

impl<R: Read> Read for BcjX86Reader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        if self.pending_pos == self.pending.len() {
            self.fill_pending()?;
        }

        let available = &self.pending[self.pending_pos..];
        if available.is_empty() {
            return Ok(0);
        }

        let n = available.len().min(out.len());
        out[..n].copy_from_slice(&available[..n]);
        self.pending_pos += n;
        Ok(n)
    }
}

impl<R: Read> BranchReader<R> {
    pub(crate) fn new(inner: R, filter: BranchFilter) -> Self {
        Self {
            inner,
            filter,
            tail: Vec::with_capacity(16),
            pending: Vec::new(),
            pending_pos: 0,
            input_offset: 0,
            eof: false,
        }
    }

    fn fill_pending(&mut self) -> io::Result<()> {
        self.pending.clear();
        self.pending_pos = 0;

        while self.pending.is_empty() && !self.eof {
            let mut chunk = [0u8; 8192];
            let n = self.inner.read(&mut chunk)?;

            if n == 0 {
                self.eof = true;
                self.pending.extend_from_slice(&self.tail);
                self.tail.clear();
                break;
            }

            let mut data = Vec::with_capacity(self.tail.len() + n);
            data.extend_from_slice(&self.tail);
            data.extend_from_slice(&chunk[..n]);

            #[allow(clippy::cast_possible_truncation)]
            let processed = self
                .filter
                .convert(&mut data, self.input_offset as u32, false);
            self.pending.extend_from_slice(&data[..processed]);
            self.tail.clear();
            self.tail.extend_from_slice(&data[processed..]);
            self.input_offset = self.input_offset.wrapping_add(processed as u64);
        }
        Ok(())
    }
}

impl<R: Read> Read for BranchReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        if self.pending_pos == self.pending.len() {
            self.fill_pending()?;
        }

        let available = &self.pending[self.pending_pos..];
        if available.is_empty() {
            return Ok(0);
        }

        let n = available.len().min(out.len());
        out[..n].copy_from_slice(&available[..n]);
        self.pending_pos += n;
        Ok(n)
    }
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

fn arm_convert(data: &mut [u8], ip: u32, encoding: bool) -> usize {
    let size = data.len() & !3;
    let ip = ip.wrapping_add(4);
    let mut pos = 0usize;

    while pos < size {
        pos += 4;
        if data[pos - 1] == 0xEB {
            let start = pos - 4;
            let mut value = get_u32_le(data, start) << 2;
            let current = ip.wrapping_add(pos as u32);
            if encoding {
                value = value.wrapping_add(current);
            } else {
                value = value.wrapping_sub(current);
            }
            value >>= 2;
            value &= 0x00FF_FFFF;
            value |= 0xEB00_0000;
            set_u32_le(data, start, value);
        }
    }

    pos
}

fn arm_thumb_convert(data: &mut [u8], ip: u32, encoding: bool) -> usize {
    let size = data.len() & !1;
    if size < 4 {
        return 0;
    }

    let limit = size - 4;
    let mut pos = 0usize;

    loop {
        let mut b1;
        loop {
            if pos > limit {
                return pos;
            }
            b1 = u32::from(data[pos + 1]);
            let b3 = u32::from(data[pos + 3]);
            pos += 2;
            b1 ^= 8;
            if (b3 & b1) >= 0xF8 {
                break;
            }
        }

        let mut value = (b1 << 19)
            + ((u32::from(data[pos + 1]) & 0x7) << 8)
            + (u32::from(data[pos - 2]) << 11)
            + u32::from(data[pos]);

        pos += 2;
        let current = ip.wrapping_add(pos as u32) >> 1;
        if encoding {
            value = value.wrapping_add(current);
        } else {
            value = value.wrapping_sub(current);
        }

        data[pos - 4] = (value >> 11) as u8;
        data[pos - 3] = (0xF0 | ((value >> 19) & 0x7)) as u8;
        data[pos - 2] = value as u8;
        data[pos - 1] = (0xF8 | (value >> 8)) as u8;
    }
}

fn ppc_convert(data: &mut [u8], ip: u32, encoding: bool) -> usize {
    let size = data.len() & !3;
    let ip = ip.wrapping_sub(4);
    let mut pos = 0usize;

    while pos < size {
        pos += 4;
        if (data[pos - 4] & 0xFC) == 0x48 && (data[pos - 1] & 3) == 1 {
            let start = pos - 4;
            let mut value = get_u32_be(data, start);
            let current = ip.wrapping_add(pos as u32);
            if encoding {
                value = value.wrapping_add(current);
            } else {
                value = value.wrapping_sub(current);
            }
            value &= 0x03FF_FFFF;
            value |= 0x4800_0000;
            set_u32_be(data, start, value);
        }
    }

    pos
}

fn sparc_convert(data: &mut [u8], ip: u32, encoding: bool) -> usize {
    let size = data.len() & !3;
    let ip = ip.wrapping_sub(4);
    let mut pos = 0usize;

    while pos < size {
        pos += 4;
        if (data[pos - 4] == 0x40 && (data[pos - 3] & 0xC0) == 0)
            || (data[pos - 4] == 0x7F && data[pos - 3] >= 0xC0)
        {
            let start = pos - 4;
            let mut value = get_u32_be(data, start) << 2;
            let current = ip.wrapping_add(pos as u32);
            if encoding {
                value = value.wrapping_add(current);
            } else {
                value = value.wrapping_sub(current);
            }
            value &= 0x01FF_FFFF;
            value = value.wrapping_sub(1 << 24);
            value ^= 0xFF00_0000;
            value >>= 2;
            value |= 0x4000_0000;
            set_u32_be(data, start, value);
        }
    }

    pos
}

fn ia64_convert(data: &mut [u8], ip: u32, encoding: bool) -> usize {
    if data.len() < 16 {
        return 0;
    }

    let limit = data.len() - 16;
    let mut pos = 0usize;

    loop {
        let mut mask = (0x334B_0000u32 >> (data[pos] & 0x1E)) & 3;
        if mask != 0 {
            mask += 1;
            while mask <= 4 {
                let p = pos + mask as usize * 5 - 8;
                if ((u32::from(data[p + 3]) >> mask) & 15) == 5
                    && (((u32::from(data[p - 1]) | (u32::from(data[p]) << 8)) >> mask) & 0x70) == 0
                {
                    let mut raw = get_u32_le(data, p);
                    let mut value = raw >> mask;
                    value = (value & 0xFFFFF) | ((value & (1 << 23)) >> 3);
                    value <<= 4;
                    let current = ip.wrapping_add(pos as u32);
                    if encoding {
                        value = value.wrapping_add(current);
                    } else {
                        value = value.wrapping_sub(current);
                    }
                    value >>= 4;

                    value &= 0x1F_FFFF;
                    value = value.wrapping_add(0x70_0000);
                    value &= 0x8F_FFFF;
                    raw &= !(0x8F_FFFF << mask);
                    raw |= value << mask;
                    set_u32_le(data, p, raw);
                }
                mask += 1;
            }
        }

        pos += 16;
        if pos > limit {
            return pos;
        }
    }
}

#[cfg(test)]
#[allow(clippy::pedantic)]
mod tests {
    use super::*;

    fn branch_payload(filter: BranchFilter) -> Vec<u8> {
        let mut data = vec![0u8; 256];
        match filter {
            BranchFilter::Arm => {
                for pos in (0..data.len()).step_by(16) {
                    data[pos] = pos as u8;
                    data[pos + 3] = 0xEB;
                }
            }
            BranchFilter::ArmThumb => {
                for pos in (0..data.len() - 4).step_by(16) {
                    data[pos..pos + 4].copy_from_slice(&[0x00, 0xF0, 0x00, 0xF8]);
                }
            }
            BranchFilter::Ia64 => {
                for pos in (0..data.len()).step_by(16) {
                    data[pos] = 0x16;
                    data[pos + 5] = 0x14;
                }
            }
            BranchFilter::Ppc => {
                for pos in (0..data.len()).step_by(16) {
                    data[pos..pos + 4].copy_from_slice(&[0x48, 0x00, 0x00, 0x01]);
                }
            }
            BranchFilter::Sparc => {
                for pos in (0..data.len()).step_by(16) {
                    data[pos..pos + 4].copy_from_slice(&[0x40, 0x00, 0x00, 0x00]);
                }
            }
        }
        data
    }

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

    #[test]
    fn streaming_decode_matches_batch_for_chunk_sizes() {
        let mut original = vec![0x90u8; 4096];
        for &pos in &[3usize, 10, 63, 127, 512, 1021, 2048, 3070] {
            original[pos] = if pos % 2 == 0 { 0xE8 } else { 0xE9 };
            original[pos + 1] = (pos * 5) as u8;
            original[pos + 2] = ((pos * 5) >> 8) as u8;
            original[pos + 3] = 0;
            original[pos + 4] = 0;
        }

        let mut encoded = original.clone();
        bcj_x86_encode(&mut encoded);

        let mut expected = encoded.clone();
        bcj_x86_decode(&mut expected);

        for chunk_size in [1usize, 2, 3, 4, 5, 7, 16, 64] {
            let cursor = std::io::Cursor::new(encoded.clone());
            let mut reader = BcjX86Reader::new(cursor);
            let mut actual = Vec::new();
            let mut buf = vec![0u8; chunk_size];
            loop {
                let n = reader.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                actual.extend_from_slice(&buf[..n]);
            }
            assert_eq!(actual, expected, "chunk_size={chunk_size}");
        }
    }

    #[test]
    fn streaming_decode_handles_split_instruction() {
        let mut original = vec![0x90u8; 32];
        original[4] = 0xE8;
        original[5] = 0x40;
        original[6] = 0x00;
        original[7] = 0x00;
        original[8] = 0x00;

        let mut encoded = original.clone();
        bcj_x86_encode(&mut encoded);

        let cursor = std::io::Cursor::new(encoded);
        let mut reader = BcjX86Reader::new(cursor);
        let mut actual = Vec::new();
        let mut buf = [0u8; 2];
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            actual.extend_from_slice(&buf[..n]);
        }

        assert_eq!(actual, original);
    }

    #[test]
    fn streaming_encode_matches_batch_for_chunk_sizes() {
        let mut data = vec![0x90u8; 4096];
        for pos in (3..data.len().saturating_sub(5)).step_by(37) {
            data[pos] = if pos % 2 == 0 { 0xE8 } else { 0xE9 };
            let target = (pos as u32).wrapping_mul(11);
            data[pos + 1..pos + 5].copy_from_slice(&target.to_le_bytes());
        }

        let mut batch = data.clone();
        bcj_x86_encode(&mut batch);

        for chunk_size in [1, 2, 3, 4, 5, 7, 31, 1024] {
            let mut writer = BcjX86Writer::new(Vec::new());
            for chunk in data.chunks(chunk_size) {
                writer.write_all(chunk).unwrap();
            }
            let streamed = writer.finish().unwrap();
            assert_eq!(streamed, batch, "chunk_size={chunk_size}");
        }
    }

    #[test]
    fn branch_filters_encode_decode_roundtrip() {
        for filter in [
            BranchFilter::Arm,
            BranchFilter::ArmThumb,
            BranchFilter::Ia64,
            BranchFilter::Ppc,
            BranchFilter::Sparc,
        ] {
            let original = branch_payload(filter);
            let mut data = original.clone();

            let processed = filter.convert(&mut data, 0, true);
            assert!(processed > 0, "filter {filter:?} processed no bytes");
            assert_ne!(data, original, "filter {filter:?} did not encode payload");

            filter.convert(&mut data, 0, false);
            assert_eq!(data, original, "filter {filter:?} failed roundtrip");
        }
    }

    #[test]
    fn branch_reader_decodes_filtered_stream() {
        for filter in [
            BranchFilter::Arm,
            BranchFilter::ArmThumb,
            BranchFilter::Ia64,
            BranchFilter::Ppc,
            BranchFilter::Sparc,
        ] {
            let original = branch_payload(filter);
            let mut encoded = original.clone();
            filter.convert(&mut encoded, 0, true);

            let cursor = std::io::Cursor::new(encoded);
            let mut reader = BranchReader::new(cursor, filter);
            let mut actual = Vec::new();
            let mut buf = [0u8; 3];
            loop {
                let n = reader.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                actual.extend_from_slice(&buf[..n]);
            }

            assert_eq!(
                actual, original,
                "filter {filter:?} failed streaming decode"
            );
        }
    }
}
