use nom::{bytes::complete::take, number::complete::le_u8, IResult};

/// Saturate a `u64` count down to `usize`, capped at `max` so that
/// `with_capacity` / `reserve_exact` never over-allocates more than the input
/// actually contains.
#[inline]
#[must_use]
pub fn usize_cap(n: u64, max: usize) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX).min(max)
}

/// Encode a u64 as a 7z variable-length integer (1–9 bytes).
///
/// Format mirrors `sevenzip_varuint64_decode`: bit (7-i) of the first byte is set
/// when byte (i+1) carries value bits [8i .. 8i+7].
///
/// # Panics
///
/// Does not panic in practice; the internal `expect` is unreachable because
/// the value is always less than the current `mask` (a `u8`) at that point.
#[must_use]
pub fn sevenzip_varuint64_encode(mut value: u64) -> Vec<u8> {
    let mut result = vec![0u8];
    let mut mask: u8 = 0x80;
    loop {
        if value < u64::from(mask) {
            // value < mask (which is a u8), so value fits in u8
            result[0] |= u8::try_from(value).expect("value < mask (u8), fits in u8");
            break;
        }
        result[0] |= mask;
        result.push((value & 0xFF) as u8);
        value >>= 8;
        mask = mask.wrapping_shr(1);
        if mask == 0 {
            break; // all 8 extra bytes pushed; first byte = 0xFF
        }
    }
    result
}

/// Decode a 7z variable-length integer from the input slice.
///
/// # Errors
///
/// Returns `nom::Err::Incomplete` if the input is empty or truncated.
pub fn sevenzip_varuint64_decode(input: &[u8]) -> IResult<&[u8], u64> {
    if input.is_empty() {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Eof,
        )));
    }
    let first_byte = input[0];
    let mut value: u64 = 0;
    let mut mask: u8 = 0x80;
    let mut addr: usize = 0;
    for i in 0..8usize {
        addr += 1;
        if (first_byte & mask) == 0 {
            value += u64::from(first_byte & (mask - 1)) << (8 * i);
            break;
        }
        if addr >= input.len() {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Eof,
            )));
        }
        let next = input[addr];
        value |= u64::from(next) << (8 * i);
        mask >>= 1;
    }
    Ok((&input[addr..], value))
}

/// Walk a digest (CRC32) block without allocating.
///
/// Reads the `AllAreDefined` flag, optional bitmap, and the corresponding
/// `le_u32` CRC values, advancing past all of them.  Returns `()` — no data
/// is retained.
///
/// # Errors
///
/// Returns a nom error if the input is truncated.
pub(crate) fn scan_digests(input: &[u8], num: usize) -> IResult<&[u8], ()> {
    let (input, all_defined) = le_u8(input)?;
    if all_defined != 0 {
        let (input, _) = take(num * 4)(input)?;
        return Ok((input, ()));
    }
    let num_bytes = num.div_ceil(8);
    let (input, bitmap) = take(num_bytes)(input)?;
    let num_defined = (0..num).filter(|&i| (bitmap[i / 8] >> (i % 8)) & 1 == 1).count();
    let (input, _) = take(num_defined * 4)(input)?;
    Ok((input, ()))
}
