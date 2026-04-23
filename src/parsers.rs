use nom::{IResult, bytes::complete::take, number::complete::le_u8};

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
    let mut consumed: usize = 1;
    for i in 0..8usize {
        if (first_byte & mask) == 0 {
            value += u64::from(first_byte & (mask - 1)) << (8 * i);
            break;
        }
        if consumed >= input.len() {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Eof,
            )));
        }
        let next = input[consumed];
        value |= u64::from(next) << (8 * i);
        consumed += 1;
        mask >>= 1;
    }
    Ok((&input[consumed..], value))
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
    let num_defined = (0..num).filter(|&i| bitmap_is_set(bitmap, i)).count();
    let (input, _) = take(num_defined * 4)(input)?;
    Ok((input, ()))
}

pub(crate) fn bitmap_is_set(bitmap: &[u8], index: usize) -> bool {
    bitmap
        .get(index / 8)
        .is_some_and(|b| (b >> (7 - (index % 8))) & 1 == 1)
}

#[cfg(test)]
mod tests {
    use super::scan_digests;

    /// `all_defined=1`: reads num*4 CRC bytes then leaves the rest.
    #[test]
    fn scan_digests_all_defined() {
        let input = [0x01u8, 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0xFF];
        let (rem, ()) = scan_digests(&input, 2).unwrap();
        assert_eq!(rem, &[0xFF]);
    }

    /// `all_defined=0`, high bits set for 2 entries → reads 2 CRCs.
    #[test]
    fn scan_digests_bitmap_all_set() {
        let input = [0x00u8, 0xC0, 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
        let (rem, ()) = scan_digests(&input, 2).unwrap();
        assert!(rem.is_empty());
    }

    /// `all_defined=0`, only entry 2 set for 3 entries → 1 CRC read.
    #[test]
    fn scan_digests_bitmap_sparse() {
        let input = [0x00u8, 0x20, 0xDE, 0xAD, 0xBE, 0xEF];
        let (rem, ()) = scan_digests(&input, 3).unwrap();
        assert!(rem.is_empty());
    }

    /// `num=0`: only the `all_defined` flag is consumed.
    #[test]
    fn scan_digests_zero_count() {
        let input = [0x01u8];
        let (rem, ()) = scan_digests(&input, 0).unwrap();
        assert!(rem.is_empty());
    }

    /// Truncated: `all_defined=1` but no CRC bytes.
    #[test]
    fn scan_digests_truncated() {
        let input = [0x01u8];
        assert!(scan_digests(&input, 1).is_err());
    }

    /// Empty input.
    #[test]
    fn scan_digests_empty() {
        assert!(scan_digests(&[], 1).is_err());
    }
}
