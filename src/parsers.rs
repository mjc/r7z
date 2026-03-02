use nom::{IResult, Needed};

/// Encode a u64 as a 7z variable-length integer (1–9 bytes).
///
/// Format mirrors `sevenzip_varuint64_decode`: bit (7-i) of the first byte is set
/// when byte (i+1) carries value bits [8i .. 8i+7].
pub fn sevenzip_varuint64_encode(mut value: u64) -> Vec<u8> {
    let mut result = vec![0u8];
    let mut mask: u8 = 0x80;
    loop {
        if value < mask as u64 {
            result[0] |= value as u8;
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

pub fn sevenzip_varuint64_decode(input: &[u8]) -> IResult<&[u8], u64> {
    if input.is_empty() {
        return Err(nom::Err::Incomplete(Needed::new(1)));
    }
    let first_byte = input[0];
    let mut value: u64 = 0;
    let mut mask: u8 = 0x80;
    let mut addr: usize = 0;
    for i in 0..8usize {
        addr += 1;
        if (first_byte & mask) == 0 {
            value += ((first_byte & (mask - 1)) as u64) << (8 * i);
            break;
        }
        if addr >= input.len() {
            return Err(nom::Err::Incomplete(Needed::new(1)));
        }
        let next = input[addr];
        value |= (next as u64) << (8 * i);
        mask >>= 1;
    }
    Ok((&input[addr..], value))
}
