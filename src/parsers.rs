use nom::{IResult, Needed};

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
