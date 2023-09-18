pub fn sevenzip_varuint64_decode(input: &[u8]) -> (&[u8], u64) {
    let mut value: u64 = 0;
    let mut mask: u8 = 0x80;
    let mut addr: usize = 0;
    let first_byte: u8 = input[0];
    for i in 0..8 {
        addr += 1;

        if (first_byte & mask) == 0 {
            value += ((first_byte & (mask - 1)) as u64) << (8 * i);
            break;
        }
        let next = input[addr];
        value |= (next << (8 * i)) as u64;
        mask >>= 1;
    }
    let (_consumed, input) = input.split_at(addr);

    (&input, value)
}
