use r7z::sevenzip_varuint64_decode;

mod support;

#[test]
fn sevenzip_varuint64_decode_zero() {
    let input = [0x00];
    let (_input, result) = sevenzip_varuint64_decode(&input).unwrap();
    assert_eq!(result, 0);
}

#[test]
fn sevenzip_varuint64_decode_max_single_byte() {
    let input = [0x7f];
    let (_input, result) = sevenzip_varuint64_decode(&input).unwrap();
    assert_eq!(result, 127);
}

#[test]
fn sevenzip_varuint64_decode_128() {
    // 128 requires 2 bytes: first byte = 0x80 (continuation), second = 128
    let input = [0x80, 0x80];
    let (_input, result) = sevenzip_varuint64_decode(&input).unwrap();
    assert_eq!(result, 128);
}

#[test]
fn sevenzip_varuint64_decode_length_1() {
    let input = [1];
    let (_input, result) = sevenzip_varuint64_decode(&input).unwrap();
    assert_eq!(result, 1);
}

#[test]
fn sevenzip_varuint64_decode_length_2() {
    let input = [129, 185];
    let (_input, result) = sevenzip_varuint64_decode(&input).unwrap();
    assert_eq!(result, 441);
}

#[test]
fn sevenzip_varuint64_decode_length_9_consumes_all_bytes() {
    let input = [0xff, 1, 0, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x3f, 0xee];
    let (remaining, result) = sevenzip_varuint64_decode(&input).unwrap();

    assert_eq!(result, 0x3f12_3456_789a_0001);
    assert_eq!(remaining, &[0xee]);
}

#[test]
fn sevenzip_varuint64_decode_incomplete() {
    let input = [];
    let result = sevenzip_varuint64_decode(&input);
    assert!(result.is_err());
}
