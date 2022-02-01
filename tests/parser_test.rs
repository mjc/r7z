use r7z::sevenzip_varuint64_decode;

mod support;

#[test]
fn sevenzip_varuint64_decode_length_1() {
    let input = [1];
    let (_input, result) = sevenzip_varuint64_decode(&input);
    assert_eq!(result, 1);
}

#[test]
fn sevenzip_varuint64_decode_length_2() {
    let input = [129, 185];
    let (_input, result) = sevenzip_varuint64_decode(&input);
    assert_eq!(result, 441);
}
