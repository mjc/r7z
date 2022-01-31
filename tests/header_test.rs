use nom::ToUsize;
use r7z::{self, find_next_property_id, SignatureHeader};
mod support;

#[test]
fn parse_signature_header_from_string() {
    let buf = support::valid_7z_string();
    let file_length = buf.len();
    assert_eq!(file_length, 657);
    let (input, signature_header) = r7z::SignatureHeader::parse(&buf).unwrap();
    assert_eq!(input.len(), file_length - 32);
    assert_eq!(
        signature_header,
        SignatureHeader {
            signature: hex::decode("377abcaf271c").unwrap(),
            major_version: 0x00,
            minor_version: 0x04,
            start_header_crc: 0xd20f5a4b,
            next_header_offset: 0x24e,
            next_header_size: 35u64,
            next_header_crc: 0xa52a90ff
        }
    );
}

// #[test]
// fn parse_encoded_header_from_string() {
//     let buf = support::valid_7z_string();
//     let (input, signature_header) = r7z::SignatureHeader::parse(&buf).unwrap();
//     let offset = signature_header.next_header_offset.to_usize();
//     let (input, property_id) = find_next_property_id(input, offset).unwrap();
//     assert_eq!(property_id, r7z::Property::EncodedHeader);

//     let (input, encoded_header) = r7z::EncodedHeader::parse(input).unwrap();
// }
