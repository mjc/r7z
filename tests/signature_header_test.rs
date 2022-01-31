use r7z::{self, SignatureHeader};
mod support;

#[test]
fn parse_signature_header_from_string() {
    let buf = support::valid_7z_string();
    let (input, signature_header) = r7z::SignatureHeader::parse(&buf).unwrap();
    assert_eq!(input.len(), 625); // not sure if this is correct yet
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
