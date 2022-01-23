use r7z::{self, SignatureHeader};
use std::{
    env,
    fs::File,
    io::{BufReader, Read},
};

#[test]
fn parse_header_from_string() {
    let mut path = env::current_dir()
        .unwrap()
        .join("tests/signature_header_test.rs");
    path.join("tests/fixtures/test_1.7z");
    let mut file = File::open(path).unwrap();
    let mut buf = String::new();
    file.read_to_string(&mut buf);
    let (input, signature_header) = r7z::parse_signature_header(&buf.as_bytes()).unwrap();
    let input = assert_eq!(
        signature_header,
        SignatureHeader {
            signature: vec![117, 115, 101, 32, 114, 55],
            major_version: 122u8,
            minor_version: 58u8,
            start_header_crc: 1702067002u32,
            next_header_offset: 7955443072516253292u64,
            next_header_size: 7018095194875982945u64,
            next_header_crc: 2104649060u32
        }
    );
}
