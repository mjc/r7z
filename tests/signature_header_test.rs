use r7z::{self, SignatureHeader};
use std::{env, fs::File, io::Read};

#[test]
fn parse_signature() {
    let signature = hex::decode("377abcaf271c").unwrap();
    let vec = vec![];
    let result = (vec.as_slice(), vec![55, 122, 188, 175, 39, 28]);

    assert_eq!(r7z::get_file_signature(&signature).unwrap(), result);
}

#[test]
fn parse_version() {
    let version = vec![0, 4];
    let consumed_input = vec![];
    let result = (consumed_input.as_slice(), (0, 4));

    assert_eq!(r7z::get_version(&version).unwrap(), result);
}

#[test]
fn parse_header_from_string() {
    let path = env::current_dir().unwrap().join("tests/fixtures/test_1.7z");
    let mut file = File::open(path).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();

    let (input, signature_header) = r7z::parse_signature_header(&buf).unwrap();
    assert_eq!(input.len(), 625); // not sure if this is correct yet
    assert_eq!(
        signature_header,
        SignatureHeader {
            signature: hex::decode("377abcaf271c").unwrap(),
            major_version: 0,
            minor_version: 4,
            start_header_crc: 3524221515u32,
            next_header_offset: 590u64,
            next_header_size: 35u64,
            next_header_crc: 2771030271u32
        }
    );
}
