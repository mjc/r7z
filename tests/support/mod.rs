use std::{env, fs::File, io::Read};

pub fn valid_7z_string() -> Vec<u8> {
    let path = env::current_dir().unwrap().join("tests/fixtures/test_1.7z");
    let mut file = File::open(path).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    buf
}
