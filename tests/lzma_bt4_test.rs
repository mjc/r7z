use std::io::{Read, Write};

use lzma_rust2::{Lzma2Options, Lzma2Reader, Lzma2Writer};
use sha2::{Digest, Sha256};

fn boundary_payload() -> Vec<u8> {
    let mut input = Vec::new();
    // Equal prefixes end at every offset, including both sides of native-word
    // and nice-length boundaries. The stream wraps the 4 KiB dictionary often.
    for mismatch in 0..=273 {
        let mut block = vec![b'a'; 289];
        block[mismatch] = b'b';
        input.extend_from_slice(&block);
        input.push(0xfe);
    }
    let mut random = 0x1234_5678_u32;
    for _ in 0..16_384 {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        input.push(random.to_le_bytes()[0]);
    }
    input.extend_from_slice(b"aaaaaaa");
    input
}

#[test]
fn bt4_word_scan_preserves_reference_bitstream() {
    let input = boundary_payload();
    // Captured from 0.21.0's unmodified BT4 encoder before applying the scan
    // optimization. These check encoded decisions as well as round-trip data.
    for (nice_len, expected) in [
        (
            8,
            "ff6e704cc6243892f91fd337418d4323544202ba259b163cf780747e8da362e6",
        ),
        (
            31,
            "74c3ab12cfcdf2a5f24425901aa486c644daa8499115e66c7723038b0b209abf",
        ),
        (
            32,
            "b152c3889e84733a4f022b1ddf53f5b6b1a18dd148ce95fac3410d091171572a",
        ),
        (
            33,
            "7e5611108228704342fc5a4e39aedcf46f7fa95085301a78131aee7fd0421e20",
        ),
        (
            64,
            "3a6e7283c820d213ccd3fabcc89bd23b67e73d05ee1f75dce82ca82488ab4793",
        ),
        (
            273,
            "0b541faaecd32e717fa6ce68075891e678b4f66eea92f306495313242eca8249",
        ),
    ] {
        let mut options = Lzma2Options::with_preset(5);
        options.lzma_options.dict_size = 4096;
        options.lzma_options.nice_len = nice_len;
        options.lzma_options.depth_limit = 32;
        let mut writer = Lzma2Writer::new(Vec::new(), options);
        for part in input.chunks(997) {
            writer.write_all(part).unwrap();
        }
        let compressed = writer.finish().unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&compressed)),
            expected,
            "BT4 bitstream changed with nice_len={nice_len}"
        );
        let mut decoded = Vec::new();
        Lzma2Reader::new(compressed.as_slice(), 4096, None)
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, input);
    }
}
