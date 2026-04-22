use r7z::{method_from_id, method_from_name, SevenZMethod, P7ZIP_ORACLE_SHA};

#[test]
fn p7zip_oracle_sha_is_pinned() {
    assert_eq!(P7ZIP_ORACLE_SHA, "6819e2dc1917e1267babddc6391cea56ead7123d");
}

#[test]
fn method_registry_tracks_current_p7zip_extension_ids() {
    let cases = [
        ("Copy", &[0x00][..], SevenZMethod::Copy),
        ("LZMA", &[0x03, 0x01, 0x01], SevenZMethod::Lzma),
        ("LZMA2", &[0x21], SevenZMethod::Lzma2),
        ("BZip2", &[0x04, 0x02, 0x02], SevenZMethod::BZip2),
        ("Deflate", &[0x04, 0x01, 0x08], SevenZMethod::Deflate),
        ("Deflate64", &[0x04, 0x01, 0x09], SevenZMethod::Deflate64),
        ("BCJ2", &[0x03, 0x03, 0x01, 0x1B], SevenZMethod::Bcj2),
        ("ZSTD", &[0x04, 0xF7, 0x11, 0x01], SevenZMethod::Zstd),
        ("BROTLI", &[0x04, 0xF7, 0x11, 0x02], SevenZMethod::Brotli),
        ("LZ4", &[0x04, 0xF7, 0x11, 0x04], SevenZMethod::Lz4),
        ("LZ5", &[0x04, 0xF7, 0x11, 0x05], SevenZMethod::Lz5),
        ("LIZARD", &[0x04, 0xF7, 0x11, 0x06], SevenZMethod::Lizard),
        ("LZHAM", &[0x04, 0xF7, 0x10, 0x01], SevenZMethod::Lzham),
        ("7zAES", &[0x06, 0xF1, 0x07, 0x01], SevenZMethod::SevenZAes),
    ];

    for (name, id, method) in cases {
        assert_eq!(method_from_name(name), Some(method));
        assert_eq!(method_from_id(id), Some(method));
    }
}
