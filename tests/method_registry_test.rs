use r7z::{
    MethodSupport, P7ZIP_ORACLE_SHA, SevenZMethod, method_from_id, method_from_name, method_info,
};

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
        ("PPMd", &[0x03, 0x04, 0x01], SevenZMethod::Ppmd),
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

#[test]
fn method_registry_separates_decode_encode_and_raw_copy_support() {
    let lzma = method_info(r7z::CODEC_LZMA).unwrap();
    assert_eq!(lzma.support, MethodSupport::DecodeAndEncode);
    assert!(lzma.can_decode());
    assert!(lzma.can_encode());

    let deflate = method_info(r7z::CODEC_DEFLATE).unwrap();
    assert_eq!(deflate.support, MethodSupport::DecodeOnly);
    assert!(deflate.can_decode());
    assert!(!deflate.can_encode());

    let zstd = method_info(&[0x04, 0xF7, 0x11, 0x01]).unwrap();
    assert_eq!(zstd.method, SevenZMethod::Zstd);
    assert_eq!(zstd.support, MethodSupport::RawCopyOnly);
    assert!(!zstd.can_decode());
    assert!(!zstd.can_encode());
    assert!(method_info(&[0xFF]).is_none());
}

#[test]
fn method_enum_and_registry_metadata_stay_in_sync() {
    assert_eq!(r7z::ALL_METHODS.len(), r7z::METHOD_REGISTRY.len());
    for method in r7z::ALL_METHODS {
        let info = r7z::METHOD_REGISTRY
            .iter()
            .find(|info| info.method == *method)
            .unwrap_or_else(|| panic!("missing metadata for {method:?}"));
        assert_eq!(method.id(), info.id);
        assert_eq!(method.name(), info.name);
        assert_eq!(method.kind(), info.kind);
        assert_eq!(method.supported_by_r7z(), info.can_decode());
    }
    assert_eq!(method_from_id(r7z::CODEC_LZMA2), Some(SevenZMethod::Lzma2));
}
