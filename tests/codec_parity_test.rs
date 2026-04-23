mod support;

use arrayvec::ArrayVec;
use smallvec::{SmallVec, smallvec};

use support::create_p7zip_archive;

fn coder_id(id: &[u8]) -> ArrayVec<u8, 15> {
    let mut out = ArrayVec::new();
    out.try_extend_from_slice(id).unwrap();
    out
}

fn single_lzma2_folder(properties: &[u8]) -> r7z::Folder {
    r7z::Folder {
        coders: smallvec![r7z::CoderInfo {
            codec_id: coder_id(r7z::CODEC_LZMA2),
            num_in_streams: 1,
            num_out_streams: 1,
            properties: Some(SmallVec::from_slice(properties)),
        }],
        bind_pairs: SmallVec::new(),
        packed_indices: SmallVec::new(),
    }
}

#[test]
fn lzma_property_block_from_archive_builder_is_exactly_five_bytes() {
    let bytes = r7z::ArchiveBuilder::new()
        .compression(r7z::Codec::Lzma)
        .add_file("payload.txt", b"payload")
        .build()
        .expect("build failed");
    let archive = r7z::Archive::from_bytes(bytes.into()).expect("from_bytes failed");
    let ui = archive
        .streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap();
    let folder = ui.parse_folder(0).unwrap();

    assert_eq!(folder.coders[0].codec_id.as_slice(), r7z::CODEC_LZMA);
    assert_eq!(folder.coders[0].properties.as_ref().unwrap().len(), 5);
}

#[test]
fn p7zip_lzma2_property_values_extract_with_r7z() {
    for (dict_arg, len) in [
        ("-md=64K", 128 * 1024),
        ("-md=1M", 2 * 1024 * 1024),
        ("-md=16M", 3 * 1024 * 1024),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let payload: Vec<u8> = (0u8..=251).cycle().take(len).collect();
        std::fs::write(dir.join("payload.bin"), &payload).unwrap();

        let archive_path = dir.join(format!("lzma2_dict_{len}.7z"));
        create_p7zip_archive(
            dir,
            &archive_path,
            &["payload.bin"],
            &["-m0=lzma2", dict_arg],
        );

        let archive = r7z::Archive::open(&archive_path).unwrap();
        let ui = archive
            .streams_info()
            .unwrap()
            .unpack_info
            .as_ref()
            .unwrap();
        let folder = ui.parse_folder(0).unwrap();
        let lzma2 = folder
            .coders
            .iter()
            .find(|coder| coder.codec_id.as_slice() == r7z::CODEC_LZMA2)
            .expect("expected LZMA2 coder");
        let properties = lzma2.properties.as_ref().unwrap();
        assert_eq!(properties.len(), 1);
        assert!(
            properties[0] <= 40,
            "p7zip emitted unsupported LZMA2 property {} for {dict_arg}",
            properties[0]
        );
        assert_eq!(archive.extract_to_memory(0).unwrap(), payload);
    }
}

#[test]
fn lzma2_property_values_zero_through_forty_decode_empty_stream_without_panic() {
    for prop in 0u8..=40 {
        let folder = single_lzma2_folder(&[prop]);
        let result = std::panic::catch_unwind(|| r7z::decompress_folder(&folder, &[0x00], 0));
        assert!(result.is_ok(), "LZMA2 property {prop} panicked");
        assert_eq!(result.unwrap().unwrap(), Vec::<u8>::new());
    }
}

#[test]
fn unsupported_lzma2_property_shapes_return_r7z_errors() {
    for properties in [&[][..], &[0x1c, 0x00][..], &[41][..]] {
        let folder = single_lzma2_folder(properties);
        let result = std::panic::catch_unwind(|| r7z::decompress_folder(&folder, &[0x00], 0));
        assert!(
            result.is_ok(),
            "LZMA2 properties {properties:?} panicked instead of returning an error"
        );
        let err = result.unwrap().unwrap_err();
        assert!(
            matches!(err, r7z::R7zError::Decompression | r7z::R7zError::Parse),
            "expected Decompression or Parse for {properties:?}, got {err:?}"
        );
    }
}
