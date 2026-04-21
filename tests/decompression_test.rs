use r7z::{decompress_folder, Archive, CODEC_BCJ_X86, CODEC_LZMA, CODEC_LZMA2};

mod support;

#[test]
fn decompress_lzma_packed_header() {
    let buf = support::valid_7z_string();
    let meta = r7z::ArchiveMetadata::parse(&buf).unwrap();

    let pi = &meta.encoded_header.pack_info;
    let ui = &meta.encoded_header.unpack_info;

    // The packed header stream starts right after the 32-byte SignatureHeader
    // at pack_pos bytes offset.
    let data_start = 32 + usize::try_from(pi.pack_pos).expect("pack_pos fits in usize");
    let data_end = data_start + usize::try_from(pi.pack_size[0]).expect("pack_size fits in usize");
    let packed = &buf[data_start..data_end];

    let folder = ui.parse_folder(0).unwrap();
    // Sanity: LZMA codec
    assert_eq!(folder.coders[0].codec_id.as_slice(), CODEC_LZMA);

    let unpack_size = ui.unpack_sizes[0];
    let decompressed = decompress_folder(&folder, packed, unpack_size).unwrap();

    assert_eq!(
        decompressed.len(),
        usize::try_from(unpack_size).expect("unpack_size fits in usize")
    );
}

#[test]
fn archive_open_and_decompress_header_stream() {
    use std::env;
    let path = env::current_dir().unwrap().join("tests/fixtures/test_1.7z");
    let meta = Archive::open(&path).unwrap();

    let eh = meta.encoded_header.as_ref().unwrap();
    let pi = &eh.pack_info;
    let ui = &eh.unpack_info;

    // Re-read the file to get the packed data
    let buf = std::fs::read(&path).unwrap();
    let data_start = 32 + usize::try_from(pi.pack_pos).expect("pack_pos fits in usize");
    let data_end = data_start + usize::try_from(pi.pack_size[0]).expect("pack_size fits in usize");
    let packed = &buf[data_start..data_end];

    let folder = ui.parse_folder(0).unwrap();
    let unpack_size = ui.unpack_sizes[0];
    let decompressed = decompress_folder(&folder, packed, unpack_size).unwrap();

    assert_eq!(
        decompressed.len(),
        usize::try_from(unpack_size).expect("unpack_size fits in usize")
    );

    // The decompressed bytes should start with a valid 7z property tag
    // (Header = 0x01 or EncodedHeader = 0x17, typically 0x01 for the full header)
    let first_byte = decompressed[0];
    assert!(
        first_byte == 0x01 || first_byte == 0x04,
        "Expected Header (0x01) or MainStreamsInfo (0x04) tag, got 0x{first_byte:02x}"
    );
}
#[test]
fn decompress_bcj_lzma2_fixture() {
    let path = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/bcj_lzma2.7z");
    let archive = Archive::open(&path).expect("failed to open BCJ+LZMA2 fixture");

    // Verify the file listing
    assert_eq!(archive.num_files(), 1);
    let fi = archive.files_info().unwrap();
    assert_eq!(fi.name(0).unwrap(), "prog.bin");

    // Verify streams_info shows BCJ + LZMA2 coders
    let si = archive.streams_info().unwrap();
    let ui = si.unpack_info.as_ref().unwrap();
    let folder = ui.parse_folder(0).unwrap();
    assert_eq!(folder.coders.len(), 2, "expected 2 coders (LZMA2 + BCJ)");

    // Check that one coder is LZMA2 and the other is BCJ
    let codec_ids: Vec<&[u8]> = folder
        .coders
        .iter()
        .map(|c| c.codec_id.as_slice())
        .collect();
    assert!(codec_ids.contains(&CODEC_LZMA2), "expected LZMA2 coder");
    assert!(codec_ids.contains(&CODEC_BCJ_X86), "expected BCJ x86 coder");

    // Verify bind pairs exist
    assert_eq!(folder.bind_pairs.len(), 1, "expected 1 bind pair");

    // Extract the file and validate against fixture-local invariants.
    let extracted = archive.extract_to_memory(0).unwrap();
    assert_eq!(extracted.len(), 4096, "expected 4096 bytes");
    assert_eq!(crc32fast::hash(&extracted), 0x5723_650d);
}
