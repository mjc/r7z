use r7z::{Archive, ArchiveMetadata};

mod support;

#[test]
fn parse_archive_metadata_from_test_fixture() {
    let buf = support::valid_7z_string();
    let meta = ArchiveMetadata::parse(&buf).unwrap();

    // SignatureHeader sanity checks
    assert_eq!(meta.signature.major_version, 0x00);
    assert_eq!(meta.signature.minor_version, 0x04);
    assert_eq!(meta.signature.next_header_size, 35);

    // EncodedHeader: PackInfo
    assert_eq!(meta.encoded_header.pack_info.num_pack_streams, 1);
    assert_eq!(meta.encoded_header.pack_info.pack_size.len(), 1);

    // EncodedHeader: UnpackInfo — 1 folder with LZMA coder
    let ui = &meta.encoded_header.unpack_info;
    assert_eq!(ui.num_folders, 1);
    assert_eq!(ui.unpack_sizes.len(), 1);

    let folder = ui.parse_folder(0).unwrap();
    assert_eq!(folder.coders.len(), 1);
    // LZMA codec ID
    assert_eq!(folder.coders[0].codec_id.as_slice(), &[0x03, 0x01, 0x01]);
    // LZMA properties present (5 bytes)
    assert_eq!(
        folder.coders[0].properties.as_deref().map(<[u8]>::len),
        Some(5)
    );
    // 1 in-stream, 1 out-stream
    assert_eq!(folder.coders[0].num_in_streams, 1);
    assert_eq!(folder.coders[0].num_out_streams, 1);
    // No bind pairs for single coder
    assert_eq!(folder.bind_pairs.len(), 0);

    // CRC digest for folder
    assert_eq!(ui.digests.len(), 1);
    assert!(ui.digests[0].is_some());
}

#[test]
fn validate_crc_test_fixture() {
    let buf = support::valid_7z_string();
    let (_, sig) = r7z::SignatureHeader::parse(&buf).unwrap();
    sig.validate_start_header_crc().unwrap();
}

#[test]
fn archive_open_full_header() {
    use std::env;
    let path = env::current_dir().unwrap().join("tests/fixtures/test_1.7z");
    let archive = Archive::open(&path).unwrap();

    // Signature
    assert_eq!(archive.signature.major_version, 0x00);

    // Encoded header
    let eh = archive.encoded_header.as_ref().unwrap();
    assert_eq!(eh.unpack_info.num_folders, 1);
    // LZMA header codec
    assert_eq!(
        eh.unpack_info.parse_folder(0).unwrap().coders[0]
            .codec_id
            .as_slice(),
        &[0x03, 0x01, 0x01]
    );

    // Full header: file listing
    assert_eq!(archive.num_files(), 4); // 1 dir + 3 files

    let fi = archive.files_info().unwrap();
    assert_eq!(fi.num_files, 4);
    assert_eq!(fi.name(0).unwrap(), "scripts");
    assert_eq!(fi.name(1).unwrap(), "scripts/py7zr");
    assert_eq!(fi.name(2).unwrap(), "setup.cfg");
    assert_eq!(fi.name(3).unwrap(), "setup.py");

    // StreamsInfo: LZMA2 file data codec
    let si = archive.streams_info().unwrap();
    let ui = si.unpack_info.as_ref().unwrap();
    assert_eq!(
        ui.parse_folder(0).unwrap().coders[0].codec_id.as_slice(),
        &[0x21]
    ); // LZMA2
}
