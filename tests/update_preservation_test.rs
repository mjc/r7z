#![allow(clippy::pedantic)]

mod support;

use std::fs;

use support::create_p7zip_archive;
use tempfile::tempdir;

#[test]
fn unpack_info_folder_bytes_round_trip_to_folder_parser() {
    let bytes = r7z::ArchiveBuilder::new()
        .compression(r7z::Codec::Lzma2Bcj)
        .add_file("program.bin", &[0x90, 0xE8, 0, 0, 0, 0, 0x90])
        .build()
        .unwrap();
    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let unpack_info = archive
        .streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap();

    let raw = unpack_info.folder_bytes(0).unwrap();
    let folder_from_bytes = r7z::Folder::parse(raw).unwrap().1;
    let folder_from_index = unpack_info.parse_folder(0).unwrap();

    assert_eq!(folder_from_bytes, folder_from_index);
}

#[test]
fn raw_folder_block_exposes_multi_pack_stream_metadata() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("program.bin"), vec![0x90u8; 4096]).unwrap();
    let archive_path = tmp.path().join("bcj2.7z");

    create_p7zip_archive(
        &input,
        &archive_path,
        &["program.bin"],
        &["-m0=BCJ2", "-m1=LZMA2", "-mmt=off"],
    );

    let archive = r7z::Archive::open(&archive_path).unwrap();
    let block = archive.raw_folder_block(0).unwrap();

    assert_eq!(block.folder_index, 0);
    assert_eq!(block.packed_streams.len(), block.pack_sizes.len());
    assert!(
        block.packed_streams.len() > 1,
        "BCJ2 fixture should have multiple packed streams"
    );
    assert_eq!(
        block
            .packed_streams
            .iter()
            .map(|stream| stream.len() as u64)
            .collect::<Vec<_>>(),
        block.pack_sizes
    );
    assert_eq!(
        r7z::Folder::parse(&block.folder_info).unwrap().1,
        archive
            .streams_info()
            .unwrap()
            .unpack_info
            .as_ref()
            .unwrap()
            .parse_folder(0)
            .unwrap()
    );
}
