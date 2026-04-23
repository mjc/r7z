#![allow(clippy::pedantic)]

mod support;

use std::{fs, path::PathBuf, process::Command};

use support::{assert_extracted_files, create_p7zip_archive, extract_with_p7zip, run_7z_checked};
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

#[test]
fn updating_archive_with_retained_zstd_folder_succeeds() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("original.txt"), b"original").unwrap();
    fs::write(input.join("new.txt"), b"new").unwrap();
    let archive = tmp.path().join("zstd-update.7z");

    create_p7zip_archive(&input, &archive, &["original.txt"], &["-m0=ZSTD"]);

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "u",
            archive.to_str().unwrap(),
            input.join("new.txt").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "r7z update failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let list = run_7z_checked(&["l", "-slt", archive.to_str().unwrap()], tmp.path());
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("Path = original.txt"));
    assert!(stdout.contains("Path = new.txt"));
    assert!(stdout.contains("Method = ZSTD"));
}

#[test]
fn deleting_only_file_from_zstd_archive_succeeds() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("original.txt"), b"original").unwrap();
    let archive = tmp.path().join("zstd-delete.7z");

    create_p7zip_archive(&input, &archive, &["original.txt"], &["-m0=ZSTD"]);

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(["d", archive.to_str().unwrap(), "original.txt"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "r7z delete failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let list = run_7z_checked(&["l", "-slt", archive.to_str().unwrap()], tmp.path());
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(!stdout.contains("Path = original.txt"));
}

#[test]
fn updating_same_name_zstd_file_replaces_without_decoding_old_folder() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("same.txt"), b"old").unwrap();
    let archive = tmp.path().join("zstd-replace.7z");

    create_p7zip_archive(&input, &archive, &["same.txt"], &["-m0=ZSTD"]);
    fs::write(input.join("same.txt"), b"new").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "u",
            archive.to_str().unwrap(),
            input.join("same.txt").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "r7z update failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let out = tmp.path().join("out");
    extract_with_p7zip(tmp.path(), &archive, &out);
    assert_extracted_files(&out, &[(PathBuf::from("same.txt"), b"new".to_vec())]);
}

#[test]
fn deleting_one_non_solid_zstd_file_preserves_other_raw_folder() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    fs::write(input.join("b.txt"), b"bravo").unwrap();
    let archive = tmp.path().join("zstd-nonsolid-delete.7z");

    create_p7zip_archive(
        &input,
        &archive,
        &["a.txt", "b.txt"],
        &["-m0=ZSTD", "-ms=off"],
    );

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(["d", archive.to_str().unwrap(), "a.txt"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "r7z delete failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let out = tmp.path().join("out");
    extract_with_p7zip(tmp.path(), &archive, &out);
    assert_extracted_files(&out, &[(PathBuf::from("b.txt"), b"bravo".to_vec())]);
    assert!(!out.join("a.txt").exists());

    let list = run_7z_checked(&["l", "-slt", archive.to_str().unwrap()], tmp.path());
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("Path = b.txt"));
    assert!(stdout.contains("Method = ZSTD"));
}
