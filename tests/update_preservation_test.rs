#![allow(clippy::pedantic)]

mod support;

use std::{fs, io::Cursor, path::PathBuf, process::Command};

use support::{
    assert_extracted_files, create_p7zip_archive, extract_with_p7zip, run_7z_checked,
    try_create_p7zip_archive,
};
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
        .raw_streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap();

    let raw = unpack_info.folder_bytes(0).unwrap();
    let folder_from_bytes = r7z::raw::Folder::parse(raw).unwrap().1;
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
    let block = archive
        .raw_folder(r7z::update::v1::FolderIndex::new(0))
        .unwrap();

    assert_eq!(block.folder_index(), r7z::update::v1::FolderIndex::new(0));
    assert_eq!(block.packed_streams().len(), block.pack_sizes().len());
    assert!(
        block.packed_streams().len() > 1,
        "BCJ2 fixture should have multiple packed streams"
    );
    assert_eq!(
        block
            .packed_streams()
            .iter()
            .map(|stream| stream.len() as u64)
            .collect::<Vec<_>>(),
        block.pack_sizes()
    );
    assert_eq!(
        r7z::raw::Folder::parse(block.folder_info()).unwrap().1,
        archive
            .raw_streams_info()
            .unwrap()
            .unpack_info
            .as_ref()
            .unwrap()
            .parse_folder(0)
            .unwrap()
    );
}

#[test]
fn preserved_raw_multi_pack_folder_uses_the_shared_folder_writer() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    let data = vec![0x90u8; 4096];
    fs::write(input.join("program.bin"), &data).unwrap();
    let archive_path = tmp.path().join("bcj2.7z");
    create_p7zip_archive(
        &input,
        &archive_path,
        &["program.bin"],
        &["-m0=BCJ2", "-m1=LZMA2", "-mmt=off"],
    );

    let archive = r7z::Archive::open(&archive_path).unwrap();
    let entry = archive.entries().next().unwrap();
    let raw = archive
        .raw_folder(r7z::update::v1::FolderIndex::new(0))
        .unwrap();
    assert!(raw.packed_streams().len() > 1);
    let output = r7z::update::v1::write_archive_update(
        &archive,
        Cursor::new(Vec::new()),
        vec![r7z::update::v1::PreservedArchiveEntry {
            name: entry.name,
            raw_name: entry.raw_name,
            kind: r7z::EntryKind::File,
            meta: r7z::EntryMeta::default(),
            stream: r7z::update::v1::PreservedEntryStream::Raw {
                folder: raw.handle(),
                source_entry: r7z::update::v1::ArchiveEntryIndex::new(0),
                size: data.len() as u64,
                crc: Some(crc32fast::hash(&data)),
            },
        }],
        vec![raw],
        &r7z::ArchiveOptions::default(),
    )
    .unwrap();
    let rewritten = r7z::Archive::from_bytes(output.into_inner().into()).unwrap();
    assert_eq!(
        rewritten
            .extract_to_memory(r7z::ArchiveEntryIndex::new(0))
            .unwrap(),
        data
    );
}

#[test]
fn raw_folder_handles_cannot_cross_archive_updates() {
    let data = b"archive-owned raw data".repeat(128);
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("kept.bin", &data)
        .build()
        .unwrap();
    let source = r7z::Archive::from_bytes(bytes.clone().into()).unwrap();
    let other = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let entry = source.entries().next().unwrap();
    let raw = other
        .raw_folder(r7z::update::v1::FolderIndex::new(0))
        .unwrap();
    let raw_handle = raw.handle();
    let original_output = vec![0xA5; 8];
    let mut output = Cursor::new(original_output.clone());

    assert!(matches!(
        r7z::update::v1::write_archive_update(
            &source,
            &mut output,
            vec![r7z::update::v1::PreservedArchiveEntry {
                name: entry.name,
                raw_name: entry.raw_name,
                kind: r7z::EntryKind::File,
                meta: r7z::EntryMeta::default(),
                stream: r7z::update::v1::PreservedEntryStream::Raw {
                    folder: raw_handle,
                    source_entry: r7z::update::v1::ArchiveEntryIndex::new(0),
                    size: data.len() as u64,
                    crc: Some(crc32fast::hash(&data)),
                },
            }],
            vec![raw],
            &r7z::ArchiveOptions::default(),
        ),
        Err(r7z::R7zError::ArchiveMismatch)
    ));
    assert_eq!(output.into_inner(), original_output);
}

#[test]
fn raw_folder_updates_require_complete_contiguous_source_entries() {
    let data = b"solid source entry".repeat(128);
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("first.bin", &data)
        .add_file("second.bin", &data)
        .build()
        .unwrap();
    let source = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let listing = source.listing(None).unwrap();
    assert_eq!(listing.entries[0].block, listing.entries[1].block);
    let folder_index = listing.entries[0].block.unwrap();
    let raw = source.raw_folder(folder_index).unwrap();
    let raw_entry = |name: &str, source_entry: usize| r7z::update::v1::PreservedArchiveEntry {
        name: name.to_owned(),
        raw_name: None,
        kind: r7z::EntryKind::File,
        meta: r7z::EntryMeta::default(),
        stream: r7z::update::v1::PreservedEntryStream::Raw {
            folder: raw.handle(),
            source_entry: r7z::update::v1::ArchiveEntryIndex::new(source_entry),
            size: data.len() as u64,
            crc: Some(crc32fast::hash(&data)),
        },
    };
    let mut output = Cursor::new(vec![0xA5; 8]);
    let original_output = output.get_ref().clone();

    assert!(matches!(
        r7z::update::v1::write_archive_update(
            &source,
            &mut output,
            vec![raw_entry("first.bin", 0)],
            vec![raw.clone()],
            &r7z::ArchiveOptions::default(),
        ),
        Err(r7z::R7zError::InvalidRawFolderLayout)
    ));
    assert_eq!(output.get_ref(), &original_output);

    assert!(matches!(
        r7z::update::v1::write_archive_update(
            &source,
            &mut output,
            vec![raw_entry("second.bin", 1), raw_entry("first.bin", 0)],
            vec![raw.clone()],
            &r7z::ArchiveOptions::default(),
        ),
        Err(r7z::R7zError::InvalidRawFolderLayout)
    ));
    assert_eq!(output.get_ref(), &original_output);

    assert!(matches!(
        r7z::update::v1::write_archive_update(
            &source,
            &mut output,
            vec![
                raw_entry("first.bin", 0),
                r7z::update::v1::PreservedArchiveEntry {
                    name: "added.bin".to_owned(),
                    raw_name: None,
                    kind: r7z::EntryKind::File,
                    meta: r7z::EntryMeta::default(),
                    stream: r7z::update::v1::PreservedEntryStream::Data(data.clone()),
                },
                raw_entry("second.bin", 1),
            ],
            vec![raw],
            &r7z::ArchiveOptions::default(),
        ),
        Err(r7z::R7zError::InvalidRawFolderLayout)
    ));
    assert_eq!(output.into_inner(), original_output);
}

#[test]
fn preserved_raw_folder_can_share_an_archive_with_streamed_ppmd_data() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    let kept = vec![0xA5; 4096];
    fs::write(input.join("kept.bin"), &kept).unwrap();
    let source_path = tmp.path().join("source.7z");
    create_p7zip_archive(&input, &source_path, &["kept.bin"], &["-m0=LZMA2"]);

    let source = r7z::Archive::open(&source_path).unwrap();
    let kept_entry = source.entries().next().unwrap();
    let raw = source
        .raw_folder(r7z::update::v1::FolderIndex::new(0))
        .unwrap();
    let added = b"new ppmd data".repeat(128);
    let added_path = tmp.path().join("added-source.txt");
    fs::write(&added_path, &added).unwrap();
    let options = r7z::ArchiveOptions {
        codec: r7z::Codec::Ppmd,
        encryption: Some(r7z::EncryptionOptions::default_for_password("Secret123")),
        ..r7z::ArchiveOptions::default()
    };
    let output = r7z::update::v1::write_archive_update(
        &source,
        Cursor::new(Vec::new()),
        vec![
            r7z::update::v1::PreservedArchiveEntry {
                name: kept_entry.name,
                raw_name: kept_entry.raw_name,
                kind: r7z::EntryKind::File,
                meta: r7z::EntryMeta::default(),
                stream: r7z::update::v1::PreservedEntryStream::Raw {
                    folder: raw.handle(),
                    source_entry: r7z::update::v1::ArchiveEntryIndex::new(0),
                    size: kept.len() as u64,
                    crc: Some(crc32fast::hash(&kept)),
                },
            },
            r7z::update::v1::PreservedArchiveEntry {
                name: "added.txt".to_owned(),
                raw_name: None,
                kind: r7z::EntryKind::File,
                meta: r7z::EntryMeta::default(),
                stream: r7z::update::v1::PreservedEntryStream::Path {
                    path: added_path,
                    size: added.len() as u64,
                },
            },
        ],
        vec![raw],
        &options,
    )
    .unwrap();
    let archive_path = tmp.path().join("mixed.7z");
    fs::write(&archive_path, output.into_inner()).unwrap();
    let rewritten = r7z::Archive::open_with_password(&archive_path, Some("Secret123")).unwrap();
    assert_eq!(
        rewritten
            .extract_to_memory_with_password(r7z::ArchiveEntryIndex::new(0), Some("Secret123"))
            .unwrap(),
        kept
    );
    assert_eq!(
        rewritten
            .extract_to_memory_with_password(r7z::ArchiveEntryIndex::new(1), Some("Secret123"))
            .unwrap(),
        added
    );

    let out_dir = tmp.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let out_arg = format!("-o{}", out_dir.display());
    run_7z_checked(
        &[
            "x",
            "-y",
            "-pSecret123",
            archive_path.to_str().unwrap(),
            &out_arg,
        ],
        tmp.path(),
    );
    assert_extracted_files(
        &out_dir,
        &[
            (PathBuf::from("kept.bin"), kept),
            (PathBuf::from("added.txt"), added),
        ],
    );
}

#[test]
fn update_keeps_raw_name_distinct_from_its_replacement_character_display() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    let new_file = input.join("�");
    fs::write(&new_file, b"new").unwrap();
    let archive_path = tmp.path().join("raw-name.7z");
    let original_name = r7z::raw::RawEntryName::from_utf16le(vec![0x00, 0xD8]).unwrap();
    let bytes = r7z::update::v1::build_archive_with_preserved_folders(
        vec![r7z::update::v1::PreservedArchiveEntry {
            name: "�".to_owned(),
            raw_name: Some(original_name.clone()),
            kind: r7z::EntryKind::File,
            meta: r7z::EntryMeta::default(),
            stream: r7z::update::v1::PreservedEntryStream::Data(b"old".to_vec()),
        }],
        Vec::new(),
        &r7z::ArchiveOptions::default(),
    )
    .unwrap();
    fs::write(&archive_path, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "u",
            archive_path.to_str().unwrap(),
            new_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "r7z update failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let entries = r7z::Archive::open(&archive_path)
        .unwrap()
        .entries()
        .collect::<Vec<_>>();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].raw_name.as_ref(), Some(&original_name));
    assert_eq!(
        entries[1].raw_name.as_ref().unwrap().as_utf16le(),
        &[0xFD, 0xFF]
    );

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(["d", archive_path.to_str().unwrap(), "�"])
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "r7z delete failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let entries = r7z::Archive::open(&archive_path)
        .unwrap()
        .entries()
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].raw_name.as_ref(), Some(&original_name));
}

fn create_zstd_archive_or_skip(
    input: &std::path::Path,
    archive: &std::path::Path,
    files: &[&str],
    args: &[&str],
) -> bool {
    let out = try_create_p7zip_archive(input, archive, files, args);
    if out.status.success() {
        true
    } else {
        eprintln!(
            "skipping ZSTD preservation test; this p7zip does not support the requested ZSTD fixture\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        false
    }
}

#[test]
fn updating_archive_with_retained_zstd_folder_succeeds() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("original.txt"), b"original").unwrap();
    fs::write(input.join("new.txt"), b"new").unwrap();
    let archive = tmp.path().join("zstd-update.7z");

    if !create_zstd_archive_or_skip(&input, &archive, &["original.txt"], &["-m0=ZSTD"]) {
        return;
    }

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

    if !create_zstd_archive_or_skip(&input, &archive, &["original.txt"], &["-m0=ZSTD"]) {
        return;
    }

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

    if !create_zstd_archive_or_skip(&input, &archive, &["same.txt"], &["-m0=ZSTD"]) {
        return;
    }
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

    if !create_zstd_archive_or_skip(
        &input,
        &archive,
        &["a.txt", "b.txt"],
        &["-m0=ZSTD", "-ms=off"],
    ) {
        return;
    }

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

#[test]
fn deleting_part_of_solid_zstd_folder_fails_without_rewriting_archive() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    fs::write(input.join("b.txt"), b"bravo").unwrap();
    let archive = tmp.path().join("zstd-solid-delete.7z");

    if !create_zstd_archive_or_skip(
        &input,
        &archive,
        &["a.txt", "b.txt"],
        &["-m0=ZSTD", "-ms=on"],
    ) {
        return;
    }
    let before = fs::read(&archive).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(["d", archive.to_str().unwrap(), "a.txt"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "partial unsupported delete unexpectedly succeeded"
    );
    assert_eq!(fs::read(&archive).unwrap(), before);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("would require decoding retained entry"));
    assert!(stderr.contains("unsupported codec"));
}

#[test]
fn replacing_part_of_solid_zstd_folder_fails_without_rewriting_archive() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    fs::write(input.join("b.txt"), b"bravo").unwrap();
    let archive = tmp.path().join("zstd-solid-replace.7z");

    if !create_zstd_archive_or_skip(
        &input,
        &archive,
        &["a.txt", "b.txt"],
        &["-m0=ZSTD", "-ms=on"],
    ) {
        return;
    }
    let before = fs::read(&archive).unwrap();
    fs::write(input.join("a.txt"), b"new alpha").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "u",
            archive.to_str().unwrap(),
            input.join("a.txt").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "partial unsupported replace unexpectedly succeeded"
    );
    assert_eq!(fs::read(&archive).unwrap(), before);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("would require decoding retained entry"));
    assert!(stderr.contains("unsupported codec"));
}

#[test]
fn deleting_part_of_solid_lzma2_folder_decodes_retained_entries() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    fs::write(input.join("b.txt"), b"bravo").unwrap();
    let archive = tmp.path().join("lzma2-solid-delete.7z");

    create_p7zip_archive(
        &input,
        &archive,
        &["a.txt", "b.txt"],
        &["-m0=LZMA2", "-ms=on"],
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
}

#[test]
fn replacing_part_of_solid_lzma2_folder_decodes_retained_entries() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    fs::write(input.join("b.txt"), b"bravo").unwrap();
    let archive = tmp.path().join("lzma2-solid-replace.7z");

    create_p7zip_archive(
        &input,
        &archive,
        &["a.txt", "b.txt"],
        &["-m0=LZMA2", "-ms=on"],
    );
    fs::write(input.join("a.txt"), b"new alpha").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "u",
            archive.to_str().unwrap(),
            input.join("a.txt").to_str().unwrap(),
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
    assert_extracted_files(
        &out,
        &[
            (PathBuf::from("a.txt"), b"new alpha".to_vec()),
            (PathBuf::from("b.txt"), b"bravo".to_vec()),
        ],
    );
}
