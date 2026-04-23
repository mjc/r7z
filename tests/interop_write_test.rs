#![allow(clippy::pedantic)]

//! Write-interop tests: create archives with r7z, extract with p7zip, byte-compare.

mod support;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use support::{assert_extracted_files, extract_with_p7zip, list_with_p7zip, run_7z};

fn parity_files() -> Vec<(PathBuf, Vec<u8>)> {
    vec![
        (
            PathBuf::from("alpha.txt"),
            b"alpha data from r7z".repeat(16),
        ),
        (
            PathBuf::from("nested/beta.bin"),
            (0u8..=255).cycle().take(8192).collect(),
        ),
        (
            PathBuf::from("nested/deep/gamma.txt"),
            b"gamma line one\ngamma line two\n".repeat(12),
        ),
    ]
}

fn executable_files() -> Vec<(PathBuf, Vec<u8>)> {
    vec![
        (PathBuf::from("bin/app.exe"), executable_payload(4096)),
        (PathBuf::from("bin/helper.dll"), executable_payload(3072)),
    ]
}

fn executable_payload(size: usize) -> Vec<u8> {
    let mut data = vec![0xCCu8; size];
    for pos in (16..size.saturating_sub(5)).step_by(89) {
        let target = (pos as u32).wrapping_mul(17);
        data[pos] = if pos % 2 == 0 { 0xE8 } else { 0xE9 };
        data[pos + 1..pos + 5].copy_from_slice(&target.to_le_bytes());
    }
    data
}

fn filetime_from_unix_secs(secs: u64) -> u64 {
    (secs + 11_644_473_600) * 10_000_000
}

fn assert_default_aes_properties(props: &[u8]) {
    assert_eq!(props.len(), 18);
    assert_eq!(props[0] & 0x3F, 19);
    assert_eq!(props[0] & 0x80, 0, "default AES salt should be absent");
    assert_eq!(props[0] & 0x40, 0x40, "default AES IV should be present");
    assert_eq!(props[1] >> 4, 0, "default AES salt length should be zero");
    assert_eq!(props[1] & 0x0F, 15, "default AES IV length should be 16");
    assert!(
        props[2..].iter().any(|&b| b != 0),
        "generated AES IV should not be all zero"
    );
}

fn assert_salted_aes_properties(props: &[u8]) {
    assert_eq!(props.len(), 18);
    assert_eq!(props[0] & 0x3F, 19);
    assert_eq!(props[0] & 0x80, 0x80, "AES salt should be present");
    assert_eq!(props[0] & 0x40, 0x40, "AES IV should be present");
    assert_eq!(props[1] >> 4, 7, "AES salt length should be 8");
    assert_eq!(props[1] & 0x0F, 7, "AES IV length should be 8");
    assert!(
        props[2..10].iter().any(|&b| b != 0),
        "generated AES salt should not be all zero"
    );
    assert!(
        props[10..].iter().any(|&b| b != 0),
        "generated AES IV should not be all zero"
    );
}

fn write_builder_archive(archive_path: &Path, codec: r7z::Codec, files: &[(PathBuf, Vec<u8>)]) {
    let mut builder = r7z::ArchiveBuilder::new().compression(codec);
    for (name, data) in files {
        let archive_name = name.to_string_lossy();
        builder = builder.add_file(archive_name.as_ref(), data);
    }
    let bytes = builder.build().expect("ArchiveBuilder build failed");
    std::fs::write(archive_path, bytes).unwrap();
}

fn write_writer_archive(archive_path: &Path, codec: r7z::Codec, files: &[(PathBuf, Vec<u8>)]) {
    let file = std::fs::File::create(archive_path).unwrap();
    let mut writer = r7z::ArchiveWriter::new(file, r7z::ArchiveOptions::default())
        .expect("ArchiveWriter::new failed")
        .compression(codec);
    for (idx, (name, data)) in files.iter().enumerate() {
        if idx == 1 {
            writer.new_folder().expect("new_folder failed");
        }
        let archive_name = name.to_string_lossy();
        writer
            .append(archive_name.as_ref(), data.as_slice())
            .expect("append failed");
    }
    writer.finish().expect("finish failed");
}

fn assert_p7zip_extracts_archive(
    dir: &Path,
    archive_path: &Path,
    expected: &[(PathBuf, Vec<u8>)],
    labels: &[&str],
) {
    let out_dir = dir.join("extracted");
    extract_with_p7zip(dir, archive_path, &out_dir);
    assert_extracted_files(&out_dir, expected);

    let listing = list_with_p7zip(dir, archive_path);
    for label in labels {
        assert!(
            listing.contains(label),
            "expected p7zip listing to contain {label:?}:\n{listing}"
        );
    }
}

/// r7z round-trip: build → `from_bytes` → `extract_to_memory`.
#[test]
fn r7z_write_r7z_read_single_file() {
    let original = b"Hello, world from r7z!";
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("hello.txt", original)
        .build()
        .expect("build failed");

    let archive = r7z::Archive::from_bytes(bytes.into()).expect("from_bytes failed");
    assert_eq!(archive.num_files(), 1);
    let fi = archive.files_info().unwrap();
    assert_eq!(fi.name(0).unwrap(), "hello.txt");

    let extracted = archive.extract_to_memory(0).unwrap();
    assert_eq!(extracted.as_slice(), original);
}

/// r7z round-trip with multiple files in a solid archive.
#[test]
fn r7z_write_r7z_read_multi_file() {
    let files = [
        ("alpha.txt", b"AAAA" as &[u8]),
        ("beta.txt", b"BBBBBBBB"),
        ("gamma.txt", b"CCCC"),
    ];

    let mut builder = r7z::ArchiveBuilder::new();
    for (name, data) in &files {
        builder = builder.add_file(name, data);
    }
    let bytes = builder.build().expect("build failed");

    let archive = r7z::Archive::from_bytes(bytes.into()).expect("from_bytes failed");
    assert_eq!(archive.num_files(), files.len());

    let fi = archive.files_info().unwrap();
    for (i, (name, original)) in files.iter().enumerate() {
        assert_eq!(fi.name(i).unwrap(), *name);
        let extracted = archive.extract_to_memory(i).unwrap();
        assert_eq!(extracted.as_slice(), *original, "mismatch for {name}");
    }
}

/// r7z builds archive; p7zip extracts it and contents match originals.
#[test]
fn r7z_write_p7zip_reads_single_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let original = b"Hello from r7z, extracted by p7zip!";
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("hello.txt", original)
        .build()
        .expect("build failed");

    let archive_path = dir.join("r7z_out.7z");
    std::fs::write(&archive_path, &bytes).unwrap();

    let out_dir = dir.join("extracted");
    std::fs::create_dir_all(&out_dir).unwrap();
    let out = run_7z(
        &[
            "e",
            archive_path.to_str().unwrap(),
            "-y",
            &format!("-o{}", out_dir.to_str().unwrap()),
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z e failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let extracted = std::fs::read(out_dir.join("hello.txt")).unwrap();
    assert_eq!(extracted, original);
}

/// r7z builds an LZMA2 archive; p7zip extracts it correctly.
#[test]
fn r7z_write_lzma2_p7zip_reads() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let original = b"Hello from r7z LZMA2, extracted by p7zip!";
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("hello.txt", original)
        .compression(r7z::Codec::Lzma2)
        .build()
        .expect("LZMA2 build failed");

    let archive_path = dir.join("r7z_lzma2.7z");
    std::fs::write(&archive_path, &bytes).unwrap();

    let out_dir = dir.join("extracted");
    std::fs::create_dir_all(&out_dir).unwrap();
    let out = run_7z(
        &[
            "e",
            archive_path.to_str().unwrap(),
            "-y",
            &format!("-o{}", out_dir.to_str().unwrap()),
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z e failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let extracted = std::fs::read(out_dir.join("hello.txt")).unwrap();
    assert_eq!(extracted, original);
}

/// r7z round-trip with LZMA2: build → `from_bytes` → `extract_to_memory`.
#[test]
fn r7z_write_lzma2_r7z_reads() {
    let original = b"LZMA2 round-trip test data";
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("data.bin", original)
        .compression(r7z::Codec::Lzma2)
        .build()
        .expect("LZMA2 build failed");

    let archive = r7z::Archive::from_bytes(bytes.into()).expect("from_bytes failed");
    let extracted = archive.extract_to_memory(0).unwrap();
    assert_eq!(extracted.as_slice(), original);
}

/// r7z builds multi-file archive; p7zip extracts all files correctly.
#[test]
fn r7z_write_p7zip_reads_multi_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let files = [
        ("one.txt", b"content one" as &[u8]),
        ("two.txt", b"content two, a bit longer"),
        ("three.txt", b"content three, even longer than the others"),
    ];

    let mut builder = r7z::ArchiveBuilder::new();
    for (name, data) in &files {
        builder = builder.add_file(name, data);
    }
    let bytes = builder.build().expect("build failed");

    let archive_path = dir.join("r7z_multi.7z");
    std::fs::write(&archive_path, &bytes).unwrap();

    let out_dir = dir.join("extracted");
    std::fs::create_dir_all(&out_dir).unwrap();
    let out = run_7z(
        &[
            "e",
            archive_path.to_str().unwrap(),
            "-y",
            &format!("-o{}", out_dir.to_str().unwrap()),
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z e failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    for (name, original) in &files {
        let extracted = std::fs::read(out_dir.join(name)).unwrap();
        assert_eq!(extracted.as_slice(), *original, "mismatch for {name}");
    }
}

/// [`ArchiveWriter`] single-folder r7z round-trip.
#[test]
fn archive_writer_single_folder_r7z_reads() {
    let files = [
        ("a.txt", b"hello from ArchiveWriter" as &[u8]),
        ("b.txt", b"second file"),
    ];

    let mut buf = std::io::Cursor::new(Vec::new());
    let mut w =
        r7z::ArchiveWriter::new(&mut buf, r7z::ArchiveOptions::default()).expect("new failed");
    for (name, data) in &files {
        w.append(name, *data).expect("append failed");
    }
    w.finish().expect("finish failed");

    let archive = r7z::Archive::from_bytes(buf.into_inner().into()).expect("from_bytes failed");
    assert_eq!(archive.num_files(), files.len());
    let fi = archive.files_info().unwrap();
    for (i, (name, original)) in files.iter().enumerate() {
        assert_eq!(fi.name(i).unwrap(), *name);
        let extracted = archive.extract_to_memory(i).unwrap();
        assert_eq!(extracted.as_slice(), *original, "mismatch for {name}");
    }
}

/// [`ArchiveWriter`] multi-folder r7z round-trip: two folders, two files each.
#[test]
fn archive_writer_multi_folder_r7z_reads() {
    let folder0 = [
        ("f0a.txt", b"folder zero file A" as &[u8]),
        ("f0b.txt", b"folder zero file B"),
    ];
    let folder1 = [
        ("f1a.txt", b"folder one file A" as &[u8]),
        ("f1b.txt", b"folder one file B"),
    ];

    let mut buf = std::io::Cursor::new(Vec::new());
    let mut w =
        r7z::ArchiveWriter::new(&mut buf, r7z::ArchiveOptions::default()).expect("new failed");
    for (name, data) in &folder0 {
        w.append(name, *data).expect("append failed");
    }
    w.new_folder().expect("new_folder failed");
    for (name, data) in &folder1 {
        w.append(name, *data).expect("append failed");
    }
    w.finish().expect("finish failed");

    let archive = r7z::Archive::from_bytes(buf.into_inner().into()).expect("from_bytes failed");
    assert_eq!(archive.num_files(), 4);

    let fi = archive.files_info().unwrap();
    let all = [folder0[0], folder0[1], folder1[0], folder1[1]];
    for (i, (name, original)) in all.iter().enumerate() {
        assert_eq!(fi.name(i).unwrap(), *name);
        let extracted = archive.extract_to_memory(i).unwrap();
        assert_eq!(extracted.as_slice(), *original, "mismatch for {name}");
    }
}

/// [`ArchiveWriter`] multi-folder archive; p7zip extracts all files correctly.
#[test]
fn archive_writer_multi_folder_p7zip_reads() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let folder0 = [
        ("alpha.txt", b"solid block A" as &[u8]),
        ("beta.txt", b"solid block B"),
    ];
    let folder1 = [("gamma.txt", b"solid block C" as &[u8])];

    let archive_path = dir.join("writer_multi.7z");
    let file = std::fs::File::create(&archive_path).unwrap();
    let mut w = r7z::ArchiveWriter::new(file, r7z::ArchiveOptions::default()).expect("new failed");
    for (name, data) in &folder0 {
        w.append(name, *data).expect("append failed");
    }
    w.new_folder().expect("new_folder failed");
    for (name, data) in &folder1 {
        w.append(name, *data).expect("append failed");
    }
    w.finish().expect("finish failed");

    let out_dir = dir.join("extracted");
    std::fs::create_dir_all(&out_dir).unwrap();
    let out = run_7z(
        &[
            "e",
            archive_path.to_str().unwrap(),
            "-y",
            &format!("-o{}", out_dir.to_str().unwrap()),
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z e failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    for (name, original) in folder0.iter().chain(folder1.iter()) {
        let extracted = std::fs::read(out_dir.join(name)).unwrap();
        assert_eq!(extracted.as_slice(), *original, "mismatch for {name}");
    }
}

/// [`Archive::from_reader`] round-trip: write to a cursor, rewind, read back.
#[test]
fn from_reader_round_trip() {
    let original = b"data read back via from_reader";
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("data.txt", original)
        .build()
        .expect("build failed");

    let archive =
        r7z::Archive::from_reader(std::io::Cursor::new(bytes)).expect("from_reader failed");
    assert_eq!(archive.num_files(), 1);
    let extracted = archive.extract_to_memory(0).unwrap();
    assert_eq!(extracted.as_slice(), original);
}

/// [`ArchiveWriter::append_entry`] round-trip: mtime survives write → read.
#[test]
fn archive_writer_mtime_r7z_reads() {
    use std::time::{Duration, UNIX_EPOCH};

    // A known Unix timestamp: 2024-03-15 12:00:00 UTC = 1710504000
    let ts = UNIX_EPOCH + Duration::from_secs(1_710_504_000);
    let meta = r7z::EntryMeta {
        mtime: Some(ts),
        ..Default::default()
    };

    let mut buf = std::io::Cursor::new(Vec::new());
    let mut w = r7z::ArchiveWriter::new(&mut buf, r7z::ArchiveOptions::default()).unwrap();
    w.append_entry("ts.txt", b"timestamp test".as_ref(), meta)
        .unwrap();
    w.finish().unwrap();

    let archive = r7z::Archive::from_bytes(buf.into_inner().into()).unwrap();
    let fi = archive.files_info().unwrap();

    // The raw FILETIME: seconds since Windows epoch × 10_000_000
    // Windows epoch offset = 11_644_473_600 s
    let expected_ft: u64 = (1_710_504_000 + 11_644_473_600) * 10_000_000;
    assert_eq!(fi.mtimes.first().copied().flatten(), Some(expected_ft));
}

/// [`ArchiveWriter::append_entry`] with Unix-mode attributes survives write -> read.
#[test]
fn archive_writer_unix_mode_r7z_reads() {
    // Regular file, rw-r--r-- = 0o100644
    let mode: u32 = 0o100_644;
    let meta = r7z::EntryMeta::from_unix_mode(mode);

    let mut buf = std::io::Cursor::new(Vec::new());
    let mut w = r7z::ArchiveWriter::new(&mut buf, r7z::ArchiveOptions::default()).unwrap();
    w.append_entry("perms.txt", b"permissions test".as_ref(), meta)
        .unwrap();
    w.finish().unwrap();

    let archive = r7z::Archive::from_bytes(buf.into_inner().into()).unwrap();
    let fi = archive.files_info().unwrap();

    let attrs = fi.attributes.first().copied().flatten().unwrap();
    // High 16 bits = st_mode, low 16 bits = Windows attribs (0x20)
    assert_eq!(attrs >> 16, mode);
    assert_eq!(attrs & 0xFFFF, 0x20);
}

#[test]
fn archive_builder_full_metadata_r7z_reads() {
    use std::time::{Duration, UNIX_EPOCH};

    let ctime_secs = 1_577_836_800; // 2020-01-01T00:00:00Z
    let atime_secs = 1_609_459_200; // 2021-01-01T00:00:00Z
    let mtime_secs = 1_640_995_200; // 2022-01-01T00:00:00Z
    let data_meta = r7z::EntryMeta {
        ctime: Some(UNIX_EPOCH + Duration::from_secs(ctime_secs)),
        atime: Some(UNIX_EPOCH + Duration::from_secs(atime_secs)),
        mtime: Some(UNIX_EPOCH + Duration::from_secs(mtime_secs)),
        start_pos: Some(123),
        ..r7z::EntryMeta::from_unix_mode(0o100_640)
    };
    let plain_meta = r7z::EntryMeta::archive_file();

    let bytes = r7z::ArchiveBuilder::new()
        .add_file_entry("meta.txt", b"metadata", data_meta)
        .add_file_entry("plain.txt", b"plain", plain_meta)
        .build()
        .expect("build failed");

    let archive = r7z::Archive::from_bytes(bytes.into()).expect("from_bytes failed");
    let fi = archive.files_info().unwrap();

    assert_eq!(fi.ctimes[0], Some(filetime_from_unix_secs(ctime_secs)));
    assert_eq!(fi.ctimes[1], None);
    assert_eq!(fi.atimes[0], Some(filetime_from_unix_secs(atime_secs)));
    assert_eq!(fi.atimes[1], None);
    assert_eq!(fi.mtimes[0], Some(filetime_from_unix_secs(mtime_secs)));
    assert_eq!(fi.mtimes[1], None);
    assert_eq!(fi.start_positions[0], Some(123));
    assert_eq!(fi.start_positions[1], None);
    assert_eq!(fi.attributes[0], Some((0o100_640 << 16) | 0x20));
    assert_eq!(fi.attributes[1], Some(0x20));
}

/// p7zip lists a non-epoch timestamp for an archive written with mtime via [`ArchiveWriter`].
#[test]
fn archive_writer_mtime_p7zip_reads() {
    use std::time::{Duration, UNIX_EPOCH};

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let ts = UNIX_EPOCH + Duration::from_secs(1_710_504_000); // 2024-03-15T12:00:00Z
    let meta = r7z::EntryMeta {
        mtime: Some(ts),
        ..Default::default()
    };

    let archive_path = dir.join("ts.7z");
    let file = std::fs::File::create(&archive_path).unwrap();
    let mut w = r7z::ArchiveWriter::new(file, r7z::ArchiveOptions::default()).unwrap();
    w.append_entry("ts.txt", b"timestamp data".as_ref(), meta)
        .unwrap();
    w.finish().unwrap();

    // `7z l` lists the archive; check it contains "2024" in output
    let out = run_7z(&["l", archive_path.to_str().unwrap()], dir);
    assert!(
        out.status.success(),
        "7z l failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("2024"),
        "expected year 2024 in p7zip listing:\n{stdout}"
    );
}
/// r7z builds BCJ+LZMA2 archive; round-trips through `from_bytes`.
#[test]
fn r7z_write_bcj_lzma2_r7z_reads() {
    // Create data with CALL instructions that BCJ should filter
    let mut original = vec![0x90u8; 512];
    for &pos in &[10u32, 50, 100, 200, 300, 400] {
        let p = pos as usize;
        original[p] = 0xE8;
        original[p + 1] = (pos * 3) as u8;
        original[p + 2] = ((pos * 3) >> 8) as u8;
        original[p + 3] = 0x00;
        original[p + 4] = 0x00;
    }

    let bytes = r7z::ArchiveBuilder::new()
        .compression(r7z::Codec::Lzma2Bcj)
        .add_file("prog.bin", &original)
        .build()
        .expect("build with BCJ+LZMA2 failed");

    let archive = r7z::Archive::from_bytes(bytes.into()).expect("from_bytes failed");
    assert_eq!(archive.num_files(), 1);

    // Verify the archive uses BCJ + LZMA2
    let si = archive.streams_info().unwrap();
    let ui = si.unpack_info.as_ref().unwrap();
    let folder = ui.parse_folder(0).unwrap();
    assert_eq!(folder.coders.len(), 2, "expected 2 coders for BCJ+LZMA2");

    let extracted = archive.extract_to_memory(0).unwrap();
    assert_eq!(extracted, original);
}

/// r7z builds BCJ+LZMA2 archive; p7zip extracts it and contents match.
#[test]
fn r7z_write_bcj_lzma2_p7zip_reads() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let mut original = vec![0x90u8; 1024];
    for &pos in &[10u32, 50, 100, 200, 400, 600, 800] {
        let p = pos as usize;
        original[p] = 0xE8;
        original[p + 1] = (pos * 5) as u8;
        original[p + 2] = ((pos * 5) >> 8) as u8;
        original[p + 3] = 0x00;
        original[p + 4] = 0x00;
    }

    let archive_path = dir.join("bcj_test.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .compression(r7z::Codec::Lzma2Bcj)
        .add_file("prog.bin", &original)
        .build()
        .expect("build with BCJ+LZMA2 failed");
    std::fs::write(&archive_path, &bytes).unwrap();

    // p7zip extracts
    let out = run_7z(&["x", "-y", archive_path.to_str().unwrap()], dir);
    assert!(
        out.status.success(),
        "7z x failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let extracted = std::fs::read(dir.join("prog.bin")).unwrap();
    assert_eq!(extracted, original, "p7zip extracted data != original");
}

/// p7zip reads BCJ+LZMA2 archive created by r7z via ArchiveWriter.
#[test]
fn archive_writer_bcj_lzma2_p7zip_reads() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let mut data = vec![0xCCu8; 2048];
    for &pos in &[16u32, 64, 128, 256, 512, 1024, 1536] {
        let p = pos as usize;
        data[p] = 0xE9; // JMP
        data[p + 1] = 0x10;
        data[p + 2] = 0x00;
        data[p + 3] = 0x00;
        data[p + 4] = 0x00;
    }

    let archive_path = dir.join("bcj_writer.7z");
    let file = std::fs::File::create(&archive_path).unwrap();
    let mut w = r7z::ArchiveWriter::new(file, r7z::ArchiveOptions::default())
        .unwrap()
        .compression(r7z::Codec::Lzma2Bcj);
    w.append("code.bin", &mut data.as_slice()).unwrap();
    w.finish().unwrap();

    let out = run_7z(&["x", "-y", archive_path.to_str().unwrap()], dir);
    assert!(
        out.status.success(),
        "7z x failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let extracted = std::fs::read(dir.join("code.bin")).unwrap();
    assert_eq!(extracted, data);
}

#[test]
fn archive_builder_lzma_multi_file_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("builder_lzma.7z");

    write_builder_archive(&archive_path, r7z::Codec::Lzma, &files);
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["LZMA"]);
}

#[test]
fn archive_builder_lzma_literal_position_options_p7zip_extracts() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("builder_lzma_literal_position.7z");
    let options = r7z::ArchiveOptions {
        codec: r7z::Codec::Lzma,
        compression: r7z::CompressionOptions {
            literal_context_bits: Some(2),
            literal_position_bits: Some(1),
            position_bits: Some(1),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut builder = r7z::ArchiveBuilder::new().options(options);
    for (name, data) in &files {
        builder = builder.add_file(&name.to_string_lossy(), data);
    }
    let bytes = builder.build().unwrap();
    std::fs::write(&archive_path, &bytes).unwrap();

    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let folder = archive
        .streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap()
        .parse_folder(0)
        .unwrap();
    let lzma = folder
        .coders
        .iter()
        .find(|coder| coder.codec_id.as_slice() == r7z::CODEC_LZMA)
        .unwrap();
    assert_eq!(lzma.properties.as_deref().map(|props| props[0]), Some(0x38));

    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["LZMA"]);
}

#[test]
fn archive_builder_lzma_match_finder_option_p7zip_extracts() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("builder_lzma_match_finder.7z");
    let options = r7z::ArchiveOptions {
        codec: r7z::Codec::Lzma,
        compression: r7z::CompressionOptions {
            match_finder: Some(r7z::MatchFinder::Hc4),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut builder = r7z::ArchiveBuilder::new().options(options);
    for (name, data) in &files {
        builder = builder.add_file(&name.to_string_lossy(), data);
    }
    std::fs::write(&archive_path, builder.build().unwrap()).unwrap();

    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["LZMA"]);
}

#[test]
fn archive_builder_lzma_algorithm_and_match_cycles_p7zip_extracts() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("builder_lzma_algorithm_cycles.7z");
    let options = r7z::ArchiveOptions {
        codec: r7z::Codec::Lzma,
        compression: r7z::CompressionOptions {
            lzma_algorithm: Some(r7z::LzmaAlgorithm::Fast),
            match_cycles: Some(16),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut builder = r7z::ArchiveBuilder::new().options(options);
    for (name, data) in &files {
        builder = builder.add_file(&name.to_string_lossy(), data);
    }
    std::fs::write(&archive_path, builder.build().unwrap()).unwrap();

    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["LZMA"]);
}

#[test]
fn archive_builder_lzma2_multi_file_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("builder_lzma2.7z");

    write_builder_archive(&archive_path, r7z::Codec::Lzma2, &files);
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["LZMA2"]);
}

#[test]
fn archive_builder_ppmd_multi_file_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("builder_ppmd.7z");

    write_builder_archive(&archive_path, r7z::Codec::Ppmd, &files);
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["PPMD"]);
}

#[test]
fn archive_builder_bcj_lzma2_multi_file_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = executable_files();
    let archive_path = dir.join("builder_bcj_lzma2.7z");

    write_builder_archive(&archive_path, r7z::Codec::Lzma2Bcj, &files);
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["BCJ", "LZMA2"]);
}

#[test]
fn archive_writer_lzma_multi_folder_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("writer_lzma.7z");

    write_writer_archive(&archive_path, r7z::Codec::Lzma, &files);
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["LZMA"]);
}

#[test]
fn archive_writer_lzma2_multi_folder_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("writer_lzma2.7z");

    write_writer_archive(&archive_path, r7z::Codec::Lzma2, &files);
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["LZMA2"]);
}

#[test]
fn archive_writer_ppmd_multi_folder_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("writer_ppmd.7z");

    write_writer_archive(&archive_path, r7z::Codec::Ppmd, &files);
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["PPMD"]);
}

#[test]
fn archive_writer_bcj_lzma2_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = executable_files();
    let archive_path = dir.join("writer_bcj_lzma2.7z");

    write_writer_archive(&archive_path, r7z::Codec::Lzma2Bcj, &files);
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["BCJ", "LZMA2"]);
}

#[test]
fn build_streaming_lzma2_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("streaming_lzma2.7z");
    let output = std::fs::File::create(&archive_path).unwrap();
    let entries = files
        .iter()
        .map(|(name, data)| (name.to_string_lossy().into_owned(), data.as_slice()));

    r7z::build_streaming(entries, output).expect("build_streaming failed");
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["LZMA2"]);
}

#[test]
fn build_streaming_with_options_copy_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("streaming_copy.7z");
    let output = std::fs::File::create(&archive_path).unwrap();
    let entries = files
        .iter()
        .map(|(name, data)| (name.to_string_lossy().into_owned(), data.as_slice()));
    let options = r7z::ArchiveOptions {
        codec: r7z::Codec::Copy,
        ..Default::default()
    };

    r7z::build_streaming_with_options(entries, output, options)
        .expect("build_streaming_with_options failed");
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["Copy"]);
}

#[test]
fn build_streaming_with_options_lzma_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("streaming_lzma.7z");
    let output = std::fs::File::create(&archive_path).unwrap();
    let entries = files
        .iter()
        .map(|(name, data)| (name.to_string_lossy().into_owned(), data.as_slice()));
    let options = r7z::ArchiveOptions {
        codec: r7z::Codec::Lzma,
        ..Default::default()
    };

    r7z::build_streaming_with_options(entries, output, options)
        .expect("build_streaming_with_options failed");
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["LZMA"]);
}

#[test]
fn build_streaming_with_options_bcj_lzma2_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = executable_files();
    let archive_path = dir.join("streaming_bcj_lzma2.7z");
    let output = std::fs::File::create(&archive_path).unwrap();
    let entries = files
        .iter()
        .map(|(name, data)| (name.to_string_lossy().into_owned(), data.as_slice()));
    let options = r7z::ArchiveOptions {
        codec: r7z::Codec::Lzma2Bcj,
        ..Default::default()
    };

    r7z::build_streaming_with_options(entries, output, options)
        .expect("build_streaming_with_options failed");
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["BCJ", "LZMA2"]);
}

#[test]
fn archive_builder_default_is_lzma2_and_uses_encoded_header_for_multi_entry() {
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("a.txt", b"alpha")
        .add_file("b.txt", b"bravo")
        .build()
        .expect("build failed");

    let archive = r7z::Archive::from_bytes(bytes.into()).expect("from_bytes failed");
    assert!(archive.encoded_header.is_some());
    let ui = archive
        .streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap();
    let folder = ui.parse_folder(0).unwrap();
    assert_eq!(folder.coders[0].codec_id.as_slice(), r7z::CODEC_LZMA2);
}

#[test]
fn archive_builder_header_modes_are_honored() {
    let single_default = r7z::ArchiveBuilder::new()
        .add_file("single.txt", b"one")
        .build()
        .expect("build failed");
    let archive = r7z::Archive::from_bytes(single_default.into()).expect("from_bytes failed");
    assert!(archive.encoded_header.is_none());

    let encoded = r7z::ArchiveBuilder::new()
        .options(r7z::ArchiveOptions {
            header_mode: r7z::HeaderMode::Encoded,
            ..Default::default()
        })
        .add_file("single.txt", b"one")
        .build()
        .expect("build failed");
    let archive = r7z::Archive::from_bytes(encoded.into()).expect("from_bytes failed");
    assert!(archive.encoded_header.is_some());

    let plain = r7z::ArchiveBuilder::new()
        .options(r7z::ArchiveOptions {
            header_mode: r7z::HeaderMode::Plain,
            ..Default::default()
        })
        .add_file("a.txt", b"alpha")
        .add_file("b.txt", b"bravo")
        .build()
        .expect("build failed");
    let archive = r7z::Archive::from_bytes(plain.into()).expect("from_bytes failed");
    assert!(archive.encoded_header.is_none());
}

#[test]
fn archive_builder_copy_p7zip_extracts_and_lists_method() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let files = parity_files();
    let archive_path = dir.join("copy.7z");

    write_builder_archive(&archive_path, r7z::Codec::Copy, &files);
    assert_p7zip_extracts_archive(dir, &archive_path, &files, &["Copy"]);
}

#[test]
fn archive_writer_copy_streams_payload_before_finish() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let archive_path = dir.join("writer_copy_streamed.7z");
    let payload = vec![0xA7; 128 * 1024];
    let file = std::fs::File::create(&archive_path).unwrap();
    let mut writer = r7z::ArchiveWriter::new(file, r7z::ArchiveOptions::default())
        .expect("new failed")
        .compression(r7z::Codec::Copy);

    writer
        .append_file(
            "streamed.bin",
            payload.as_slice(),
            r7z::EntryMeta::archive_file(),
        )
        .expect("append failed");
    assert!(
        std::fs::metadata(&archive_path).unwrap().len() > payload.len() as u64,
        "Copy writer should write payload bytes before finish"
    );

    writer.finish().expect("finish failed");
    assert_p7zip_extracts_archive(
        dir,
        &archive_path,
        &[(PathBuf::from("streamed.bin"), payload)],
        &["Copy"],
    );
}

#[test]
fn archive_writer_lzma2_streams_payload_before_finish() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let archive_path = dir.join("writer_lzma2_streamed.7z");
    let payload = (0u8..=255).cycle().take(1024 * 1024).collect::<Vec<_>>();
    let file = std::fs::File::create(&archive_path).unwrap();
    let mut writer =
        r7z::ArchiveWriter::new(file, r7z::ArchiveOptions::default()).expect("new failed");

    writer
        .append_file(
            "streamed.bin",
            payload.as_slice(),
            r7z::EntryMeta::archive_file(),
        )
        .expect("append failed");
    writer.new_folder().expect("new_folder failed");
    assert!(
        std::fs::metadata(&archive_path).unwrap().len() > 32,
        "LZMA2 writer should emit compressed payload bytes after sealing a folder"
    );

    writer.finish().expect("finish failed");
    assert_p7zip_extracts_archive(
        dir,
        &archive_path,
        &[(PathBuf::from("streamed.bin"), payload)],
        &["LZMA2"],
    );
}

#[test]
fn archive_writer_lzma_streams_payload_before_finish() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let archive_path = dir.join("writer_lzma_streamed.7z");
    let payload = (0u8..=255)
        .rev()
        .cycle()
        .take(1024 * 1024)
        .collect::<Vec<_>>();
    let file = std::fs::File::create(&archive_path).unwrap();
    let mut writer = r7z::ArchiveWriter::new(file, r7z::ArchiveOptions::default())
        .expect("new failed")
        .compression(r7z::Codec::Lzma);

    writer
        .append_file(
            "streamed.bin",
            payload.as_slice(),
            r7z::EntryMeta::archive_file(),
        )
        .expect("append failed");
    writer.new_folder().expect("new_folder failed");
    assert!(
        std::fs::metadata(&archive_path).unwrap().len() > 32,
        "LZMA writer should emit compressed payload bytes after sealing a folder"
    );

    writer.finish().expect("finish failed");
    assert_p7zip_extracts_archive(
        dir,
        &archive_path,
        &[(PathBuf::from("streamed.bin"), payload)],
        &["LZMA"],
    );
}

#[test]
fn archive_writer_bcj_lzma2_streams_payload_before_finish() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let archive_path = dir.join("writer_bcj_lzma2_streamed.7z");
    let payload = executable_payload(1024 * 1024);
    let file = std::fs::File::create(&archive_path).unwrap();
    let mut writer = r7z::ArchiveWriter::new(file, r7z::ArchiveOptions::default())
        .expect("new failed")
        .compression(r7z::Codec::Lzma2Bcj);

    writer
        .append_file(
            "streamed.exe",
            payload.as_slice(),
            r7z::EntryMeta::archive_file(),
        )
        .expect("append failed");
    writer.new_folder().expect("new_folder failed");
    assert!(
        std::fs::metadata(&archive_path).unwrap().len() > 32,
        "BCJ+LZMA2 writer should emit compressed payload bytes after sealing a folder"
    );

    writer.finish().expect("finish failed");
    assert_p7zip_extracts_archive(
        dir,
        &archive_path,
        &[(PathBuf::from("streamed.exe"), payload)],
        &["BCJ", "LZMA2"],
    );
}

#[test]
fn archive_writer_mixed_empty_entries_preserve_order_and_folder_boundaries() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let archive_path = dir.join("writer_mixed.7z");
    let file = std::fs::File::create(&archive_path).unwrap();
    let mut writer =
        r7z::ArchiveWriter::new(file, r7z::ArchiveOptions::default()).expect("new failed");
    writer
        .append_file("a.txt", b"alpha".as_slice(), r7z::EntryMeta::archive_file())
        .expect("append file failed");
    writer.new_folder().expect("new_folder failed");
    writer
        .append_directory("nested", r7z::EntryMeta::directory_unix_mode(0o040_755))
        .expect("append directory failed");
    writer
        .append_empty_file("nested/empty.txt", r7z::EntryMeta::archive_file())
        .expect("append empty file failed");
    writer
        .append_anti_item("removed.txt", r7z::EntryMeta::default())
        .expect("append anti failed");
    writer.new_folder().expect("new_folder failed");
    writer
        .append_file(
            "nested/b.txt",
            b"bravo".as_slice(),
            r7z::EntryMeta::archive_file(),
        )
        .expect("append file failed");
    writer.finish().expect("finish failed");

    let archive = r7z::Archive::open(&archive_path).unwrap();
    let fi = archive.files_info().unwrap();
    assert_eq!(archive.num_files(), 5);
    assert_eq!(fi.name(0).unwrap(), "a.txt");
    assert_eq!(fi.name(1).unwrap(), "nested");
    assert_eq!(fi.name(2).unwrap(), "nested/empty.txt");
    assert_eq!(fi.name(3).unwrap(), "removed.txt");
    assert_eq!(fi.name(4).unwrap(), "nested/b.txt");
    assert!(fi.is_directory(1));
    assert!(fi.is_empty_file(2));
    assert!(fi.is_anti(3));
    let unpack_info = archive
        .streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap();
    assert_eq!(unpack_info.num_folders, 2);
    assert_eq!(archive.extract_to_memory(0).unwrap(), b"alpha");
    assert_eq!(archive.extract_to_memory(2).unwrap(), b"");
    assert_eq!(archive.extract_to_memory(4).unwrap(), b"bravo");

    let out_dir = dir.join("out");
    extract_with_p7zip(dir, &archive_path, &out_dir);
    assert_eq!(std::fs::read(out_dir.join("a.txt")).unwrap(), b"alpha");
    assert!(out_dir.join("nested").is_dir());
    assert_eq!(
        std::fs::read(out_dir.join("nested/empty.txt")).unwrap(),
        b""
    );
    assert_eq!(
        std::fs::read(out_dir.join("nested/b.txt")).unwrap(),
        b"bravo"
    );
}

#[test]
fn archive_entry_helpers_round_trip_and_validate_stream_kind() {
    let builder = r7z::ArchiveBuilder::new()
        .add_entry(
            r7z::ArchiveEntry::directory("dir", r7z::EntryMeta::default()),
            None,
        )
        .unwrap()
        .add_entry(
            r7z::ArchiveEntry::file("dir/data.txt", r7z::EntryMeta::archive_file()),
            Some(b"hello"),
        )
        .unwrap()
        .add_entry(
            r7z::ArchiveEntry::file("dir/empty.txt", r7z::EntryMeta::default()),
            None,
        )
        .unwrap()
        .add_entry(
            r7z::ArchiveEntry::anti("removed.txt", r7z::EntryMeta::default()),
            None,
        )
        .unwrap();
    let archive = r7z::Archive::from_bytes(builder.build().unwrap().into()).unwrap();
    let fi = archive.files_info().unwrap();
    assert!(fi.is_directory(0));
    assert_eq!(archive.extract_to_memory(1).unwrap(), b"hello");
    assert!(fi.is_empty_file(2));
    assert!(fi.is_anti(3));

    let invalid = r7z::ArchiveBuilder::new().add_entry(
        r7z::ArchiveEntry::directory("bad", r7z::EntryMeta::default()),
        Some(b"not allowed"),
    );
    assert!(matches!(invalid, Err(r7z::R7zError::InvalidOptions(_))));

    let mut buf = std::io::Cursor::new(Vec::new());
    let mut writer =
        r7z::ArchiveWriter::new(&mut buf, r7z::ArchiveOptions::default()).expect("new failed");
    writer
        .append_empty_entry(r7z::ArchiveEntry::directory(
            "dir",
            r7z::EntryMeta::default(),
        ))
        .unwrap();
    writer
        .append_archive_entry(
            r7z::ArchiveEntry::file("dir/data.txt", r7z::EntryMeta::archive_file()),
            b"hello".as_slice(),
        )
        .unwrap();
    writer
        .append_empty_entry(r7z::ArchiveEntry::file(
            "dir/empty.txt",
            r7z::EntryMeta::default(),
        ))
        .unwrap();
    writer
        .append_empty_entry(r7z::ArchiveEntry::anti(
            "removed.txt",
            r7z::EntryMeta::default(),
        ))
        .unwrap();
    writer.finish().unwrap();

    let archive = r7z::Archive::from_bytes(buf.into_inner().into()).unwrap();
    let fi = archive.files_info().unwrap();
    assert!(fi.is_directory(0));
    assert_eq!(archive.extract_to_memory(1).unwrap(), b"hello");
    assert!(fi.is_empty_file(2));
    assert!(fi.is_anti(3));
}

#[test]
fn archive_builder_empty_directory_and_anti_items_round_trip_and_p7zip_lists() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let archive_path = dir.join("specials.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .add_directory("nested", r7z::EntryMeta::default())
        .add_empty_file("nested/empty.txt", r7z::EntryMeta::default())
        .add_file("nested/data.txt", b"payload")
        .add_anti_item("deleted.txt", r7z::EntryMeta::default())
        .build()
        .expect("build failed");
    std::fs::write(&archive_path, bytes).unwrap();

    let archive = r7z::Archive::open(&archive_path).unwrap();
    let fi = archive.files_info().unwrap();
    assert!(fi.is_directory(0));
    assert!(fi.is_empty_file(1));
    assert!(fi.is_anti(3));
    assert!(!fi.is_directory(3));
    assert_eq!(archive.extract_to_memory(2).unwrap(), b"payload");

    let listing = list_with_p7zip(dir, &archive_path);
    assert!(listing.contains("nested/empty.txt"));
    assert!(listing.contains("deleted.txt"));

    let out_dir = dir.join("out");
    extract_with_p7zip(dir, &archive_path, &out_dir);
    assert!(out_dir.join("nested").is_dir());
    assert_eq!(
        std::fs::read(out_dir.join("nested/empty.txt")).unwrap(),
        b""
    );
    assert_eq!(
        std::fs::read(out_dir.join("nested/data.txt")).unwrap(),
        b"payload"
    );
}

#[test]
fn archive_builder_empty_only_p7zip_extracts_and_r7z_reads() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let archive_path = dir.join("empty_only.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .add_directory("emptydir", r7z::EntryMeta::directory_unix_mode(0o040_755))
        .add_empty_file("emptydir/empty.txt", r7z::EntryMeta::archive_file())
        .add_anti_item("removed.txt", r7z::EntryMeta::default())
        .build()
        .expect("build failed");
    std::fs::write(&archive_path, bytes).unwrap();

    let archive = r7z::Archive::open(&archive_path).unwrap();
    assert!(archive.streams_info().is_none());
    let fi = archive.files_info().unwrap();
    assert_eq!(archive.num_files(), 3);
    assert_eq!(fi.name(0).unwrap(), "emptydir");
    assert_eq!(fi.name(1).unwrap(), "emptydir/empty.txt");
    assert_eq!(fi.name(2).unwrap(), "removed.txt");
    assert!(fi.is_directory(0));
    assert!(fi.is_empty_file(1));
    assert!(fi.is_anti(2));
    assert!(!fi.is_directory(2));
    assert_eq!(archive.extract_to_memory(1).unwrap(), b"");

    let listing = list_with_p7zip(dir, &archive_path);
    assert!(listing.contains("emptydir"));
    assert!(listing.contains("emptydir/empty.txt"));
    assert!(listing.contains("removed.txt"));

    let out_dir = dir.join("out");
    extract_with_p7zip(dir, &archive_path, &out_dir);
    assert!(out_dir.join("emptydir").is_dir());
    assert_eq!(
        std::fs::read(out_dir.join("emptydir/empty.txt")).unwrap(),
        b""
    );
}

#[test]
fn archive_builder_aes_content_p7zip_and_r7z_extract_with_password() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let archive_path = dir.join("aes_content.7z");
    let options = r7z::ArchiveOptions {
        encryption: Some(r7z::EncryptionOptions::default_for_password("Secret123")),
        ..Default::default()
    };
    let bytes = r7z::ArchiveBuilder::new()
        .options(options)
        .add_file("secret.txt", b"classified")
        .build()
        .expect("build failed");
    std::fs::write(&archive_path, bytes).unwrap();

    let archive = r7z::Archive::open(&archive_path).unwrap();
    assert!(matches!(
        archive.extract_to_memory(0).unwrap_err(),
        r7z::R7zError::PasswordRequired
    ));
    assert_eq!(
        archive
            .extract_to_memory_with_password(0, Some("Secret123"))
            .unwrap(),
        b"classified"
    );

    let out_dir = dir.join("out");
    let out_arg = format!("-o{}", out_dir.to_str().unwrap());
    let out = run_7z(
        &[
            "x",
            "-y",
            "-pSecret123",
            archive_path.to_str().unwrap(),
            &out_arg,
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z x failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(out_dir.join("secret.txt")).unwrap(),
        b"classified"
    );
}

#[test]
fn archive_builder_default_aes_properties_match_p7zip_settings() {
    let options = r7z::ArchiveOptions {
        encryption: Some(r7z::EncryptionOptions::default_for_password("Secret123")),
        ..Default::default()
    };
    let bytes = r7z::ArchiveBuilder::new()
        .options(options)
        .add_file("secret.txt", b"classified")
        .build()
        .expect("build failed");

    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let streams = archive.streams_info().unwrap();
    let unpack_info = streams.unpack_info.as_ref().unwrap();
    let folder = unpack_info.parse_folder(0).unwrap();
    let aes_coder = &folder.coders[0];
    assert_eq!(aes_coder.codec_id.as_slice(), r7z::CODEC_AES_256_SHA_256);
    assert_default_aes_properties(aes_coder.properties.as_deref().unwrap());

    let mut enc = r7z::EncryptionOptions::default_for_password("HeaderSecret");
    enc.encrypt_header = true;
    let bytes = r7z::ArchiveBuilder::new()
        .options(r7z::ArchiveOptions {
            encryption: Some(enc),
            ..Default::default()
        })
        .add_file("hidden.txt", b"hidden payload")
        .build()
        .expect("build failed");
    let archive = r7z::Archive::from_bytes_with_password(bytes.into(), Some("HeaderSecret"))
        .expect("from_bytes_with_password failed");
    let encoded_header = archive.encoded_header.as_ref().unwrap();
    let folder = encoded_header.unpack_info.parse_folder(0).unwrap();
    let aes_coder = &folder.coders[0];
    assert_eq!(aes_coder.codec_id.as_slice(), r7z::CODEC_AES_256_SHA_256);
    assert_default_aes_properties(aes_coder.properties.as_deref().unwrap());
}

#[test]
fn archive_builder_salted_aes_content_p7zip_and_r7z_extract() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let archive_path = dir.join("aes_salted.7z");
    let mut enc = r7z::EncryptionOptions::default_for_password("Secret123");
    enc.salt_len = 8;
    enc.iv_len = 8;
    let bytes = r7z::ArchiveBuilder::new()
        .options(r7z::ArchiveOptions {
            encryption: Some(enc),
            ..Default::default()
        })
        .add_file("secret.txt", b"salted secret")
        .build()
        .expect("build failed");
    std::fs::write(&archive_path, bytes).unwrap();

    let archive = r7z::Archive::open(&archive_path).unwrap();
    let streams = archive.streams_info().unwrap();
    let unpack_info = streams.unpack_info.as_ref().unwrap();
    let folder = unpack_info.parse_folder(0).unwrap();
    let aes_coder = &folder.coders[0];
    assert_eq!(aes_coder.codec_id.as_slice(), r7z::CODEC_AES_256_SHA_256);
    assert_salted_aes_properties(aes_coder.properties.as_deref().unwrap());
    assert_eq!(
        archive
            .extract_to_memory_with_password(0, Some("Secret123"))
            .unwrap(),
        b"salted secret"
    );

    let out_dir = dir.join("out");
    let out_arg = format!("-o{}", out_dir.to_str().unwrap());
    let out = run_7z(
        &[
            "x",
            "-y",
            "-pSecret123",
            archive_path.to_str().unwrap(),
            &out_arg,
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z x failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(out_dir.join("secret.txt")).unwrap(),
        b"salted secret"
    );
}

#[test]
fn archive_builder_salted_aes_encrypted_header_p7zip_and_r7z_extract() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let archive_path = dir.join("aes_salted_header.7z");
    let mut enc = r7z::EncryptionOptions::default_for_password("HeaderSecret");
    enc.encrypt_header = true;
    enc.salt_len = 8;
    enc.iv_len = 8;
    let bytes = r7z::ArchiveBuilder::new()
        .options(r7z::ArchiveOptions {
            encryption: Some(enc),
            ..Default::default()
        })
        .add_file("hidden.txt", b"salted header")
        .build()
        .expect("build failed");
    std::fs::write(&archive_path, bytes).unwrap();

    let err = match r7z::Archive::open(&archive_path) {
        Ok(_) => panic!("encrypted salted header opened without password"),
        Err(err) => err,
    };
    assert!(matches!(err, r7z::R7zError::PasswordRequired));
    let archive = r7z::Archive::open_with_password(&archive_path, Some("HeaderSecret")).unwrap();
    let encoded_header = archive.encoded_header.as_ref().unwrap();
    let folder = encoded_header.unpack_info.parse_folder(0).unwrap();
    let aes_coder = &folder.coders[0];
    assert_eq!(aes_coder.codec_id.as_slice(), r7z::CODEC_AES_256_SHA_256);
    assert_salted_aes_properties(aes_coder.properties.as_deref().unwrap());
    assert_eq!(
        archive
            .extract_to_memory_with_password(0, Some("HeaderSecret"))
            .unwrap(),
        b"salted header"
    );

    let out_dir = dir.join("out");
    let out_arg = format!("-o{}", out_dir.to_str().unwrap());
    let out = run_7z(
        &[
            "x",
            "-y",
            "-pHeaderSecret",
            archive_path.to_str().unwrap(),
            &out_arg,
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z x failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(out_dir.join("hidden.txt")).unwrap(),
        b"salted header"
    );
}

#[test]
fn archive_builder_aes_content_copy_and_bcj_p7zip_and_r7z_extract() {
    let cases = [
        (
            r7z::Codec::Copy,
            "aes_copy.7z",
            "raw.bin",
            (0u8..=255).cycle().take(4097).collect::<Vec<_>>(),
        ),
        (
            r7z::Codec::Lzma2Bcj,
            "aes_bcj.7z",
            "bin/app.exe",
            executable_payload(4096),
        ),
        (
            r7z::Codec::Ppmd,
            "aes_ppmd.7z",
            "text/secret.txt",
            b"ppmd encrypted payload\n".repeat(64),
        ),
    ];

    for (codec, archive_name, entry_name, payload) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let archive_path = dir.join(archive_name);
        let options = r7z::ArchiveOptions {
            codec,
            encryption: Some(r7z::EncryptionOptions::default_for_password("Secret123")),
            ..Default::default()
        };
        let bytes = r7z::ArchiveBuilder::new()
            .options(options)
            .add_file(entry_name, &payload)
            .build()
            .expect("build failed");
        std::fs::write(&archive_path, bytes).unwrap();

        let archive = r7z::Archive::open(&archive_path).unwrap();
        assert_eq!(
            archive
                .extract_to_memory_with_password(0, Some("Secret123"))
                .unwrap(),
            payload
        );

        let out_dir = dir.join("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let out_arg = format!("-o{}", out_dir.to_str().unwrap());
        let out = run_7z(
            &[
                "x",
                "-y",
                "-pSecret123",
                archive_path.to_str().unwrap(),
                &out_arg,
            ],
            dir,
        );
        assert!(
            out.status.success(),
            "7z x failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(std::fs::read(out_dir.join(entry_name)).unwrap(), payload);
    }
}

#[test]
fn archive_builder_rejects_invalid_aes_options() {
    let mut enc = r7z::EncryptionOptions::default_for_password("Secret123");
    enc.salt_len = 17;
    let err = r7z::ArchiveBuilder::new()
        .options(r7z::ArchiveOptions {
            encryption: Some(enc),
            ..Default::default()
        })
        .add_file("secret.txt", b"classified")
        .build()
        .unwrap_err();
    assert!(matches!(err, r7z::R7zError::InvalidOptions(_)));

    let mut enc = r7z::EncryptionOptions::default_for_password("Secret123");
    enc.iv_len = 17;
    let err = r7z::ArchiveBuilder::new()
        .options(r7z::ArchiveOptions {
            encryption: Some(enc),
            ..Default::default()
        })
        .add_file("secret.txt", b"classified")
        .build()
        .unwrap_err();
    assert!(matches!(err, r7z::R7zError::InvalidOptions(_)));

    let mut enc = r7z::EncryptionOptions::default_for_password("Secret123");
    enc.num_cycles_power = 25;
    enc.encrypt_header = true;
    let err = r7z::ArchiveBuilder::new()
        .options(r7z::ArchiveOptions {
            encryption: Some(enc),
            ..Default::default()
        })
        .add_file("secret.txt", b"classified")
        .build()
        .unwrap_err();
    assert!(matches!(err, r7z::R7zError::InvalidOptions(_)));

    let mut enc = r7z::EncryptionOptions::default_for_password("Secret123");
    enc.num_cycles_power = 25;
    let mut buf = std::io::Cursor::new(Vec::new());
    let err = match r7z::ArchiveWriter::new(
        &mut buf,
        r7z::ArchiveOptions {
            encryption: Some(enc),
            ..Default::default()
        },
    ) {
        Ok(_) => panic!("ArchiveWriter accepted unsupported AES cycle power"),
        Err(err) => err,
    };
    assert!(matches!(err, r7z::R7zError::InvalidOptions(_)));

    let mut enc = r7z::EncryptionOptions::default_for_password("Secret123");
    enc.encrypt_header = true;
    let invalid_options = r7z::ArchiveOptions {
        header_mode: r7z::HeaderMode::Plain,
        encryption: Some(enc),
        ..Default::default()
    };
    let err = r7z::ArchiveBuilder::new()
        .options(invalid_options.clone())
        .add_file("secret.txt", b"classified")
        .build()
        .unwrap_err();
    assert!(matches!(err, r7z::R7zError::InvalidOptions(_)));

    let mut buf = std::io::Cursor::new(Vec::new());
    let err = match r7z::ArchiveWriter::new(&mut buf, invalid_options) {
        Ok(_) => panic!("ArchiveWriter accepted invalid encrypted header options"),
        Err(err) => err,
    };
    assert!(matches!(err, r7z::R7zError::InvalidOptions(_)));
}

#[test]
fn archive_builder_aes_encrypted_header_p7zip_and_r7z_require_password() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let archive_path = dir.join("aes_header.7z");
    let mut enc = r7z::EncryptionOptions::default_for_password("HeaderSecret");
    enc.encrypt_header = true;
    let options = r7z::ArchiveOptions {
        encryption: Some(enc),
        ..Default::default()
    };
    let bytes = r7z::ArchiveBuilder::new()
        .options(options)
        .add_file("hidden.txt", b"hidden payload")
        .build()
        .expect("build failed");
    std::fs::write(&archive_path, bytes).unwrap();

    let err = match r7z::Archive::open(&archive_path) {
        Ok(_) => panic!("encrypted header opened without password"),
        Err(err) => err,
    };
    assert!(matches!(err, r7z::R7zError::PasswordRequired));
    let archive = r7z::Archive::open_with_password(&archive_path, Some("HeaderSecret")).unwrap();
    assert_eq!(
        archive
            .extract_to_memory_with_password(0, Some("HeaderSecret"))
            .unwrap(),
        b"hidden payload"
    );

    let no_password = run_7z(&["l", archive_path.to_str().unwrap()], dir);
    assert!(!no_password.status.success());

    let out_dir = dir.join("out");
    let out_arg = format!("-o{}", out_dir.to_str().unwrap());
    let out = run_7z(
        &[
            "x",
            "-y",
            "-pHeaderSecret",
            archive_path.to_str().unwrap(),
            &out_arg,
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z x failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(out_dir.join("hidden.txt")).unwrap(),
        b"hidden payload"
    );
}

#[test]
fn archive_builder_empty_only_encrypted_header_p7zip_and_r7z_read() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let archive_path = dir.join("empty_aes_header.7z");
    let mut enc = r7z::EncryptionOptions::default_for_password("HeaderSecret");
    enc.encrypt_header = true;
    let options = r7z::ArchiveOptions {
        encryption: Some(enc),
        ..Default::default()
    };
    let bytes = r7z::ArchiveBuilder::new()
        .options(options)
        .add_directory("emptydir", r7z::EntryMeta::directory_unix_mode(0o040_755))
        .add_empty_file("emptydir/empty.txt", r7z::EntryMeta::archive_file())
        .add_anti_item("removed.txt", r7z::EntryMeta::default())
        .build()
        .expect("build failed");
    std::fs::write(&archive_path, bytes).unwrap();

    let err = match r7z::Archive::open(&archive_path) {
        Ok(_) => panic!("encrypted empty header opened without password"),
        Err(err) => err,
    };
    assert!(matches!(err, r7z::R7zError::PasswordRequired));

    let archive = r7z::Archive::open_with_password(&archive_path, Some("HeaderSecret")).unwrap();
    assert!(archive.streams_info().is_none());
    let fi = archive.files_info().unwrap();
    assert_eq!(archive.num_files(), 3);
    assert!(fi.is_directory(0));
    assert!(fi.is_empty_file(1));
    assert!(fi.is_anti(2));
    assert_eq!(
        archive
            .extract_to_memory_with_password(1, Some("HeaderSecret"))
            .unwrap(),
        b""
    );

    let no_password = run_7z(&["l", archive_path.to_str().unwrap()], dir);
    assert!(!no_password.status.success());

    let listing = run_7z(
        &["l", "-pHeaderSecret", archive_path.to_str().unwrap()],
        dir,
    );
    assert!(
        listing.status.success(),
        "7z l failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&listing.stdout),
        String::from_utf8_lossy(&listing.stderr)
    );
    let listing_stdout = String::from_utf8_lossy(&listing.stdout);
    assert!(listing_stdout.contains("emptydir/empty.txt"));
    assert!(listing_stdout.contains("removed.txt"));

    let out_dir = dir.join("out");
    let out_arg = format!("-o{}", out_dir.to_str().unwrap());
    let out = run_7z(
        &[
            "x",
            "-y",
            "-pHeaderSecret",
            archive_path.to_str().unwrap(),
            &out_arg,
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z x failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out_dir.join("emptydir").is_dir());
    assert_eq!(
        std::fs::read(out_dir.join("emptydir/empty.txt")).unwrap(),
        b""
    );
}

#[test]
fn compression_options_control_lzma2_properties_and_solid_blocks() {
    let options = r7z::ArchiveOptions {
        compression: r7z::CompressionOptions {
            dictionary_size: Some(1 << 20),
            solid: r7z::SolidMode::NonSolid,
            ..Default::default()
        },
        ..Default::default()
    };
    let bytes = r7z::ArchiveBuilder::new()
        .options(options)
        .add_file("a.txt", b"alpha")
        .add_file("b.txt", b"bravo")
        .build()
        .unwrap();
    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let unpack_info = archive
        .streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap();
    assert_eq!(unpack_info.num_folders, 2);
    let folder = unpack_info.parse_folder(0).unwrap();
    assert_eq!(folder.coders[0].properties.as_deref(), Some(&[16][..]));
}

#[test]
fn build_streaming_to_writer_matches_seek_backed_output() {
    let files = vec![
        ("a.txt".to_string(), b"alpha".as_slice()),
        ("b.txt".to_string(), b"bravo".as_slice()),
    ];
    let mut seek_backed = std::io::Cursor::new(Vec::new());
    r7z::build_streaming_with_options(
        files.clone(),
        &mut seek_backed,
        r7z::ArchiveOptions::default(),
    )
    .unwrap();

    struct WriteOnly(Vec<u8>);
    impl std::io::Write for WriteOnly {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut write_only = WriteOnly(Vec::new());
    r7z::build_streaming_to_writer(files, &mut write_only, r7z::ArchiveOptions::default()).unwrap();
    assert_eq!(write_only.0, seek_backed.into_inner());

    let tmp = tempfile::tempdir().unwrap();
    let mut temp_spooled = WriteOnly(Vec::new());
    r7z::build_streaming_to_writer(
        vec![
            ("a.txt".to_string(), b"alpha".as_slice()),
            ("b.txt".to_string(), b"bravo".as_slice()),
        ],
        &mut temp_spooled,
        r7z::ArchiveOptions {
            streaming: r7z::StreamingOptions {
                spool: r7z::SpoolMode::TempFile {
                    dir: Some(tmp.path().to_path_buf()),
                },
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    let archive = r7z::Archive::from_bytes(temp_spooled.0.into()).unwrap();
    assert_eq!(archive.extract_to_memory(1).unwrap(), b"bravo");

    let mut auto_spooled = WriteOnly(Vec::new());
    r7z::build_streaming_to_writer(
        vec![
            ("a.txt".to_string(), b"alpha".as_slice()),
            ("b.txt".to_string(), b"bravo".as_slice()),
        ],
        &mut auto_spooled,
        r7z::ArchiveOptions {
            streaming: r7z::StreamingOptions {
                spool: r7z::SpoolMode::Auto {
                    memory_threshold: 1,
                    dir: Some(tmp.path().to_path_buf()),
                },
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    let archive = r7z::Archive::from_bytes(auto_spooled.0.into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), b"alpha");
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn build_streaming_volumes_splits_final_archive_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("split.7z");
    let payload = (0u8..=255).cycle().take(16 * 1024).collect::<Vec<_>>();
    let entries = vec![("payload.bin".to_string(), payload.as_slice())];
    let options = r7z::ArchiveOptions {
        codec: r7z::Codec::Copy,
        ..Default::default()
    };
    let paths = r7z::build_streaming_volumes(
        entries,
        &base,
        options,
        r7z::VolumeOptions {
            sizes: vec![NonZeroU64::new(2048).unwrap()],
        },
    )
    .unwrap();
    assert!(paths.len() > 1);
    assert_eq!(paths[0], tmp.path().join("split.7z.001"));

    let mut joined = Vec::new();
    for path in &paths {
        joined.extend_from_slice(&std::fs::read(path).unwrap());
    }
    let archive = r7z::Archive::from_bytes(joined.into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), payload);
}

#[test]
fn symlink_entries_round_trip_as_metadata_and_regular_extraction() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let bytes = r7z::ArchiveBuilder::new()
        .add_symlink("link.txt", "target.txt", r7z::EntryMeta::default())
        .build()
        .unwrap();
    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let fi = archive.files_info().unwrap();
    assert!(fi.is_symlink(0));
    assert_eq!(fi.entry_type(0), r7z::EntryType::Symlink);
    assert_eq!(
        archive.symlink_target(0).unwrap().as_deref(),
        Some("target.txt")
    );

    archive.extract_all(&out).unwrap();
    assert_eq!(std::fs::read(out.join("link.txt")).unwrap(), b"target.txt");
    assert!(
        !std::fs::symlink_metadata(out.join("link.txt"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
