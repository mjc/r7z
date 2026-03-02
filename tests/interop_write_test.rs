//! Write-interop tests: create archives with r7z, extract with p7zip, byte-compare.

mod support;
use support::run_7z;

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
