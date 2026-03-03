//! Interop tests: create archives with p7zip, extract with r7z, byte-compare.
//!
//! These tests require `7z` (p7zip) to be available in PATH or via nix-shell.
//! Run with: `nix-shell -p p7zip --run "cargo test interop"`

mod support;

use support::run_7z;

#[test]
fn p7zip_read_interop_single_lzma() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // Create a test file
    let original = b"Hello, 7z world! This is a test of the r7z library.";
    std::fs::write(dir.join("hello.txt"), original).unwrap();

    // Create a 7z archive with LZMA
    let archive_path = dir.join("test_lzma.7z");
    let out = run_7z(
        &[
            "a",
            archive_path.to_str().unwrap(),
            "hello.txt",
            "-m0=lzma",
            "-mx=1",
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Open and extract with r7z
    let archive =
        r7z::Archive::open(&archive_path).expect("r7z failed to open p7zip-created archive");

    assert_eq!(archive.num_files(), 1);
    let fi = archive.files_info().unwrap();
    assert_eq!(fi.name(0).unwrap(), "hello.txt");

    let extracted = archive.extract_to_memory(0).unwrap();
    assert_eq!(extracted, original);
}

#[test]
fn p7zip_read_interop_multi_file_lzma2() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // Create multiple test files
    let files = [
        ("alpha.txt", b"AAAA" as &[u8]),
        ("beta.txt", b"BBBB"),
        ("gamma.txt", b"CCCCCCCC"),
    ];
    for (name, data) in &files {
        std::fs::write(dir.join(name), data).unwrap();
    }

    // Create solid LZMA2 archive
    let archive_path = dir.join("test_lzma2.7z");
    let out = run_7z(
        &[
            "a",
            archive_path.to_str().unwrap(),
            "alpha.txt",
            "beta.txt",
            "gamma.txt",
            "-m0=lzma2",
            "-mx=1",
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let archive =
        r7z::Archive::open(&archive_path).expect("r7z failed to open p7zip LZMA2 archive");

    assert_eq!(archive.num_files(), 3);
    let fi = archive.files_info().unwrap();
    let names: Vec<String> = fi.names().collect();
    for (name, original) in &files {
        let idx = names
            .iter()
            .position(|n| n == name)
            .unwrap_or_else(|| panic!("{name} not found in archive"));
        let extracted = archive.extract_to_memory(idx).unwrap();
        assert_eq!(extracted.as_slice(), *original, "mismatch for {name}");
    }
}

#[test]
fn p7zip_read_interop_extract_all() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // Create files
    std::fs::write(dir.join("file_a.txt"), b"content A").unwrap();
    std::fs::write(dir.join("file_b.txt"), b"content B long long long").unwrap();

    let archive_path = dir.join("extract_test.7z");
    let out = run_7z(
        &[
            "a",
            archive_path.to_str().unwrap(),
            "file_a.txt",
            "file_b.txt",
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z a failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let archive = r7z::Archive::open(&archive_path).unwrap();
    let out_dir = tmp.path().join("extracted");
    std::fs::create_dir_all(&out_dir).unwrap();
    archive.extract_all(&out_dir).unwrap();

    assert_eq!(
        std::fs::read(out_dir.join("file_a.txt")).unwrap(),
        b"content A"
    );
    assert_eq!(
        std::fs::read(out_dir.join("file_b.txt")).unwrap(),
        b"content B long long long"
    );
}
/// p7zip creates a BCJ+LZMA2 archive; r7z extracts it correctly.
#[test]
fn p7zip_read_interop_bcj_lzma2() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // Create a file with CALL/JMP patterns that BCJ will filter
    let mut data = vec![0x90u8; 2048];
    for &pos in &[16u32, 64, 128, 256, 512, 1024, 1536] {
        let p = pos as usize;
        data[p] = 0xE8; // CALL
        data[p + 1] = (pos * 7) as u8;
        data[p + 2] = ((pos * 7) >> 8) as u8;
        data[p + 3] = 0x00;
        data[p + 4] = 0x00;
    }
    std::fs::write(dir.join("code.bin"), &data).unwrap();

    // Create 7z with BCJ + LZMA2
    let archive_path = dir.join("bcj_test.7z");
    let out = run_7z(
        &[
            "a",
            archive_path.to_str().unwrap(),
            "code.bin",
            "-mf=BCJ",
            "-mx=7",
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z a failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let archive = r7z::Archive::open(&archive_path).unwrap();
    assert_eq!(archive.num_files(), 1);

    // Verify that the folder has 2 coders (BCJ + LZMA2)
    let si = archive.streams_info().unwrap();
    let ui = si.unpack_info.as_ref().unwrap();
    let folder = ui.parse_folder(0).unwrap();
    assert_eq!(folder.coders.len(), 2, "expected BCJ + LZMA2");

    let extracted = archive.extract_to_memory(0).unwrap();
    assert_eq!(extracted, data, "extracted data should match original");
}
