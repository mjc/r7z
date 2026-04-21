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
fn p7zip_read_interop_multi_file_lzma2_non_solid() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let files = [
        ("one.txt", b"one" as &[u8]),
        ("two.txt", b"two two"),
        ("three.txt", b"three three three"),
    ];
    for (name, data) in &files {
        std::fs::write(dir.join(name), data).unwrap();
    }

    let archive_path = dir.join("non_solid.7z");
    let out = run_7z(
        &[
            "a",
            archive_path.to_str().unwrap(),
            "one.txt",
            "two.txt",
            "three.txt",
            "-m0=lzma2",
            "-ms=off",
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let archive = r7z::Archive::open(&archive_path).unwrap();
    let fi = archive.files_info().unwrap();
    let names: Vec<String> = fi.names().collect();
    for (name, original) in &files {
        let idx = names.iter().position(|n| n == name).unwrap();
        assert_eq!(
            archive.extract_to_memory(idx).unwrap().as_slice(),
            *original
        );
    }
}

#[test]
fn p7zip_read_interop_copy_codec() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let original = b"stored without compression";
    std::fs::write(dir.join("stored.bin"), original).unwrap();

    let archive_path = dir.join("copy.7z");
    let out = run_7z(
        &[
            "a",
            archive_path.to_str().unwrap(),
            "stored.bin",
            "-m0=Copy",
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let archive = r7z::Archive::open(&archive_path).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), original);
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

#[test]
fn p7zip_extract_all_preserves_directories_and_zero_byte_files() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let input = dir.join("input");
    std::fs::create_dir_all(input.join("nested/empty_dir")).unwrap();
    std::fs::write(input.join("nested/file.txt"), b"nested content").unwrap();
    std::fs::write(input.join("empty.txt"), b"").unwrap();

    let archive_path = dir.join("tree.7z");
    let out = run_7z(&["a", archive_path.to_str().unwrap(), "input"], dir);
    assert!(
        out.status.success(),
        "7z a failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let archive = r7z::Archive::open(&archive_path).unwrap();
    let out_dir = dir.join("out");
    archive.extract_all(&out_dir).unwrap();

    assert!(out_dir.join("input/nested/empty_dir").is_dir());
    assert_eq!(
        std::fs::read(out_dir.join("input/nested/file.txt")).unwrap(),
        b"nested content"
    );
    assert_eq!(std::fs::read(out_dir.join("input/empty.txt")).unwrap(), b"");
}

#[test]
fn p7zip_read_interop_names_with_spaces_unicode_and_nested_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    std::fs::create_dir_all(dir.join("nested dir")).unwrap();
    std::fs::write(dir.join("space name.txt"), b"space").unwrap();
    std::fs::write(dir.join("nested dir/unicode-\u{2603}.txt"), b"unicode").unwrap();

    let archive_path = dir.join("names.7z");
    let out = run_7z(
        &[
            "a",
            archive_path.to_str().unwrap(),
            "space name.txt",
            "nested dir/unicode-\u{2603}.txt",
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z a failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let archive = r7z::Archive::open(&archive_path).unwrap();
    let fi = archive.files_info().unwrap();
    let names: Vec<String> = fi.names().collect();
    let space_idx = names.iter().position(|n| n == "space name.txt").unwrap();
    let unicode_idx = names
        .iter()
        .position(|n| n == "nested dir/unicode-\u{2603}.txt")
        .unwrap();
    assert_eq!(archive.extract_to_memory(space_idx).unwrap(), b"space");
    assert_eq!(archive.extract_to_memory(unicode_idx).unwrap(), b"unicode");
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

// ── AES-256-SHA-256 encrypted archive tests ──────────────────────────────────

/// Decrypt a pre-built AES-encrypted fixture with the correct password.
#[test]
fn aes_decrypt_fixture_correct_password() {
    let archive = r7z::Archive::open(std::path::Path::new("tests/fixtures/aes256.7z"))
        .expect("failed to open AES fixture");

    assert_eq!(archive.num_files(), 1);

    let fi = archive.files_info().unwrap();
    assert_eq!(fi.name(0).unwrap(), "encrypted_test.txt");

    let extracted = archive
        .extract_to_memory_with_password(0, Some("test123"))
        .expect("decryption should succeed");
    assert_eq!(
        extracted, b"Hello from an encrypted 7z archive!\n",
        "decrypted content mismatch"
    );
}

/// Attempting to extract an AES-encrypted file without a password gives PasswordRequired.
#[test]
fn aes_decrypt_no_password_returns_error() {
    let archive = r7z::Archive::open(std::path::Path::new("tests/fixtures/aes256.7z")).unwrap();

    let err = archive.extract_to_memory(0).unwrap_err();
    assert!(
        matches!(err, r7z::R7zError::PasswordRequired),
        "expected PasswordRequired, got {err:?}"
    );
}

/// extract_all_with_password round-trips the AES fixture to disk.
#[test]
fn aes_extract_all_with_password() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = r7z::Archive::open(std::path::Path::new("tests/fixtures/aes256.7z")).unwrap();

    archive
        .extract_all_with_password(tmp.path(), Some("test123"))
        .expect("extract_all_with_password should succeed");

    let content = std::fs::read(tmp.path().join("encrypted_test.txt")).unwrap();
    assert_eq!(content, b"Hello from an encrypted 7z archive!\n");
}

/// p7zip creates an AES+LZMA2 archive on the fly; r7z decrypts it.
#[test]
fn p7zip_aes_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let original = b"Encryption round-trip test payload for r7z!";
    std::fs::write(dir.join("secret.txt"), original).unwrap();

    let archive_path = dir.join("encrypted.7z");
    let out = run_7z(
        &[
            "a",
            archive_path.to_str().unwrap(),
            "secret.txt",
            "-pMyS3cret!",
            "-mhe=off",
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z a failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let archive = r7z::Archive::open(&archive_path).unwrap();
    let err = archive.extract_to_memory(0).unwrap_err();
    assert!(matches!(err, r7z::R7zError::PasswordRequired));
    let err = archive
        .extract_to_memory_with_password(0, Some("wrong"))
        .unwrap_err();
    assert!(matches!(
        err,
        r7z::R7zError::Decompression | r7z::R7zError::Crc
    ));
    let extracted = archive
        .extract_to_memory_with_password(0, Some("MyS3cret!"))
        .expect("round-trip decryption failed");
    assert_eq!(extracted, original.as_slice());
}

#[test]
fn p7zip_aes_encrypted_headers_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    std::fs::write(dir.join("header_secret.txt"), b"header encrypted").unwrap();

    let archive_path = dir.join("encrypted_headers.7z");
    let out = run_7z(
        &[
            "a",
            archive_path.to_str().unwrap(),
            "header_secret.txt",
            "-pHeaderPass!",
            "-mhe=on",
        ],
        dir,
    );
    assert!(
        out.status.success(),
        "7z a failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let err = match r7z::Archive::open(&archive_path) {
        Ok(_) => panic!("encrypted headers opened without a password"),
        Err(err) => err,
    };
    assert!(matches!(err, r7z::R7zError::PasswordRequired));

    let archive = r7z::Archive::open_with_password(&archive_path, Some("HeaderPass!")).unwrap();
    let fi = archive.files_info().unwrap();
    assert_eq!(fi.name(0).unwrap(), "header_secret.txt");
    let extracted = archive
        .extract_to_memory_with_password(0, Some("HeaderPass!"))
        .unwrap();
    assert_eq!(extracted, b"header encrypted");
}

#[test]
fn p7zip_unsupported_codecs_return_unsupported_codec() {
    for method in ["BZip2", "PPMd", "Deflate"] {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("payload.txt"), b"unsupported codec payload").unwrap();

        let archive_path = dir.join(format!("{method}.7z"));
        let method_arg = format!("-m0={method}");
        let out = run_7z(
            &[
                "a",
                archive_path.to_str().unwrap(),
                "payload.txt",
                method_arg.as_str(),
            ],
            dir,
        );
        if !out.status.success() {
            eprintln!(
                "skipping unsupported-codec interop for {method}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            continue;
        }

        let archive = r7z::Archive::open(&archive_path).unwrap();
        let err = archive.extract_to_memory(0).unwrap_err();
        assert!(
            matches!(err, r7z::R7zError::UnsupportedCodec(_)),
            "expected UnsupportedCodec for {method}, got {err:?}"
        );
    }
}

/// Decrypt a file from a large real-world AES-encrypted archive.
/// Requires /mnt/emulation/Nintendo64Archive.7z to be present.
#[test]
#[ignore]
fn aes_decrypt_n64_archive() {
    let path = std::path::Path::new("/mnt/emulation/Nintendo64Archive.7z");
    if !path.exists() {
        eprintln!("skipping: {path:?} not found");
        return;
    }

    let archive = r7z::Archive::open_with_password(path, Some("snahp.it"))
        .expect("failed to open N64 archive");
    let num = archive.num_files();
    eprintln!("N64 archive: {num} files");
    assert!(num > 600, "expected 600+ files, got {num}");

    let fi = archive.files_info().unwrap();
    for i in 0..5.min(num) {
        eprintln!("  [{i}] {:?}", fi.name(i));
    }

    // Verify specific known file names from this archive
    assert_eq!(
        fi.name(0).unwrap(),
        "Betas, Unreleased ROMS, and Protos/Tower&Shaft.eep"
    );
    assert_eq!(
        fi.name(1).unwrap(),
        "Full Retail NTSC ROM Set/007 - GoldenEye (USA).n64"
    );

    // Extract ALL files from the encrypted archive
    let tmp = tempfile::tempdir().unwrap();
    let t0 = std::time::Instant::now();
    archive
        .extract_all_with_password(tmp.path(), Some("snahp.it"))
        .expect("extract_all failed");
    let elapsed = t0.elapsed();

    // Count extracted files
    let mut count = 0u64;
    let mut total_bytes = 0u64;
    for entry in walkdir::WalkDir::new(tmp.path())
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            total_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
            count += 1;
        }
    }
    eprintln!(
        "Extracted {count} files, {:.2} GB total in {elapsed:.2?}",
        total_bytes as f64 / 1_073_741_824.0
    );

    // Spot-check: verify Tower&Shaft.eep
    let eep = std::fs::read(
        tmp.path()
            .join("Betas, Unreleased ROMS, and Protos/Tower&Shaft.eep"),
    )
    .unwrap();
    assert_eq!(eep.len(), 512);
    assert_eq!(crc32fast::hash(&eep), 0xEDDBB2AD);

    // Spot-check: verify GoldenEye
    let ge = std::fs::read(
        tmp.path()
            .join("Full Retail NTSC ROM Set/007 - GoldenEye (USA).n64"),
    )
    .unwrap();
    assert_eq!(ge.len(), 12_582_912, "GoldenEye should be 12MB");
    assert_eq!(crc32fast::hash(&ge), 0x8B70CB5B, "GoldenEye CRC mismatch");
}
