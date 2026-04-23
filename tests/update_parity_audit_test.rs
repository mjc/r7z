#![allow(clippy::pedantic)]

mod support;

use std::{fs, process::Command};

use support::{assert_extracted_files, create_p7zip_archive, extract_with_p7zip};
use tempfile::tempdir;

#[test]
fn update_preserves_unsupported_method_archive_when_folder_is_unchanged() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("original.txt"), b"original").unwrap();
    fs::write(input.join("new.txt"), b"new").unwrap();
    let archive = tmp.path().join("zstd.7z");

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

    let out = tmp.path().join("out");
    extract_with_p7zip(tmp.path(), &archive, &out);
    assert_extracted_files(
        &out,
        &[
            (
                std::path::PathBuf::from("original.txt"),
                b"original".to_vec(),
            ),
            (std::path::PathBuf::from("new.txt"), b"new".to_vec()),
        ],
    );
}
