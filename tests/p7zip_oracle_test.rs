use std::{path::Path, process::Command};

#[test]
#[ignore = "builds the pinned p7zip-project/p7zip oracle from source"]
fn source_built_p7zip_oracle_is_pinned_and_reports_methods() {
    let output = Command::new("scripts/ensure_p7zip_oracle.sh")
        .output()
        .expect("oracle helper should run");
    assert!(
        output.status.success(),
        "oracle helper failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let bin = stdout.lines().last().unwrap_or("").trim();
    assert!(Path::new(bin).is_file(), "7zz path missing: {bin}");

    let head = Command::new("git")
        .args(["-C", "/tmp/r7z-p7zip-compare", "rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        r7z::P7ZIP_ORACLE_SHA
    );

    let info = std::fs::read_to_string("/tmp/r7z-p7zip-compare/7zz-i.txt").unwrap();
    for method in ["LZMA2", "ZSTD", "BROTLI", "LZ4", "LZ5", "LIZARD", "LZHAM"] {
        assert!(info.contains(method), "7zz i output missing {method}");
    }
}
