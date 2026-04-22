use std::{fs, process::Command};

use tempfile::tempdir;

fn run_r7z(args: &[String]) -> std::process::Output {
    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(args)
        .output()
        .expect("r7z binary should run");
    assert!(
        output.status.success(),
        "r7z failed with args {args:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn cli_create_list_test_extract_update_delete() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(input.join("nested")).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    fs::write(input.join("nested/b.txt"), b"bravo").unwrap();
    let archive = tmp.path().join("case.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("a.txt").display().to_string(),
        input.join("nested").display().to_string(),
    ]);

    let listing = run_r7z(&["l".into(), "-slt".into(), archive.display().to_string()]);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("Path = a.txt"));
    assert!(listing.contains("Path = nested/b.txt"));

    run_r7z(&["t".into(), archive.display().to_string()]);

    let out = tmp.path().join("out");
    run_r7z(&[
        "x".into(),
        archive.display().to_string(),
        format!("-o{}", out.display()),
    ]);
    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(fs::read(out.join("nested/b.txt")).unwrap(), b"bravo");

    fs::write(input.join("c.txt"), b"charlie").unwrap();
    run_r7z(&[
        "u".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("c.txt").display().to_string(),
    ]);

    run_r7z(&[
        "d".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        "a.txt".into(),
    ]);

    let out2 = tmp.path().join("out2");
    run_r7z(&[
        "x".into(),
        archive.display().to_string(),
        format!("-o{}", out2.display()),
    ]);
    assert!(!out2.join("a.txt").exists());
    assert_eq!(fs::read(out2.join("c.txt")).unwrap(), b"charlie");
    assert_eq!(fs::read(out2.join("nested/b.txt")).unwrap(), b"bravo");
}

#[test]
fn cli_extract_accepts_wildcard_entry_patterns() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(input.join("nested")).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    fs::write(input.join("b.log"), b"bravo").unwrap();
    fs::write(input.join("nested/c.txt"), b"charlie").unwrap();
    let archive = tmp.path().join("wildcards.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("a.txt").display().to_string(),
        input.join("b.log").display().to_string(),
        input.join("nested").display().to_string(),
    ]);

    let out = tmp.path().join("out");
    run_r7z(&[
        "x".into(),
        archive.display().to_string(),
        "*.txt".into(),
        format!("-o{}", out.display()),
    ]);

    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(fs::read(out.join("nested/c.txt")).unwrap(), b"charlie");
    assert!(!out.join("b.log").exists());
}

#[test]
fn cli_delete_accepts_wildcard_entry_patterns() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.tmp"), b"alpha").unwrap();
    fs::write(input.join("b.tmp"), b"bravo").unwrap();
    fs::write(input.join("keep.txt"), b"keep").unwrap();
    let archive = tmp.path().join("delete-wildcards.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("a.tmp").display().to_string(),
        input.join("b.tmp").display().to_string(),
        input.join("keep.txt").display().to_string(),
    ]);

    run_r7z(&[
        "d".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        "*.tmp".into(),
    ]);

    let out = tmp.path().join("out-delete");
    run_r7z(&[
        "x".into(),
        archive.display().to_string(),
        format!("-o{}", out.display()),
    ]);

    assert!(!out.join("a.tmp").exists());
    assert!(!out.join("b.tmp").exists());
    assert_eq!(fs::read(out.join("keep.txt")).unwrap(), b"keep");
}

#[test]
fn cli_unsupported_p7zip_method_is_command_line_error() {
    let tmp = tempdir().unwrap();
    let archive = tmp.path().join("bad.7z");
    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(["a", "-m0=ZSTD", archive.to_str().unwrap(), "missing.txt"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not yet supported"));
}
