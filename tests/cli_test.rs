use std::{fs, io::Cursor, process::Command};

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
fn cli_create_expands_wildcard_input_paths() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    fs::write(input.join("b.log"), b"bravo").unwrap();
    let archive = tmp.path().join("create-wildcards.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("*.txt").display().to_string(),
    ]);

    let listing = run_r7z(&["l".into(), "-slt".into(), archive.display().to_string()]);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("Path = a.txt"));
    assert!(!listing.contains("Path = b.log"));
}

#[test]
fn cli_update_expands_wildcard_input_paths() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("base.txt"), b"base").unwrap();
    fs::write(input.join("new.txt"), b"new").unwrap();
    fs::write(input.join("skip.log"), b"skip").unwrap();
    let archive = tmp.path().join("update-wildcards.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("base.txt").display().to_string(),
    ]);
    run_r7z(&[
        "u".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("new.*").display().to_string(),
    ]);

    let listing = run_r7z(&["l".into(), "-slt".into(), archive.display().to_string()]);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("Path = base.txt"));
    assert!(listing.contains("Path = new.txt"));
    assert!(!listing.contains("Path = skip.log"));
}

#[test]
fn cli_create_warns_for_missing_literal_but_adds_existing() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    let missing = input.join("missing.bin");
    let archive = tmp.path().join("missing-literal.7z");

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "a",
            "-m0=Copy",
            archive.to_str().unwrap(),
            input.join("a.txt").to_str().unwrap(),
            missing.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing.bin"));
    assert!(stderr.contains("No such file or directory"));
    let listing = run_r7z(&["l".into(), "-slt".into(), archive.display().to_string()]);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("Path = a.txt"));
    assert!(!listing.contains("Path = missing.bin"));
}

#[test]
fn cli_update_warns_for_missing_literal_but_keeps_existing_archive() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("base.txt"), b"base").unwrap();
    fs::write(input.join("new.txt"), b"new").unwrap();
    let missing = input.join("missing.bin");
    let archive = tmp.path().join("missing-update.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("base.txt").display().to_string(),
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "u",
            "-m0=Copy",
            archive.to_str().unwrap(),
            input.join("new.txt").to_str().unwrap(),
            missing.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing.bin"));
    assert!(stderr.contains("No such file or directory"));
    let listing = run_r7z(&["l".into(), "-slt".into(), archive.display().to_string()]);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("Path = base.txt"));
    assert!(listing.contains("Path = new.txt"));
    assert!(!listing.contains("Path = missing.bin"));
}

#[test]
fn cli_create_ignores_unmatched_wildcard_input() {
    let tmp = tempdir().unwrap();
    let archive = tmp.path().join("empty-wildcard.7z");

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .current_dir(tmp.path())
        .args(["a", "-m0=Copy", archive.to_str().unwrap(), "*.bin"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let archive = r7z::Archive::open(&archive).unwrap();
    assert_eq!(archive.num_files(), 0);
}

#[test]
fn cli_create_ignores_unmatched_wildcard_when_other_operands_match() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    fs::write(input.join("skip.log"), b"skip").unwrap();
    let archive = tmp.path().join("mixed-wildcards.7z");

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "a",
            "-m0=Copy",
            archive.to_str().unwrap(),
            input.join("*.txt").to_str().unwrap(),
            input.join("*.bin").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let listing = run_r7z(&["l".into(), "-slt".into(), archive.display().to_string()]);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("Path = a.txt"));
    assert!(!listing.contains("Path = skip.log"));
}

#[test]
fn cli_create_accepts_p7zip_method_chain_options() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), vec![0x5Au8; 4096]).unwrap();
    let archive = tmp.path().join("method-chain.7z");

    run_r7z(&[
        "a".into(),
        "-m0=LZMA2:d=1m:fb=32".into(),
        archive.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);

    let archive = r7z::Archive::open(&archive).unwrap();
    let folder = archive
        .streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap()
        .parse_folder(0)
        .unwrap();
    let lzma2 = folder
        .coders
        .iter()
        .find(|coder| coder.codec_id.as_slice() == r7z::CODEC_LZMA2)
        .unwrap();
    assert_eq!(lzma2.properties.as_deref(), Some(&[16][..]));
    assert_eq!(archive.extract_to_memory(0).unwrap(), vec![0x5Au8; 4096]);
}

#[test]
fn cli_create_accepts_lzma_literal_position_options() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"literal position payload").unwrap();
    let archive = tmp.path().join("lzma-literal-position.7z");

    run_r7z(&[
        "a".into(),
        "-m0=LZMA:lc=2:lp=1:pb=1".into(),
        archive.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);

    let archive = r7z::Archive::open(&archive).unwrap();
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
    assert_eq!(
        archive.extract_to_memory(0).unwrap(),
        b"literal position payload"
    );
}

#[test]
fn cli_rejects_invalid_lzma_literal_position_options() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"payload").unwrap();
    let archive = tmp.path().join("bad-lzma-literal-position.7z");

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "a",
            "-m0=LZMA:lc=5:lp=1",
            archive.to_str().unwrap(),
            input.join("payload.bin").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(7));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("lc"));
    assert!(stderr.contains("lp"));
}

#[test]
fn cli_create_accepts_ppmd_method() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.txt"), b"ppmd payload from cli").unwrap();
    let archive = tmp.path().join("ppmd.7z");

    run_r7z(&[
        "a".into(),
        "-m0=PPMd".into(),
        archive.display().to_string(),
        input.join("payload.txt").display().to_string(),
    ]);

    let archive = r7z::Archive::open(&archive).unwrap();
    let folder = archive
        .streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap()
        .parse_folder(0)
        .unwrap();
    assert_eq!(folder.coders[0].codec_id.as_slice(), r7z::CODEC_PPMD);
    assert_eq!(
        archive.extract_to_memory(0).unwrap(),
        b"ppmd payload from cli"
    );
}

#[test]
fn cli_create_accepts_method_scoped_threading_as_noop() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"payload").unwrap();
    let archive = tmp.path().join("method-threading.7z");

    run_r7z(&[
        "a".into(),
        "-m0=LZMA2:mt=off".into(),
        archive.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);

    let archive = r7z::Archive::open(&archive).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), b"payload");
}

#[test]
fn cli_rejects_invalid_method_scoped_threading_value() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"payload").unwrap();
    let archive = tmp.path().join("bad-method-threading.7z");

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "a",
            "-m0=LZMA2:mt=maybe",
            archive.to_str().unwrap(),
            input.join("payload.bin").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&output.stderr).contains("mt"));
}

#[test]
fn cli_create_accepts_p7zip_standalone_compression_options() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), vec![0xA5u8; 4096]).unwrap();
    let archive = tmp.path().join("standalone-options.7z");

    run_r7z(&[
        "a".into(),
        "-m0=LZMA2".into(),
        "-md=1m".into(),
        "-mfb=32".into(),
        archive.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);

    let archive = r7z::Archive::open(&archive).unwrap();
    let folder = archive
        .streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap()
        .parse_folder(0)
        .unwrap();
    let lzma2 = folder
        .coders
        .iter()
        .find(|coder| coder.codec_id.as_slice() == r7z::CODEC_LZMA2)
        .unwrap();
    assert_eq!(lzma2.properties.as_deref(), Some(&[16][..]));
    assert_eq!(archive.extract_to_memory(0).unwrap(), vec![0xA5u8; 4096]);
}

#[test]
fn cli_create_accepts_p7zip_threading_switch_as_noop() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"payload").unwrap();
    let archive = tmp.path().join("threading-noop.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        "-mmt=off".into(),
        archive.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);

    let archive = r7z::Archive::open(&archive).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), b"payload");
}

#[test]
fn cli_create_accepts_p7zip_output_control_switches_as_noop() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"payload").unwrap();
    let archive = tmp.path().join("output-control-noop.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        "-bd".into(),
        "-bb0".into(),
        "-y".into(),
        archive.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);

    let archive = r7z::Archive::open(&archive).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), b"payload");
}

#[test]
fn cli_create_accepts_p7zip_solid_file_limit() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.bin"), b"alpha").unwrap();
    fs::write(input.join("b.bin"), b"bravo").unwrap();
    let archive = tmp.path().join("solid-limit.7z");

    run_r7z(&[
        "a".into(),
        "-m0=LZMA2".into(),
        "-ms=1f".into(),
        archive.display().to_string(),
        input.join("a.bin").display().to_string(),
        input.join("b.bin").display().to_string(),
    ]);

    let archive = r7z::Archive::open(&archive).unwrap();
    assert_eq!(
        archive
            .streams_info()
            .unwrap()
            .unpack_info
            .as_ref()
            .unwrap()
            .num_folders,
        2
    );
    assert_eq!(archive.extract_to_memory(0).unwrap(), b"alpha");
    assert_eq!(archive.extract_to_memory(1).unwrap(), b"bravo");
}

#[test]
fn cli_create_accepts_p7zip_solid_byte_limit() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.bin"), vec![b'a'; 6 * 1024]).unwrap();
    fs::write(input.join("b.bin"), vec![b'b'; 6 * 1024]).unwrap();
    let archive = tmp.path().join("solid-byte-limit.7z");

    run_r7z(&[
        "a".into(),
        "-m0=LZMA2".into(),
        "-ms=8k".into(),
        archive.display().to_string(),
        input.join("a.bin").display().to_string(),
        input.join("b.bin").display().to_string(),
    ]);

    let archive = r7z::Archive::open(&archive).unwrap();
    assert_eq!(
        archive
            .streams_info()
            .unwrap()
            .unpack_info
            .as_ref()
            .unwrap()
            .num_folders,
        2
    );
    assert_eq!(archive.extract_to_memory(0).unwrap(), vec![b'a'; 6 * 1024]);
    assert_eq!(archive.extract_to_memory(1).unwrap(), vec![b'b'; 6 * 1024]);
}

#[test]
fn cli_extract_aos_skips_existing_files() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"archive").unwrap();
    let archive = tmp.path().join("overwrite.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("a.txt").display().to_string(),
    ]);

    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("a.txt"), b"existing").unwrap();

    run_r7z(&[
        "x".into(),
        "-aos".into(),
        archive.display().to_string(),
        format!("-o{}", out.display()),
    ]);

    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"existing");
}

#[test]
fn cli_extract_aoa_overwrites_existing_files() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"archive").unwrap();
    let archive = tmp.path().join("overwrite-all.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("a.txt").display().to_string(),
    ]);

    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("a.txt"), b"existing").unwrap();

    run_r7z(&[
        "x".into(),
        "-aoa".into(),
        archive.display().to_string(),
        format!("-o{}", out.display()),
    ]);

    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"archive");
}

#[test]
fn cli_extract_default_noninteractive_refuses_existing_file() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"archive").unwrap();
    let archive = tmp.path().join("default-overwrite.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("a.txt").display().to_string(),
    ]);

    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("a.txt"), b"existing").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "x",
            archive.to_str().unwrap(),
            &format!("-o{}", out.display()),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"existing");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Skipping existing path"));
}

#[test]
fn cli_extract_y_overwrites_existing_file() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"archive").unwrap();
    let archive = tmp.path().join("yes-overwrite.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("a.txt").display().to_string(),
    ]);

    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("a.txt"), b"existing").unwrap();

    run_r7z(&[
        "x".into(),
        "-y".into(),
        archive.display().to_string(),
        format!("-o{}", out.display()),
    ]);

    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"archive");
}

#[test]
fn cli_extract_flat_duplicate_basenames_use_overwrite_policy() {
    let tmp = tempdir().unwrap();
    let archive = tmp.path().join("flat-duplicates.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .compression(r7z::Codec::Copy)
        .add_file("one/a.txt", b"one")
        .add_file("two/a.txt", b"two")
        .build()
        .unwrap();
    fs::write(&archive, bytes).unwrap();

    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "e",
            archive.to_str().unwrap(),
            &format!("-o{}", out.display()),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"one");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Skipping existing path"));
}

#[test]
fn cli_extract_directory_over_file_replaces_file_with_yes() {
    let tmp = tempdir().unwrap();
    let archive = tmp.path().join("dir-over-file.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .add_directory("dir", r7z::EntryMeta::default())
        .build()
        .unwrap();
    fs::write(&archive, bytes).unwrap();

    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("dir"), b"file").unwrap();

    run_r7z(&[
        "x".into(),
        "-y".into(),
        archive.display().to_string(),
        format!("-o{}", out.display()),
    ]);

    assert!(out.join("dir").is_dir());
}

#[test]
fn cli_extract_file_over_directory_is_not_recursive_delete() {
    let tmp = tempdir().unwrap();
    let archive = tmp.path().join("file-over-dir.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .compression(r7z::Codec::Copy)
        .add_file("dir", b"archive")
        .build()
        .unwrap();
    fs::write(&archive, bytes).unwrap();

    let out = tmp.path().join("out");
    fs::create_dir_all(out.join("dir")).unwrap();
    fs::write(out.join("dir/keep.txt"), b"keep").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "x",
            "-y",
            archive.to_str().unwrap(),
            &format!("-o{}", out.display()),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(out.join("dir").is_dir());
    assert_eq!(fs::read(out.join("dir/keep.txt")).unwrap(), b"keep");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Skipping existing path"));
}

#[test]
fn cli_extract_warns_when_operands_match_nothing() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"archive").unwrap();
    let archive = tmp.path().join("missing-selection.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("a.txt").display().to_string(),
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(["x", archive.to_str().unwrap(), "*.bin"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("No files to process"));
}

#[test]
fn cli_test_warns_when_operands_match_nothing() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"archive").unwrap();
    let archive = tmp.path().join("missing-test-selection.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("a.txt").display().to_string(),
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(["t", archive.to_str().unwrap(), "*.bin"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("No files to process"));
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
fn cli_list_accepts_wildcard_entry_patterns() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    fs::write(input.join("b.log"), b"bravo").unwrap();
    let archive = tmp.path().join("list-wildcards.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        archive.display().to_string(),
        input.join("a.txt").display().to_string(),
        input.join("b.log").display().to_string(),
    ]);

    let listing = run_r7z(&[
        "l".into(),
        "-slt".into(),
        archive.display().to_string(),
        "*.txt".into(),
    ]);
    let listing = String::from_utf8_lossy(&listing.stdout);

    assert!(listing.contains("Path = a.txt"));
    assert!(!listing.contains("Path = b.log"));
}

#[test]
fn cli_test_accepts_wildcard_entry_patterns() {
    let tmp = tempdir().unwrap();
    let archive = tmp.path().join("test-wildcards.7z");
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = r7z::ArchiveWriter::new(&mut cursor, r7z::ArchiveOptions::default())
            .unwrap()
            .compression(r7z::Codec::Copy);
        writer.append("good.txt", &b"good-payload"[..]).unwrap();
        writer.new_folder().unwrap();
        writer
            .append("bad.log", &b"bad-payload-unique"[..])
            .unwrap();
        writer.finish().unwrap();
    }
    let mut bytes = cursor.into_inner();
    let bad_offset = bytes
        .windows(b"bad-payload-unique".len())
        .position(|window| window == b"bad-payload-unique")
        .unwrap();
    bytes[bad_offset] ^= 0x55;
    fs::write(&archive, bytes).unwrap();

    let all = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(["t", archive.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(all.status.code(), Some(1));

    run_r7z(&["t".into(), archive.display().to_string(), "*.txt".into()]);
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
