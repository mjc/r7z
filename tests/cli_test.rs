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
fn cli_help_describes_encoder_thread_selection() {
    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .arg("--help")
        .output()
        .expect("r7z binary should run");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(help.contains("-mmt=off|on|N"), "{help}");
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
fn cli_create_accepts_lzma_match_finder_options() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"match finder payload").unwrap();
    let scoped = tmp.path().join("lzma-mf-scoped.7z");
    let standalone = tmp.path().join("lzma-mf-standalone.7z");

    run_r7z(&[
        "a".into(),
        "-m0=LZMA:mf=bt4".into(),
        scoped.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);
    run_r7z(&[
        "a".into(),
        "-m0=LZMA".into(),
        "-mmf=hc4".into(),
        standalone.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);

    assert_eq!(
        r7z::Archive::open(&scoped)
            .unwrap()
            .extract_to_memory(0)
            .unwrap(),
        b"match finder payload"
    );
    assert_eq!(
        r7z::Archive::open(&standalone)
            .unwrap()
            .extract_to_memory(0)
            .unwrap(),
        b"match finder payload"
    );
}

#[test]
fn cli_create_accepts_lzma_algorithm_and_match_cycles_options() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"algorithm cycle payload").unwrap();
    let scoped = tmp.path().join("lzma-algo-scoped.7z");
    let standalone = tmp.path().join("lzma-algo-standalone.7z");

    run_r7z(&[
        "a".into(),
        "-m0=LZMA:a=0:mc=16".into(),
        scoped.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);
    run_r7z(&[
        "a".into(),
        "-m0=LZMA".into(),
        "-ma=1".into(),
        "-mmc=32".into(),
        standalone.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);

    assert_eq!(
        r7z::Archive::open(&scoped)
            .unwrap()
            .extract_to_memory(0)
            .unwrap(),
        b"algorithm cycle payload"
    );
    assert_eq!(
        r7z::Archive::open(&standalone)
            .unwrap()
            .extract_to_memory(0)
            .unwrap(),
        b"algorithm cycle payload"
    );
}

#[test]
fn cli_rejects_invalid_lzma_algorithm_and_match_cycles_options() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"payload").unwrap();
    let archive = tmp.path().join("bad-lzma-algorithm.7z");

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "a",
            "-m0=LZMA:a=2",
            archive.to_str().unwrap(),
            input.join("payload.bin").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&output.stderr).contains("algorithm"));

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "a",
            "-m0=LZMA:mc=bad",
            archive.to_str().unwrap(),
            input.join("payload.bin").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&output.stderr).contains("match cycles"));
}

#[test]
fn cli_create_accepts_lzma2_chunk_size_options() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), vec![0x5Au8; 64 * 1024]).unwrap();
    let scoped = tmp.path().join("lzma2-chunk-scoped.7z");
    let standalone = tmp.path().join("lzma2-chunk-standalone.7z");

    run_r7z(&[
        "a".into(),
        "-m0=LZMA2:d=1m:c=1m".into(),
        scoped.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);
    run_r7z(&[
        "a".into(),
        "-m0=LZMA2".into(),
        "-md=1m".into(),
        "-mc=1m".into(),
        standalone.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);

    assert_eq!(
        r7z::Archive::open(&scoped)
            .unwrap()
            .extract_to_memory(0)
            .unwrap(),
        vec![0x5Au8; 64 * 1024]
    );
    assert_eq!(
        r7z::Archive::open(&standalone)
            .unwrap()
            .extract_to_memory(0)
            .unwrap(),
        vec![0x5Au8; 64 * 1024]
    );
}

#[test]
fn cli_create_rejects_oversized_lzma2_chunk_size() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"payload").unwrap();
    let archive = tmp.path().join("too-large-lzma2-chunk.7z");

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "a",
            "-m0=LZMA2:c=2g",
            archive.to_str().unwrap(),
            input.join("payload.bin").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&output.stderr).contains("lzma2_chunk_size"));
}

#[test]
fn cli_create_split_volumes_from_path_backed_input() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    let payload = (0u8..=255).cycle().take(16 * 1024).collect::<Vec<_>>();
    fs::write(input.join("payload.bin"), &payload).unwrap();
    let archive = tmp.path().join("split.7z");

    run_r7z(&[
        "a".into(),
        "-m0=Copy".into(),
        "-v2k".into(),
        archive.display().to_string(),
        input.join("payload.bin").display().to_string(),
    ]);

    assert!(tmp.path().join("split.7z.001").exists());
    assert!(tmp.path().join("split.7z.002").exists());

    let mut joined = Vec::new();
    let mut idx = 1;
    loop {
        let path = tmp.path().join(format!("split.7z.{idx:03}"));
        if !path.exists() {
            break;
        }
        joined.extend_from_slice(&fs::read(path).unwrap());
        idx += 1;
    }
    let archive = r7z::Archive::from_bytes(joined.into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), payload);
}

#[test]
fn cli_rejects_invalid_lzma_match_finder_option() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"payload").unwrap();
    let archive = tmp.path().join("bad-lzma-mf.7z");

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "a",
            "-m0=LZMA:mf=bt3",
            archive.to_str().unwrap(),
            input.join("payload.bin").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&output.stderr).contains("match finder"));
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
fn cli_create_accepts_standalone_lzma_literal_position_switches() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"standalone literal position").unwrap();
    let archive = tmp.path().join("standalone-lzma-literal-position.7z");

    run_r7z(&[
        "a".into(),
        "-m0=LZMA".into(),
        "-mlc=2".into(),
        "-mlp=1".into(),
        "-mpb=1".into(),
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
fn cli_create_accepts_single_method_thread() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"payload").unwrap();
    for (index, threads) in ["off", "1"].into_iter().enumerate() {
        let archive = tmp.path().join(format!("method-threading-{index}.7z"));
        run_r7z(&[
            "a".into(),
            format!("-m0=LZMA2:mt={threads}"),
            archive.display().to_string(),
            input.join("payload.bin").display().to_string(),
        ]);
        let archive = r7z::Archive::open(&archive).unwrap();
        assert_eq!(archive.extract_to_memory(0).unwrap(), b"payload");
    }
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
fn cli_create_accepts_single_thread_switches() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("payload.bin"), b"payload").unwrap();
    for (index, threads) in ["-mmt=off", "-mmt=1", "-mmt1"].into_iter().enumerate() {
        let archive = tmp.path().join(format!("threading-{index}.7z"));
        run_r7z(&[
            "a".into(),
            "-m0=Copy".into(),
            threads.into(),
            archive.display().to_string(),
            input.join("payload.bin").display().to_string(),
        ]);
        let archive = r7z::Archive::open(&archive).unwrap();
        assert_eq!(archive.extract_to_memory(0).unwrap(), b"payload");
    }
}

#[test]
fn cli_encoder_thread_switches_create_readable_archives() {
    let tmp = tempdir().unwrap();
    let payload = tmp.path().join("payload.bin");
    let data = (0..(3 * 1024 * 1024 + 17))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(&payload, &data).unwrap();

    for (index, switch) in ["-mmt", "-mmt=on", "-mmt=2", "-mmt2", "-m0=LZMA2:mt=2"]
        .into_iter()
        .enumerate()
    {
        let archive = tmp.path().join(format!("threads-{index}.7z"));
        run_r7z(&[
            "a".into(),
            "-md=1m".into(),
            "-mc=1m".into(),
            switch.into(),
            archive.display().to_string(),
            payload.display().to_string(),
        ]);
        assert_eq!(
            r7z::Archive::open(&archive)
                .unwrap()
                .extract_to_memory(0)
                .unwrap(),
            data
        );
    }
}

#[test]
fn cli_rejects_threads_for_unsupported_codec_and_out_of_range_count() {
    let tmp = tempdir().unwrap();
    let payload = tmp.path().join("payload.bin");
    fs::write(&payload, b"payload").unwrap();
    for switch in ["-m0=Copy", "-mmt=257"] {
        let archive = tmp.path().join(format!("bad-{switch}.7z"));
        let args = if switch == "-m0=Copy" {
            vec![
                "a",
                switch,
                "-mmt=2",
                archive.to_str().unwrap(),
                payload.to_str().unwrap(),
            ]
        } else {
            vec![
                "a",
                switch,
                archive.to_str().unwrap(),
                payload.to_str().unwrap(),
            ]
        };
        let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(7), "{switch}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("thread"));
        assert!(!archive.exists());
    }
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

#[cfg(windows)]
#[test]
fn cli_extract_case_insensitive_name_collisions_use_overwrite_policy() {
    let tmp = tempdir().unwrap();
    let archive = tmp.path().join("case-collisions.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .compression(r7z::Codec::Copy)
        .add_file("Name.txt", b"first")
        .add_file("name.txt", b"second")
        .build()
        .unwrap();
    fs::write(&archive, bytes).unwrap();

    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args([
            "x",
            "-y",
            archive.to_str().unwrap(),
            &format!("-o{}", out.display()),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(fs::read(out.join("Name.txt")).unwrap(), b"second");
    assert_eq!(fs::read_dir(out).unwrap().count(), 1);
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
#[cfg(unix)]
fn cli_extract_applies_overwrite_policy_to_destination_symlinks() {
    ["x", "e"]
        .into_iter()
        .flat_map(|command| {
            ["missing", "file", "directory"]
                .into_iter()
                .map(move |kind| (command, kind))
        })
        .for_each(|(command, kind)| {
            let tmp = tempdir().unwrap();
            let archive = tmp.path().join("symlink-destination.7z");
            let bytes = r7z::ArchiveBuilder::new()
                .compression(r7z::Codec::Copy)
                .add_file("entry", b"archive")
                .build()
                .unwrap();
            fs::write(&archive, bytes).unwrap();
            let outside = tmp.path().join("outside");
            match kind {
                "file" => fs::write(&outside, b"keep").unwrap(),
                "directory" => {
                    fs::create_dir(&outside).unwrap();
                    fs::write(outside.join("keep"), b"keep").unwrap();
                }
                _ => {}
            }
            let out = tmp.path().join("out");
            fs::create_dir(&out).unwrap();
            let destination = out.join("entry");
            std::os::unix::fs::symlink(&outside, &destination).unwrap();

            ["-aos", "-y"].into_iter().for_each(|mode| {
                run_r7z(&[
                    command.into(),
                    mode.into(),
                    archive.display().to_string(),
                    format!("-o{}", out.display()),
                ]);
                let metadata = fs::symlink_metadata(&destination).unwrap();
                match mode {
                    "-aos" => assert!(metadata.is_symlink()),
                    _ => {
                        assert!(metadata.is_file());
                        assert_eq!(fs::read(&destination).unwrap(), b"archive");
                    }
                }
                match kind {
                    "file" => assert_eq!(fs::read(&outside).unwrap(), b"keep"),
                    "directory" => assert_eq!(fs::read(outside.join("keep")).unwrap(), b"keep"),
                    _ => assert!(!outside.exists()),
                }
            });
        });
}

#[cfg(unix)]
#[test]
fn cli_extract_replaces_hard_links_without_modifying_the_linked_file() {
    let tmp = tempdir().unwrap();
    let archive = tmp.path().join("hard-link-destination.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .compression(r7z::Codec::Copy)
        .add_file("entry.txt", b"archive contents")
        .build()
        .unwrap();
    fs::write(&archive, bytes).unwrap();
    let output = tmp.path().join("out");
    fs::create_dir(&output).unwrap();
    let outside = tmp.path().join("outside.txt");
    fs::write(&outside, b"outside contents").unwrap();
    fs::hard_link(&outside, output.join("entry.txt")).unwrap();

    run_r7z(&[
        "x".into(),
        "-y".into(),
        archive.display().to_string(),
        format!("-o{}", output.display()),
    ]);

    assert_eq!(fs::read(outside).unwrap(), b"outside contents");
    assert_eq!(
        fs::read(output.join("entry.txt")).unwrap(),
        b"archive contents"
    );
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
fn cli_test_empty_archive_distinguishes_all_from_unmatched_patterns() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("empty.7z");
    fs::write(&path, r7z::ArchiveBuilder::new().build().unwrap()).unwrap();

    let output = run_r7z(&["t".into(), path.display().to_string()]);
    assert!(String::from_utf8_lossy(&output.stdout).contains("Everything is Ok"));

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(["t", path.to_str().unwrap(), "*"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("No files to process"));
}

#[test]
fn cli_metadata_only_selection_does_not_open_encrypted_data() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("metadata.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .options(r7z::ArchiveOptions {
            codec: r7z::Codec::Copy,
            encryption: Some(r7z::EncryptionOptions::default_for_password("secret")),
            ..Default::default()
        })
        .add_file("payload", b"encrypted payload")
        .add_directory("directory", r7z::EntryMeta::default())
        .add_empty_file("empty", r7z::EntryMeta::default())
        .add_empty_file("empty-link", r7z::EntryMeta::symlink())
        .add_anti_item("removed", r7z::EntryMeta::default())
        .build()
        .unwrap();
    fs::write(&path, bytes).unwrap();

    ["directory", "empty", "empty-link", "removed"]
        .into_iter()
        .for_each(|name| {
            let output = run_r7z(&["t".into(), path.display().to_string(), name.into()]);
            assert!(String::from_utf8_lossy(&output.stdout).contains("Everything is Ok"));
            ["x", "e"].into_iter().for_each(|command| {
                let destination = tmp.path().join(format!("{command}-{name}"));
                run_r7z(&[
                    command.into(),
                    path.display().to_string(),
                    name.into(),
                    format!("-o{}", destination.display()),
                ]);
                match (command, name) {
                    ("x", "directory") => assert!(destination.join(name).is_dir()),
                    (_, "empty" | "empty-link") => {
                        assert_eq!(fs::read(destination.join(name)).unwrap(), b"");
                    }
                    _ => assert!(!destination.join(name).exists()),
                }
                assert!(!destination.join("payload").exists());
            });
        });

    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(["x", path.to_str().unwrap(), "missing"])
        .arg(format!("-o{}", tmp.path().join("unmatched").display()))
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
            .compression(r7z::Codec::Copy)
            .expect("codec selection failed");
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

fn create_sparse_lzma2_archive_and_list_size(size: u64) {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("large.bin");
    let file = fs::File::create(&input).unwrap();
    file.set_len(size).unwrap();
    drop(file);
    let archive = tmp.path().join("large.7z");

    run_r7z(&[
        "a".into(),
        archive.display().to_string(),
        input.display().to_string(),
    ]);

    let listing = run_r7z(&["l".into(), "-slt".into(), archive.display().to_string()]);
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("Path = large.bin"));
    assert!(listing.contains(&format!("Size = {size}")));
}

#[test]
#[ignore = "large"]
fn large_cli_create_1gb_sparse_lzma2_archive() {
    create_sparse_lzma2_archive_and_list_size(1024 * 1024 * 1024);
}

#[test]
#[ignore = "large"]
fn large_cli_create_5gb_sparse_lzma2_archive() {
    create_sparse_lzma2_archive_and_list_size(5 * 1024 * 1024 * 1024);
}

#[test]
fn cli_mixed_entry_kinds_survive_testing_extraction_and_rewrite() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mixed.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .compression(r7z::Codec::Copy)
        .add_directory("directory", r7z::EntryMeta::default())
        .add_empty_file("empty", r7z::EntryMeta::default())
        .add_empty_file("empty-link", r7z::EntryMeta::symlink())
        .add_directory("mode-link", r7z::EntryMeta::symlink())
        .add_anti_item("removed", r7z::EntryMeta::symlink())
        .add_file("keep", b"payload")
        .add_file("drop", b"discard")
        .add_file_entry("link", b"target", r7z::EntryMeta::symlink())
        .build()
        .unwrap();
    fs::write(&path, bytes).unwrap();
    run_r7z(&["t".into(), path.display().to_string()]);
    let output = tmp.path().join("out");
    run_r7z(&[
        "x".into(),
        path.display().to_string(),
        format!("-o{}", output.display()),
    ]);
    assert!(output.join("directory").is_dir());
    assert!(!output.join("removed").exists());
    for (name, data) in [
        ("empty", &b""[..]),
        ("empty-link", &b""[..]),
        ("mode-link", &b""[..]),
        ("keep", &b"payload"[..]),
        ("drop", &b"discard"[..]),
        ("link", &b"target"[..]),
    ] {
        assert_eq!(fs::read(output.join(name)).unwrap(), data);
    }
    let metadata = |archive: &r7z::Archive| {
        archive
            .listing(None)
            .unwrap()
            .entries
            .into_iter()
            .filter(|entry| entry.path != "drop")
            .map(|entry| {
                (
                    entry.path,
                    entry.kind,
                    entry.size,
                    entry.crc,
                    entry.attributes,
                )
            })
            .collect::<Vec<_>>()
    };
    let before = metadata(&r7z::Archive::open(&path).unwrap());
    run_r7z(&[
        "d".into(),
        "-m0=Copy".into(),
        path.display().to_string(),
        "drop".into(),
    ]);
    let rewritten = r7z::Archive::open(&path).unwrap();
    assert_eq!(metadata(&rewritten), before);
    assert!(rewritten.entries().all(|entry| entry.name != "drop"));
    let mut keep = Vec::new();
    rewritten.extract_by_name("keep", &mut keep).unwrap();
    assert_eq!(keep, b"payload");
    run_r7z(&["t".into(), path.display().to_string()]);
}

#[test]
fn cli_test_continues_with_independent_folders_after_corruption() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("corrupt.7z");
    let mut bytes = r7z::ArchiveBuilder::new()
        .options(r7z::ArchiveOptions {
            codec: r7z::Codec::Copy,
            compression: r7z::CompressionOptions {
                solid: r7z::SolidMode::NonSolid,
                ..Default::default()
            },
            ..Default::default()
        })
        .add_file("first", b"first")
        .add_file("middle", b"middle")
        .add_file("last", b"last")
        .build()
        .unwrap();
    bytes[32] ^= 1;
    bytes[32 + 5 + 6] ^= 1;
    fs::write(&path, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(["t", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let errors = String::from_utf8_lossy(&output.stderr);
    assert!(errors.contains("Testing block 0 failed"), "{errors}");
    assert!(errors.contains("Testing block 2 failed"), "{errors}");
    assert!(!errors.contains("Testing block 1 failed"), "{errors}");
    run_r7z(&["t".into(), path.display().to_string(), "middle".into()]);
}

#[test]
fn cli_skipped_encrypted_files_do_not_open_a_decoder() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("encrypted.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .options(r7z::ArchiveOptions {
            codec: r7z::Codec::Copy,
            encryption: Some(r7z::EncryptionOptions::default_for_password("secret")),
            ..Default::default()
        })
        .add_file("keep", b"encrypted payload")
        .build()
        .unwrap();
    fs::write(&path, bytes).unwrap();
    let out = tmp.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("keep"), b"existing").unwrap();
    run_r7z(&[
        "x".into(),
        "-aos".into(),
        path.display().to_string(),
        format!("-o{}", out.display()),
    ]);
    assert_eq!(fs::read(out.join("keep")).unwrap(), b"existing");
}
