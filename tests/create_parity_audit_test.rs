#![allow(clippy::pedantic)]

mod support;

use support::{extract_with_p7zip, run_7z_checked};

type CompressionCase<'a> = (&'a str, &'a [&'a str], &'a [u8], Option<usize>);

fn write_payload(dir: &std::path::Path) {
    let data = (0u8..=255).cycle().take(16 * 1024).collect::<Vec<_>>();
    std::fs::write(dir.join("payload.bin"), data).unwrap();
    std::fs::write(dir.join("notes.txt"), b"alpha\nbravo\ncharlie\n".repeat(64)).unwrap();
}

#[test]
fn create_parity_audit_p7zip_compression_switches_open_with_r7z() {
    let cases: &[CompressionCase<'_>] = &[
        ("mx0", &["-mx0"], &[0x00], None),
        ("mx1", &["-mx1"], &[0x21], Some(1)),
        ("mx3", &["-mx3"], &[0x21], Some(1)),
        ("mx5", &["-mx5"], &[0x21], Some(1)),
        ("mx7", &["-mx7"], &[0x21], Some(1)),
        ("mx9", &["-mx9"], &[0x21], Some(1)),
        ("lzma", &["-m0=LZMA"], &[0x03, 0x01, 0x01], Some(5)),
        ("lzma2", &["-m0=LZMA2"], &[0x21], Some(1)),
        ("dict", &["-md=1m"], &[0x21], Some(1)),
        ("fast_bytes", &["-mfb=32"], &[0x21], Some(1)),
        ("dict_fb", &["-m0=LZMA2:d=1m:fb=32"], &[0x21], Some(1)),
        ("solid_off", &["-ms=off"], &[0x21], Some(1)),
        ("solid_on", &["-ms=on"], &[0x21], Some(1)),
        ("solid_limit", &["-ms=1f"], &[0x21], Some(1)),
    ];

    for (label, args, expected_codec, expected_props_len) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write_payload(dir);
        let archive_path = dir.join(format!("{label}.7z"));
        let mut argv = vec![
            "a",
            archive_path.to_str().unwrap(),
            "payload.bin",
            "notes.txt",
        ];
        argv.extend_from_slice(args);
        run_7z_checked(&argv, dir);

        let archive = r7z::Archive::open(&archive_path)
            .unwrap_or_else(|err| panic!("r7z failed to open {label}: {err}"));
        assert_eq!(archive.num_files(), 2, "{label}");
        let unpack_info = archive
            .streams_info()
            .unwrap()
            .unpack_info
            .as_ref()
            .unwrap_or_else(|| panic!("missing unpack info for {label}"));
        assert!(unpack_info.num_folders >= 1, "{label}");
        let folder = unpack_info.parse_folder(0).unwrap();
        let coder = folder
            .coders
            .first()
            .unwrap_or_else(|| panic!("missing coder for {label}"));
        assert_eq!(coder.codec_id.as_slice(), *expected_codec, "{label}");
        assert_eq!(
            coder.properties.as_deref().map(<[u8]>::len),
            *expected_props_len,
            "{label}"
        );

        let names = archive.files_info().unwrap().names().collect::<Vec<_>>();
        let payload_idx = names
            .iter()
            .position(|name| name == "payload.bin")
            .unwrap_or_else(|| panic!("payload.bin missing from {label}: {names:?}"));
        assert_eq!(
            archive.extract_to_memory(payload_idx).unwrap(),
            std::fs::read(dir.join("payload.bin")).unwrap(),
            "{label}"
        );
    }
}

#[test]
fn create_parity_audit_p7zip_volumes_concatenate_to_unsplit_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    write_payload(dir);

    let full = dir.join("full.7z");
    run_7z_checked(&["a", full.to_str().unwrap(), "payload.bin", "-mx0"], dir);

    let split = dir.join("split.7z");
    run_7z_checked(
        &["a", split.to_str().unwrap(), "payload.bin", "-mx0", "-v2k"],
        dir,
    );
    let mut joined = Vec::new();
    for idx in 1.. {
        let path = dir.join(format!("split.7z.{idx:03}"));
        if !path.exists() {
            break;
        }
        joined.extend_from_slice(&std::fs::read(path).unwrap());
    }
    assert_eq!(joined, std::fs::read(&full).unwrap());

    let list = run_7z_checked(&["l", "split.7z.001"], dir);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("Type = Split"));

    let out = dir.join("out");
    extract_with_p7zip(dir, &dir.join("split.7z.001"), &out);
    assert_eq!(
        std::fs::read(out.join("payload.bin")).unwrap(),
        std::fs::read(dir.join("payload.bin")).unwrap()
    );

    let archive = r7z::Archive::open(&dir.join("split.7z.001")).unwrap();
    assert_eq!(archive.num_files(), 1);
    assert_eq!(
        archive.extract_to_memory(0).unwrap(),
        std::fs::read(dir.join("payload.bin")).unwrap()
    );
}

#[cfg(unix)]
#[test]
fn create_parity_audit_p7zip_link_payloads_and_metadata() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    std::fs::write(dir.join("target.txt"), b"target").unwrap();
    symlink("target.txt", dir.join("link.txt")).unwrap();
    std::fs::hard_link(dir.join("target.txt"), dir.join("hard.txt")).unwrap();

    let archive_path = dir.join("links.7z");
    run_7z_checked(
        &[
            "a",
            archive_path.to_str().unwrap(),
            "target.txt",
            "link.txt",
            "hard.txt",
            "-snl",
            "-snh",
        ],
        dir,
    );

    let archive = r7z::Archive::open(&archive_path).unwrap();
    let fi = archive.files_info().unwrap();
    let names = fi.names().collect::<Vec<_>>();
    let link_idx = names.iter().position(|name| name == "link.txt").unwrap();
    let hard_idx = names.iter().position(|name| name == "hard.txt").unwrap();
    assert!(matches!(
        fi.entry_type(link_idx),
        r7z::EntryType::File | r7z::EntryType::Symlink
    ));
    assert_eq!(fi.entry_type(hard_idx), r7z::EntryType::File);
    assert_eq!(archive.extract_to_memory(link_idx).unwrap(), b"target.txt");
    assert_eq!(
        archive.symlink_target(link_idx).unwrap().as_deref(),
        fi.is_symlink(link_idx).then_some("target.txt")
    );
    assert_eq!(archive.extract_to_memory(hard_idx).unwrap(), b"target");
}
