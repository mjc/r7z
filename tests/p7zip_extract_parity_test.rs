mod support;

use std::path::{Path, PathBuf};

use support::{
    assert_trees_equal, extract_with_p7zip, extract_with_r7z, run_7z_checked, write_fixture_files,
    write_fixture_tree,
};

#[test]
fn p7zip_created_archives_extract_with_r7z_byte_for_byte() {
    let matrix = [
        ("lzma_solid", &["-m0=LZMA", "-ms=on", "-mmt=off"][..]),
        ("lzma_non_solid", &["-m0=LZMA", "-ms=off", "-mmt=off"][..]),
        ("lzma2_solid", &["-m0=LZMA2", "-ms=on", "-mmt=off"][..]),
        ("lzma2_non_solid", &["-m0=LZMA2", "-ms=off", "-mmt=off"][..]),
        (
            "bcj_lzma2_solid",
            &["-mf=BCJ", "-m0=LZMA2", "-ms=on", "-mmt=off"][..],
        ),
        (
            "bcj_lzma2_non_solid",
            &["-mf=BCJ", "-m0=LZMA2", "-ms=off", "-mmt=off"][..],
        ),
    ];

    for (name, options) in matrix {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("input");
        write_fixture_tree(&input);

        let archive_path = tmp.path().join(format!("{name}.7z"));
        let mut args = vec![
            "a".to_string(),
            archive_path.to_string_lossy().into_owned(),
            "input".to_string(),
        ];
        args.extend(options.iter().map(|arg| (*arg).to_string()));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run_7z_checked(&args, tmp.path());

        let p7zip_out = tmp.path().join("p7zip-out");
        let r7z_out = tmp.path().join("r7z-out");
        extract_with_p7zip(tmp.path(), &archive_path, &p7zip_out);
        extract_with_r7z(&archive_path, &r7z_out);
        assert_trees_equal(&p7zip_out, &r7z_out);

        assert_archive_file_apis_match_source(&archive_path, &input, "input");
    }
}

#[test]
fn r7z_created_archives_extract_with_p7zip_byte_for_byte() {
    let codecs = [
        ("lzma", r7z::Codec::Lzma),
        ("lzma2", r7z::Codec::Lzma2),
        ("bcj_lzma2", r7z::Codec::Lzma2Bcj),
    ];

    for (codec_name, codec) in codecs {
        let tmp = tempfile::tempdir().unwrap();
        let expected = tmp.path().join("expected");
        let files = write_fixture_files(&expected);

        let archive_path = tmp.path().join(format!("builder_{codec_name}.7z"));
        let mut builder = r7z::ArchiveBuilder::new().compression(codec);
        for (path, data) in &files {
            builder = builder.add_file(path.to_str().unwrap(), data);
        }
        std::fs::write(&archive_path, builder.build().unwrap()).unwrap();
        assert_r7z_and_p7zip_outputs_match(&archive_path, &expected);

        let archive_path = tmp.path().join(format!("writer_single_{codec_name}.7z"));
        write_with_archive_writer(&archive_path, codec, &files, false);
        assert_r7z_and_p7zip_outputs_match(&archive_path, &expected);

        let archive_path = tmp.path().join(format!("writer_multi_{codec_name}.7z"));
        write_with_archive_writer(&archive_path, codec, &files, true);
        assert_r7z_and_p7zip_outputs_match(&archive_path, &expected);
    }
}

#[test]
fn streaming_extract_reports_corrupt_lzma_and_lzma2_payloads() {
    for codec in [r7z::Codec::Lzma, r7z::Codec::Lzma2] {
        let mut bytes = r7z::ArchiveBuilder::new()
            .compression(codec)
            .add_file("payload.bin", &vec![0x55u8; 64 * 1024])
            .build()
            .unwrap();
        corrupt_middle_of_pack_stream(&mut bytes);

        let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
        let mut out = Vec::new();
        let err = archive.extract_to_writer(0, &mut out).unwrap_err();
        assert!(matches!(
            err,
            r7z::R7zError::Crc | r7z::R7zError::Decompression
        ));
    }
}

#[test]
fn streaming_extract_stops_after_target_when_folder_crc_is_absent() {
    let mut bytes = r7z::ArchiveBuilder::new()
        .options(r7z::ArchiveOptions {
            header_mode: r7z::HeaderMode::Plain,
            ..Default::default()
        })
        .compression(r7z::Codec::Lzma2)
        .add_file("first.txt", b"first")
        .add_file("second.bin", &vec![0xA5u8; 128 * 1024])
        .build()
        .unwrap();
    let archive = r7z::Archive::from_bytes(bytes.clone().into()).unwrap();
    let folder_digest = archive
        .streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap()
        .digests
        .first()
        .copied()
        .flatten();
    assert!(
        folder_digest.is_none(),
        "fixture should not carry a folder CRC"
    );
    corrupt_late_in_pack_stream(&mut bytes);

    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let mut out = Vec::new();
    let written = archive.extract_to_writer(0, &mut out).unwrap();
    assert_eq!(written, 5);
    assert_eq!(out, b"first");
}

fn assert_archive_file_apis_match_source(archive_path: &Path, source_root: &Path, prefix: &str) {
    let archive = r7z::Archive::open(archive_path).unwrap();
    let fi = archive.files_info().unwrap();

    for i in 0..archive.num_files() {
        if fi.is_directory(i) || fi.is_anti(i) {
            continue;
        }

        let name = fi.name(i).unwrap();
        let relative = name
            .strip_prefix(prefix)
            .and_then(|name| name.strip_prefix('/'))
            .unwrap_or(name.as_str());
        let expected = std::fs::read(source_root.join(relative)).unwrap();

        assert_eq!(archive.extract_to_memory(i).unwrap(), expected, "{name}");

        let mut out = Vec::new();
        let written = archive.extract_to_writer(i, &mut out).unwrap();
        assert_eq!(written, expected.len() as u64, "{name}");
        assert_eq!(out, expected, "{name}");
    }
}

fn assert_r7z_and_p7zip_outputs_match(archive_path: &Path, expected: &Path) {
    let tmp = tempfile::tempdir().unwrap();
    let p7zip_out = tmp.path().join("p7zip");
    let r7z_out = tmp.path().join("r7z");

    extract_with_p7zip(tmp.path(), archive_path, &p7zip_out);
    extract_with_r7z(archive_path, &r7z_out);

    assert_trees_equal(expected, &p7zip_out);
    assert_trees_equal(expected, &r7z_out);
}

fn write_with_archive_writer(
    archive_path: &Path,
    codec: r7z::Codec,
    files: &[(PathBuf, Vec<u8>)],
    multi_folder: bool,
) {
    let file = std::fs::File::create(archive_path).unwrap();
    let mut writer = r7z::ArchiveWriter::new(file).unwrap().compression(codec);
    for (idx, (path, data)) in files.iter().enumerate() {
        if multi_folder && idx == files.len() / 2 {
            writer.new_folder().unwrap();
        }
        writer
            .append(path.to_str().unwrap(), data.as_slice())
            .unwrap();
    }
    writer.finish().unwrap();
}

fn corrupt_middle_of_pack_stream(bytes: &mut [u8]) {
    let pack_len = next_header_offset(bytes);
    let offset = 32 + usize::try_from(pack_len / 2).unwrap();
    bytes[offset] ^= 0x55;
}

fn corrupt_late_in_pack_stream(bytes: &mut [u8]) {
    let pack_len = next_header_offset(bytes);
    let offset = 32 + usize::try_from(pack_len.saturating_sub(8)).unwrap();
    bytes[offset] ^= 0x55;
}

fn next_header_offset(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[12..20].try_into().unwrap())
}
