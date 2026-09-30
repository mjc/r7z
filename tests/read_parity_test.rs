#![allow(clippy::pedantic)]

use std::path::PathBuf;

fn build_copy_archive(name: &str, data: &[u8]) -> Vec<u8> {
    build_copy_archive_with_pack_crc(name, data, None)
}

fn build_archive_with_external_folder_definition(name: &str, data: &[u8]) -> Vec<u8> {
    let plain = build_copy_archive(name, data);
    let mut header = plain[32 + data.len()..].to_vec();
    let inline_folder = [0x07, 0x0b, 0x01, 0x00, 0x01, 0x01, 0x00];
    let folder_pos = header
        .windows(inline_folder.len())
        .position(|window| window == inline_folder)
        .unwrap();
    header.splice(
        folder_pos..folder_pos + inline_folder.len(),
        [0x07, 0x0b, 0x01, 0x01, 0x01],
    );

    let folder_data: [&[u8]; 2] = [&[0x01, 0x01, 0x00, 0xff], &[0x01, 0x01, 0x00]];
    let folder_crcs = folder_data.map(crc32fast::hash);
    let mut additional = vec![0x03, 0x06]; // AdditionalStreamsInfo, PackInfo
    additional.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(data.len() as u64));
    additional.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(2));
    additional.push(0x09);
    additional.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(4));
    additional.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(3));
    additional.extend_from_slice(&[0x0a, 0x01]);
    for crc in folder_crcs {
        additional.extend_from_slice(&crc.to_le_bytes());
    }
    additional.push(0x00);
    additional.extend_from_slice(&[0x07, 0x0b, 0x02, 0x00]); // two inline Copy folders
    additional.extend_from_slice(&[0x01, 0x01, 0x00]);
    additional.extend_from_slice(&[0x01, 0x01, 0x00]);
    additional.push(0x0c);
    additional.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(4));
    additional.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(3));
    additional.extend_from_slice(&[0x0a, 0x01]);
    for crc in folder_crcs {
        additional.extend_from_slice(&crc.to_le_bytes());
    }
    additional.extend_from_slice(&[0x00, 0x00]); // UnpackInfo and StreamInfo end
    header.splice(1..1, additional);

    let next_header_offset =
        (data.len() + folder_data.iter().map(|bytes| bytes.len()).sum::<usize>()) as u64;
    let next_header_size = header.len() as u64;
    let next_header_crc = crc32fast::hash(&header);
    let mut start_header = [0u8; 20];
    start_header[..8].copy_from_slice(&next_header_offset.to_le_bytes());
    start_header[8..16].copy_from_slice(&next_header_size.to_le_bytes());
    start_header[16..].copy_from_slice(&next_header_crc.to_le_bytes());

    let mut archive = Vec::new();
    archive.extend_from_slice(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]);
    archive.extend_from_slice(&crc32fast::hash(&start_header).to_le_bytes());
    archive.extend_from_slice(&start_header);
    archive.extend_from_slice(data);
    for bytes in folder_data {
        archive.extend_from_slice(bytes);
    }
    archive.extend_from_slice(&header);
    archive
}

fn build_copy_archive_with_pack_crc(name: &str, data: &[u8], pack_crc: Option<u32>) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(0x01); // Header
    header.push(0x04); // MainStreamsInfo

    header.push(0x06); // PackInfo
    header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(0));
    header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(1));
    header.push(0x09); // Size
    header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(data.len() as u64));
    if let Some(crc) = pack_crc {
        header.push(0x0a); // CRC
        header.push(0x01); // all defined
        header.extend_from_slice(&crc.to_le_bytes());
    }
    header.push(0x00);

    header.push(0x07); // UnpackInfo
    header.push(0x0b); // Folder
    header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(1));
    header.push(0x00); // external = false
    header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(1)); // one coder
    header.push(0x01); // simple coder, one-byte id, no properties
    header.push(0x00); // Copy codec
    header.push(0x0c); // CodersUnPackSize
    header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(data.len() as u64));
    header.push(0x0a); // CRC
    header.push(0x01); // all defined
    header.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
    header.push(0x00);

    header.push(0x00); // END MainStreamsInfo

    header.push(0x05); // FilesInfo
    header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(1));
    header.push(0x11); // Name
    let mut name_data = Vec::new();
    for unit in name.encode_utf16() {
        name_data.extend_from_slice(&unit.to_le_bytes());
    }
    name_data.extend_from_slice(&[0, 0]);
    header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(
        1 + name_data.len() as u64,
    ));
    header.push(0x00); // external = false
    header.extend_from_slice(&name_data);
    header.push(0x00); // END FilesInfo
    header.push(0x00); // END Header

    let next_header_offset = data.len() as u64;
    let next_header_size = header.len() as u64;
    let next_header_crc = crc32fast::hash(&header);
    let mut start_header = [0u8; 20];
    start_header[..8].copy_from_slice(&next_header_offset.to_le_bytes());
    start_header[8..16].copy_from_slice(&next_header_size.to_le_bytes());
    start_header[16..].copy_from_slice(&next_header_crc.to_le_bytes());
    let start_header_crc = crc32fast::hash(&start_header);

    let mut archive = Vec::new();
    archive.extend_from_slice(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
    archive.push(0x00);
    archive.push(0x04);
    archive.extend_from_slice(&start_header_crc.to_le_bytes());
    archive.extend_from_slice(&next_header_offset.to_le_bytes());
    archive.extend_from_slice(&next_header_size.to_le_bytes());
    archive.extend_from_slice(&next_header_crc.to_le_bytes());
    archive.extend_from_slice(data);
    archive.extend_from_slice(&header);
    archive
}

fn build_encoded_copy_archive(name: &str, data: &[u8], header_pack_crc: u32) -> Vec<u8> {
    let plain = build_copy_archive(name, data);
    let inner_header = &plain[32 + data.len()..];

    let mut encoded_header = vec![0x17, 0x06]; // EncodedHeader, PackInfo
    encoded_header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(data.len() as u64));
    encoded_header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(1));
    encoded_header.extend_from_slice(&[0x09]); // Size
    encoded_header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(
        inner_header.len() as u64
    ));
    encoded_header.extend_from_slice(&[0x0a, 0x01]); // CRC, all defined
    encoded_header.extend_from_slice(&header_pack_crc.to_le_bytes());
    encoded_header.push(0x00); // END PackInfo
    encoded_header.extend_from_slice(&[0x07, 0x0b]); // UnpackInfo, Folder
    encoded_header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(1));
    encoded_header.extend_from_slice(&[0x00, 0x01, 0x01, 0x00]); // inline Copy coder
    encoded_header.push(0x0c); // CodersUnPackSize
    encoded_header.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(
        inner_header.len() as u64
    ));
    encoded_header.extend_from_slice(&[0x0a, 0x01]); // CRC, all defined
    encoded_header.extend_from_slice(&crc32fast::hash(inner_header).to_le_bytes());
    encoded_header.push(0x00); // END UnpackInfo

    let next_header_offset = (data.len() + inner_header.len()) as u64;
    let next_header_size = encoded_header.len() as u64;
    let next_header_crc = crc32fast::hash(&encoded_header);
    let mut start_header = [0u8; 20];
    start_header[..8].copy_from_slice(&next_header_offset.to_le_bytes());
    start_header[8..16].copy_from_slice(&next_header_size.to_le_bytes());
    start_header[16..].copy_from_slice(&next_header_crc.to_le_bytes());

    let mut archive = Vec::new();
    archive.extend_from_slice(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]);
    archive.extend_from_slice(&crc32fast::hash(&start_header).to_le_bytes());
    archive.extend_from_slice(&start_header);
    archive.extend_from_slice(data);
    archive.extend_from_slice(inner_header);
    archive.extend_from_slice(&encoded_header);
    archive
}

fn build_copy_archive_with_additional_crc(
    name: &str,
    data: &[u8],
    additional_data: &[u8],
    additional_crc: u32,
) -> Vec<u8> {
    let plain = build_copy_archive(name, data);
    let mut header = plain[32 + data.len()..].to_vec();
    let files_info = header
        .windows(2)
        .position(|window| window == [0x05, 0x01])
        .unwrap();

    let mut additional_info = vec![0x03, 0x06]; // AdditionalStreamsInfo, PackInfo
    additional_info.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(data.len() as u64));
    additional_info.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(1));
    additional_info.push(0x09); // Size
    additional_info.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(
        additional_data.len() as u64
    ));
    additional_info.extend_from_slice(&[0x0a, 0x01]); // CRC, all defined
    additional_info.extend_from_slice(&additional_crc.to_le_bytes());
    additional_info.push(0x00); // END PackInfo
    additional_info.extend_from_slice(&[0x07, 0x0b]); // UnpackInfo, Folder
    additional_info.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(1));
    additional_info.extend_from_slice(&[0x00, 0x01, 0x01, 0x00]); // inline Copy coder
    additional_info.push(0x0c); // CodersUnPackSize
    additional_info.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(
        additional_data.len() as u64
    ));
    additional_info.extend_from_slice(&[0x0a, 0x01]); // CRC, all defined
    additional_info.extend_from_slice(&crc32fast::hash(additional_data).to_le_bytes());
    additional_info.push(0x00); // END UnpackInfo
    additional_info.push(0x00); // END AdditionalStreamsInfo
    header.splice(files_info..files_info, additional_info);

    let next_header_offset = (data.len() + additional_data.len()) as u64;
    let next_header_size = header.len() as u64;
    let next_header_crc = crc32fast::hash(&header);
    let mut start_header = [0u8; 20];
    start_header[..8].copy_from_slice(&next_header_offset.to_le_bytes());
    start_header[8..16].copy_from_slice(&next_header_size.to_le_bytes());
    start_header[16..].copy_from_slice(&next_header_crc.to_le_bytes());

    let mut archive = Vec::new();
    archive.extend_from_slice(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]);
    archive.extend_from_slice(&crc32fast::hash(&start_header).to_le_bytes());
    archive.extend_from_slice(&start_header);
    archive.extend_from_slice(data);
    archive.extend_from_slice(additional_data);
    archive.extend_from_slice(&header);
    archive
}

fn build_copy_archive_with_external_name(name: &str, data: &[u8]) -> Vec<u8> {
    let mut external_name = Vec::new();
    for unit in name.encode_utf16() {
        external_name.extend_from_slice(&unit.to_le_bytes());
    }
    external_name.extend_from_slice(&[0, 0]);

    let mut archive = build_copy_archive_with_additional_crc(
        name,
        data,
        &external_name,
        crc32fast::hash(&external_name),
    );
    let header_start = 32 + data.len() + external_name.len();
    let additional_start = archive[header_start..]
        .windows(2)
        .position(|window| window == [0x03, 0x06])
        .map(|offset| header_start + offset)
        .unwrap();
    let files_info_start = archive[additional_start..]
        .windows(2)
        .position(|window| window == [0x05, 0x01])
        .map(|offset| additional_start + offset)
        .unwrap();
    let additional_info = archive[additional_start..files_info_start].to_vec();
    archive.drain(additional_start..files_info_start);
    let main_streams_start = archive[header_start..]
        .iter()
        .position(|&tag| tag == 0x04)
        .map(|offset| header_start + offset)
        .unwrap();
    archive.splice(main_streams_start..main_streams_start, additional_info);

    let mut inline_name_property = vec![0x11];
    inline_name_property.extend_from_slice(&r7z::raw::sevenzip_varuint64_encode(
        1 + external_name.len() as u64,
    ));
    inline_name_property.push(0x00);
    inline_name_property.extend_from_slice(&external_name);
    let name_property_start = archive[header_start..]
        .windows(inline_name_property.len())
        .position(|window| window == inline_name_property)
        .map(|offset| header_start + offset)
        .unwrap();
    archive.splice(
        name_property_start..name_property_start + inline_name_property.len(),
        [0x11, 0x02, 0x22, 0x00],
    );

    let header_size = (archive.len() - header_start) as u64;
    let header_crc = crc32fast::hash(&archive[header_start..]);
    archive[20..28].copy_from_slice(&header_size.to_le_bytes());
    archive[28..32].copy_from_slice(&header_crc.to_le_bytes());
    let start_header_crc = crc32fast::hash(&archive[12..32]);
    archive[8..12].copy_from_slice(&start_header_crc.to_le_bytes());
    archive
}

#[test]
fn extract_all_rejects_parent_path() {
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("../evil.txt", b"bad")
        .build()
        .unwrap();
    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let out = tempfile::tempdir().unwrap();
    let err = archive.extract_all(out.path()).unwrap_err();
    assert!(matches!(err, r7z::R7zError::UnsafePath(path) if path == "../evil.txt"));
}

#[test]
fn extract_all_rejects_absolute_path() {
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("/tmp/evil.txt", b"bad")
        .build()
        .unwrap();
    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let out = tempfile::tempdir().unwrap();
    let err = archive.extract_all(out.path()).unwrap_err();
    assert!(matches!(err, r7z::R7zError::UnsafePath(path) if path == "/tmp/evil.txt"));
}

#[test]
fn extract_all_rejects_windows_prefixed_path() {
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("C:\\evil.txt", b"bad")
        .build()
        .unwrap();
    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let out = tempfile::tempdir().unwrap();
    let err = archive.extract_all(out.path()).unwrap_err();
    assert!(matches!(err, r7z::R7zError::UnsafePath(path) if path == "C:\\evil.txt"));
}

#[cfg(unix)]
#[test]
fn extract_all_does_not_follow_a_parent_symlink_outside_destination() {
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("nested/escaped.txt", b"must stay in destination")
        .build()
        .unwrap();
    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let destination = tmp.path().join("destination");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&destination).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, destination.join("nested")).unwrap();

    assert!(archive.extract_all(&destination).is_err());
    assert!(!outside.join("escaped.txt").exists());
}

#[cfg(unix)]
#[test]
fn extract_all_replaces_hard_links_without_modifying_the_linked_file() {
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("entry.txt", b"archive contents")
        .build()
        .unwrap();
    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let destination = tmp.path().join("destination");
    let outside = tmp.path().join("outside.txt");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(&outside, b"outside contents").unwrap();
    std::fs::hard_link(&outside, destination.join("entry.txt")).unwrap();

    archive.extract_all(&destination).unwrap();

    assert_eq!(std::fs::read(&outside).unwrap(), b"outside contents");
    assert_eq!(
        std::fs::read(destination.join("entry.txt")).unwrap(),
        b"archive contents"
    );
}

#[test]
fn safe_archive_name_normalizes_separators_and_rejects_unsafe_names() {
    assert_eq!(
        r7z::safe_archive_name("dir\\.\\nested//file.txt").unwrap(),
        PathBuf::from("dir").join("nested").join("file.txt")
    );
    assert!(matches!(
        r7z::safe_archive_name("../evil.txt"),
        Err(r7z::R7zError::UnsafePath(path)) if path == "../evil.txt"
    ));
    assert!(matches!(
        r7z::safe_archive_name("C:\\evil.txt"),
        Err(r7z::R7zError::UnsafePath(path)) if path == "C:\\evil.txt"
    ));
}

#[test]
fn entries_and_name_based_extraction_use_safe_names() {
    let bytes = r7z::ArchiveBuilder::new()
        .add_directory("dir", r7z::EntryMeta::default())
        .add_file("dir\\payload.txt", b"payload")
        .add_empty_file("dir/empty.txt", r7z::EntryMeta::default())
        .add_anti_item("removed.txt", r7z::EntryMeta::default())
        .build()
        .unwrap();
    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let entries = archive.entries().collect::<Vec<_>>();

    assert_eq!(entries.len(), 4);
    assert!(entries[0].is_directory());
    assert!(entries[1].is_file());
    assert!(entries[3].is_anti());
    let payload_path = PathBuf::from("dir").join("payload.txt");
    assert_eq!(entries[1].safe_path(), Some(payload_path.as_path()));
    assert_eq!(archive.safe_name(1).unwrap(), payload_path);

    let mut out = Vec::new();
    let written = archive
        .extract_by_name("dir/payload.txt", &mut out)
        .unwrap();
    assert_eq!(written, 7);
    assert_eq!(out, b"payload");
    assert!(matches!(
        archive.extract_to_memory_by_name("missing.txt"),
        Err(r7z::R7zError::EntryNotFound(name)) if name == "missing.txt"
    ));
}

#[test]
fn stream_files_visits_file_entries_and_drains_solid_folders() {
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("a.txt", b"alpha")
        .add_empty_file("empty.txt", r7z::EntryMeta::default())
        .add_file("b.txt", b"bravo")
        .build()
        .unwrap();
    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    let mut seen = Vec::new();

    archive
        .stream_files(|entry, reader| {
            let mut data = Vec::new();
            reader.read_to_end(&mut data)?;
            seen.push((entry.name.clone(), data));
            Ok(())
        })
        .unwrap();

    assert_eq!(
        seen,
        vec![
            ("a.txt".to_string(), b"alpha".to_vec()),
            ("empty.txt".to_string(), Vec::new()),
            ("b.txt".to_string(), b"bravo".to_vec()),
        ]
    );
}

#[test]
fn copy_codec_extracts_and_detects_packed_data_crc_mismatch() {
    let archive_bytes = build_copy_archive("plain.txt", b"copy codec payload");
    let archive = r7z::Archive::from_bytes(archive_bytes.clone().into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), b"copy codec payload");

    let mut corrupted = archive_bytes;
    corrupted[32] ^= 0x01;
    let archive = r7z::Archive::from_bytes(corrupted.into()).unwrap();
    let err = archive.extract_to_memory(0).unwrap_err();
    assert!(matches!(err, r7z::R7zError::Crc));
}

#[test]
fn external_folder_definitions_are_loaded_from_additional_streams() {
    let bytes = build_archive_with_external_folder_definition("external.txt", b"external data");
    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), b"external data");
}

#[test]
fn external_file_names_are_loaded_from_additional_streams() {
    let bytes = build_copy_archive_with_external_name("external-name.txt", b"external data");
    let archive = r7z::Archive::from_bytes(bytes.into()).unwrap();

    assert_eq!(
        archive.raw_files_info().unwrap().name(0).as_deref(),
        Some("external-name.txt")
    );
    assert_eq!(archive.extract_to_memory(0).unwrap(), b"external data");
}

#[test]
fn external_metadata_matches_official_7zip_fixture() {
    let archive = r7z::Archive::open(std::path::Path::new(
        "tests/corpus/7z/generated/external_metadata.7z",
    ))
    .unwrap();
    let files = archive.try_raw_files_info().unwrap().unwrap();

    assert_eq!(files.name(0).as_deref(), Some("external-metadata.txt"));
    assert_eq!(files.ctimes, [Some(132_223_104_000_000_000)]);
    assert_eq!(files.attributes, [Some(0x20)]);
    assert_eq!(archive.extract_to_memory(0).unwrap(), b"");
}

#[test]
fn packed_stream_crc_is_checked_independently_of_unpacked_crc() {
    let data = b"copy codec payload";
    let expected_crc = crc32fast::hash(data);
    let good = build_copy_archive_with_pack_crc("plain.txt", data, Some(expected_crc));
    let archive = r7z::Archive::from_bytes(good.into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), data);

    let bad = build_copy_archive_with_pack_crc("plain.txt", data, Some(expected_crc ^ 1));
    let archive = r7z::Archive::from_bytes(bad.into()).unwrap();
    assert!(matches!(
        archive.extract_to_memory(0),
        Err(r7z::R7zError::Crc)
    ));

    let no_crc = build_copy_archive_with_pack_crc("plain.txt", data, None);
    let archive = r7z::Archive::from_bytes(no_crc.into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), data);
}

#[test]
fn encoded_header_pack_crc_is_checked_before_header_decode() {
    let data = b"payload";
    let encoded_header = build_copy_archive("file.txt", data);
    let packed_header = &encoded_header[32 + data.len()..];
    let good = build_encoded_copy_archive("file.txt", data, crc32fast::hash(packed_header));
    let archive = r7z::Archive::from_bytes(good.into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), data);

    let bad = build_encoded_copy_archive("file.txt", data, crc32fast::hash(packed_header) ^ 1);
    assert!(matches!(
        r7z::Archive::from_bytes(bad.into()),
        Err(r7z::R7zError::Crc)
    ));
}

#[test]
fn additional_metadata_pack_crc_is_checked_when_opening() {
    let data = b"payload";
    let additional = b"external metadata";
    let good = build_copy_archive_with_additional_crc(
        "file.txt",
        data,
        additional,
        crc32fast::hash(additional),
    );
    let archive = r7z::Archive::from_bytes(good.into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), data);

    let bad = build_copy_archive_with_additional_crc(
        "file.txt",
        data,
        additional,
        crc32fast::hash(additional) ^ 1,
    );
    assert!(matches!(
        r7z::Archive::from_bytes(bad.into()),
        Err(r7z::R7zError::Crc)
    ));
}

#[test]
fn truncated_archive_returns_parse_or_crc() {
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("ok.txt", b"data")
        .build()
        .unwrap();

    for len in [0, 4, 31, bytes.len() - 1] {
        let err = match r7z::Archive::from_bytes(bytes[..len].to_vec().into()) {
            Ok(_) => panic!("truncated archive unexpectedly parsed"),
            Err(err) => err,
        };
        assert!(matches!(err, r7z::R7zError::Parse | r7z::R7zError::Crc));
    }
}
