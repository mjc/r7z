#![allow(clippy::pedantic)]

fn build_copy_archive(name: &str, data: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(0x01); // Header
    header.push(0x04); // MainStreamsInfo

    header.push(0x06); // PackInfo
    header.extend_from_slice(&r7z::sevenzip_varuint64_encode(0));
    header.extend_from_slice(&r7z::sevenzip_varuint64_encode(1));
    header.push(0x09); // Size
    header.extend_from_slice(&r7z::sevenzip_varuint64_encode(data.len() as u64));
    header.push(0x00);

    header.push(0x07); // UnpackInfo
    header.push(0x0b); // Folder
    header.extend_from_slice(&r7z::sevenzip_varuint64_encode(1));
    header.push(0x00); // external = false
    header.extend_from_slice(&r7z::sevenzip_varuint64_encode(1)); // one coder
    header.push(0x01); // simple coder, one-byte id, no properties
    header.push(0x00); // Copy codec
    header.push(0x0c); // CodersUnPackSize
    header.extend_from_slice(&r7z::sevenzip_varuint64_encode(data.len() as u64));
    header.push(0x0a); // CRC
    header.push(0x01); // all defined
    header.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
    header.push(0x00);

    header.push(0x00); // END MainStreamsInfo

    header.push(0x05); // FilesInfo
    header.extend_from_slice(&r7z::sevenzip_varuint64_encode(1));
    header.push(0x11); // Name
    let mut name_data = Vec::new();
    for unit in name.encode_utf16() {
        name_data.extend_from_slice(&unit.to_le_bytes());
    }
    name_data.extend_from_slice(&[0, 0]);
    header.extend_from_slice(&r7z::sevenzip_varuint64_encode(1 + name_data.len() as u64));
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
