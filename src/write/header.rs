use super::model::{CompletedFolder, EntryKind, WriteEntry};
use crate::parsers::sevenzip_varuint64_encode;
use std::time::SystemTime;

pub(crate) fn encode_coder_info_copy() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&sevenzip_varuint64_encode(1));
    bytes.push(0x01);
    bytes.push(0x00);
    bytes
}

pub(crate) fn encode_coder_info_lzma(props: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&sevenzip_varuint64_encode(1));
    bytes.extend_from_slice(&[0x23, 0x03, 0x01, 0x01]);
    bytes.extend_from_slice(&sevenzip_varuint64_encode(5));
    bytes.extend_from_slice(props);
    bytes
}

pub(crate) fn encode_coder_info_lzma2(props_byte: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&sevenzip_varuint64_encode(1));
    bytes.push(0x21);
    bytes.push(0x21);
    bytes.extend_from_slice(&sevenzip_varuint64_encode(1));
    bytes.push(props_byte);
    bytes
}

pub(crate) fn encode_coder_info_bcj_lzma2(props_byte: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&sevenzip_varuint64_encode(2));
    bytes.push(0x21);
    bytes.push(0x21);
    bytes.extend_from_slice(&sevenzip_varuint64_encode(1));
    bytes.push(props_byte);
    bytes.push(0x04);
    bytes.extend_from_slice(&[0x03, 0x03, 0x01, 0x03]);
    bytes.extend_from_slice(&sevenzip_varuint64_encode(1));
    bytes.extend_from_slice(&sevenzip_varuint64_encode(0));
    bytes
}

pub(crate) fn encode_coder_info_aes_then(inner: &[CoderSpec], aes_props: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let num_coders = 1 + inner.len() as u64;
    bytes.extend_from_slice(&sevenzip_varuint64_encode(num_coders));

    bytes.push(0x24);
    bytes.extend_from_slice(&[0x06, 0xF1, 0x07, 0x01]);
    bytes.extend_from_slice(&sevenzip_varuint64_encode(aes_props.len() as u64));
    bytes.extend_from_slice(aes_props);

    for spec in inner {
        match spec {
            CoderSpec::Copy => {
                bytes.push(0x01);
                bytes.push(0x00);
            }
            CoderSpec::Lzma(props) => {
                bytes.extend_from_slice(&[0x23, 0x03, 0x01, 0x01]);
                bytes.extend_from_slice(&sevenzip_varuint64_encode(5));
                bytes.extend_from_slice(props);
            }
            CoderSpec::Lzma2(prop) => {
                bytes.push(0x21);
                bytes.push(0x21);
                bytes.extend_from_slice(&sevenzip_varuint64_encode(1));
                bytes.push(*prop);
            }
            CoderSpec::Bcj => {
                bytes.push(0x04);
                bytes.extend_from_slice(&[0x03, 0x03, 0x01, 0x03]);
            }
        }
    }

    for out_idx in 0..inner.len() {
        bytes.extend_from_slice(&sevenzip_varuint64_encode((out_idx + 1) as u64));
        bytes.extend_from_slice(&sevenzip_varuint64_encode(out_idx as u64));
    }
    bytes
}

#[derive(Clone)]
pub(crate) enum CoderSpec {
    Copy,
    Lzma(Vec<u8>),
    Lzma2(u8),
    Bcj,
}

pub(crate) fn build_header(entries: &[WriteEntry], folders: &[CompletedFolder]) -> Vec<u8> {
    let mut h = Vec::new();
    h.push(0x01);

    if !folders.is_empty() {
        h.push(0x04);
        write_pack_info(&mut h, folders);
        write_unpack_info(&mut h, folders);
        write_substreams_info(&mut h, folders);
        h.push(0x00);
    }

    write_files_info(&mut h, entries);
    h.push(0x00);
    h
}

pub(crate) fn build_encoded_header_descriptor(
    pack_pos: u64,
    pack_size: u64,
    coder_info: &[u8],
    coder_unpack_sizes: &[u64],
) -> Vec<u8> {
    let mut h = Vec::new();
    h.push(0x17);
    h.push(0x06);
    h.extend_from_slice(&sevenzip_varuint64_encode(pack_pos));
    h.extend_from_slice(&sevenzip_varuint64_encode(1));
    h.push(0x09);
    h.extend_from_slice(&sevenzip_varuint64_encode(pack_size));
    h.push(0x00);

    h.push(0x07);
    h.push(0x0b);
    h.extend_from_slice(&sevenzip_varuint64_encode(1));
    h.push(0x00);
    h.extend_from_slice(coder_info);
    h.push(0x0c);
    for &size in coder_unpack_sizes {
        h.extend_from_slice(&sevenzip_varuint64_encode(size));
    }
    h.push(0x00);
    h.push(0x00);
    h
}

fn write_pack_info(h: &mut Vec<u8>, folders: &[CompletedFolder]) {
    h.push(0x06);
    h.extend_from_slice(&sevenzip_varuint64_encode(0));
    h.extend_from_slice(&sevenzip_varuint64_encode(folders.len() as u64));
    h.push(0x09);
    for folder in folders {
        h.extend_from_slice(&sevenzip_varuint64_encode(folder.pack_size));
    }
    h.push(0x00);
}

fn write_unpack_info(h: &mut Vec<u8>, folders: &[CompletedFolder]) {
    h.push(0x07);
    h.push(0x0b);
    h.extend_from_slice(&sevenzip_varuint64_encode(folders.len() as u64));
    h.push(0x00);
    for folder in folders {
        h.extend_from_slice(&folder.coder_info);
    }
    h.push(0x0c);
    for folder in folders {
        for &size in &folder.coder_unpack_sizes {
            h.extend_from_slice(&sevenzip_varuint64_encode(size));
        }
    }
    h.push(0x00);
}

fn write_substreams_info(h: &mut Vec<u8>, folders: &[CompletedFolder]) {
    h.push(0x08);
    if folders.iter().any(|f| f.file_indices.len() != 1) {
        h.push(0x0d);
        for folder in folders {
            h.extend_from_slice(&sevenzip_varuint64_encode(folder.file_indices.len() as u64));
        }
    }
    if folders.iter().any(|f| f.file_indices.len() > 1) {
        h.push(0x09);
        for folder in folders {
            for &size in &folder.file_sizes[..folder.file_sizes.len().saturating_sub(1)] {
                h.extend_from_slice(&sevenzip_varuint64_encode(size));
            }
        }
    }
    h.push(0x0a);
    h.push(0x01);
    for folder in folders {
        for &crc in &folder.file_crcs {
            h.extend_from_slice(&crc.to_le_bytes());
        }
    }
    h.push(0x00);
}

fn write_files_info(h: &mut Vec<u8>, entries: &[WriteEntry]) {
    h.push(0x05);
    h.extend_from_slice(&sevenzip_varuint64_encode(entries.len() as u64));
    write_empty_properties(h, entries);
    write_names(h, entries);
    write_time_property(h, 0x12, entries, |e| e.meta.ctime);
    write_time_property(h, 0x13, entries, |e| e.meta.atime);
    write_time_property(h, 0x14, entries, |e| e.meta.mtime);
    write_u64_property(h, 0x18, entries, |e| e.meta.start_pos);
    write_u32_property(h, 0x15, entries, |e| {
        e.meta
            .attributes
            .or_else(|| e.meta.unix_mode.map(|mode| (mode << 16) | 0x20))
    });
    h.push(0x00);
}

fn write_empty_properties(h: &mut Vec<u8>, entries: &[WriteEntry]) {
    let empty: Vec<bool> = entries.iter().map(|entry| !entry.has_stream).collect();
    if !empty.iter().any(|&v| v) {
        return;
    }
    h.push(0x0e);
    let empty_bytes = bools_to_bytes(&empty);
    h.extend_from_slice(&sevenzip_varuint64_encode(empty_bytes.len() as u64));
    h.extend_from_slice(&empty_bytes);

    let mut empty_files = Vec::new();
    let mut anti = Vec::new();
    for entry in entries.iter().filter(|entry| !entry.has_stream) {
        empty_files.push(entry.kind == EntryKind::File);
        anti.push(entry.kind == EntryKind::Anti);
    }
    if empty_files.iter().any(|&v| v) {
        h.push(0x0f);
        let bytes = bools_to_bytes(&empty_files);
        h.extend_from_slice(&sevenzip_varuint64_encode(bytes.len() as u64));
        h.extend_from_slice(&bytes);
    }
    if anti.iter().any(|&v| v) {
        h.push(0x10);
        let bytes = bools_to_bytes(&anti);
        h.extend_from_slice(&sevenzip_varuint64_encode(bytes.len() as u64));
        h.extend_from_slice(&bytes);
    }
}

fn write_names(h: &mut Vec<u8>, entries: &[WriteEntry]) {
    h.push(0x11);
    let mut name_data = Vec::new();
    for entry in entries {
        for unit in entry.name.encode_utf16() {
            name_data.extend_from_slice(&unit.to_le_bytes());
        }
        name_data.extend_from_slice(&[0, 0]);
    }
    h.extend_from_slice(&sevenzip_varuint64_encode(1 + name_data.len() as u64));
    h.push(0x00);
    h.extend_from_slice(&name_data);
}

fn write_time_property(
    h: &mut Vec<u8>,
    tag: u8,
    entries: &[WriteEntry],
    value: impl Fn(&WriteEntry) -> Option<SystemTime>,
) {
    write_u64_property(h, tag, entries, |entry| {
        value(entry).map(system_time_to_filetime)
    });
}

fn write_u64_property(
    h: &mut Vec<u8>,
    tag: u8,
    entries: &[WriteEntry],
    value: impl Fn(&WriteEntry) -> Option<u64>,
) {
    let values: Vec<Option<u64>> = entries.iter().map(value).collect();
    if !values.iter().any(Option::is_some) {
        return;
    }
    let all_defined = values.iter().all(Option::is_some);
    let bitmap = (!all_defined)
        .then(|| bools_to_bytes(&values.iter().map(Option::is_some).collect::<Vec<bool>>()));
    let data_len = values.iter().filter(|v| v.is_some()).count() * 8;
    let size = 1 + bitmap.as_ref().map_or(0, Vec::len) + 1 + data_len;
    h.push(tag);
    h.extend_from_slice(&sevenzip_varuint64_encode(size as u64));
    h.push(u8::from(all_defined));
    if let Some(bitmap) = bitmap {
        h.extend_from_slice(&bitmap);
    }
    h.push(0x00);
    for val in values.into_iter().flatten() {
        h.extend_from_slice(&val.to_le_bytes());
    }
}

fn write_u32_property(
    h: &mut Vec<u8>,
    tag: u8,
    entries: &[WriteEntry],
    value: impl Fn(&WriteEntry) -> Option<u32>,
) {
    let values: Vec<Option<u32>> = entries.iter().map(value).collect();
    if !values.iter().any(Option::is_some) {
        return;
    }
    let all_defined = values.iter().all(Option::is_some);
    let bitmap = (!all_defined)
        .then(|| bools_to_bytes(&values.iter().map(Option::is_some).collect::<Vec<bool>>()));
    let data_len = values.iter().filter(|v| v.is_some()).count() * 4;
    let size = 1 + bitmap.as_ref().map_or(0, Vec::len) + 1 + data_len;
    h.push(tag);
    h.extend_from_slice(&sevenzip_varuint64_encode(size as u64));
    h.push(u8::from(all_defined));
    if let Some(bitmap) = bitmap {
        h.extend_from_slice(&bitmap);
    }
    h.push(0x00);
    for val in values.into_iter().flatten() {
        h.extend_from_slice(&val.to_le_bytes());
    }
}

fn bools_to_bytes(values: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; values.len().div_ceil(8)];
    for (idx, &value) in values.iter().enumerate() {
        if value {
            out[idx / 8] |= 1 << (7 - (idx % 8));
        }
    }
    out
}

fn system_time_to_filetime(t: SystemTime) -> u64 {
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    const TICKS_PER_SEC: u64 = 10_000_000;
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs().saturating_add(EPOCH_DIFF_SECS);
            let subsec_ticks = u64::from(d.subsec_nanos()) / 100;
            secs.saturating_mul(TICKS_PER_SEC)
                .saturating_add(subsec_ticks)
        }
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::build_header;
    use crate::write::model::{EntryKind, EntryMeta, WriteEntry};
    use bytes::Bytes;
    use std::time::{Duration, UNIX_EPOCH};

    fn entry(name: &str, kind: EntryKind, has_stream: bool, meta: EntryMeta) -> WriteEntry {
        WriteEntry {
            name: name.to_string(),
            kind,
            meta,
            has_stream,
            data: has_stream.then(|| vec![0xAA]),
            folder_id: 0,
        }
    }

    fn filetime_from_unix_secs(secs: u64) -> u64 {
        (secs + 11_644_473_600) * 10_000_000
    }

    fn parse_header(header: Vec<u8>) -> crate::Header {
        let backing = Bytes::from(header);
        let (_, parsed) = crate::Header::parse(&backing).unwrap();
        parsed
    }

    #[test]
    fn files_info_writer_emits_empty_stream_empty_file_and_anti_bitmaps() {
        let entries = vec![
            entry("dir", EntryKind::Directory, false, EntryMeta::default()),
            entry("empty.txt", EntryKind::File, false, EntryMeta::default()),
            entry("deleted.txt", EntryKind::Anti, false, EntryMeta::default()),
            entry("data.txt", EntryKind::File, true, EntryMeta::default()),
        ];

        let header = parse_header(build_header(&entries, &[]));
        let fi = header.files_info().unwrap();

        assert_eq!(fi.empty_streams.as_ref(), &[0b1110_0000]);
        assert_eq!(fi.empty_files.as_ref(), &[0b0100_0000]);
        assert_eq!(fi.anti_items.as_ref(), &[0b0010_0000]);
        assert!(fi.is_directory(0));
        assert!(fi.is_empty_file(1));
        assert!(fi.is_anti(2));
        assert!(!fi.is_empty_stream(3));
    }

    #[test]
    fn files_info_writer_emits_partial_metadata_definition_bitmaps() {
        let ctime_secs = 1_577_836_800;
        let atime_secs = 1_609_459_200;
        let mtime_secs = 1_640_995_200;
        let entries = vec![
            entry(
                "ctime-mtime.txt",
                EntryKind::File,
                true,
                EntryMeta {
                    ctime: Some(UNIX_EPOCH + Duration::from_secs(ctime_secs)),
                    mtime: Some(UNIX_EPOCH + Duration::from_secs(mtime_secs)),
                    ..EntryMeta::default()
                },
            ),
            entry(
                "atime-attrs.txt",
                EntryKind::File,
                true,
                EntryMeta {
                    atime: Some(UNIX_EPOCH + Duration::from_secs(atime_secs)),
                    attributes: Some(0x20),
                    ..EntryMeta::default()
                },
            ),
            entry(
                "start-pos.txt",
                EntryKind::File,
                true,
                EntryMeta {
                    mtime: Some(UNIX_EPOCH + Duration::from_secs(mtime_secs + 60)),
                    start_pos: Some(77),
                    ..EntryMeta::default()
                },
            ),
        ];

        let header = parse_header(build_header(&entries, &[]));
        let fi = header.files_info().unwrap();

        assert_eq!(
            fi.ctimes,
            vec![Some(filetime_from_unix_secs(ctime_secs)), None, None]
        );
        assert_eq!(
            fi.atimes,
            vec![None, Some(filetime_from_unix_secs(atime_secs)), None]
        );
        assert_eq!(
            fi.mtimes,
            vec![
                Some(filetime_from_unix_secs(mtime_secs)),
                None,
                Some(filetime_from_unix_secs(mtime_secs + 60)),
            ]
        );
        assert_eq!(fi.start_positions, vec![None, None, Some(77)]);
        assert_eq!(fi.attributes, vec![None, Some(0x20), None]);
    }
}
