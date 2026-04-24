#![allow(clippy::missing_errors_doc)]

mod encode;
mod header;
mod model;

use crate::{R7zError, RawFolderBlock, bcj::BcjX86Writer};
use header::{
    encode_coder_info_bcj_lzma2, encode_coder_info_copy, encode_coder_info_lzma,
    encode_coder_info_lzma2,
};
use lzma_rust2::{Lzma2Writer, LzmaWriter};
use std::{
    fs::{File, OpenOptions},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub use model::{
    ArchiveEntry, ArchiveOptions, Codec, CompressionLevel, CompressionOptions, EncryptionOptions,
    EntryKind, EntryMeta, HeaderMode, LzmaAlgorithm, MatchFinder, SolidMode, SpoolMode,
    StreamingOptions, VolumeOptions,
};

use model::WriteEntry;

#[doc(hidden)]
pub struct PreservedArchiveEntry {
    pub name: String,
    pub kind: EntryKind,
    pub meta: EntryMeta,
    pub stream: PreservedEntryStream,
}

#[doc(hidden)]
pub enum PreservedEntryStream {
    None,
    Data(Vec<u8>),
    Path {
        path: PathBuf,
        size: u64,
    },
    Raw {
        folder_id: usize,
        size: u64,
        crc: Option<u32>,
    },
}

struct StreamingCopyFolder {
    file_indices: Vec<usize>,
    pack_size: u64,
    file_sizes: Vec<u64>,
    file_crcs: Vec<u32>,
}

impl StreamingCopyFolder {
    fn new() -> Self {
        Self {
            file_indices: Vec::new(),
            pack_size: 0,
            file_sizes: Vec::new(),
            file_crcs: Vec::new(),
        }
    }
}

struct CountingWriter<W> {
    inner: W,
    count: u64,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count = self.count.checked_add(n as u64).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "archive stream too large")
        })?;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct StreamingLzma2Folder<W: Write> {
    writer: Lzma2Writer<CountingWriter<W>>,
    file_indices: Vec<usize>,
    unpack_size: u64,
    file_sizes: Vec<u64>,
    file_crcs: Vec<u32>,
}

struct StreamingBcjLzma2Folder<W: Write> {
    writer: BcjX86Writer<Lzma2Writer<CountingWriter<W>>>,
    file_indices: Vec<usize>,
    unpack_size: u64,
    file_sizes: Vec<u64>,
    file_crcs: Vec<u32>,
}

struct StreamingLzmaFolder<W: Write> {
    writer: LzmaWriter<CountingWriter<W>>,
    props: Vec<u8>,
    file_indices: Vec<usize>,
    unpack_size: u64,
    file_sizes: Vec<u64>,
    file_crcs: Vec<u32>,
}

pub struct ArchiveBuilder {
    entries: Vec<WriteEntry>,
    options: ArchiveOptions,
}

impl Default for ArchiveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            options: ArchiveOptions::default(),
        }
    }

    #[must_use]
    pub fn options(mut self, options: ArchiveOptions) -> Self {
        self.options = options;
        self
    }

    #[must_use]
    pub fn compression(mut self, codec: Codec) -> Self {
        self.options.codec = codec;
        self
    }

    #[must_use]
    pub fn add_file(mut self, name: &str, data: &[u8]) -> Self {
        if data.is_empty() {
            self.entries.push(WriteEntry {
                name: name.to_string(),
                kind: EntryKind::File,
                meta: EntryMeta::default(),
                has_stream: false,
                data: None,
                folder_id: 0,
            });
        } else {
            self.entries.push(WriteEntry {
                name: name.to_string(),
                kind: EntryKind::File,
                meta: EntryMeta::default(),
                has_stream: true,
                data: Some(data.to_vec()),
                folder_id: 0,
            });
        }
        self
    }

    #[must_use]
    pub fn add_file_entry(mut self, name: &str, data: &[u8], meta: EntryMeta) -> Self {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: !data.is_empty(),
            data: (!data.is_empty()).then(|| data.to_vec()),
            folder_id: 0,
        });
        self
    }

    #[must_use]
    pub fn add_symlink(mut self, name: &str, target: &str, meta: EntryMeta) -> Self {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta: meta.with_symlink_default(),
            has_stream: true,
            data: Some(target.as_bytes().to_vec()),
            folder_id: 0,
        });
        self
    }

    pub fn add_entry(mut self, entry: ArchiveEntry, data: Option<&[u8]>) -> Result<Self, R7zError> {
        self.entries.push(write_entry_from_archive_entry(
            entry,
            data.map(<[u8]>::to_vec),
            0,
        )?);
        Ok(self)
    }

    #[must_use]
    pub fn add_empty_file(mut self, name: &str, meta: EntryMeta) -> Self {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: false,
            data: None,
            folder_id: 0,
        });
        self
    }

    #[must_use]
    pub fn add_directory(mut self, name: &str, meta: EntryMeta) -> Self {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::Directory,
            meta,
            has_stream: false,
            data: None,
            folder_id: 0,
        });
        self
    }

    #[must_use]
    pub fn add_anti_item(mut self, name: &str, meta: EntryMeta) -> Self {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::Anti,
            meta,
            has_stream: false,
            data: None,
            folder_id: 0,
        });
        self
    }

    pub fn build(self) -> Result<Vec<u8>, R7zError> {
        let entries = entries_with_solid_folders(self.entries, &self.options.compression.solid)?;
        encode::build_archive(&entries, &self.options)
    }
}

#[doc(hidden)]
pub fn build_archive_with_preserved_folders(
    entries: Vec<PreservedArchiveEntry>,
    raw_folders: Vec<RawFolderBlock>,
    options: &ArchiveOptions,
) -> Result<Vec<u8>, R7zError> {
    build_archive_with_preserved_folders_buffered(entries, raw_folders, options)
}

#[doc(hidden)]
pub fn write_archive_with_preserved_folders<W: Write + Seek>(
    out: W,
    entries: Vec<PreservedArchiveEntry>,
    raw_folders: Vec<RawFolderBlock>,
    options: &ArchiveOptions,
) -> Result<W, R7zError> {
    if entries.is_empty() || !can_stream_preserved_options(options) {
        let bytes = build_archive_with_preserved_folders_buffered(entries, raw_folders, options)?;
        let mut out = out;
        out.seek(SeekFrom::Start(0))?;
        out.write_all(&bytes)?;
        out.flush()?;
        return Ok(out);
    }

    let (write_entries, streams, folder_order, raw_by_id) =
        stage_preserved_entries(entries, raw_folders, options)?;
    let mut out = out;
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&[0u8; 32])?;

    let mut completed = Vec::with_capacity(folder_order.len());
    for folder_id in folder_order {
        let file_indices = write_entries
            .iter()
            .enumerate()
            .filter_map(|(idx, entry)| {
                (entry.has_stream && entry.folder_id == folder_id).then_some(idx)
            })
            .collect::<Vec<_>>();
        if let Some(raw) = raw_by_id.get(&folder_id) {
            for packed in &raw.packed_streams {
                out.write_all(packed)?;
            }
            completed.push(completed_folder_from_raw(
                raw,
                &write_entries,
                &streams,
                &file_indices,
            )?);
        } else {
            completed.push(write_encoded_folder_streaming(
                &mut out,
                &write_entries,
                &streams,
                file_indices,
                options,
            )?);
        }
    }

    encode::finish_streamed_archive(out, &write_entries, &completed, options)
}

fn build_archive_with_preserved_folders_buffered(
    entries: Vec<PreservedArchiveEntry>,
    raw_folders: Vec<RawFolderBlock>,
    options: &ArchiveOptions,
) -> Result<Vec<u8>, R7zError> {
    let max_raw_folder = raw_folders
        .iter()
        .map(|folder| folder.folder_index)
        .max()
        .unwrap_or(0);
    let mut next_data_folder = max_raw_folder.checked_add(1).ok_or(R7zError::Parse)?;
    let mut current_data_folder: Option<usize> = None;
    let mut current_data_files = 0u64;
    let mut current_data_bytes = 0u64;

    let mut write_entries = Vec::with_capacity(entries.len());
    let mut raw_stream_meta = Vec::with_capacity(entries.len());
    for entry in entries {
        let mut raw_meta = None;
        let (has_stream, data, folder_id) = match entry.stream {
            PreservedEntryStream::None => (false, None, 0),
            PreservedEntryStream::Raw {
                folder_id,
                size,
                crc,
            } => {
                current_data_folder = None;
                current_data_files = 0;
                current_data_bytes = 0;
                raw_meta = Some((size, crc));
                (true, None, folder_id)
            }
            PreservedEntryStream::Data(data) => {
                let size = data.len() as u64;
                let folder_id = next_data_folder_id(
                    &options.compression.solid,
                    &mut next_data_folder,
                    &mut current_data_folder,
                    &mut current_data_files,
                    &mut current_data_bytes,
                    size,
                )?;
                (true, Some(data), folder_id)
            }
            PreservedEntryStream::Path { path, size } => {
                let folder_id = next_data_folder_id(
                    &options.compression.solid,
                    &mut next_data_folder,
                    &mut current_data_folder,
                    &mut current_data_files,
                    &mut current_data_bytes,
                    size,
                )?;
                let data = std::fs::read(path)?;
                (true, Some(data), folder_id)
            }
        };
        write_entries.push(WriteEntry {
            name: entry.name,
            kind: entry.kind,
            meta: entry.meta,
            has_stream,
            data,
            folder_id,
        });
        raw_stream_meta.push(raw_meta);
    }

    let mut folder_order = Vec::new();
    for entry in &write_entries {
        if entry.has_stream && !folder_order.contains(&entry.folder_id) {
            folder_order.push(entry.folder_id);
        }
    }

    let raw_by_id = raw_folders
        .into_iter()
        .map(|folder| (folder.folder_index, folder))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut prepared = Vec::with_capacity(folder_order.len());
    for folder_id in folder_order {
        let file_indices = write_entries
            .iter()
            .enumerate()
            .filter_map(|(idx, entry)| {
                (entry.has_stream && entry.folder_id == folder_id).then_some(idx)
            })
            .collect::<Vec<_>>();
        if let Some(raw) = raw_by_id.get(&folder_id) {
            prepared.push(model::PreparedFolder {
                metadata: model::CompletedFolder {
                    file_indices: file_indices.clone(),
                    pack_sizes: raw.pack_sizes.clone(),
                    coder_info: raw.folder_info.clone(),
                    coder_unpack_sizes: raw.coder_unpack_sizes.clone(),
                    folder_crc: raw.folder_crc,
                    file_sizes: file_indices
                        .iter()
                        .map(|&idx| {
                            preserved_stream_size(&write_entries[idx], raw_stream_meta[idx])
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    file_crcs: file_indices
                        .iter()
                        .map(|&idx| preserved_stream_crc(&write_entries[idx], raw_stream_meta[idx]))
                        .collect::<Result<Vec<_>, _>>()?,
                },
                packed_streams: raw.packed_streams.clone(),
            });
        } else {
            prepared.push(encode::encode_folder(
                &write_entries,
                file_indices,
                options,
            )?);
        }
    }

    encode::build_archive_from_prepared(&write_entries, &prepared, options)
}

enum StagedStream {
    None,
    Data(Vec<u8>),
    Path { path: PathBuf, size: u64 },
    Raw { size: u64, crc: Option<u32> },
}

type StagedPreserved = (
    Vec<WriteEntry>,
    Vec<StagedStream>,
    Vec<usize>,
    std::collections::BTreeMap<usize, RawFolderBlock>,
);

fn can_stream_preserved_options(options: &ArchiveOptions) -> bool {
    options.encryption.is_none()
        && matches!(
            options.codec,
            Codec::Copy | Codec::Lzma | Codec::Lzma2 | Codec::Lzma2Bcj
        )
}

fn stage_preserved_entries(
    entries: Vec<PreservedArchiveEntry>,
    raw_folders: Vec<RawFolderBlock>,
    options: &ArchiveOptions,
) -> Result<StagedPreserved, R7zError> {
    let max_raw_folder = raw_folders
        .iter()
        .map(|folder| folder.folder_index)
        .max()
        .unwrap_or(0);
    let mut next_data_folder = max_raw_folder.checked_add(1).ok_or(R7zError::Parse)?;
    let mut current_data_folder: Option<usize> = None;
    let mut current_data_files = 0u64;
    let mut current_data_bytes = 0u64;

    let mut write_entries = Vec::with_capacity(entries.len());
    let mut streams = Vec::with_capacity(entries.len());
    for entry in entries {
        let PreservedArchiveEntry {
            name,
            kind,
            meta,
            stream,
        } = entry;
        let (has_stream, folder_id, staged) = match stream {
            PreservedEntryStream::None => (false, 0, StagedStream::None),
            PreservedEntryStream::Raw {
                folder_id,
                size,
                crc,
            } => {
                current_data_folder = None;
                current_data_files = 0;
                current_data_bytes = 0;
                (true, folder_id, StagedStream::Raw { size, crc })
            }
            PreservedEntryStream::Data(data) => {
                let size = data.len() as u64;
                let folder_id = next_data_folder_id(
                    &options.compression.solid,
                    &mut next_data_folder,
                    &mut current_data_folder,
                    &mut current_data_files,
                    &mut current_data_bytes,
                    size,
                )?;
                (true, folder_id, StagedStream::Data(data))
            }
            PreservedEntryStream::Path { path, size } => {
                let folder_id = next_data_folder_id(
                    &options.compression.solid,
                    &mut next_data_folder,
                    &mut current_data_folder,
                    &mut current_data_files,
                    &mut current_data_bytes,
                    size,
                )?;
                (true, folder_id, StagedStream::Path { path, size })
            }
        };
        write_entries.push(WriteEntry {
            name,
            kind,
            meta,
            has_stream,
            data: None,
            folder_id,
        });
        streams.push(staged);
    }

    let mut folder_order = Vec::new();
    for entry in &write_entries {
        if entry.has_stream && !folder_order.contains(&entry.folder_id) {
            folder_order.push(entry.folder_id);
        }
    }

    let raw_by_id = raw_folders
        .into_iter()
        .map(|folder| (folder.folder_index, folder))
        .collect::<std::collections::BTreeMap<_, _>>();
    Ok((write_entries, streams, folder_order, raw_by_id))
}

fn completed_folder_from_raw(
    raw: &RawFolderBlock,
    write_entries: &[WriteEntry],
    streams: &[StagedStream],
    file_indices: &[usize],
) -> Result<model::CompletedFolder, R7zError> {
    Ok(model::CompletedFolder {
        file_indices: file_indices.to_vec(),
        pack_sizes: raw.pack_sizes.clone(),
        coder_info: raw.folder_info.clone(),
        coder_unpack_sizes: raw.coder_unpack_sizes.clone(),
        folder_crc: raw.folder_crc,
        file_sizes: file_indices
            .iter()
            .map(|&idx| staged_stream_size(&write_entries[idx], &streams[idx]))
            .collect::<Result<Vec<_>, _>>()?,
        file_crcs: file_indices
            .iter()
            .map(|&idx| staged_stream_crc(&write_entries[idx], &streams[idx]))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn write_encoded_folder_streaming<W: Write>(
    out: &mut W,
    _write_entries: &[WriteEntry],
    streams: &[StagedStream],
    file_indices: Vec<usize>,
    options: &ArchiveOptions,
) -> Result<model::CompletedFolder, R7zError> {
    match options.codec {
        Codec::Copy => write_copy_folder_streaming(out, streams, file_indices),
        Codec::Lzma2 => write_lzma2_folder_streaming(out, streams, file_indices, options),
        Codec::Lzma => write_lzma_folder_streaming(out, streams, file_indices, options),
        Codec::Lzma2Bcj => write_bcj_lzma2_folder_streaming(out, streams, file_indices, options),
        Codec::Ppmd => Err(R7zError::InvalidOptions(
            "PPMd streaming preserved writer is not supported",
        )),
    }
}

fn write_copy_folder_streaming<W: Write>(
    out: &mut W,
    streams: &[StagedStream],
    file_indices: Vec<usize>,
) -> Result<model::CompletedFolder, R7zError> {
    let mut file_sizes = Vec::new();
    let mut file_crcs = Vec::new();
    let mut pack_size = 0u64;
    for &idx in &file_indices {
        let (size, crc) = write_staged_stream_to(idx, streams, out)?;
        pack_size = pack_size.checked_add(size).ok_or(R7zError::Parse)?;
        file_sizes.push(size);
        file_crcs.push(Some(crc));
    }
    Ok(model::CompletedFolder {
        file_indices,
        pack_sizes: vec![pack_size],
        coder_info: encode_coder_info_copy(),
        coder_unpack_sizes: vec![pack_size],
        folder_crc: None,
        file_sizes,
        file_crcs,
    })
}

fn write_lzma2_folder_streaming<W: Write>(
    out: &mut W,
    streams: &[StagedStream],
    file_indices: Vec<usize>,
    options: &ArchiveOptions,
) -> Result<model::CompletedFolder, R7zError> {
    let counting = CountingWriter {
        inner: out,
        count: 0,
    };
    let mut writer = Lzma2Writer::new(counting, encode::lzma2_options(&options.compression));
    let mut file_sizes = Vec::new();
    let mut file_crcs = Vec::new();
    let mut unpack_size = 0u64;
    for &idx in &file_indices {
        let (size, crc) = write_staged_stream_to(idx, streams, &mut writer)?;
        unpack_size = unpack_size.checked_add(size).ok_or(R7zError::Parse)?;
        file_sizes.push(size);
        file_crcs.push(Some(crc));
    }
    let counting = writer.finish().map_err(|_| R7zError::Decompression)?;
    Ok(model::CompletedFolder {
        file_indices,
        pack_sizes: vec![counting.count],
        coder_info: encode_coder_info_lzma2(encode::lzma2_property_byte(&options.compression)?),
        coder_unpack_sizes: vec![unpack_size],
        folder_crc: None,
        file_sizes,
        file_crcs,
    })
}

fn write_lzma_folder_streaming<W: Write>(
    out: &mut W,
    streams: &[StagedStream],
    file_indices: Vec<usize>,
    options: &ArchiveOptions,
) -> Result<model::CompletedFolder, R7zError> {
    let lzma_options = encode::lzma_options(&options.compression);
    let dict_size = lzma_options.dict_size;
    let counting = CountingWriter {
        inner: out,
        count: 0,
    };
    let mut writer = LzmaWriter::new_no_header(counting, &lzma_options, false)
        .map_err(|_| R7zError::Decompression)?;
    let mut file_sizes = Vec::new();
    let mut file_crcs = Vec::new();
    let mut unpack_size = 0u64;
    for &idx in &file_indices {
        let (size, crc) = write_staged_stream_to(idx, streams, &mut writer)?;
        unpack_size = unpack_size.checked_add(size).ok_or(R7zError::Parse)?;
        file_sizes.push(size);
        file_crcs.push(Some(crc));
    }
    let props_byte = writer.props();
    let counting = writer.finish().map_err(|_| R7zError::Decompression)?;
    let mut props = Vec::with_capacity(5);
    props.push(props_byte);
    props.extend_from_slice(&dict_size.to_le_bytes());
    Ok(model::CompletedFolder {
        file_indices,
        pack_sizes: vec![counting.count],
        coder_info: encode_coder_info_lzma(&props),
        coder_unpack_sizes: vec![unpack_size],
        folder_crc: None,
        file_sizes,
        file_crcs,
    })
}

fn write_bcj_lzma2_folder_streaming<W: Write>(
    out: &mut W,
    streams: &[StagedStream],
    file_indices: Vec<usize>,
    options: &ArchiveOptions,
) -> Result<model::CompletedFolder, R7zError> {
    let counting = CountingWriter {
        inner: out,
        count: 0,
    };
    let lzma2 = Lzma2Writer::new(counting, encode::lzma2_options(&options.compression));
    let mut writer = BcjX86Writer::new(lzma2);
    let mut file_sizes = Vec::new();
    let mut file_crcs = Vec::new();
    let mut unpack_size = 0u64;
    for &idx in &file_indices {
        let (size, crc) = write_staged_stream_to(idx, streams, &mut writer)?;
        unpack_size = unpack_size.checked_add(size).ok_or(R7zError::Parse)?;
        file_sizes.push(size);
        file_crcs.push(Some(crc));
    }
    let lzma2 = writer.finish().map_err(|_| R7zError::Decompression)?;
    let counting = lzma2.finish().map_err(|_| R7zError::Decompression)?;
    Ok(model::CompletedFolder {
        file_indices,
        pack_sizes: vec![counting.count],
        coder_info: encode_coder_info_bcj_lzma2(encode::lzma2_property_byte(&options.compression)?),
        coder_unpack_sizes: vec![unpack_size, unpack_size],
        folder_crc: None,
        file_sizes,
        file_crcs,
    })
}

fn write_staged_stream_to<W: Write>(
    index: usize,
    streams: &[StagedStream],
    out: &mut W,
) -> Result<(u64, u32), R7zError> {
    let mut hasher = crc32fast::Hasher::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 8192];
    match streams.get(index).ok_or(R7zError::Parse)? {
        StagedStream::Data(data) => {
            out.write_all(data)?;
            hasher.update(data);
            size = data.len() as u64;
        }
        StagedStream::Path { path, .. } => {
            let mut file = File::open(path)?;
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n])?;
                hasher.update(&buf[..n]);
                size = size.checked_add(n as u64).ok_or(R7zError::Parse)?;
            }
        }
        StagedStream::None | StagedStream::Raw { .. } => return Err(R7zError::Parse),
    }
    Ok((size, hasher.finalize()))
}

fn staged_stream_size(entry: &WriteEntry, stream: &StagedStream) -> Result<u64, R7zError> {
    match stream {
        StagedStream::Raw { size, .. } | StagedStream::Path { size, .. } => Ok(*size),
        StagedStream::Data(data) => Ok(data.len() as u64),
        StagedStream::None => {
            if entry.has_stream {
                Err(R7zError::Parse)
            } else {
                Ok(0)
            }
        }
    }
}

fn staged_stream_crc(entry: &WriteEntry, stream: &StagedStream) -> Result<Option<u32>, R7zError> {
    match stream {
        StagedStream::Raw { crc, .. } => Ok(*crc),
        StagedStream::Data(data) => Ok(Some(crc32fast::hash(data))),
        StagedStream::Path { path, .. } => {
            let mut file = File::open(path)?;
            let mut hasher = crc32fast::Hasher::new();
            let mut buf = vec![0u8; 8192];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(Some(hasher.finalize()))
        }
        StagedStream::None => {
            if entry.has_stream {
                Err(R7zError::Parse)
            } else {
                Ok(None)
            }
        }
    }
}

fn next_data_folder_id(
    solid: &SolidMode,
    next_data_folder: &mut usize,
    current_folder: &mut Option<usize>,
    current_files: &mut u64,
    current_bytes: &mut u64,
    size: u64,
) -> Result<usize, R7zError> {
    let needs_new = match current_folder {
        None => true,
        Some(_) if matches!(solid, SolidMode::NonSolid) => true,
        Some(_) => match solid {
            SolidMode::Solid => false,
            SolidMode::NonSolid => true,
            SolidMode::Limit {
                max_files,
                max_bytes,
            } => {
                let next_files = current_files.checked_add(1).ok_or(R7zError::Parse)?;
                let next_bytes = current_bytes.checked_add(size).ok_or(R7zError::Parse)?;
                max_files.is_some_and(|n| *current_files > 0 && next_files > n.get())
                    || max_bytes.is_some_and(|n| *current_files > 0 && next_bytes > n.get())
            }
        },
    };
    if needs_new {
        *current_folder = Some(*next_data_folder);
        *next_data_folder = next_data_folder.checked_add(1).ok_or(R7zError::Parse)?;
        *current_files = 0;
        *current_bytes = 0;
    }
    let folder_id = current_folder.ok_or(R7zError::Parse)?;
    *current_files = current_files.checked_add(1).ok_or(R7zError::Parse)?;
    *current_bytes = current_bytes.checked_add(size).ok_or(R7zError::Parse)?;
    Ok(folder_id)
}

fn preserved_stream_size(
    entry: &WriteEntry,
    raw: Option<(u64, Option<u32>)>,
) -> Result<u64, R7zError> {
    if let Some((size, _)) = raw {
        return Ok(size);
    }
    entry
        .data
        .as_ref()
        .map(|data| data.len() as u64)
        .ok_or(R7zError::Parse)
}

fn preserved_stream_crc(
    entry: &WriteEntry,
    raw: Option<(u64, Option<u32>)>,
) -> Result<Option<u32>, R7zError> {
    if let Some((_, crc)) = raw {
        return Ok(crc);
    }
    entry
        .data
        .as_ref()
        .map(|data| Some(crc32fast::hash(data)))
        .ok_or(R7zError::Parse)
}

pub struct ArchiveWriter<W: Write + Seek> {
    out: Option<W>,
    entries: Vec<WriteEntry>,
    options: ArchiveOptions,
    current_folder: usize,
    current_folder_files: u64,
    current_folder_bytes: u64,
    copy_current: StreamingCopyFolder,
    copy_completed: Vec<StreamingCopyFolder>,
    lzma2_current: Option<StreamingLzma2Folder<W>>,
    lzma2_completed: Vec<model::CompletedFolder>,
    bcj_lzma2_current: Option<StreamingBcjLzma2Folder<W>>,
    bcj_lzma2_completed: Vec<model::CompletedFolder>,
    lzma_current: Option<StreamingLzmaFolder<W>>,
    lzma_completed: Vec<model::CompletedFolder>,
}

impl<W: Write + Seek> ArchiveWriter<W> {
    pub fn new(out: W, options: ArchiveOptions) -> Result<Self, R7zError> {
        encode::validate_archive_options(&options)?;
        Ok(Self {
            out: Some(out),
            entries: Vec::new(),
            options,
            current_folder: 0,
            current_folder_files: 0,
            current_folder_bytes: 0,
            copy_current: StreamingCopyFolder::new(),
            copy_completed: Vec::new(),
            lzma2_current: None,
            lzma2_completed: Vec::new(),
            bcj_lzma2_current: None,
            bcj_lzma2_completed: Vec::new(),
            lzma_current: None,
            lzma_completed: Vec::new(),
        })
    }

    pub fn new_default(out: W) -> Result<Self, R7zError> {
        Self::new(out, ArchiveOptions::default())
    }

    #[must_use]
    pub fn compression(mut self, codec: Codec) -> Self {
        self.options.codec = codec;
        self
    }

    pub fn append(&mut self, name: &str, reader: impl Read) -> Result<(), R7zError> {
        self.append_file(name, reader, EntryMeta::default())
    }

    pub fn append_entry(
        &mut self,
        name: &str,
        reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        self.append_file(name, reader, meta)
    }

    pub fn append_archive_entry(
        &mut self,
        entry: ArchiveEntry,
        reader: impl Read,
    ) -> Result<(), R7zError> {
        let ArchiveEntry { name, kind, meta } = entry;
        if kind != EntryKind::File {
            return Err(R7zError::InvalidOptions(
                "only file entries can have stream data",
            ));
        }
        self.append_file(&name, reader, meta)
    }

    pub fn append_empty_entry(&mut self, entry: ArchiveEntry) -> Result<(), R7zError> {
        match entry.kind {
            EntryKind::File => self.append_empty_file(&entry.name, entry.meta),
            EntryKind::Directory => self.append_directory(&entry.name, entry.meta),
            EntryKind::Anti => self.append_anti_item(&entry.name, entry.meta),
        }
    }

    pub fn append_file(
        &mut self,
        name: &str,
        mut reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        if self.should_stream_copy() {
            return self.append_copy_streaming(name, reader, meta);
        }
        if self.should_stream_lzma2() {
            return self.append_lzma2_streaming(name, reader, meta);
        }
        if self.should_stream_lzma() {
            return self.append_lzma_streaming(name, reader, meta);
        }
        if self.should_stream_bcj_lzma2() {
            return self.append_bcj_lzma2_streaming(name, reader, meta);
        }

        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        let size = data.len() as u64;
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: !data.is_empty(),
            data: (!data.is_empty()).then_some(data),
            folder_id: self.current_folder,
        });
        self.finish_entry_folder_accounting(size)?;
        Ok(())
    }

    pub fn append_symlink(
        &mut self,
        name: &str,
        target: &str,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        self.append_file(name, target.as_bytes(), meta.with_symlink_default())
    }

    pub fn append_empty_file(&mut self, name: &str, meta: EntryMeta) -> Result<(), R7zError> {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: false,
            data: None,
            folder_id: self.current_folder,
        });
        Ok(())
    }

    pub fn append_directory(&mut self, name: &str, meta: EntryMeta) -> Result<(), R7zError> {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::Directory,
            meta,
            has_stream: false,
            data: None,
            folder_id: self.current_folder,
        });
        Ok(())
    }

    pub fn append_anti_item(&mut self, name: &str, meta: EntryMeta) -> Result<(), R7zError> {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::Anti,
            meta,
            has_stream: false,
            data: None,
            folder_id: self.current_folder,
        });
        Ok(())
    }

    pub fn new_folder(&mut self) -> Result<(), R7zError> {
        if self.should_stream_copy() {
            self.seal_copy_folder();
        } else if self.should_stream_lzma2() {
            self.seal_lzma2_folder()?;
        } else if self.should_stream_lzma() {
            self.seal_lzma_folder()?;
        } else if self.should_stream_bcj_lzma2() {
            self.seal_bcj_lzma2_folder()?;
        } else if self
            .entries
            .iter()
            .any(|entry| entry.folder_id == self.current_folder && entry.has_stream)
        {
            self.current_folder += 1;
        }
        self.current_folder_files = 0;
        self.current_folder_bytes = 0;
        Ok(())
    }

    fn finish_entry_folder_accounting(&mut self, size: u64) -> Result<(), R7zError> {
        if size == 0 {
            return Ok(());
        }
        self.current_folder_files = self
            .current_folder_files
            .checked_add(1)
            .ok_or(R7zError::Parse)?;
        self.current_folder_bytes = self
            .current_folder_bytes
            .checked_add(size)
            .ok_or(R7zError::Parse)?;
        match &self.options.compression.solid {
            SolidMode::Solid => Ok(()),
            SolidMode::NonSolid => self.new_folder(),
            SolidMode::Limit {
                max_files,
                max_bytes,
            } => {
                let files_hit = max_files.is_some_and(|n| self.current_folder_files >= n.get());
                let bytes_hit = max_bytes.is_some_and(|n| self.current_folder_bytes >= n.get());
                if files_hit || bytes_hit {
                    self.new_folder()
                } else {
                    Ok(())
                }
            }
        }
    }

    pub fn finish(mut self) -> Result<W, R7zError> {
        if !self.copy_completed.is_empty() || !self.copy_current.file_indices.is_empty() {
            self.seal_copy_folder();
            let folders: Vec<model::CompletedFolder> = self
                .copy_completed
                .into_iter()
                .map(model::CompletedFolder::from)
                .collect();
            return encode::finish_streamed_archive(
                self.out.take().ok_or(R7zError::Parse)?,
                &self.entries,
                &folders,
                &self.options,
            );
        }
        if self.lzma2_current.is_some() || !self.lzma2_completed.is_empty() {
            self.seal_lzma2_folder()?;
            return encode::finish_streamed_archive(
                self.out.take().ok_or(R7zError::Parse)?,
                &self.entries,
                &self.lzma2_completed,
                &self.options,
            );
        }
        if self.lzma_current.is_some() || !self.lzma_completed.is_empty() {
            self.seal_lzma_folder()?;
            return encode::finish_streamed_archive(
                self.out.take().ok_or(R7zError::Parse)?,
                &self.entries,
                &self.lzma_completed,
                &self.options,
            );
        }
        if self.bcj_lzma2_current.is_some() || !self.bcj_lzma2_completed.is_empty() {
            self.seal_bcj_lzma2_folder()?;
            return encode::finish_streamed_archive(
                self.out.take().ok_or(R7zError::Parse)?,
                &self.entries,
                &self.bcj_lzma2_completed,
                &self.options,
            );
        }

        let bytes = encode::build_archive(&self.entries, &self.options)?;
        let out = self.out.as_mut().ok_or(R7zError::Parse)?;
        out.seek(SeekFrom::Start(0))?;
        out.write_all(&bytes)?;
        out.flush()?;
        self.out.take().ok_or(R7zError::Parse)
    }

    fn should_stream_copy(&self) -> bool {
        self.options.codec == Codec::Copy && self.options.encryption.is_none()
    }

    fn should_stream_lzma2(&self) -> bool {
        self.options.codec == Codec::Lzma2 && self.options.encryption.is_none()
    }

    fn should_stream_lzma(&self) -> bool {
        self.options.codec == Codec::Lzma && self.options.encryption.is_none()
    }

    fn should_stream_bcj_lzma2(&self) -> bool {
        self.options.codec == Codec::Lzma2Bcj && self.options.encryption.is_none()
    }

    fn append_copy_streaming(
        &mut self,
        name: &str,
        mut reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        let mut hasher = crc32fast::Hasher::new();
        let mut size = 0u64;
        let mut buf = vec![0u8; self.options.streaming.buffer_size];
        let first = reader.read(&mut buf)?;
        if first == 0 {
            self.entries.push(WriteEntry {
                name: name.to_string(),
                kind: EntryKind::File,
                meta,
                has_stream: false,
                data: None,
                folder_id: self.current_folder,
            });
            return Ok(());
        }
        self.ensure_copy_stream_started()?;
        self.out
            .as_mut()
            .ok_or(R7zError::Parse)?
            .write_all(&buf[..first])?;
        hasher.update(&buf[..first]);
        size = size.checked_add(first as u64).ok_or(R7zError::Parse)?;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.out
                .as_mut()
                .ok_or(R7zError::Parse)?
                .write_all(&buf[..n])?;
            hasher.update(&buf[..n]);
            size = size.checked_add(n as u64).ok_or(R7zError::Parse)?;
        }

        let index = self.entries.len();
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: size > 0,
            data: None,
            folder_id: self.current_folder,
        });

        self.copy_current.file_indices.push(index);
        self.copy_current.pack_size = self
            .copy_current
            .pack_size
            .checked_add(size)
            .ok_or(R7zError::Parse)?;
        self.copy_current.file_sizes.push(size);
        self.copy_current.file_crcs.push(hasher.finalize());

        self.finish_entry_folder_accounting(size)?;
        Ok(())
    }

    fn ensure_copy_stream_started(&mut self) -> Result<(), R7zError> {
        if !self.copy_completed.is_empty() || !self.copy_current.file_indices.is_empty() {
            return Ok(());
        }
        let out = self.out.as_mut().ok_or(R7zError::Parse)?;
        out.seek(SeekFrom::Start(0))?;
        out.write_all(&[0u8; 32])?;
        Ok(())
    }

    fn seal_copy_folder(&mut self) {
        if !self.copy_current.file_indices.is_empty() {
            self.copy_completed.push(std::mem::replace(
                &mut self.copy_current,
                StreamingCopyFolder::new(),
            ));
            self.current_folder += 1;
        }
    }

    fn append_lzma2_streaming(
        &mut self,
        name: &str,
        mut reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        let mut buf = vec![0u8; self.options.streaming.buffer_size];
        let first = reader.read(&mut buf)?;
        if first == 0 {
            self.entries.push(WriteEntry {
                name: name.to_string(),
                kind: EntryKind::File,
                meta,
                has_stream: false,
                data: None,
                folder_id: self.current_folder,
            });
            return Ok(());
        }

        self.ensure_lzma2_folder()?;
        let mut hasher = crc32fast::Hasher::new();
        let mut size = 0u64;
        self.write_lzma2_file_chunk(&buf[..first], &mut hasher, &mut size)?;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.write_lzma2_file_chunk(&buf[..n], &mut hasher, &mut size)?;
        }

        let index = self.entries.len();
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: true,
            data: None,
            folder_id: self.current_folder,
        });
        let folder = self.lzma2_current.as_mut().ok_or(R7zError::Parse)?;
        folder.file_indices.push(index);
        folder.unpack_size = folder
            .unpack_size
            .checked_add(size)
            .ok_or(R7zError::Parse)?;
        folder.file_sizes.push(size);
        folder.file_crcs.push(hasher.finalize());
        self.finish_entry_folder_accounting(size)?;
        Ok(())
    }

    fn write_lzma2_file_chunk(
        &mut self,
        chunk: &[u8],
        hasher: &mut crc32fast::Hasher,
        size: &mut u64,
    ) -> Result<(), R7zError> {
        let folder = self.lzma2_current.as_mut().ok_or(R7zError::Parse)?;
        folder
            .writer
            .write_all(chunk)
            .map_err(|_| R7zError::Decompression)?;
        hasher.update(chunk);
        *size = size
            .checked_add(chunk.len() as u64)
            .ok_or(R7zError::Parse)?;
        Ok(())
    }

    fn ensure_lzma2_folder(&mut self) -> Result<(), R7zError> {
        if self.lzma2_current.is_some() {
            return Ok(());
        }
        if self.lzma2_completed.is_empty() {
            let out = self.out.as_mut().ok_or(R7zError::Parse)?;
            out.seek(SeekFrom::Start(0))?;
            out.write_all(&[0u8; 32])?;
        }
        let out = self.out.take().ok_or(R7zError::Parse)?;
        let writer = Lzma2Writer::new(
            CountingWriter {
                inner: out,
                count: 0,
            },
            encode::lzma2_options(&self.options.compression),
        );
        self.lzma2_current = Some(StreamingLzma2Folder {
            writer,
            file_indices: Vec::new(),
            unpack_size: 0,
            file_sizes: Vec::new(),
            file_crcs: Vec::new(),
        });
        Ok(())
    }

    fn seal_lzma2_folder(&mut self) -> Result<(), R7zError> {
        let Some(folder) = self.lzma2_current.take() else {
            return Ok(());
        };
        let StreamingLzma2Folder {
            writer,
            file_indices,
            unpack_size,
            file_sizes,
            file_crcs,
        } = folder;
        let count_writer = writer.finish().map_err(|_| R7zError::Decompression)?;
        let pack_size = count_writer.count;
        self.out = Some(count_writer.inner);
        self.lzma2_completed.push(model::CompletedFolder {
            file_indices,
            pack_sizes: vec![pack_size],
            coder_info: encode_coder_info_lzma2(encode::lzma2_property_byte(
                &self.options.compression,
            )?),
            coder_unpack_sizes: vec![unpack_size],
            folder_crc: None,
            file_sizes,
            file_crcs: file_crcs.into_iter().map(Some).collect(),
        });
        self.current_folder += 1;
        Ok(())
    }

    fn append_lzma_streaming(
        &mut self,
        name: &str,
        mut reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        let mut buf = vec![0u8; self.options.streaming.buffer_size];
        let first = reader.read(&mut buf)?;
        if first == 0 {
            self.entries.push(WriteEntry {
                name: name.to_string(),
                kind: EntryKind::File,
                meta,
                has_stream: false,
                data: None,
                folder_id: self.current_folder,
            });
            return Ok(());
        }

        self.ensure_lzma_folder()?;
        let mut hasher = crc32fast::Hasher::new();
        let mut size = 0u64;
        self.write_lzma_file_chunk(&buf[..first], &mut hasher, &mut size)?;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.write_lzma_file_chunk(&buf[..n], &mut hasher, &mut size)?;
        }

        let index = self.entries.len();
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: true,
            data: None,
            folder_id: self.current_folder,
        });
        let folder = self.lzma_current.as_mut().ok_or(R7zError::Parse)?;
        folder.file_indices.push(index);
        folder.unpack_size = folder
            .unpack_size
            .checked_add(size)
            .ok_or(R7zError::Parse)?;
        folder.file_sizes.push(size);
        folder.file_crcs.push(hasher.finalize());
        self.finish_entry_folder_accounting(size)?;
        Ok(())
    }

    fn write_lzma_file_chunk(
        &mut self,
        chunk: &[u8],
        hasher: &mut crc32fast::Hasher,
        size: &mut u64,
    ) -> Result<(), R7zError> {
        let folder = self.lzma_current.as_mut().ok_or(R7zError::Parse)?;
        folder
            .writer
            .write_all(chunk)
            .map_err(|_| R7zError::Decompression)?;
        hasher.update(chunk);
        *size = size
            .checked_add(chunk.len() as u64)
            .ok_or(R7zError::Parse)?;
        Ok(())
    }

    fn ensure_lzma_folder(&mut self) -> Result<(), R7zError> {
        if self.lzma_current.is_some() {
            return Ok(());
        }
        if self.lzma_completed.is_empty() {
            let out = self.out.as_mut().ok_or(R7zError::Parse)?;
            out.seek(SeekFrom::Start(0))?;
            out.write_all(&[0u8; 32])?;
        }
        let out = self.out.take().ok_or(R7zError::Parse)?;
        let options = encode::lzma_options(&self.options.compression);
        let dict_size = options.dict_size;
        let writer = LzmaWriter::new_no_header(
            CountingWriter {
                inner: out,
                count: 0,
            },
            &options,
            false,
        )
        .map_err(|_| R7zError::Decompression)?;
        let mut props = Vec::with_capacity(5);
        props.push(writer.props());
        props.extend_from_slice(&dict_size.to_le_bytes());
        self.lzma_current = Some(StreamingLzmaFolder {
            writer,
            props,
            file_indices: Vec::new(),
            unpack_size: 0,
            file_sizes: Vec::new(),
            file_crcs: Vec::new(),
        });
        Ok(())
    }

    fn seal_lzma_folder(&mut self) -> Result<(), R7zError> {
        let Some(folder) = self.lzma_current.take() else {
            return Ok(());
        };
        let StreamingLzmaFolder {
            writer,
            props,
            file_indices,
            unpack_size,
            file_sizes,
            file_crcs,
        } = folder;
        let count_writer = writer.finish().map_err(|_| R7zError::Decompression)?;
        let pack_size = count_writer.count;
        self.out = Some(count_writer.inner);
        self.lzma_completed.push(model::CompletedFolder {
            file_indices,
            pack_sizes: vec![pack_size],
            coder_info: encode_coder_info_lzma(&props),
            coder_unpack_sizes: vec![unpack_size],
            folder_crc: None,
            file_sizes,
            file_crcs: file_crcs.into_iter().map(Some).collect(),
        });
        self.current_folder += 1;
        Ok(())
    }

    fn append_bcj_lzma2_streaming(
        &mut self,
        name: &str,
        mut reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        let mut buf = vec![0u8; self.options.streaming.buffer_size];
        let first = reader.read(&mut buf)?;
        if first == 0 {
            self.entries.push(WriteEntry {
                name: name.to_string(),
                kind: EntryKind::File,
                meta,
                has_stream: false,
                data: None,
                folder_id: self.current_folder,
            });
            return Ok(());
        }

        self.ensure_bcj_lzma2_folder()?;
        let mut hasher = crc32fast::Hasher::new();
        let mut size = 0u64;
        self.write_bcj_lzma2_file_chunk(&buf[..first], &mut hasher, &mut size)?;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.write_bcj_lzma2_file_chunk(&buf[..n], &mut hasher, &mut size)?;
        }

        let index = self.entries.len();
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: true,
            data: None,
            folder_id: self.current_folder,
        });
        let folder = self.bcj_lzma2_current.as_mut().ok_or(R7zError::Parse)?;
        folder.file_indices.push(index);
        folder.unpack_size = folder
            .unpack_size
            .checked_add(size)
            .ok_or(R7zError::Parse)?;
        folder.file_sizes.push(size);
        folder.file_crcs.push(hasher.finalize());
        self.finish_entry_folder_accounting(size)?;
        Ok(())
    }

    fn write_bcj_lzma2_file_chunk(
        &mut self,
        chunk: &[u8],
        hasher: &mut crc32fast::Hasher,
        size: &mut u64,
    ) -> Result<(), R7zError> {
        let folder = self.bcj_lzma2_current.as_mut().ok_or(R7zError::Parse)?;
        folder
            .writer
            .write_all(chunk)
            .map_err(|_| R7zError::Decompression)?;
        hasher.update(chunk);
        *size = size
            .checked_add(chunk.len() as u64)
            .ok_or(R7zError::Parse)?;
        Ok(())
    }

    fn ensure_bcj_lzma2_folder(&mut self) -> Result<(), R7zError> {
        if self.bcj_lzma2_current.is_some() {
            return Ok(());
        }
        if self.bcj_lzma2_completed.is_empty() {
            let out = self.out.as_mut().ok_or(R7zError::Parse)?;
            out.seek(SeekFrom::Start(0))?;
            out.write_all(&[0u8; 32])?;
        }
        let out = self.out.take().ok_or(R7zError::Parse)?;
        let lzma2 = Lzma2Writer::new(
            CountingWriter {
                inner: out,
                count: 0,
            },
            encode::lzma2_options(&self.options.compression),
        );
        self.bcj_lzma2_current = Some(StreamingBcjLzma2Folder {
            writer: BcjX86Writer::new(lzma2),
            file_indices: Vec::new(),
            unpack_size: 0,
            file_sizes: Vec::new(),
            file_crcs: Vec::new(),
        });
        Ok(())
    }

    fn seal_bcj_lzma2_folder(&mut self) -> Result<(), R7zError> {
        let Some(folder) = self.bcj_lzma2_current.take() else {
            return Ok(());
        };
        let StreamingBcjLzma2Folder {
            writer,
            file_indices,
            unpack_size,
            file_sizes,
            file_crcs,
        } = folder;
        let lzma2 = writer.finish().map_err(|_| R7zError::Decompression)?;
        let count_writer = lzma2.finish().map_err(|_| R7zError::Decompression)?;
        let pack_size = count_writer.count;
        self.out = Some(count_writer.inner);
        self.bcj_lzma2_completed.push(model::CompletedFolder {
            file_indices,
            pack_sizes: vec![pack_size],
            coder_info: encode_coder_info_bcj_lzma2(encode::lzma2_property_byte(
                &self.options.compression,
            )?),
            coder_unpack_sizes: vec![unpack_size, unpack_size],
            folder_crc: None,
            file_sizes,
            file_crcs: file_crcs.into_iter().map(Some).collect(),
        });
        self.current_folder += 1;
        Ok(())
    }
}

impl From<StreamingCopyFolder> for model::CompletedFolder {
    fn from(folder: StreamingCopyFolder) -> Self {
        Self {
            file_indices: folder.file_indices,
            pack_sizes: vec![folder.pack_size],
            coder_info: encode_coder_info_copy(),
            coder_unpack_sizes: vec![folder.pack_size],
            folder_crc: None,
            file_sizes: folder.file_sizes,
            file_crcs: folder.file_crcs.into_iter().map(Some).collect(),
        }
    }
}

fn entries_with_solid_folders(
    mut entries: Vec<WriteEntry>,
    solid: &SolidMode,
) -> Result<Vec<WriteEntry>, R7zError> {
    let mut folder_id = 0usize;
    let mut folder_files = 0u64;
    let mut folder_bytes = 0u64;

    for entry in &mut entries {
        if !entry.has_stream {
            entry.folder_id = folder_id;
            continue;
        }
        let size = entry
            .data
            .as_ref()
            .map(|data| data.len() as u64)
            .ok_or(R7zError::Parse)?;

        let would_exceed = match solid {
            SolidMode::Solid | SolidMode::NonSolid => false,
            SolidMode::Limit {
                max_files,
                max_bytes,
            } => {
                let next_files = folder_files.checked_add(1).ok_or(R7zError::Parse)?;
                let next_bytes = folder_bytes.checked_add(size).ok_or(R7zError::Parse)?;
                let files_hit = max_files.is_some_and(|n| folder_files > 0 && next_files > n.get());
                let bytes_hit = max_bytes.is_some_and(|n| folder_files > 0 && next_bytes > n.get());
                files_hit || bytes_hit
            }
        };
        if would_exceed {
            folder_id = folder_id.checked_add(1).ok_or(R7zError::Parse)?;
            folder_files = 0;
            folder_bytes = 0;
        }

        entry.folder_id = folder_id;
        folder_files = folder_files.checked_add(1).ok_or(R7zError::Parse)?;
        folder_bytes = folder_bytes.checked_add(size).ok_or(R7zError::Parse)?;

        if matches!(solid, SolidMode::NonSolid) {
            folder_id = folder_id.checked_add(1).ok_or(R7zError::Parse)?;
            folder_files = 0;
            folder_bytes = 0;
        }
    }

    Ok(entries)
}

fn write_entry_from_archive_entry(
    entry: ArchiveEntry,
    data: Option<Vec<u8>>,
    folder_id: usize,
) -> Result<WriteEntry, R7zError> {
    let has_stream = entry.kind == EntryKind::File && data.as_ref().is_some_and(|d| !d.is_empty());
    if entry.kind != EntryKind::File && data.as_ref().is_some_and(|d| !d.is_empty()) {
        return Err(R7zError::InvalidOptions(
            "only file entries can have stream data",
        ));
    }
    Ok(WriteEntry {
        name: entry.name,
        kind: entry.kind,
        meta: entry.meta,
        has_stream,
        data: has_stream.then_some(data).flatten(),
        folder_id,
    })
}

pub fn build_streaming<W, I, R>(entries: I, out: W) -> Result<(), R7zError>
where
    W: Write + Seek,
    I: IntoIterator<Item = (String, R)>,
    R: Read,
{
    build_streaming_with_options(entries, out, ArchiveOptions::default())
}

pub fn build_streaming_with_options<W, I, R>(
    entries: I,
    out: W,
    options: ArchiveOptions,
) -> Result<(), R7zError>
where
    W: Write + Seek,
    I: IntoIterator<Item = (String, R)>,
    R: Read,
{
    let mut writer = ArchiveWriter::new(out, options)?;
    for (name, reader) in entries {
        writer.append(&name, reader)?;
    }
    writer.finish()?;
    Ok(())
}

pub fn build_streaming_to_writer<W, I, R>(
    entries: I,
    mut out: W,
    options: ArchiveOptions,
) -> Result<(), R7zError>
where
    W: Write,
    I: IntoIterator<Item = (String, R)>,
    R: Read,
{
    encode::validate_archive_options(&options)?;
    match options.streaming.spool.clone() {
        SpoolMode::Memory => {
            let mut spool = Cursor::new(Vec::new());
            build_streaming_with_options(entries, &mut spool, options)?;
            out.write_all(spool.get_ref())?;
            out.flush()?;
            Ok(())
        }
        SpoolMode::Auto {
            memory_threshold,
            dir,
        } => {
            let mut spool = AutoSpool::new(memory_threshold, dir)?;
            let result = (|| {
                build_streaming_with_options(entries, &mut spool, options)?;
                spool.seek(SeekFrom::Start(0))?;
                io::copy(&mut spool, &mut out)?;
                out.flush()?;
                Ok(())
            })();
            let remove_result = spool.cleanup();
            match (result, remove_result) {
                (Err(err), _) => Err(err),
                (Ok(()), Err(err)) => Err(err.into()),
                (Ok(()), Ok(())) => Ok(()),
            }
        }
        SpoolMode::TempFile { dir } => {
            let (mut spool, path) = create_temp_spool(dir.as_deref())?;
            let result = (|| {
                build_streaming_with_options(entries, &mut spool, options)?;
                spool.seek(SeekFrom::Start(0))?;
                io::copy(&mut spool, &mut out)?;
                out.flush()?;
                Ok(())
            })();
            let remove_result = std::fs::remove_file(&path);
            match (result, remove_result) {
                (Err(err), _) => Err(err),
                (Ok(()), Err(err)) => Err(err.into()),
                (Ok(()), Ok(())) => Ok(()),
            }
        }
    }
}

pub fn build_streaming_volumes<P, I, R>(
    entries: I,
    base_path: P,
    archive_options: ArchiveOptions,
    volume_options: VolumeOptions,
) -> Result<Vec<PathBuf>, R7zError>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = (String, R)>,
    R: Read,
{
    if volume_options.sizes.is_empty() {
        return Err(R7zError::InvalidOptions(
            "volume options require at least one size",
        ));
    }

    let mut archive = Vec::new();
    build_streaming_to_writer(entries, &mut archive, archive_options)?;

    let base = base_path.as_ref();
    let mut paths = Vec::new();
    let mut offset = 0usize;
    let mut volume_idx = 0usize;
    while offset < archive.len() || (archive.is_empty() && volume_idx == 0) {
        let size_idx = volume_idx.min(volume_options.sizes.len() - 1);
        let size = usize::try_from(volume_options.sizes[size_idx].get())
            .map_err(|_| R7zError::InvalidOptions("volume size is too large"))?;
        let end = offset.saturating_add(size).min(archive.len());
        let path = PathBuf::from(format!("{}.{:03}", base.display(), volume_idx + 1));
        let mut file = File::create(&path)?;
        file.write_all(&archive[offset..end])?;
        file.flush()?;
        paths.push(path);
        offset = end;
        volume_idx += 1;
        if size == 0 {
            return Err(R7zError::InvalidOptions(
                "volume size must be greater than zero",
            ));
        }
    }

    Ok(paths)
}

fn create_temp_spool(dir: Option<&Path>) -> Result<(File, PathBuf), R7zError> {
    let dir = dir
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&dir)?;
    for attempt in 0..100u32 {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).map_err(|_| R7zError::Parse)?;
        let name = format!(
            "r7z-spool-{}-{attempt}-{:016x}.tmp",
            std::process::id(),
            u64::from_le_bytes(random)
        );
        let path = dir.join(name);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Err(R7zError::InvalidOptions("could not create temp spool file"))
}

enum AutoSpoolInner {
    Memory(Cursor<Vec<u8>>),
    TempFile { file: File, path: PathBuf },
}

struct AutoSpool {
    memory_threshold: u64,
    dir: Option<PathBuf>,
    inner: AutoSpoolInner,
}

impl AutoSpool {
    fn new(memory_threshold: u64, dir: Option<PathBuf>) -> Result<Self, R7zError> {
        let inner = if memory_threshold == 0 {
            let (file, path) = create_temp_spool(dir.as_deref())?;
            AutoSpoolInner::TempFile { file, path }
        } else {
            AutoSpoolInner::Memory(Cursor::new(Vec::new()))
        };
        Ok(Self {
            memory_threshold,
            dir,
            inner,
        })
    }

    fn maybe_roll_to_file(&mut self, write_len: usize) -> io::Result<()> {
        let AutoSpoolInner::Memory(cursor) = &mut self.inner else {
            return Ok(());
        };

        let projected_len = cursor
            .position()
            .saturating_add(write_len as u64)
            .max(cursor.get_ref().len() as u64);
        if projected_len <= self.memory_threshold {
            return Ok(());
        }

        let current_pos = cursor.position();
        let (mut file, path) = create_temp_spool(self.dir.as_deref()).map_err(io::Error::other)?;
        file.write_all(cursor.get_ref())?;
        file.seek(SeekFrom::Start(current_pos))?;
        self.inner = AutoSpoolInner::TempFile { file, path };
        Ok(())
    }

    fn cleanup(self) -> io::Result<()> {
        match self.inner {
            AutoSpoolInner::Memory(_) => Ok(()),
            AutoSpoolInner::TempFile { path, .. } => std::fs::remove_file(path),
        }
    }
}

impl Write for AutoSpool {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.maybe_roll_to_file(buf.len())?;
        match &mut self.inner {
            AutoSpoolInner::Memory(cursor) => cursor.write(buf),
            AutoSpoolInner::TempFile { file, .. } => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            AutoSpoolInner::Memory(cursor) => cursor.flush(),
            AutoSpoolInner::TempFile { file, .. } => file.flush(),
        }
    }
}

impl Read for AutoSpool {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            AutoSpoolInner::Memory(cursor) => cursor.read(buf),
            AutoSpoolInner::TempFile { file, .. } => file.read(buf),
        }
    }
}

impl Seek for AutoSpool {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match &mut self.inner {
            AutoSpoolInner::Memory(cursor) => cursor.seek(pos),
            AutoSpoolInner::TempFile { file, .. } => file.seek(pos),
        }
    }
}
