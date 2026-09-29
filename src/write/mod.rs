#![allow(clippy::missing_errors_doc)]

mod encode;
mod header;
mod lzma2;
mod model;

use crate::aes::Aes256CbcEncryptWriter;
use crate::{Archive, R7zError, RawEntryName, RawFolderBlock, RawFolderHandle, bcj::BcjX86Writer};
use header::{
    CoderSpec, encode_coder_info_aes_then, encode_coder_info_bcj_lzma2, encode_coder_info_copy,
    encode_coder_info_lzma, encode_coder_info_lzma2, encode_coder_info_ppmd,
};
use lzma_rust2::LzmaWriter;
use ppmd_rust::Ppmd7Encoder;
use std::{
    fs::{File, OpenOptions},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub use model::{
    ArchiveEntry, ArchiveOptions, Codec, CompressionLevel, CompressionOptions, EncoderThreads,
    EncryptionOptions, EntryKind, EntryMeta, HeaderMode, LzmaAlgorithm, MatchFinder, SolidMode,
    SpoolMode, StreamingOptions, VolumeOptions,
};

use model::WriteEntry;

/// Archive entry used by [`write_archive_update`] to retain or add an item.
pub struct PreservedArchiveEntry {
    /// Display name stored in the archive.
    pub name: String,
    /// Original encoded name when retaining an existing entry.
    pub raw_name: Option<RawEntryName>,
    /// File, directory, or anti-item kind.
    pub kind: EntryKind,
    /// Metadata written for this entry.
    pub meta: EntryMeta,
    /// Data source for the entry.
    pub stream: PreservedEntryStream,
}

/// Data source for an entry passed to [`write_archive_update`].
pub enum PreservedEntryStream {
    /// Entry has no data stream.
    None,
    /// Data already held in memory.
    Data(Vec<u8>),
    /// Data read from a file while writing.
    Path {
        /// File to read.
        path: PathBuf,
        /// Expected uncompressed size.
        size: u64,
    },
    /// Compressed folder data retained from the source archive.
    Raw {
        /// Archive-scoped handle returned by [`RawFolderBlock::handle`].
        folder: RawFolderHandle,
        /// Uncompressed entry size.
        size: u64,
        /// Entry checksum, when present.
        crc: Option<u32>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CopyEntryIndex(usize);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CopyStreamSize(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CopyFileChecksum(u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CopyFileStream {
    entry: CopyEntryIndex,
    size: CopyStreamSize,
    checksum: CopyFileChecksum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FolderPlan {
    Automatic,
    Preplanned { folder_size: u64 },
}

#[derive(Default)]
struct StreamingCopyFolder {
    streams: Vec<CopyFileStream>,
    packed_size: CopyStreamSize,
}

impl StreamingCopyFolder {
    fn push(&mut self, stream: CopyFileStream) -> Result<(), R7zError> {
        self.packed_size = CopyStreamSize(
            self.packed_size
                .0
                .checked_add(stream.size.0)
                .ok_or(R7zError::Parse)?,
        );
        self.streams.push(stream);
        Ok(())
    }

    fn complete(self) -> model::CompletedFolder {
        model::CompletedFolder {
            file_indices: self.streams.iter().map(|stream| stream.entry.0).collect(),
            pack_sizes: vec![self.packed_size.0],
            coder_info: encode_coder_info_copy(),
            coder_unpack_sizes: vec![self.packed_size.0],
            folder_crc: None,
            file_sizes: self.streams.iter().map(|stream| stream.size.0).collect(),
            file_crcs: self
                .streams
                .iter()
                .map(|stream| Some(stream.checksum.0))
                .collect(),
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

enum PayloadWriter<W: Write> {
    Plain(CountingWriter<W>),
    Aes {
        writer: Box<Aes256CbcEncryptWriter<CountingWriter<W>>>,
        props: Vec<u8>,
    },
}

struct EncryptedPayload {
    plaintext_size: u64,
    props: Vec<u8>,
}

struct PayloadCompletion<W: Write> {
    writer: CountingWriter<W>,
    encrypted: Option<EncryptedPayload>,
}

impl<W: Write> PayloadWriter<W> {
    fn new(out: W, encryption: Option<&EncryptionOptions>) -> Result<Self, R7zError> {
        match encryption {
            Some(options) => {
                let aes = encode::make_aes_material(options)?;
                Ok(Self::Aes {
                    writer: Box::new(Aes256CbcEncryptWriter::new(
                        CountingWriter {
                            inner: out,
                            count: 0,
                        },
                        &aes.key,
                        &aes.iv,
                    )),
                    props: aes.props,
                })
            }
            None => Ok(Self::Plain(CountingWriter {
                inner: out,
                count: 0,
            })),
        }
    }

    fn finish(self) -> Result<PayloadCompletion<W>, R7zError> {
        match self {
            Self::Plain(writer) => Ok(PayloadCompletion {
                writer,
                encrypted: None,
            }),
            Self::Aes { writer, props } => {
                let (writer, plaintext_size) = (*writer).finish()?;
                Ok(PayloadCompletion {
                    writer,
                    encrypted: Some(EncryptedPayload {
                        plaintext_size,
                        props,
                    }),
                })
            }
        }
    }
}

impl<W: Write> Write for PayloadWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(writer) => writer.write(bytes),
            Self::Aes { writer, .. } => writer.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(writer) => writer.flush(),
            Self::Aes { writer, .. } => writer.flush(),
        }
    }
}

enum StreamingEncoder<W: Write> {
    Raw {
        writer: CountingWriter<W>,
        pack_sizes: Vec<u64>,
        coder_info: Vec<u8>,
        coder_unpack_sizes: Vec<u64>,
        folder_crc: Option<u32>,
    },
    Copy(PayloadWriter<W>),
    Lzma2(lzma2::Encoder<PayloadWriter<W>>),
    Lzma {
        writer: Box<LzmaWriter<PayloadWriter<W>>>,
        props: Vec<u8>,
    },
    Ppmd {
        writer: Box<Ppmd7Encoder<PayloadWriter<W>>>,
        props: Vec<u8>,
    },
    BcjLzma2(BcjX86Writer<lzma2::Encoder<PayloadWriter<W>>>),
}

struct StreamingFolder<W: Write> {
    encoder: StreamingEncoder<W>,
    copy: StreamingCopyFolder,
    file_indices: Vec<usize>,
    unpack_size: u64,
    file_sizes: Vec<u64>,
    file_crcs: Vec<Option<u32>>,
}

impl<W: Write> Write for StreamingFolder<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match &mut self.encoder {
            StreamingEncoder::Raw { writer, .. } => writer.write(bytes),
            StreamingEncoder::Copy(writer) => writer.write(bytes),
            StreamingEncoder::Lzma2(writer) => writer.write(bytes),
            StreamingEncoder::Lzma { writer, .. } => writer.write(bytes),
            StreamingEncoder::Ppmd { writer, .. } => writer.write(bytes),
            StreamingEncoder::BcjLzma2(writer) => writer.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.encoder {
            StreamingEncoder::Raw { writer, .. } => writer.flush(),
            StreamingEncoder::Copy(writer) => writer.flush(),
            StreamingEncoder::Lzma2(writer) => writer.flush(),
            StreamingEncoder::Lzma { writer, .. } => writer.flush(),
            StreamingEncoder::Ppmd { writer, .. } => writer.flush(),
            StreamingEncoder::BcjLzma2(writer) => writer.flush(),
        }
    }
}

impl<W: Write> StreamingFolder<W> {
    fn encoded(
        codec: Codec,
        out: W,
        options: &ArchiveOptions,
        known_size: Option<u64>,
    ) -> Result<Self, R7zError> {
        let payload = PayloadWriter::new(out, options.encryption.as_ref())?;
        let encoder =
            match codec {
                Codec::Copy => StreamingEncoder::Copy(payload),
                Codec::Lzma2 => StreamingEncoder::Lzma2(lzma2::Encoder::new(
                    payload,
                    &options.compression,
                    known_size,
                )?),
                Codec::Lzma => {
                    let lzma_options = encode::lzma_options(&options.compression);
                    let dict_size = lzma_options.dict_size;
                    let writer = LzmaWriter::new_no_header(payload, &lzma_options, false)?;
                    let mut props = Vec::with_capacity(5);
                    props.push(writer.props());
                    props.extend_from_slice(&dict_size.to_le_bytes());
                    StreamingEncoder::Lzma {
                        writer: Box::new(writer),
                        props,
                    }
                }
                Codec::Ppmd => {
                    let (order, mem_size) = encode::ppmd_options(&options.compression)?;
                    let mut props = Vec::with_capacity(5);
                    props.push(order);
                    props.extend_from_slice(&mem_size.to_le_bytes());
                    let writer = Box::new(
                        Ppmd7Encoder::new(payload, u32::from(order), mem_size).map_err(|_| {
                            R7zError::InvalidOptions(
                                "PPMd order or memory size is outside supported range",
                            )
                        })?,
                    );
                    StreamingEncoder::Ppmd { writer, props }
                }
                Codec::Lzma2Bcj => StreamingEncoder::BcjLzma2(BcjX86Writer::new(
                    lzma2::Encoder::new(payload, &options.compression, known_size)?,
                )),
            };
        Ok(Self {
            encoder,
            copy: StreamingCopyFolder::default(),
            file_indices: Vec::new(),
            unpack_size: 0,
            file_sizes: Vec::new(),
            file_crcs: Vec::new(),
        })
    }

    fn raw(
        mut writer: CountingWriter<W>,
        raw: RawFolderBlock,
        write_entries: &[WriteEntry],
        streams: &[StagedStream],
        file_indices: Vec<usize>,
    ) -> Result<Self, R7zError> {
        if raw.packed_streams.len() != raw.pack_sizes.len() {
            return Err(R7zError::Parse);
        }
        for (packed, &size) in raw.packed_streams.iter().zip(&raw.pack_sizes) {
            if packed.len() as u64 != size {
                return Err(R7zError::Parse);
            }
            writer.write_all(packed)?;
        }
        let file_sizes = file_indices
            .iter()
            .map(|&index| staged_stream_size(&write_entries[index], &streams[index]))
            .collect::<Result<_, _>>()?;
        let file_crcs = file_indices
            .iter()
            .map(|&index| staged_stream_crc(&write_entries[index], &streams[index]))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            encoder: StreamingEncoder::Raw {
                writer,
                pack_sizes: raw.pack_sizes,
                coder_info: raw.folder_info,
                coder_unpack_sizes: raw.coder_unpack_sizes,
                folder_crc: raw.folder_crc,
            },
            copy: StreamingCopyFolder::default(),
            file_indices,
            unpack_size: 0,
            file_sizes,
            file_crcs,
        })
    }

    fn record_stream(&mut self, index: usize, size: u64, checksum: u32) -> Result<(), R7zError> {
        match &mut self.encoder {
            StreamingEncoder::Copy(_) => self.copy.push(CopyFileStream {
                entry: CopyEntryIndex(index),
                size: CopyStreamSize(size),
                checksum: CopyFileChecksum(checksum),
            }),
            StreamingEncoder::Raw { .. } => Err(R7zError::Parse),
            StreamingEncoder::Lzma2(_)
            | StreamingEncoder::Lzma { .. }
            | StreamingEncoder::Ppmd { .. }
            | StreamingEncoder::BcjLzma2(_) => {
                self.file_indices.push(index);
                self.unpack_size = self.unpack_size.checked_add(size).ok_or(R7zError::Parse)?;
                self.file_sizes.push(size);
                self.file_crcs.push(Some(checksum));
                Ok(())
            }
        }
    }

    fn complete(
        self,
        options: &ArchiveOptions,
    ) -> Result<(CountingWriter<W>, model::CompletedFolder), R7zError> {
        let Self {
            encoder,
            copy,
            file_indices,
            unpack_size,
            file_sizes,
            file_crcs,
        } = self;
        let (writer, mut coder_info, mut coder_unpack_sizes, specs) = match encoder {
            StreamingEncoder::Raw {
                writer,
                pack_sizes,
                coder_info,
                coder_unpack_sizes,
                folder_crc,
            } => {
                return Ok((
                    writer,
                    model::CompletedFolder {
                        file_indices,
                        pack_sizes,
                        coder_info,
                        coder_unpack_sizes,
                        folder_crc,
                        file_sizes,
                        file_crcs,
                    },
                ));
            }
            StreamingEncoder::Copy(writer) => {
                let PayloadCompletion { writer, encrypted } = writer.finish()?;
                let mut folder = copy.complete();
                folder.pack_sizes = vec![writer.count];
                if let Some(encrypted) = encrypted {
                    folder.coder_info =
                        encode_coder_info_aes_then(&[CoderSpec::Copy], &encrypted.props);
                    folder
                        .coder_unpack_sizes
                        .insert(0, encrypted.plaintext_size);
                }
                return Ok((writer, folder));
            }
            StreamingEncoder::Lzma2(writer) => {
                let property = encode::lzma2_property_byte(&options.compression)?;
                (
                    writer.finish()?,
                    encode_coder_info_lzma2(property),
                    vec![unpack_size],
                    vec![CoderSpec::Lzma2(property)],
                )
            }
            StreamingEncoder::Lzma { writer, props } => (
                writer.finish()?,
                encode_coder_info_lzma(&props),
                vec![unpack_size],
                vec![CoderSpec::Lzma(props)],
            ),
            StreamingEncoder::Ppmd { writer, props } => (
                (*writer).finish(false)?,
                encode_coder_info_ppmd(&props),
                vec![unpack_size],
                vec![CoderSpec::Ppmd(props)],
            ),
            StreamingEncoder::BcjLzma2(writer) => {
                let writer = writer.finish()?.finish()?;
                let property = encode::lzma2_property_byte(&options.compression)?;
                (
                    writer,
                    encode_coder_info_bcj_lzma2(property),
                    vec![unpack_size, unpack_size],
                    vec![CoderSpec::Lzma2(property), CoderSpec::Bcj],
                )
            }
        };
        let PayloadCompletion { writer, encrypted } = writer.finish()?;
        let pack_size = writer.count;
        if let Some(encrypted) = encrypted {
            coder_info = encode_coder_info_aes_then(&specs, &encrypted.props);
            coder_unpack_sizes.insert(0, encrypted.plaintext_size);
        }
        Ok((
            writer,
            model::CompletedFolder {
                file_indices,
                pack_sizes: vec![pack_size],
                coder_info,
                coder_unpack_sizes,
                folder_crc: None,
                file_sizes,
                file_crcs,
            },
        ))
    }
}

enum WriterMode<W: Write> {
    Streaming {
        codec: Codec,
        current: Option<Box<StreamingFolder<W>>>,
        completed: Vec<model::CompletedFolder>,
    },
    Failed,
}

impl<W: Write> WriterMode<W> {
    fn select(options: &ArchiveOptions) -> Self {
        Self::Streaming {
            codec: options.codec,
            current: None,
            completed: Vec::new(),
        }
    }
}

fn writer_failed() -> R7zError {
    R7zError::InvalidOptions("archive writer cannot be reused after an I/O or encoder failure")
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
                raw_name: None,
                name: name.to_string(),
                kind: EntryKind::File,
                meta: EntryMeta::default(),
                has_stream: false,
                data: None,
                folder_id: 0,
            });
        } else {
            self.entries.push(WriteEntry {
                raw_name: None,
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
            raw_name: None,
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
            raw_name: None,
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
            raw_name: None,
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
            raw_name: None,
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
            raw_name: None,
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
        let mut options = self.options;
        lzma2::set_default_budget(&mut options);
        if matches!(
            options.codec,
            Codec::Copy | Codec::Lzma | Codec::Lzma2 | Codec::Ppmd | Codec::Lzma2Bcj
        ) && self.entries.iter().any(|entry| entry.has_stream)
        {
            let entries = entries_with_solid_folders(self.entries, &options.compression.solid)?;
            let mut folder_sizes = std::collections::BTreeMap::<usize, u64>::new();
            for entry in &entries {
                if entry.has_stream {
                    let size = entry
                        .data
                        .as_ref()
                        .map(|data| data.len() as u64)
                        .ok_or(R7zError::Parse)?;
                    let folder_size = folder_sizes.entry(entry.folder_id).or_default();
                    *folder_size = folder_size.checked_add(size).ok_or(R7zError::Parse)?;
                }
            }
            let mut writer = ArchiveWriter::new(Cursor::new(Vec::new()), options)?;
            for entry in entries {
                let folder_size = folder_sizes.get(&entry.folder_id).copied().unwrap_or(0);
                match entry.folder_id.cmp(&writer.current_folder) {
                    std::cmp::Ordering::Less => return Err(R7zError::Parse),
                    std::cmp::Ordering::Equal => {}
                    std::cmp::Ordering::Greater => {
                        writer.new_folder()?;
                        if entry.folder_id != writer.current_folder {
                            return Err(R7zError::Parse);
                        }
                    }
                }
                writer.append_builder_entry(entry, folder_size)?;
            }
            return Ok(writer.finish()?.into_inner());
        }
        let entries = entries_with_solid_folders(self.entries, &options.compression.solid)?;
        encode::build_archive(&entries, &options)
    }
}

#[doc(hidden)]
pub fn build_archive_with_preserved_folders(
    entries: Vec<PreservedArchiveEntry>,
    raw_folders: Vec<RawFolderBlock>,
    options: &ArchiveOptions,
) -> Result<Vec<u8>, R7zError> {
    write_preserved_archive(Cursor::new(Vec::new()), entries, raw_folders, options)
        .map(Cursor::into_inner)
}

/// Write an updated archive while copying unchanged compressed folders from `source`.
///
/// Every raw folder handle must come from `source`; a handle obtained from another
/// archive is rejected before any output is written.
pub fn write_archive_update<W: Write + Seek>(
    source: &Archive,
    out: W,
    entries: Vec<PreservedArchiveEntry>,
    raw_folders: Vec<RawFolderBlock>,
    options: &ArchiveOptions,
) -> Result<W, R7zError> {
    validate_raw_folder_ownership(source, &entries, &raw_folders)?;
    write_preserved_archive(out, entries, raw_folders, options)
}

#[doc(hidden)]
pub fn write_archive_with_preserved_folders<W: Write + Seek>(
    out: W,
    entries: Vec<PreservedArchiveEntry>,
    raw_folders: Vec<RawFolderBlock>,
    options: &ArchiveOptions,
) -> Result<W, R7zError> {
    write_preserved_archive(out, entries, raw_folders, options)
}

fn validate_raw_folder_ownership(
    source: &Archive,
    entries: &[PreservedArchiveEntry],
    raw_folders: &[RawFolderBlock],
) -> Result<(), R7zError> {
    if raw_folders
        .iter()
        .any(|folder| !folder.handle().belongs_to(source))
    {
        return Err(R7zError::ArchiveMismatch);
    }

    for handle in entries.iter().filter_map(|entry| match &entry.stream {
        PreservedEntryStream::Raw { folder, .. } => Some(folder),
        PreservedEntryStream::None
        | PreservedEntryStream::Data(_)
        | PreservedEntryStream::Path { .. } => None,
    }) {
        if !handle.belongs_to(source)
            || !raw_folders.iter().any(|folder| folder.handle() == *handle)
        {
            return Err(R7zError::ArchiveMismatch);
        }
    }

    Ok(())
}

fn write_preserved_archive<W: Write + Seek>(
    out: W,
    entries: Vec<PreservedArchiveEntry>,
    raw_folders: Vec<RawFolderBlock>,
    options: &ArchiveOptions,
) -> Result<W, R7zError> {
    let mut options = options.clone();
    lzma2::set_default_budget(&mut options);
    encode::validate_archive_options(&options)?;
    let (write_entries, streams, folder_order, mut raw_by_id) =
        stage_preserved_entries(entries, raw_folders, &options)?;
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
        if let Some(raw) = raw_by_id.remove(&folder_id) {
            let folder = {
                let writer = CountingWriter {
                    inner: &mut out,
                    count: 0,
                };
                StreamingFolder::raw(writer, raw, &write_entries, &streams, file_indices)?
            };
            let (_writer, folder) = folder.complete(&options)?;
            completed.push(folder);
        } else {
            completed.push(write_encoded_folder_streaming(
                &mut out,
                &streams,
                file_indices,
                &options,
            )?);
        }
    }

    encode::finish_streamed_archive(out, &write_entries, &completed, &options)
}

enum StagedStream {
    None,
    Data(Vec<u8>),
    Path { path: PathBuf, size: u64 },
    Raw { size: u64, crc: Option<u32> },
}

fn staged_folder_size(streams: &[StagedStream], indices: &[usize]) -> Result<u64, R7zError> {
    indices.iter().try_fold(0u64, |total, &index| {
        let size = match streams.get(index).ok_or(R7zError::Parse)? {
            StagedStream::Data(data) => data.len() as u64,
            StagedStream::Path { size, .. } => *size,
            StagedStream::None | StagedStream::Raw { .. } => return Err(R7zError::Parse),
        };
        total.checked_add(size).ok_or(R7zError::Parse)
    })
}

type StagedPreserved = (
    Vec<WriteEntry>,
    Vec<StagedStream>,
    Vec<usize>,
    std::collections::BTreeMap<usize, RawFolderBlock>,
);

fn stage_preserved_entries(
    entries: Vec<PreservedArchiveEntry>,
    raw_folders: Vec<RawFolderBlock>,
    options: &ArchiveOptions,
) -> Result<StagedPreserved, R7zError> {
    let raw_by_id = raw_folders
        .into_iter()
        .map(|folder| (folder.folder_index, folder))
        .collect::<std::collections::BTreeMap<_, _>>();
    let max_raw_folder = raw_by_id.keys().copied().max().unwrap_or(0);
    let mut next_data_folder = max_raw_folder.checked_add(1).ok_or(R7zError::Parse)?;
    let mut current_data_folder: Option<usize> = None;
    let mut current_data_files = 0u64;
    let mut current_data_bytes = 0u64;

    let mut write_entries = Vec::with_capacity(entries.len());
    let mut streams = Vec::with_capacity(entries.len());
    for entry in entries {
        let PreservedArchiveEntry {
            name,
            raw_name,
            kind,
            meta,
            stream,
        } = entry;
        let (has_stream, folder_id, staged) = match stream {
            PreservedEntryStream::None => (false, 0, StagedStream::None),
            PreservedEntryStream::Raw { folder, size, crc } => {
                let folder_id = folder.index().get();
                if raw_by_id
                    .get(&folder_id)
                    .is_none_or(|raw| raw.handle() != folder)
                {
                    return Err(R7zError::ArchiveMismatch);
                }
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
            raw_name,
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

    Ok((write_entries, streams, folder_order, raw_by_id))
}

fn write_encoded_folder_streaming<W: Write>(
    out: &mut W,
    streams: &[StagedStream],
    file_indices: Vec<usize>,
    options: &ArchiveOptions,
) -> Result<model::CompletedFolder, R7zError> {
    let known_size = staged_folder_size(streams, &file_indices)?;
    let mut folder = StreamingFolder::encoded(options.codec, out, options, Some(known_size))?;
    for index in file_indices {
        let (size, checksum) = write_staged_stream_to(index, streams, &mut folder)?;
        folder.record_stream(index, size, checksum)?;
    }
    let (_out, folder) = folder.complete(options)?;
    Ok(folder)
}

fn write_staged_stream_to<W: Write>(
    index: usize,
    streams: &[StagedStream],
    out: &mut W,
) -> Result<(u64, u32), R7zError> {
    let mut hasher = crc32fast::Hasher::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];
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

pub struct ArchiveWriter<W: Write + Seek> {
    out: Option<W>,
    mode: WriterMode<W>,
    entries: Vec<WriteEntry>,
    options: ArchiveOptions,
    current_folder: usize,
    current_folder_files: u64,
    current_folder_bytes: u64,
}

impl<W: Write + Seek> ArchiveWriter<W> {
    pub fn new(out: W, mut options: ArchiveOptions) -> Result<Self, R7zError> {
        encode::validate_archive_options(&options)?;
        lzma2::set_default_budget(&mut options);
        Ok(Self {
            out: Some(out),
            mode: WriterMode::select(&options),
            entries: Vec::new(),
            options,
            current_folder: 0,
            current_folder_files: 0,
            current_folder_bytes: 0,
        })
    }

    pub fn new_default(out: W) -> Result<Self, R7zError> {
        Self::new(out, ArchiveOptions::default())
    }

    pub fn compression(mut self, codec: Codec) -> Result<Self, R7zError> {
        self.set_compression(codec)?;
        Ok(self)
    }

    pub fn set_compression(&mut self, codec: Codec) -> Result<(), R7zError> {
        if matches!(self.mode, WriterMode::Failed) {
            return Err(writer_failed());
        }
        if self.entries.iter().any(|entry| entry.has_stream) {
            return Err(R7zError::InvalidOptions(
                "cannot change compression after appending nonempty file data",
            ));
        }
        let mut options = self.options.clone();
        options.codec = codec;
        encode::validate_archive_options(&options)?;
        lzma2::set_default_budget(&mut options);
        self.mode = WriterMode::select(&options);
        self.options = options;
        Ok(())
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
        if matches!(self.mode, WriterMode::Failed) {
            return Err(writer_failed());
        }
        self.entries.push(WriteEntry {
            raw_name: None,
            name: entry.name,
            kind: entry.kind,
            meta: entry.meta,
            has_stream: false,
            data: None,
            folder_id: self.current_folder,
        });
        Ok(())
    }

    pub fn append_file(
        &mut self,
        name: &str,
        reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        if matches!(self.mode, WriterMode::Failed) {
            return Err(writer_failed());
        }
        let result = self.append_file_inner(name, reader, meta);
        if result.is_err() {
            self.mode = WriterMode::Failed;
        }
        result
    }

    fn append_file_inner(
        &mut self,
        name: &str,
        reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        match &self.mode {
            WriterMode::Streaming { .. } => {
                self.append_streaming(name, reader, meta, FolderPlan::Automatic)
            }
            WriterMode::Failed => Err(writer_failed()),
        }
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
        self.append_empty_entry(ArchiveEntry {
            name: name.to_owned(),
            kind: EntryKind::File,
            meta,
        })
    }

    pub fn append_directory(&mut self, name: &str, meta: EntryMeta) -> Result<(), R7zError> {
        self.append_empty_entry(ArchiveEntry {
            name: name.to_owned(),
            kind: EntryKind::Directory,
            meta,
        })
    }

    pub fn append_anti_item(&mut self, name: &str, meta: EntryMeta) -> Result<(), R7zError> {
        self.append_empty_entry(ArchiveEntry {
            name: name.to_owned(),
            kind: EntryKind::Anti,
            meta,
        })
    }

    pub fn new_folder(&mut self) -> Result<(), R7zError> {
        let result = match &self.mode {
            WriterMode::Streaming { .. } => self.seal_streaming_folder(),
            WriterMode::Failed => Err(writer_failed()),
        };
        if result.is_err() {
            self.mode = WriterMode::Failed;
        }
        result?;
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
        if matches!(self.mode, WriterMode::Failed) {
            return Err(writer_failed());
        }
        if !self.entries.iter().any(|entry| entry.has_stream) {
            return self.finish_buffered();
        }
        let folders = match &self.mode {
            WriterMode::Streaming { .. } => {
                self.seal_streaming_folder()?;
                let WriterMode::Streaming { completed, .. } = self.mode else {
                    unreachable!()
                };
                completed
            }
            WriterMode::Failed => return Err(writer_failed()),
        };
        encode::finish_streamed_archive(
            self.out.take().ok_or(R7zError::Parse)?,
            &self.entries,
            &folders,
            &self.options,
        )
    }

    fn finish_buffered(mut self) -> Result<W, R7zError> {
        let bytes = encode::build_archive(&self.entries, &self.options)?;
        let out = self.out.as_mut().ok_or(R7zError::Parse)?;
        out.seek(SeekFrom::Start(0))?;
        out.write_all(&bytes)?;
        out.flush()?;
        self.out.take().ok_or(R7zError::Parse)
    }

    fn append_streaming(
        &mut self,
        name: &str,
        mut reader: impl Read,
        meta: EntryMeta,
        folder_plan: FolderPlan,
    ) -> Result<(), R7zError> {
        let mut buffer = vec![0u8; self.options.streaming.buffer_size];
        let first = reader.read(&mut buffer)?;
        if first == 0 {
            if matches!(folder_plan, FolderPlan::Preplanned { .. }) {
                self.ensure_streaming_folder(folder_plan)?;
                let index = self.entries.len();
                self.entries.push(WriteEntry {
                    raw_name: None,
                    name: name.to_owned(),
                    kind: EntryKind::File,
                    meta,
                    has_stream: true,
                    data: None,
                    folder_id: self.current_folder,
                });
                let WriterMode::Streaming {
                    current: Some(folder),
                    ..
                } = &mut self.mode
                else {
                    unreachable!()
                };
                folder.record_stream(index, 0, crc32fast::hash(&[]))?;
                return Ok(());
            }
            self.entries.push(WriteEntry {
                raw_name: None,
                name: name.to_owned(),
                kind: EntryKind::File,
                meta,
                has_stream: false,
                data: None,
                folder_id: self.current_folder,
            });
            return Ok(());
        }

        self.ensure_streaming_folder(folder_plan)?;
        let mut checksum = crc32fast::Hasher::new();
        let mut size = 0u64;
        let mut chunk = &buffer[..first];
        loop {
            let WriterMode::Streaming {
                current: Some(folder),
                ..
            } = &mut self.mode
            else {
                unreachable!()
            };
            folder.write_all(chunk)?;
            checksum.update(chunk);
            size = size
                .checked_add(chunk.len() as u64)
                .ok_or(R7zError::Parse)?;
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            chunk = &buffer[..read];
        }

        let index = self.entries.len();
        self.entries.push(WriteEntry {
            raw_name: None,
            name: name.to_owned(),
            kind: EntryKind::File,
            meta,
            has_stream: true,
            data: None,
            folder_id: self.current_folder,
        });
        let checksum = checksum.finalize();
        let WriterMode::Streaming {
            current: Some(folder),
            ..
        } = &mut self.mode
        else {
            unreachable!()
        };
        folder.record_stream(index, size, checksum)?;
        if matches!(folder_plan, FolderPlan::Automatic) {
            self.finish_entry_folder_accounting(size)?;
        }
        Ok(())
    }

    fn append_builder_entry(
        &mut self,
        entry: WriteEntry,
        folder_size: u64,
    ) -> Result<(), R7zError> {
        let WriteEntry {
            name,
            kind,
            meta,
            has_stream,
            data,
            ..
        } = entry;
        match (has_stream, data) {
            (true, Some(data)) => self.append_streaming(
                &name,
                data.as_slice(),
                meta,
                FolderPlan::Preplanned { folder_size },
            ),
            (false, None) => self.append_empty_entry(ArchiveEntry { name, kind, meta }),
            _ => Err(R7zError::Parse),
        }
    }

    fn ensure_streaming_folder(&mut self, folder_plan: FolderPlan) -> Result<(), R7zError> {
        let (codec, has_current, has_completed) = match &self.mode {
            WriterMode::Streaming {
                codec,
                current,
                completed,
            } => (*codec, current.is_some(), !completed.is_empty()),
            _ => unreachable!(),
        };
        if has_current {
            return Ok(());
        }
        if !has_completed {
            let out = self.out.as_mut().ok_or(R7zError::Parse)?;
            out.seek(SeekFrom::Start(0))?;
            out.write_all(&[0u8; 32])?;
        }

        let out = self.out.take().ok_or(R7zError::Parse)?;
        let known_size = match folder_plan {
            FolderPlan::Automatic => None,
            FolderPlan::Preplanned { folder_size } => Some(folder_size),
        };
        let folder = StreamingFolder::encoded(codec, out, &self.options, known_size)?;
        let WriterMode::Streaming { current, .. } = &mut self.mode else {
            unreachable!()
        };
        *current = Some(Box::new(folder));
        Ok(())
    }

    fn seal_streaming_folder(&mut self) -> Result<(), R7zError> {
        let WriterMode::Streaming {
            current, completed, ..
        } = &mut self.mode
        else {
            unreachable!()
        };
        let Some(folder) = current.take() else {
            return Ok(());
        };
        let (output, folder) = (*folder).complete(&self.options)?;
        self.out = Some(output.inner);
        completed.push(folder);
        self.current_folder += 1;
        Ok(())
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
        raw_name: None,
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
    let max_temporary_storage_bytes = options.streaming.max_temporary_storage_bytes;
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
        } => build_streaming_with_temp_spool(
            entries,
            &mut out,
            options,
            memory_threshold,
            dir,
            max_temporary_storage_bytes,
        ),
        SpoolMode::TempFile { dir } => build_streaming_with_temp_spool(
            entries,
            &mut out,
            options,
            0,
            dir,
            max_temporary_storage_bytes,
        ),
    }
}

fn build_streaming_with_temp_spool<W, I, R>(
    entries: I,
    out: &mut W,
    options: ArchiveOptions,
    memory_threshold: u64,
    dir: Option<PathBuf>,
    max_temporary_storage_bytes: Option<u64>,
) -> Result<(), R7zError>
where
    W: Write,
    I: IntoIterator<Item = (String, R)>,
    R: Read,
{
    let mut spool = AutoSpool::new(memory_threshold, dir, max_temporary_storage_bytes)?;
    let result = (|| {
        build_streaming_with_options(entries, &mut spool, options)?;
        spool.seek(SeekFrom::Start(0))?;
        io::copy(&mut spool, out)?;
        out.flush()?;
        Ok(())
    })();
    let limit_exceeded = spool.limit_exceeded;
    let cleanup_result = spool.cleanup();

    if limit_exceeded {
        return Err(R7zError::ResourceLimitExceeded {
            resource: "temporary storage",
            limit: max_temporary_storage_bytes.expect("limit exceeded only when configured"),
        });
    }

    match (result, cleanup_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error.into()),
        (Ok(()), Ok(())) => Ok(()),
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
    max_temporary_storage_bytes: Option<u64>,
    limit_exceeded: bool,
    inner: AutoSpoolInner,
}

impl AutoSpool {
    fn new(
        memory_threshold: u64,
        dir: Option<PathBuf>,
        max_temporary_storage_bytes: Option<u64>,
    ) -> Result<Self, R7zError> {
        let inner = if memory_threshold == 0 {
            let (file, path) = create_temp_spool(dir.as_deref())?;
            AutoSpoolInner::TempFile { file, path }
        } else {
            AutoSpoolInner::Memory(Cursor::new(Vec::new()))
        };
        Ok(Self {
            memory_threshold,
            dir,
            max_temporary_storage_bytes,
            limit_exceeded: false,
            inner,
        })
    }

    fn maybe_roll_to_file(&mut self, write_len: usize) -> io::Result<()> {
        let AutoSpoolInner::Memory(cursor) = &self.inner else {
            return Ok(());
        };

        let write_len = u64::try_from(write_len).unwrap_or(u64::MAX);
        let projected_len = cursor
            .position()
            .saturating_add(write_len)
            .max(cursor.get_ref().len() as u64);
        if projected_len <= self.memory_threshold {
            return Ok(());
        }
        if self
            .max_temporary_storage_bytes
            .is_some_and(|limit| projected_len > limit)
        {
            self.limit_exceeded = true;
            return Err(io::Error::other("temporary storage limit exceeded"));
        }

        let current_pos = cursor.position();
        let (mut file, path) = create_temp_spool(self.dir.as_deref()).map_err(io::Error::other)?;
        let result = file
            .write_all(cursor.get_ref())
            .and_then(|()| file.seek(SeekFrom::Start(current_pos)).map(|_| ()));
        if let Err(error) = result {
            drop(file);
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        self.inner = AutoSpoolInner::TempFile { file, path };
        Ok(())
    }

    fn check_temporary_file_write(&mut self, write_len: usize) -> io::Result<()> {
        if self.max_temporary_storage_bytes.is_none() || write_len == 0 {
            return Ok(());
        }
        let AutoSpoolInner::TempFile { file, .. } = &mut self.inner else {
            return Ok(());
        };
        let write_len = u64::try_from(write_len).unwrap_or(u64::MAX);
        let projected_len = file
            .stream_position()?
            .saturating_add(write_len)
            .max(file.metadata()?.len());
        if self
            .max_temporary_storage_bytes
            .is_some_and(|limit| projected_len > limit)
        {
            self.limit_exceeded = true;
            return Err(io::Error::other("temporary storage limit exceeded"));
        }
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
        self.check_temporary_file_write(buf.len())?;
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
