mod encode;
mod header;
mod lzma2;
mod model;

use crate::aes::Aes256CbcEncryptWriter;
use crate::resources::{
    OpenVolumeBudget, OperationBudget, RetainedOutputBytes, SpoolBudget, TemporaryStorageBudget,
    TemporaryStorageBytes, VolumeCountBudget, WriterBudgets, WriterOperation,
};
use crate::{
    Archive, ArchiveEntryIndex, R7zError, RawEntryName, RawFolderBlock, RawFolderHandle,
    bcj::BcjX86Writer,
};
use header::{
    CoderSpec, encode_coder_info_aes_then, encode_coder_info_bcj_lzma2, encode_coder_info_copy,
    encode_coder_info_lzma, encode_coder_info_lzma2, encode_coder_info_ppmd,
};
use lzma_rust2::LzmaWriter;
use ppmd_rust::Ppmd7Encoder;
use std::{
    fs::{File, OpenOptions},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    num::NonZeroU64,
    path::{Path, PathBuf},
};

pub use model::{
    ArchiveEntry, ArchiveOptions, Codec, CompressionLevel, CompressionOptions, EncoderThreads,
    EncryptionOptions, EntryKind, EntryMeta, HeaderMode, LzmaAlgorithm, MatchFinder, SolidMode,
    SpoolMode, StreamingOptions, VolumeOptions,
};

use model::{WriteEntry, WriteEntryIndex, WriteEntryStream, WriteFolderId};

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
        /// Source entry represented by this raw substream.
        source_entry: ArchiveEntryIndex,
        /// Uncompressed entry size.
        size: u64,
        /// Entry checksum, when present.
        crc: Option<u32>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FolderPlan {
    Automatic,
    Preplanned { folder_size: u64 },
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
    fn new(
        out: W,
        prepared: &encode::PreparedArchiveOptions,
        budget: &mut WriterOperation,
    ) -> Result<Self, R7zError> {
        match prepared.encryption() {
            Some(encryption) => {
                let aes = encode::make_aes_material(encryption, budget)?;
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
    files: Vec<FolderFile>,
    unpack_size: u64,
}

struct FolderFile {
    entry_index: WriteEntryIndex,
    size: u64,
    crc: Option<u32>,
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
        out: W,
        known_size: Option<u64>,
        prepared: &encode::PreparedArchiveOptions,
        budget: &mut WriterOperation,
    ) -> Result<Self, R7zError> {
        prepared.validate_encoder_working_set()?;
        let options = prepared.archive();
        let settings = prepared.settings();
        let payload = PayloadWriter::new(out, prepared, budget)?;
        let encoder = match settings.codec {
            encode::PreparedCodec::Copy => StreamingEncoder::Copy(payload),
            encode::PreparedCodec::Lzma2(threads) => StreamingEncoder::Lzma2(
                lzma2::Encoder::new(payload, &options.compression, known_size, threads)?
                    .with_control(budget.monitor.control().cloned())?,
            ),
            encode::PreparedCodec::Lzma => {
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
            encode::PreparedCodec::Ppmd(ppmd) => {
                let encode::PpmdSettings { order, memory_size } = ppmd;
                let mut props = Vec::with_capacity(5);
                props.push(order);
                props.extend_from_slice(&memory_size.to_le_bytes());
                let writer = Box::new(
                    Ppmd7Encoder::new(payload, u32::from(order), memory_size).map_err(|_| {
                        R7zError::InvalidOptions(
                            "PPMd order or memory size is outside supported range",
                        )
                    })?,
                );
                StreamingEncoder::Ppmd { writer, props }
            }
            encode::PreparedCodec::Lzma2Bcj(threads) => {
                StreamingEncoder::BcjLzma2(BcjX86Writer::new(
                    lzma2::Encoder::new(payload, &options.compression, known_size, threads)?
                        .with_control(budget.monitor.control().cloned())?,
                ))
            }
        };
        Ok(Self {
            encoder,
            files: Vec::new(),
            unpack_size: 0,
        })
    }

    fn raw(
        mut writer: CountingWriter<W>,
        raw: RawFolderBlock,
        streams: &[StagedEntry],
        file_indices: Vec<WriteEntryIndex>,
        monitor: &mut crate::operation::OperationMonitor,
    ) -> Result<Self, R7zError> {
        monitor.check()?;
        if raw.packed_streams.len() != raw.pack_sizes.len() {
            return Err(R7zError::Parse);
        }
        for (packed, &size) in raw.packed_streams.iter().zip(&raw.pack_sizes) {
            if packed.len() as u64 != size {
                return Err(R7zError::Parse);
            }
            for chunk in packed.chunks(monitor.buffer_size(packed.len().max(1))) {
                monitor.check()?;
                writer.write_all(chunk)?;
                monitor.advance(chunk.len())?;
            }
        }
        let files = file_indices
            .into_iter()
            .map(|entry_index| {
                let stream = streams.get(entry_index.index()).ok_or(R7zError::Parse)?;
                Ok(FolderFile {
                    entry_index,
                    size: staged_stream_size(stream),
                    crc: staged_stream_crc(stream)?,
                })
            })
            .collect::<Result<_, R7zError>>()?;
        Ok(Self {
            encoder: StreamingEncoder::Raw {
                writer,
                pack_sizes: raw.pack_sizes,
                coder_info: raw.folder_info,
                coder_unpack_sizes: raw.coder_unpack_sizes,
                folder_crc: raw.folder_crc,
            },
            files,
            unpack_size: 0,
        })
    }

    fn record_stream(
        &mut self,
        entry_index: WriteEntryIndex,
        size: u64,
        checksum: u32,
    ) -> Result<(), R7zError> {
        match &mut self.encoder {
            StreamingEncoder::Raw { .. } => Err(R7zError::Parse),
            StreamingEncoder::Copy(_)
            | StreamingEncoder::Lzma2(_)
            | StreamingEncoder::Lzma { .. }
            | StreamingEncoder::Ppmd { .. }
            | StreamingEncoder::BcjLzma2(_) => {
                let unpack_size = self.unpack_size.checked_add(size).ok_or(R7zError::Parse)?;
                self.files.push(FolderFile {
                    entry_index,
                    size,
                    crc: Some(checksum),
                });
                self.unpack_size = unpack_size;
                Ok(())
            }
        }
    }

    fn complete(
        self,
        prepared: &encode::PreparedArchiveOptions,
    ) -> Result<(CountingWriter<W>, model::CompletedFolder), R7zError> {
        let Self {
            encoder,
            files,
            unpack_size,
        } = self;
        let (file_indices, file_sizes, file_crcs) = files.into_iter().fold(
            (Vec::new(), Vec::new(), Vec::new()),
            |(mut indices, mut sizes, mut crcs), file| {
                indices.push(file.entry_index);
                sizes.push(file.size);
                crcs.push(file.crc);
                (indices, sizes, crcs)
            },
        );
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
            StreamingEncoder::Copy(writer) => (
                writer,
                encode_coder_info_copy(),
                vec![unpack_size],
                smallvec::smallvec![CoderSpec::Copy],
            ),
            StreamingEncoder::Lzma2(writer) => {
                let property = encode::lzma2_property_byte(&prepared.archive().compression)?;
                (
                    writer.finish()?,
                    encode_coder_info_lzma2(property),
                    vec![unpack_size],
                    smallvec::smallvec![CoderSpec::Lzma2(property)],
                )
            }
            StreamingEncoder::Lzma { writer, props } => (
                writer.finish()?,
                encode_coder_info_lzma(&props),
                vec![unpack_size],
                smallvec::smallvec![CoderSpec::Lzma(props)],
            ),
            StreamingEncoder::Ppmd { writer, props } => (
                (*writer).finish(false)?,
                encode_coder_info_ppmd(&props),
                vec![unpack_size],
                smallvec::smallvec![CoderSpec::Ppmd(props)],
            ),
            StreamingEncoder::BcjLzma2(writer) => {
                let writer = writer.finish()?.finish()?;
                let property = encode::lzma2_property_byte(&prepared.archive().compression)?;
                (
                    writer,
                    encode_coder_info_bcj_lzma2(property),
                    vec![unpack_size, unpack_size],
                    smallvec::smallvec![CoderSpec::Lzma2(property), CoderSpec::Bcj],
                )
            }
        };
        let specs: smallvec::SmallVec<[CoderSpec; 2]> = specs;
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

enum WriterState<W: Write> {
    Ready {
        output: W,
        completed: Vec<model::CompletedFolder>,
    },
    Active {
        folder: Box<StreamingFolder<W>>,
        completed: Vec<model::CompletedFolder>,
        progress: FolderProgress,
    },
    Failed,
}

#[derive(Clone, Copy, Default)]
struct FolderProgress {
    files: u64,
    bytes: u64,
}

impl FolderProgress {
    fn record(&mut self, size: u64) -> Result<(), R7zError> {
        self.files = self.files.checked_add(1).ok_or(R7zError::Parse)?;
        self.bytes = self.bytes.checked_add(size).ok_or(R7zError::Parse)?;
        Ok(())
    }

    fn would_exceed(&self, solid: &SolidMode, size: u64) -> Result<bool, R7zError> {
        Ok(match solid {
            SolidMode::Solid => false,
            SolidMode::NonSolid => self.files > 0,
            SolidMode::Limit {
                max_files,
                max_bytes,
            } => {
                let next_files = self.files.checked_add(1).ok_or(R7zError::Parse)?;
                let next_bytes = self.bytes.checked_add(size).ok_or(R7zError::Parse)?;
                self.files > 0
                    && (max_files.is_some_and(|limit| next_files > limit.get())
                        || max_bytes.is_some_and(|limit| next_bytes > limit.get()))
            }
        })
    }

    fn reached_limit(&self, solid: &SolidMode) -> bool {
        match solid {
            SolidMode::Solid => false,
            SolidMode::NonSolid => self.files > 0,
            SolidMode::Limit {
                max_files,
                max_bytes,
            } => {
                max_files.is_some_and(|limit| self.files >= limit.get())
                    || max_bytes.is_some_and(|limit| self.bytes >= limit.get())
            }
        }
    }
}

impl<W: Write> WriterState<W> {
    fn active_folder_mut(&mut self) -> Result<&mut StreamingFolder<W>, R7zError> {
        match self {
            Self::Ready { .. } => Err(R7zError::Parse),
            Self::Active { folder, .. } => Ok(folder),
            Self::Failed => Err(writer_failed()),
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
                stream: WriteEntryStream::Empty,
                folder_id: WriteFolderId::FIRST,
            });
        } else {
            self.entries.push(WriteEntry {
                raw_name: None,
                name: name.to_string(),
                kind: EntryKind::File,
                meta: EntryMeta::default(),
                stream: WriteEntryStream::Buffered(data.to_vec()),
                folder_id: WriteFolderId::FIRST,
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
            stream: if data.is_empty() {
                WriteEntryStream::Empty
            } else {
                WriteEntryStream::Buffered(data.to_vec())
            },
            folder_id: WriteFolderId::FIRST,
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
            stream: WriteEntryStream::Buffered(target.as_bytes().to_vec()),
            folder_id: WriteFolderId::FIRST,
        });
        self
    }

    /// Add entry metadata and optional buffered contents.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::InvalidOptions`] if a non-file entry has stream data.
    pub fn add_entry(mut self, entry: ArchiveEntry, data: Option<&[u8]>) -> Result<Self, R7zError> {
        self.entries.push(write_entry_from_archive_entry(
            entry,
            data.map(<[u8]>::to_vec),
            WriteFolderId::FIRST,
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
            stream: WriteEntryStream::Empty,
            folder_id: WriteFolderId::FIRST,
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
            stream: WriteEntryStream::Empty,
            folder_id: WriteFolderId::FIRST,
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
            stream: WriteEntryStream::Empty,
            folder_id: WriteFolderId::FIRST,
        });
        self
    }

    /// Encode the buffered entries into an archive.
    ///
    /// # Errors
    ///
    /// Returns invalid-option, encoding, encryption, or resource-limit errors.
    pub fn build(self) -> Result<Vec<u8>, R7zError> {
        let mut options = self.options;
        lzma2::set_default_budget(&mut options);
        if matches!(
            options.codec,
            Codec::Copy | Codec::Lzma | Codec::Lzma2 | Codec::Ppmd | Codec::Lzma2Bcj
        ) && self.entries.iter().any(|entry| entry.stream.has_stream())
        {
            let entries = entries_with_solid_folders(self.entries, &options.compression.solid)?;
            let mut folder_sizes = std::collections::BTreeMap::<WriteFolderId, u64>::new();
            for entry in &entries {
                if entry.stream.has_stream() {
                    let size = entry
                        .stream
                        .buffered_data()
                        .map(|data| data.len() as u64)
                        .ok_or(R7zError::Parse)?;
                    let folder_size = folder_sizes.entry(entry.folder_id).or_default();
                    *folder_size = folder_size.checked_add(size).ok_or(R7zError::Parse)?;
                }
            }
            let mut writer = ArchiveWriter::new(Cursor::new(Vec::new()), options)?.start();
            for entry in entries {
                let folder_size = folder_sizes.get(&entry.folder_id).copied().unwrap_or(0);
                match entry.folder_id.cmp(&writer.next_folder_id()?) {
                    std::cmp::Ordering::Less => return Err(R7zError::Parse),
                    std::cmp::Ordering::Equal => {}
                    std::cmp::Ordering::Greater => {
                        writer.new_folder()?;
                        if entry.folder_id != writer.next_folder_id()? {
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
/// Every raw folder and entry handle must come from `source`. Each copied folder
/// must include every source substream once, in order, and its output entries must
/// stay together. Invalid layouts are rejected before any output is written.
///
/// # Errors
///
/// Returns [`R7zError::ArchiveMismatch`] for handles from another archive,
/// [`R7zError::InvalidRawFolderLayout`] when copied entries do not match the
/// source folder layout, or an encoding or I/O error while writing.
pub fn write_archive_update<W: Write + Seek>(
    source: &Archive,
    out: W,
    entries: Vec<PreservedArchiveEntry>,
    raw_folders: Vec<RawFolderBlock>,
    options: &ArchiveOptions,
) -> Result<W, R7zError> {
    validate_raw_folder_update(source, &entries, &raw_folders)?;
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

fn validate_raw_folder_update(
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

    let listing = source.listing(None)?;
    let mut raw_entries = std::collections::BTreeMap::<
        crate::archive::FolderIndex,
        Vec<crate::archive::ArchiveEntryIndex>,
    >::new();
    for preserved in entries {
        let PreservedEntryStream::Raw {
            folder,
            source_entry,
            size,
            crc,
        } = &preserved.stream
        else {
            continue;
        };
        let source_entry_index = *source_entry;
        let folder_index = folder.index();
        let source_info = listing
            .entries
            .get(source_entry_index.get())
            .filter(|source_info| source_info.index == source_entry_index)
            .ok_or(R7zError::InvalidRawFolderLayout)?;
        if !folder.belongs_to(source) || !raw_folders.iter().any(|raw| raw.handle() == *folder) {
            return Err(R7zError::ArchiveMismatch);
        }
        if source_info.block != Some(folder_index)
            || source_info.size != Some(*size)
            || source_info.crc != *crc
        {
            return Err(R7zError::InvalidRawFolderLayout);
        }
        raw_entries
            .entry(folder_index)
            .or_default()
            .push(source_entry_index);
    }

    for (folder_index, entries) in raw_entries {
        let source_entries = listing
            .entries
            .iter()
            .filter(|source_entry| source_entry.block == Some(folder_index))
            .map(|source_entry| source_entry.index)
            .collect::<Vec<_>>();
        if entries.into_iter().ne(source_entries) {
            return Err(R7zError::InvalidRawFolderLayout);
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
    let prepared = encode::prepare_archive_options(options)?;
    let budget = OperationBudget::new(prepared.archive().streaming.resource_limits)
        .with_control(prepared.archive().streaming.control.clone());
    let writer_budgets = budget.into_writer_budgets();
    let mut operation = writer_budgets.operation;
    operation.monitor.check()?;
    let mut retained_output_budget = writer_budgets.spool.retained_output;
    for entry in &entries {
        if let PreservedEntryStream::Data(data) = &entry.stream {
            retained_output_budget.reserve(RetainedOutputBytes::new(
                u64::try_from(data.len()).unwrap_or(u64::MAX),
            ))?;
        }
    }
    let StagedPreserved {
        entries,
        folder_order,
        mut raw_by_id,
    } = stage_preserved_entries(entries, raw_folders, prepared.archive())?;
    let mut out = out;
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&[0u8; 32])?;

    let mut completed = Vec::with_capacity(folder_order.len());
    for folder_id in folder_order {
        let file_indices = entries
            .iter()
            .enumerate()
            .filter_map(|(idx, entry)| {
                (entry.folder_id() == Some(folder_id)).then_some(WriteEntryIndex::from_index(idx))
            })
            .collect::<Vec<_>>();
        if let Some(raw) = raw_by_id.remove(&folder_id) {
            let folder = {
                let writer = CountingWriter {
                    inner: &mut out,
                    count: 0,
                };
                StreamingFolder::raw(writer, raw, &entries, file_indices, &mut operation.monitor)?
            };
            let (_writer, folder) = folder.complete(&prepared)?;
            completed.push(folder);
        } else {
            completed.push(write_encoded_folder_streaming(
                &mut out,
                &entries,
                file_indices,
                &prepared,
                &mut operation,
            )?);
        }
    }

    let write_entries = entries
        .into_iter()
        .map(StagedEntry::into_write_entry)
        .collect::<Vec<_>>();
    encode::finish_streamed_archive(out, &write_entries, &completed, &prepared, &mut operation)
}

enum StagedStream {
    None,
    Folder {
        id: WriteFolderId,
        data: StagedFolderData,
    },
}

enum StagedFolderData {
    Data(Vec<u8>),
    Path { path: PathBuf, size: u64 },
    Raw { size: u64, crc: Option<u32> },
}

struct StagedEntry {
    header: StagedHeaderEntry,
    stream: StagedStream,
}

struct StagedHeaderEntry {
    name: String,
    raw_name: Option<crate::RawEntryName>,
    kind: EntryKind,
    meta: EntryMeta,
}

impl StagedEntry {
    fn folder_id(&self) -> Option<WriteFolderId> {
        match self.stream {
            StagedStream::None => None,
            StagedStream::Folder { id, .. } => Some(id),
        }
    }

    fn into_write_entry(self) -> WriteEntry {
        let folder_id = self.folder_id().unwrap_or(WriteFolderId::FIRST);
        let has_stream = !matches!(self.stream, StagedStream::None);
        WriteEntry {
            name: self.header.name,
            raw_name: self.header.raw_name,
            kind: self.header.kind,
            meta: self.header.meta,
            stream: if has_stream {
                WriteEntryStream::Streaming
            } else {
                WriteEntryStream::Empty
            },
            folder_id,
        }
    }
}

enum StagedDataSource<'a> {
    Bytes(&'a [u8]),
    Path { path: &'a Path, size: u64 },
}

struct StagedDataEntry<'a> {
    index: WriteEntryIndex,
    source: StagedDataSource<'a>,
}

fn staged_folder_size(entries: &[StagedDataEntry<'_>]) -> Result<u64, R7zError> {
    entries.iter().try_fold(0u64, |total, entry| {
        let size = match &entry.source {
            StagedDataSource::Bytes(data) => data.len() as u64,
            StagedDataSource::Path { size, .. } => *size,
        };
        total.checked_add(size).ok_or(R7zError::Parse)
    })
}

struct StagedPreserved {
    entries: Vec<StagedEntry>,
    folder_order: Vec<WriteFolderId>,
    raw_by_id: std::collections::BTreeMap<WriteFolderId, RawFolderBlock>,
}

fn stage_preserved_entries(
    entries: Vec<PreservedArchiveEntry>,
    raw_folders: Vec<RawFolderBlock>,
    options: &ArchiveOptions,
) -> Result<StagedPreserved, R7zError> {
    let raw_by_id = raw_folders
        .into_iter()
        .map(|folder| {
            (
                WriteFolderId::from_index(folder.folder_index().get()),
                folder,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let max_raw_folder = raw_by_id
        .keys()
        .copied()
        .max()
        .unwrap_or(WriteFolderId::FIRST);
    let next_data_folder = max_raw_folder.next().ok_or(R7zError::Parse)?;
    let mut data_folders = StagedDataFolders::new(next_data_folder);

    let mut staged_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        let PreservedArchiveEntry {
            name,
            raw_name,
            kind,
            meta,
            stream,
        } = entry;
        let staged = match stream {
            PreservedEntryStream::None => StagedStream::None,
            PreservedEntryStream::Raw {
                folder, size, crc, ..
            } => {
                let folder_id = WriteFolderId::from_index(folder.index().get());
                if raw_by_id
                    .get(&folder_id)
                    .is_none_or(|raw| raw.handle() != folder)
                {
                    return Err(R7zError::ArchiveMismatch);
                }
                data_folders.break_folder();
                StagedStream::Folder {
                    id: folder_id,
                    data: StagedFolderData::Raw { size, crc },
                }
            }
            PreservedEntryStream::Data(data) => {
                let size = data.len() as u64;
                let folder_id = data_folders.assign(&options.compression.solid, size)?;
                StagedStream::Folder {
                    id: folder_id,
                    data: StagedFolderData::Data(data),
                }
            }
            PreservedEntryStream::Path { path, size } => {
                let folder_id = data_folders.assign(&options.compression.solid, size)?;
                StagedStream::Folder {
                    id: folder_id,
                    data: StagedFolderData::Path { path, size },
                }
            }
        };
        staged_entries.push(StagedEntry {
            header: StagedHeaderEntry {
                name,
                raw_name,
                kind,
                meta,
            },
            stream: staged,
        });
    }

    let mut folder_order = Vec::new();
    for entry in &staged_entries {
        if let Some(folder_id) = entry.folder_id()
            && !folder_order.contains(&folder_id)
        {
            folder_order.push(folder_id);
        }
    }

    let mut completed_folders = std::collections::BTreeSet::new();
    let mut current_folder = None;
    for folder_id in staged_entries.iter().filter_map(StagedEntry::folder_id) {
        if current_folder == Some(folder_id) {
            continue;
        }
        if !completed_folders.insert(folder_id) {
            return Err(R7zError::InvalidRawFolderLayout);
        }
        current_folder = Some(folder_id);
    }

    Ok(StagedPreserved {
        entries: staged_entries,
        folder_order,
        raw_by_id,
    })
}

fn write_encoded_folder_streaming<W: Write>(
    out: &mut W,
    streams: &[StagedEntry],
    file_indices: Vec<WriteEntryIndex>,
    prepared: &encode::PreparedArchiveOptions,
    budget: &mut WriterOperation,
) -> Result<model::CompletedFolder, R7zError> {
    let data_entries = file_indices
        .into_iter()
        .map(|index| {
            let source = match &streams.get(index.index()).ok_or(R7zError::Parse)?.stream {
                StagedStream::Folder {
                    data: StagedFolderData::Data(data),
                    ..
                } => StagedDataSource::Bytes(data),
                StagedStream::Folder {
                    data: StagedFolderData::Path { path, size },
                    ..
                } => StagedDataSource::Path { path, size: *size },
                StagedStream::None
                | StagedStream::Folder {
                    data: StagedFolderData::Raw { .. },
                    ..
                } => return Err(R7zError::Parse),
            };
            Ok(StagedDataEntry { index, source })
        })
        .collect::<Result<Vec<_>, R7zError>>()?;
    let known_size = staged_folder_size(&data_entries)?;
    let mut folder = StreamingFolder::encoded(out, Some(known_size), prepared, budget)?;
    for entry in data_entries {
        let (size, checksum) =
            write_staged_stream_to(&entry.source, &mut folder, &mut budget.monitor)?;
        folder.record_stream(entry.index, size, checksum)?;
    }
    let (_out, folder) = folder.complete(prepared)?;
    Ok(folder)
}

fn write_staged_stream_to<W: Write>(
    source: &StagedDataSource<'_>,
    out: &mut W,
    monitor: &mut crate::operation::OperationMonitor,
) -> Result<(u64, u32), R7zError> {
    match source {
        StagedDataSource::Bytes(data) => write_staged_reader(*data, out, monitor),
        StagedDataSource::Path { path, .. } => write_staged_reader(File::open(path)?, out, monitor),
    }
}

fn write_staged_reader(
    mut reader: impl Read,
    out: &mut impl Write,
    monitor: &mut crate::operation::OperationMonitor,
) -> Result<(u64, u32), R7zError> {
    let mut hasher = crc32fast::Hasher::new();
    let mut buf = vec![0u8; monitor.buffer_size(1024 * 1024)];
    let size = std::iter::from_fn(|| match monitor.read(&mut reader, &mut buf) {
        Ok(0) => None,
        Ok(count) => Some(
            out.write_all(&buf[..count])
                .map(|()| {
                    hasher.update(&buf[..count]);
                    count as u64
                })
                .map_err(R7zError::from),
        ),
        Err(error) => Some(Err(error)),
    })
    .try_fold(0u64, |total, count| {
        total.checked_add(count?).ok_or(R7zError::Parse)
    })?;
    Ok((size, hasher.finalize()))
}

fn staged_stream_size(entry: &StagedEntry) -> u64 {
    match &entry.stream {
        StagedStream::None => 0,
        StagedStream::Folder { data, .. } => match data {
            StagedFolderData::Data(data) => data.len() as u64,
            StagedFolderData::Path { size, .. } | StagedFolderData::Raw { size, .. } => *size,
        },
    }
}

fn staged_stream_crc(entry: &StagedEntry) -> Result<Option<u32>, R7zError> {
    match &entry.stream {
        StagedStream::None => Ok(None),
        StagedStream::Folder { data, .. } => match data {
            StagedFolderData::Raw { crc, .. } => Ok(*crc),
            StagedFolderData::Data(data) => Ok(Some(crc32fast::hash(data))),
            StagedFolderData::Path { path, .. } => {
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
        },
    }
}

struct StagedDataFolders {
    next: WriteFolderId,
    current: Option<StagedDataFolder>,
}

struct StagedDataFolder {
    id: WriteFolderId,
    progress: FolderProgress,
}

impl StagedDataFolders {
    fn new(next: WriteFolderId) -> Self {
        Self {
            next,
            current: None,
        }
    }

    fn assign(&mut self, solid: &SolidMode, size: u64) -> Result<WriteFolderId, R7zError> {
        let needs_new = self
            .current
            .as_ref()
            .map(|folder| folder.progress.would_exceed(solid, size))
            .transpose()?
            .unwrap_or(true);
        if needs_new {
            let id = self.next;
            self.next = self.next.next().ok_or(R7zError::Parse)?;
            self.current = Some(StagedDataFolder {
                id,
                progress: FolderProgress::default(),
            });
        }

        let folder = self.current.as_mut().ok_or(R7zError::Parse)?;
        folder.progress.record(size)?;
        Ok(folder.id)
    }

    fn break_folder(&mut self) {
        self.current = None;
    }
}

pub struct ArchiveWriter<W: Write + Seek, const STARTED: bool = false> {
    state: WriterState<W>,
    entries: Vec<WriteEntry>,
    prepared: encode::PreparedArchiveOptions,
    budget: WriterOperation,
}

impl<W: Write + Seek> ArchiveWriter<W, false> {
    /// Prepare a streaming archive writer with the supplied options.
    ///
    /// # Errors
    ///
    /// Returns an error if compression, encryption, or resource-limit settings are invalid.
    pub fn new(out: W, options: ArchiveOptions) -> Result<Self, R7zError> {
        let mut options = options;
        lzma2::set_default_budget(&mut options);
        let prepared = encode::prepare_archive_options(options)?;
        let budget = OperationBudget::new(prepared.archive().streaming.resource_limits)
            .with_control(prepared.archive().streaming.control.clone());
        let operation = budget.into_writer_budgets().operation;
        Ok(Self::new_prepared(out, prepared, operation))
    }

    fn new_prepared(
        out: W,
        prepared: encode::PreparedArchiveOptions,
        operation: WriterOperation,
    ) -> Self {
        Self {
            state: WriterState::Ready {
                output: out,
                completed: Vec::new(),
            },
            entries: Vec::new(),
            prepared,
            budget: operation,
        }
    }

    /// Prepare a streaming archive writer with default options.
    ///
    /// # Errors
    ///
    /// Returns an error if the default encoder settings cannot be prepared.
    pub fn new_default(out: W) -> Result<Self, R7zError> {
        Self::new(out, ArchiveOptions::default())
    }

    /// Lock the archive options and enable streaming entry methods.
    #[must_use]
    pub fn start(self) -> ArchiveWriter<W, true> {
        ArchiveWriter {
            state: self.state,
            entries: self.entries,
            prepared: self.prepared,
            budget: self.budget,
        }
    }

    /// Select the codec before starting the archive.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::InvalidOptions`] if the codec conflicts with the current settings.
    pub fn compression(mut self, codec: Codec) -> Result<Self, R7zError> {
        self.set_compression(codec)?;
        Ok(self)
    }

    /// Update the codec before starting the archive.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::InvalidOptions`] if the codec conflicts with the current settings.
    pub fn set_compression(&mut self, codec: Codec) -> Result<(), R7zError> {
        let mut options = self.prepared.archive().clone();
        options.codec = codec;
        lzma2::set_default_budget(&mut options);
        self.prepared = encode::prepare_archive_options(options)?;
        Ok(())
    }
}

impl<W: Write + Seek, const STARTED: bool> ArchiveWriter<W, STARTED> {
    /// Append entry metadata without a data stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer has already failed.
    pub fn append_empty_entry(&mut self, entry: ArchiveEntry) -> Result<(), R7zError> {
        self.budget.monitor.check()?;
        let folder_id = self.next_folder_id()?;
        self.entries.push(WriteEntry {
            raw_name: None,
            name: entry.name,
            kind: entry.kind,
            meta: entry.meta,
            stream: WriteEntryStream::Empty,
            folder_id,
        });
        Ok(())
    }

    fn next_folder_id(&self) -> Result<WriteFolderId, R7zError> {
        match &self.state {
            WriterState::Ready { completed, .. } | WriterState::Active { completed, .. } => {
                Ok(WriteFolderId::from_index(completed.len()))
            }
            WriterState::Failed => Err(writer_failed()),
        }
    }
}

impl<W: Write + Seek> ArchiveWriter<W, true> {
    /// Read and encode a file into the current archive folder.
    ///
    /// # Errors
    ///
    /// Returns prior writer failures, input/output I/O errors, encoding errors,
    /// or errors from enforcing resource limits.
    pub fn append_file(
        &mut self,
        name: &str,
        reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        let result = match &self.state {
            WriterState::Ready { .. } | WriterState::Active { .. } => {
                self.append_streaming(name, reader, meta, FolderPlan::Automatic)
            }
            WriterState::Failed => Err(writer_failed()),
        };
        if result.is_err() {
            self.state = WriterState::Failed;
        }
        result
    }

    /// Append a symlink whose data stream contains its target.
    ///
    /// # Errors
    ///
    /// Returns prior writer failures, output or encoding errors, or resource-limit errors.
    pub fn append_symlink(
        &mut self,
        name: &str,
        target: &str,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        self.append_file(name, target.as_bytes(), meta.with_symlink_default())
    }

    /// Append a zero-length file.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer has already failed.
    pub fn append_empty_file(&mut self, name: &str, meta: EntryMeta) -> Result<(), R7zError> {
        self.append_empty_entry(ArchiveEntry {
            name: name.to_owned(),
            kind: EntryKind::File,
            meta,
        })
    }

    /// Append a directory entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer has already failed.
    pub fn append_directory(&mut self, name: &str, meta: EntryMeta) -> Result<(), R7zError> {
        self.append_empty_entry(ArchiveEntry {
            name: name.to_owned(),
            kind: EntryKind::Directory,
            meta,
        })
    }

    /// Append an anti-item entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer has already failed.
    pub fn append_anti_item(&mut self, name: &str, meta: EntryMeta) -> Result<(), R7zError> {
        self.append_empty_entry(ArchiveEntry {
            name: name.to_owned(),
            kind: EntryKind::Anti,
            meta,
        })
    }
}

impl<W: Write + Seek> ArchiveWriter<W, true> {
    /// Append a file with default metadata.
    ///
    /// # Errors
    ///
    /// Returns prior writer failures, input/output I/O errors, encoding errors,
    /// or errors from enforcing resource limits.
    pub fn append(&mut self, name: &str, reader: impl Read) -> Result<(), R7zError> {
        self.append_file(name, reader, EntryMeta::default())
    }

    /// Append a file with the supplied metadata.
    ///
    /// # Errors
    ///
    /// Returns prior writer failures, input/output I/O errors, encoding errors,
    /// or errors from enforcing resource limits.
    pub fn append_entry(
        &mut self,
        name: &str,
        reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        self.append_file(name, reader, meta)
    }

    /// Append entry metadata and encode its contents when it has a stream.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::InvalidOptions`] if the entry is not a file, or
    /// writer, input/output, encoding, or resource-limit errors.
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

    /// Finish the current folder and begin a new one on the next file.
    ///
    /// # Errors
    ///
    /// Returns cancellation, a prior writer failure, or an encoding/output error
    /// while finishing the current folder.
    pub fn new_folder(&mut self) -> Result<(), R7zError> {
        self.seal_streaming_folder()
    }

    fn finish_entry_folder_accounting(&mut self, size: u64) -> Result<(), R7zError> {
        let progress = match &mut self.state {
            WriterState::Ready { .. } => return Err(R7zError::Parse),
            WriterState::Active { progress, .. } => {
                progress.record(size)?;
                *progress
            }
            WriterState::Failed => return Err(writer_failed()),
        };
        if progress.reached_limit(&self.prepared.archive().compression.solid) {
            self.new_folder()
        } else {
            Ok(())
        }
    }

    /// Finish the current folder, write the headers, and return the output writer.
    ///
    /// # Errors
    ///
    /// Returns a prior writer failure, or an encoding, output, or resource-limit
    /// error while finishing folders and writing the header.
    pub fn finish(mut self) -> Result<W, R7zError> {
        self.budget.monitor.check()?;
        if matches!(self.state, WriterState::Failed) {
            return Err(writer_failed());
        }
        if !self.entries.iter().any(|entry| entry.stream.has_stream()) {
            return self.finish_buffered();
        }
        self.seal_streaming_folder()?;
        let WriterState::Ready {
            output: out,
            completed: folders,
        } = std::mem::replace(&mut self.state, WriterState::Failed)
        else {
            return Err(writer_failed());
        };
        encode::finish_streamed_archive(
            out,
            &self.entries,
            &folders,
            &self.prepared,
            &mut self.budget,
        )
    }

    fn finish_buffered(mut self) -> Result<W, R7zError> {
        let bytes =
            encode::build_archive_with_settings(&self.entries, &self.prepared, &mut self.budget)?;
        let WriterState::Ready {
            output: mut out, ..
        } = std::mem::replace(&mut self.state, WriterState::Failed)
        else {
            return Err(R7zError::Parse);
        };
        out.seek(SeekFrom::Start(0))?;
        out.write_all(&bytes)?;
        out.flush()?;
        self.budget.monitor.check()?;
        Ok(out)
    }

    fn append_streaming(
        &mut self,
        name: &str,
        mut reader: impl Read,
        meta: EntryMeta,
        folder_plan: FolderPlan,
    ) -> Result<(), R7zError> {
        let mut buffer = vec![0u8; self.prepared.archive().streaming.buffer_size];
        let first = self.budget.monitor.read(&mut reader, &mut buffer)?;
        if first == 0 {
            if matches!(folder_plan, FolderPlan::Preplanned { .. }) {
                self.ensure_streaming_folder(folder_plan)?;
                let index = self.entries.len();
                let folder_id = self.next_folder_id()?;
                self.entries.push(WriteEntry {
                    raw_name: None,
                    name: name.to_owned(),
                    kind: EntryKind::File,
                    meta,
                    stream: WriteEntryStream::Streaming,
                    folder_id,
                });
                self.state.active_folder_mut()?.record_stream(
                    WriteEntryIndex::from_index(index),
                    0,
                    crc32fast::hash(&[]),
                )?;
                return Ok(());
            }
            let folder_id = self.next_folder_id()?;
            self.entries.push(WriteEntry {
                raw_name: None,
                name: name.to_owned(),
                kind: EntryKind::File,
                meta,
                stream: WriteEntryStream::Empty,
                folder_id,
            });
            return Ok(());
        }

        self.ensure_streaming_folder(folder_plan)?;
        let mut checksum = crc32fast::Hasher::new();
        let mut size = 0u64;
        let mut chunk = &buffer[..first];
        loop {
            let folder = self.state.active_folder_mut()?;
            folder.write_all(chunk)?;
            checksum.update(chunk);
            size = size
                .checked_add(chunk.len() as u64)
                .ok_or(R7zError::Parse)?;
            let read = self.budget.monitor.read(&mut reader, &mut buffer)?;
            if read == 0 {
                break;
            }
            chunk = &buffer[..read];
        }

        let index = self.entries.len();
        let folder_id = self.next_folder_id()?;
        self.entries.push(WriteEntry {
            raw_name: None,
            name: name.to_owned(),
            kind: EntryKind::File,
            meta,
            stream: WriteEntryStream::Streaming,
            folder_id,
        });
        let checksum = checksum.finalize();
        self.state.active_folder_mut()?.record_stream(
            WriteEntryIndex::from_index(index),
            size,
            checksum,
        )?;
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
            stream,
            ..
        } = entry;
        match stream {
            WriteEntryStream::Buffered(data) => self.append_streaming(
                &name,
                data.as_slice(),
                meta,
                FolderPlan::Preplanned { folder_size },
            ),
            WriteEntryStream::Empty => self.append_empty_entry(ArchiveEntry { name, kind, meta }),
            WriteEntryStream::Streaming => Err(R7zError::Parse),
        }
    }

    fn ensure_streaming_folder(&mut self, folder_plan: FolderPlan) -> Result<(), R7zError> {
        let (mut output, completed) = match std::mem::replace(&mut self.state, WriterState::Failed)
        {
            WriterState::Ready { output, completed } => (output, completed),
            WriterState::Active {
                folder,
                completed,
                progress,
            } => {
                self.state = WriterState::Active {
                    folder,
                    completed,
                    progress,
                };
                return Ok(());
            }
            WriterState::Failed => return Err(writer_failed()),
        };
        if completed.is_empty() {
            output.seek(SeekFrom::Start(0))?;
            output.write_all(&[0u8; 32])?;
        }
        let known_size = match folder_plan {
            FolderPlan::Automatic => None,
            FolderPlan::Preplanned { folder_size } => Some(folder_size),
        };
        let folder =
            StreamingFolder::encoded(output, known_size, &self.prepared, &mut self.budget)?;
        self.state = WriterState::Active {
            folder: Box::new(folder),
            completed,
            progress: FolderProgress::default(),
        };
        Ok(())
    }

    fn seal_streaming_folder(&mut self) -> Result<(), R7zError> {
        let state = std::mem::replace(&mut self.state, WriterState::Failed);
        self.budget.monitor.check()?;
        let (output, completed) = match state {
            WriterState::Ready { output, completed } => (output, completed),
            WriterState::Active {
                folder,
                mut completed,
                ..
            } => {
                let (output, folder) = (*folder).complete(&self.prepared)?;
                completed.push(folder);
                (output.inner, completed)
            }
            WriterState::Failed => return Err(writer_failed()),
        };
        self.budget.monitor.check()?;
        self.state = WriterState::Ready { output, completed };
        Ok(())
    }
}

fn entries_with_solid_folders(
    mut entries: Vec<WriteEntry>,
    solid: &SolidMode,
) -> Result<Vec<WriteEntry>, R7zError> {
    let mut folder_id = WriteFolderId::FIRST;
    let mut progress = FolderProgress::default();

    for entry in &mut entries {
        if !entry.stream.has_stream() {
            if matches!(solid, SolidMode::NonSolid) && progress.files > 0 {
                folder_id = folder_id.next().ok_or(R7zError::Parse)?;
                progress = FolderProgress::default();
            }
            entry.folder_id = folder_id;
            continue;
        }
        let size = entry
            .stream
            .buffered_data()
            .map(|data| data.len() as u64)
            .ok_or(R7zError::Parse)?;

        if progress.would_exceed(solid, size)? {
            folder_id = folder_id.next().ok_or(R7zError::Parse)?;
            progress = FolderProgress::default();
        }

        entry.folder_id = folder_id;
        progress.record(size)?;
    }

    Ok(entries)
}

fn write_entry_from_archive_entry(
    entry: ArchiveEntry,
    data: Option<Vec<u8>>,
    folder_id: WriteFolderId,
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
        stream: if has_stream {
            WriteEntryStream::Buffered(data.ok_or(R7zError::Parse)?)
        } else {
            WriteEntryStream::Empty
        },
        folder_id,
    })
}

/// Write an archive from file readers using default options.
///
/// # Errors
///
/// Returns input/output I/O, encoding, encryption, or resource-limit errors.
pub fn build_streaming<W, I, R>(entries: I, out: W) -> Result<(), R7zError>
where
    W: Write + Seek,
    I: IntoIterator<Item = (String, R)>,
    R: Read,
{
    build_streaming_with_options(entries, out, ArchiveOptions::default())
}

/// Write an archive from file readers with the supplied options.
///
/// # Errors
///
/// Returns invalid-option, input/output I/O, encoding, encryption, or resource-limit errors.
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
    let mut options = options;
    lzma2::set_default_budget(&mut options);
    let prepared = encode::prepare_archive_options(options)?;
    let budget = OperationBudget::new(prepared.archive().streaming.resource_limits)
        .with_control(prepared.archive().streaming.control.clone());
    let operation = budget.into_writer_budgets().operation;
    build_streaming_with_prepared_options(entries, out, prepared, operation)
}

fn build_streaming_with_prepared_options<W, I, R>(
    entries: I,
    out: W,
    prepared: encode::PreparedArchiveOptions,
    operation: WriterOperation,
) -> Result<(), R7zError>
where
    W: Write + Seek,
    I: IntoIterator<Item = (String, R)>,
    R: Read,
{
    let mut writer = ArchiveWriter::new_prepared(out, prepared, operation).start();
    for (name, reader) in entries {
        writer.append(&name, reader)?;
    }
    writer.finish()?;
    Ok(())
}

/// Stage an archive, then copy it to a writer that need not support seeking.
///
/// # Errors
///
/// Returns invalid-option, input/output I/O, spool creation or cleanup,
/// encoding, encryption, or resource-limit errors.
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
    let mut options = options;
    lzma2::set_default_budget(&mut options);
    let prepared = encode::prepare_archive_options(options)?;
    let resource_limits = prepared.archive().streaming.resource_limits;
    let budget = OperationBudget::new(resource_limits)
        .with_control(prepared.archive().streaming.control.clone());
    let all_budgets = budget.into_writer_budgets();
    let streaming_budgets = StreamingWriteBudgets {
        operation: all_budgets.operation,
        spool: all_budgets.spool,
    };
    match prepared.archive().streaming.spool.clone() {
        SpoolMode::Memory => {
            build_streaming_via_spool(entries, &mut out, None, None, streaming_budgets, prepared)
        }
        SpoolMode::Auto {
            memory_threshold,
            dir,
        } => build_streaming_via_spool(
            entries,
            &mut out,
            Some(memory_threshold),
            dir,
            streaming_budgets,
            prepared,
        ),
        SpoolMode::TempFile { dir } => {
            build_streaming_via_spool(entries, &mut out, Some(0), dir, streaming_budgets, prepared)
        }
    }
}

struct StreamingWriteBudgets {
    operation: WriterOperation,
    spool: SpoolBudget,
}

fn build_streaming_via_spool<W, I, R>(
    entries: I,
    out: &mut W,
    memory_threshold: Option<u64>,
    dir: Option<PathBuf>,
    budgets: StreamingWriteBudgets,
    prepared: encode::PreparedArchiveOptions,
) -> Result<(), R7zError>
where
    W: Write,
    I: IntoIterator<Item = (String, R)>,
    R: Read,
{
    let StreamingWriteBudgets { operation, spool } = budgets;
    let mut output_monitor =
        crate::operation::OperationMonitor::new(prepared.archive().streaming.control.clone())
            .for_phase(crate::OperationPhase::CopyOutput);
    let mut spool = AutoSpool::new(memory_threshold, dir, spool)?;
    let result = (|| {
        build_streaming_with_prepared_options(entries, &mut spool, prepared, operation)?;
        spool.seek(SeekFrom::Start(0))?;
        output_monitor.copy_to(&mut spool, out)?;
        out.flush()?;
        output_monitor.check()?;
        Ok(())
    })();
    let limit_error = spool.limit_error();
    let cleanup_result = spool.cleanup();

    if let Some(error) = limit_error {
        return Err(error);
    }

    match (result, cleanup_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error.into()),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// Write an archive split across volumes.
///
/// # Errors
///
/// Returns invalid-option, input/output I/O, spool creation or cleanup,
/// encoding, encryption, or resource-limit errors.
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
    let VolumeOptions { sizes } = volume_options;
    if sizes.is_empty() {
        return Err(R7zError::InvalidOptions(
            "volume options require at least one size",
        ));
    }
    let mut archive_options = archive_options;
    lzma2::set_default_budget(&mut archive_options);
    let prepared = encode::prepare_archive_options(archive_options)?;
    let resource_limits = prepared.archive().streaming.resource_limits;
    let budget = OperationBudget::new(resource_limits)
        .with_control(prepared.archive().streaming.control.clone());
    let WriterBudgets {
        operation,
        spool,
        open_volumes: mut open_volume_budget,
        volume_count: mut volume_count_budget,
    } = budget.into_writer_budgets();
    let (memory_threshold, dir) = match prepared.archive().streaming.spool.clone() {
        SpoolMode::Memory => (None, None),
        SpoolMode::Auto {
            memory_threshold,
            dir,
        } => (Some(memory_threshold), dir),
        SpoolMode::TempFile { dir } => (Some(0), dir),
    };
    let mut output_monitor =
        crate::operation::OperationMonitor::new(prepared.archive().streaming.control.clone())
            .for_phase(crate::OperationPhase::CopyOutput);
    let mut archive = AutoSpool::new(memory_threshold, dir, spool)?;
    let result = (|| {
        build_streaming_with_prepared_options(entries, &mut archive, prepared, operation)?;
        write_volume_files(
            &mut archive,
            base_path.as_ref(),
            &sizes,
            &mut open_volume_budget,
            &mut volume_count_budget,
            &mut output_monitor,
        )
    })();
    let limit_error = archive.limit_error();
    let cleanup_result = archive.cleanup();

    if let Some(error) = limit_error {
        return Err(error);
    }
    match (result, cleanup_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Ok(paths), Ok(())) => Ok(paths),
    }
}

fn write_volume_files<R: Read + Seek>(
    archive: &mut R,
    base: &Path,
    volume_sizes: &[NonZeroU64],
    open_volume_budget: &mut OpenVolumeBudget,
    volume_count_budget: &mut VolumeCountBudget,
    monitor: &mut crate::operation::OperationMonitor,
) -> Result<Vec<PathBuf>, R7zError> {
    monitor.check()?;
    let total_size = archive.seek(SeekFrom::End(0))?;
    let volume_count = required_volume_count(total_size, volume_sizes)?;
    volume_count_budget.charge(volume_count)?;

    archive.seek(SeekFrom::Start(0))?;
    let mut next = [0u8; 1];
    let mut has_next = monitor.read(archive, &mut next)? != 0;
    let mut volume_index = 0usize;
    let mut paths = Vec::new();

    if !has_next {
        let path = volume_path(base, volume_index);
        write_volume_file(&path, open_volume_budget, |_| Ok(()))?;
        paths.push(path);
        return Ok(paths);
    }

    while has_next {
        let size = volume_sizes[volume_index.min(volume_sizes.len() - 1)].get();
        let path = volume_path(base, volume_index);
        let remaining = size - 1;
        let copied = write_volume_file(&path, open_volume_budget, |file| {
            file.write_all(&next)?;
            let copied = monitor.copy_to(&mut archive.take(remaining), file)?;
            file.flush()?;
            monitor.check()?;
            Ok(copied)
        })?;
        paths.push(path);
        if copied < remaining {
            break;
        }
        has_next = monitor.read(archive, &mut next)? != 0;
        volume_index += 1;
    }

    Ok(paths)
}

fn required_volume_count(total_size: u64, volume_sizes: &[NonZeroU64]) -> Result<usize, R7zError> {
    let Some(last_size) = volume_sizes.last() else {
        return Err(R7zError::InvalidOptions(
            "volume options require at least one size",
        ));
    };
    if total_size == 0 {
        return Ok(1);
    }

    let mut remaining = total_size;
    for (index, size) in volume_sizes.iter().enumerate() {
        let count = index + 1;
        if remaining <= size.get() {
            return Ok(count);
        }
        remaining -= size.get();
    }

    let tail_count = remaining.div_ceil(last_size.get());
    let count = u64::try_from(volume_sizes.len())
        .ok()
        .and_then(|count| count.checked_add(tail_count))
        .ok_or(R7zError::Parse)?;
    usize::try_from(count).map_err(|_| R7zError::ResourceLimitExceeded {
        resource: "archive volume count",
        limit: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
    })
}

fn write_volume_file<T>(
    path: &Path,
    budget: &mut OpenVolumeBudget,
    write: impl FnOnce(&mut File) -> Result<T, R7zError>,
) -> Result<T, R7zError> {
    budget.charge()?;
    let result = File::create(path)
        .map_err(R7zError::from)
        .and_then(|mut file| write(&mut file));
    budget.release();
    result
}

fn volume_path(base: &Path, index: usize) -> PathBuf {
    PathBuf::from(format!("{}.{:03}", base.display(), index + 1))
}

fn create_temp_spool(dir: Option<&Path>) -> Result<(File, PathBuf), R7zError> {
    let dir = dir.map_or_else(std::env::temp_dir, Path::to_path_buf);
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
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
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
    memory_threshold: Option<u64>,
    dir: Option<PathBuf>,
    budget: SpoolBudget,
    temporary_storage_limit_exceeded: bool,
    retained_output_limit_exceeded: bool,
    inner: AutoSpoolInner,
}

impl AutoSpool {
    fn new(
        memory_threshold: Option<u64>,
        dir: Option<PathBuf>,
        budget: SpoolBudget,
    ) -> Result<Self, R7zError> {
        let inner = if memory_threshold == Some(0) {
            let (file, path) = create_temp_spool(dir.as_deref())?;
            AutoSpoolInner::TempFile { file, path }
        } else {
            AutoSpoolInner::Memory(Cursor::new(Vec::new()))
        };
        Ok(Self {
            memory_threshold,
            dir,
            budget,
            temporary_storage_limit_exceeded: false,
            retained_output_limit_exceeded: false,
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
        let exceeds_memory_threshold = self
            .memory_threshold
            .is_some_and(|threshold| projected_len > threshold);
        let exceeds_retained_limit = self
            .budget
            .retained_output
            .limit()
            .is_some_and(|limit| projected_len > limit);
        if !exceeds_memory_threshold && !exceeds_retained_limit {
            return Ok(());
        }
        if self.memory_threshold.is_none() {
            return Ok(());
        }
        let migration_bytes = cursor.get_ref().len() as u64;
        let write_bytes = write_len;
        check_temporary_storage_write(
            &self.budget.temporary_storage,
            &mut self.temporary_storage_limit_exceeded,
            migration_bytes.saturating_add(write_bytes),
        )?;

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
        charge_temporary_storage_write(
            &mut self.budget.temporary_storage,
            &mut self.temporary_storage_limit_exceeded,
            migration_bytes,
        )?;
        self.budget
            .retained_output
            .release(RetainedOutputBytes::new(migration_bytes));
        self.inner = AutoSpoolInner::TempFile { file, path };
        Ok(())
    }

    fn check_temporary_file_write(&mut self, write_len: usize) -> io::Result<()> {
        if write_len == 0 {
            return Ok(());
        }
        let AutoSpoolInner::TempFile { .. } = &self.inner else {
            return Ok(());
        };
        let write_len = u64::try_from(write_len).unwrap_or(u64::MAX);
        check_temporary_storage_write(
            &self.budget.temporary_storage,
            &mut self.temporary_storage_limit_exceeded,
            write_len,
        )
    }

    fn charge_temporary_file_write(&mut self, written: usize) -> io::Result<()> {
        if written == 0 || !matches!(&self.inner, AutoSpoolInner::TempFile { .. }) {
            return Ok(());
        }
        let written = u64::try_from(written).unwrap_or(u64::MAX);
        charge_temporary_storage_write(
            &mut self.budget.temporary_storage,
            &mut self.temporary_storage_limit_exceeded,
            written,
        )
    }

    fn check_retained_memory_write(&mut self, write_len: usize) -> io::Result<()> {
        let AutoSpoolInner::Memory(cursor) = &self.inner else {
            return Ok(());
        };
        let current_len = cursor.get_ref().len() as u64;
        let projected_len = cursor
            .position()
            .saturating_add(u64::try_from(write_len).unwrap_or(u64::MAX))
            .max(current_len);
        self.budget
            .retained_output
            .check_resize(
                RetainedOutputBytes::new(current_len),
                RetainedOutputBytes::new(projected_len),
            )
            .map_err(|_| {
                self.retained_output_limit_exceeded = true;
                io::Error::other("retained output limit exceeded")
            })
    }

    fn charge_retained_memory_write(&mut self, previous_len: u64) -> io::Result<()> {
        let AutoSpoolInner::Memory(cursor) = &self.inner else {
            return Ok(());
        };
        self.budget
            .retained_output
            .resize(
                RetainedOutputBytes::new(previous_len),
                RetainedOutputBytes::new(cursor.get_ref().len() as u64),
            )
            .map_err(|_| {
                self.retained_output_limit_exceeded = true;
                io::Error::other("retained output limit exceeded")
            })
    }

    fn limit_error(&self) -> Option<R7zError> {
        if self.retained_output_limit_exceeded {
            return self.budget.retained_output.limit().map(|limit| {
                R7zError::ResourceLimitExceeded {
                    resource: "retained output",
                    limit,
                }
            });
        }
        self.temporary_storage_limit_exceeded
            .then(|| R7zError::ResourceLimitExceeded {
                resource: "temporary storage",
                limit: self
                    .budget
                    .temporary_storage
                    .limit()
                    .expect("limit exceeded only when configured"),
            })
    }

    fn cleanup(self) -> io::Result<()> {
        match self.inner {
            AutoSpoolInner::Memory(_) => Ok(()),
            AutoSpoolInner::TempFile { path, .. } => std::fs::remove_file(path),
        }
    }
}

fn check_temporary_storage_write(
    budget: &TemporaryStorageBudget,
    limit_exceeded: &mut bool,
    bytes: u64,
) -> io::Result<()> {
    budget
        .check_write(TemporaryStorageBytes::new(bytes))
        .map_err(|_| {
            *limit_exceeded = true;
            io::Error::other("temporary storage limit exceeded")
        })
}

fn charge_temporary_storage_write(
    budget: &mut TemporaryStorageBudget,
    limit_exceeded: &mut bool,
    bytes: u64,
) -> io::Result<()> {
    budget
        .charge_write(TemporaryStorageBytes::new(bytes))
        .map_err(|_| {
            *limit_exceeded = true;
            io::Error::other("temporary storage limit exceeded")
        })
}

impl Write for AutoSpool {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_temporary_file_write(buf.len())?;
        self.maybe_roll_to_file(buf.len())?;
        let previous_len = match &self.inner {
            AutoSpoolInner::Memory(cursor) => Some(cursor.get_ref().len() as u64),
            AutoSpoolInner::TempFile { .. } => None,
        };
        self.check_retained_memory_write(buf.len())?;
        let written = match &mut self.inner {
            AutoSpoolInner::Memory(cursor) => cursor.write(buf),
            AutoSpoolInner::TempFile { file, .. } => file.write(buf),
        }?;
        self.charge_temporary_file_write(written)?;
        if let Some(previous_len) = previous_len {
            self.charge_retained_memory_write(previous_len)?;
        }
        Ok(written)
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
