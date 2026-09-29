use crate::entries::{Entries, Entry, EntryKind, EntrySelection};
use crate::file_streams::{FileStream, FileStreams, FolderIndex, StreamLocation};
use crate::folder_decode::{
    ActiveFolder, CompletionMode, DecodedFolder, ExternalFolderPlan, FolderLayout, FolderLayouts,
    MetadataBudget, PackedStream, VerifiedExternalData,
};
use crate::headers::{HeaderResolution, NextHeader};
use crate::{
    EncodedHeader, EntryType, FilesInfo, Header, Property, R7zError, SignatureHeader, StreamInfo,
    codec, find_next_property_id,
};
use bytes::Bytes;
use memmap2::Mmap;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Budget for retained header buffers, decoded external metadata, and stream slots.
/// Extracted file data and decoder working memory have separate limits.
const DEFAULT_MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const SEVEN_Z_MAGIC: &[u8; 6] = b"7z\xbc\xaf'\x1c";
const SIGNATURE_SCAN_CHUNK: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveStorageMode {
    Mmap,
    Seek,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveOpenOptions {
    /// Combined limit for header buffers, decoded external metadata, and its stream slots.
    /// Decoder working memory and parsed metadata tables are bounded separately.
    pub max_metadata_bytes: u64,
    pub storage_mode: ArchiveStorageMode,
}

impl Default for ArchiveOpenOptions {
    fn default() -> Self {
        Self {
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
            storage_mode: ArchiveStorageMode::Mmap,
        }
    }
}

trait ReadSeek: Read + Seek {}

impl<T: Read + Seek> ReadSeek for T {}

enum ArchiveSource {
    Bytes(Bytes),
    Seekable {
        reader: Mutex<Box<dyn ReadSeek + Send>>,
        len: u64,
    },
    Volumes {
        readers: Mutex<Vec<VolumeReader>>,
        len: u64,
    },
}

impl ArchiveSource {
    fn from_reader<R>(mut reader: R) -> Result<Self, R7zError>
    where
        R: Read + Seek + Send + 'static,
    {
        let len = reader.seek(SeekFrom::End(0)).map_err(R7zError::Io)?;
        Ok(Self::Seekable {
            reader: Mutex::new(Box::new(reader)),
            len,
        })
    }

    fn from_split_first_volume(path: &Path) -> Result<Option<Self>, R7zError> {
        if !is_split_first_volume(path) {
            return Ok(None);
        }

        let mut readers = Vec::new();
        let mut len = 0u64;
        for idx in 1.. {
            let path = split_volume_path(path, idx);
            if !path.exists() {
                break;
            }
            let mut file = std::fs::File::open(&path)?;
            let volume_len = file.seek(SeekFrom::End(0)).map_err(R7zError::Io)?;
            let start = len;
            len = checked_add_u64(len, volume_len)?;
            readers.push(VolumeReader {
                file,
                start,
                end: len,
            });
        }

        if readers.len() > 1 {
            Ok(Some(Self::Volumes {
                readers: Mutex::new(readers),
                len,
            }))
        } else {
            Ok(None)
        }
    }

    fn len(&self) -> Result<u64, R7zError> {
        match self {
            Self::Bytes(bytes) => u64::try_from(bytes.len()).map_err(|_| R7zError::Parse),
            Self::Seekable { len, .. } => Ok(*len),
            Self::Volumes { len, .. } => Ok(*len),
        }
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> Result<(), R7zError> {
        if dst.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(u64::try_from(dst.len()).map_err(|_| R7zError::Parse)?)
            .ok_or(R7zError::Parse)?;
        if end > self.len()? {
            return Err(R7zError::Parse);
        }
        match self {
            Self::Bytes(bytes) => {
                let start = usize::try_from(offset).map_err(|_| R7zError::Parse)?;
                let end = usize::try_from(end).map_err(|_| R7zError::Parse)?;
                dst.copy_from_slice(bytes.get(start..end).ok_or(R7zError::Parse)?);
                Ok(())
            }
            Self::Seekable { reader, .. } => {
                let mut reader = reader.lock().map_err(|_| R7zError::Parse)?;
                reader.seek(SeekFrom::Start(offset))?;
                reader.read_exact(dst)?;
                Ok(())
            }
            Self::Volumes { readers, .. } => {
                let mut readers = readers.lock().map_err(|_| R7zError::Parse)?;
                let mut logical_offset = offset;
                let mut remaining = dst;
                while !remaining.is_empty() {
                    let volume = readers
                        .iter_mut()
                        .find(|volume| {
                            logical_offset >= volume.start && logical_offset < volume.end
                        })
                        .ok_or(R7zError::Parse)?;
                    let volume_offset = logical_offset - volume.start;
                    let available = volume.end - logical_offset;
                    let n = usize::try_from(available.min(remaining.len() as u64))
                        .map_err(|_| R7zError::Parse)?;
                    volume.file.seek(SeekFrom::Start(volume_offset))?;
                    volume.file.read_exact(&mut remaining[..n])?;
                    logical_offset = logical_offset
                        .checked_add(n as u64)
                        .ok_or(R7zError::Parse)?;
                    remaining = &mut remaining[n..];
                }
                Ok(())
            }
        }
    }

    fn read_range_to_vec(&self, range: Range<u64>, limit: u64) -> Result<Vec<u8>, R7zError> {
        let len = checked_sub_u64(range.end, range.start)?;
        if len > limit {
            return Err(R7zError::LimitExceeded("metadata"));
        }
        let len = usize::try_from(len).map_err(|_| R7zError::Parse)?;
        let mut out = vec![0u8; len];
        self.read_exact_at(range.start, &mut out)?;
        Ok(out)
    }

    fn range_reader(&self, range: Range<u64>) -> Result<ArchiveRangeReader<'_>, R7zError> {
        if range.start > range.end || range.end > self.len()? {
            return Err(R7zError::Parse);
        }
        Ok(ArchiveRangeReader {
            source: self,
            pos: range.start,
            end: range.end,
        })
    }

    fn packed_input(
        &self,
        range: Range<u64>,
    ) -> Result<codec::PackedInput<ArchiveRangeReader<'_>>, R7zError> {
        let size = usize::try_from(checked_sub_u64(range.end, range.start)?)
            .map_err(|_| R7zError::Parse)?;
        Ok(codec::PackedInput {
            reader: self.range_reader(range)?,
            size,
        })
    }

    fn find_signature(&self, limit: u64) -> Result<(u64, SignatureHeader), R7zError> {
        let source_len = self.len()?;
        let scan_len = source_len.min(limit);
        let mut offset = 0u64;
        let mut carry = Vec::new();
        let mut saw_bad_signature = false;

        while offset < scan_len {
            let remaining = scan_len - offset;
            let chunk_len = usize::try_from(remaining.min(SIGNATURE_SCAN_CHUNK as u64))
                .map_err(|_| R7zError::Parse)?;
            let mut chunk = vec![0u8; chunk_len];
            self.read_exact_at(offset, &mut chunk)?;

            let carry_len = carry.len();
            carry.extend_from_slice(&chunk);
            let search_start = carry_len.saturating_sub(SEVEN_Z_MAGIC.len() - 1);
            let base = offset
                .checked_sub(carry_len as u64)
                .ok_or(R7zError::Parse)?;

            for pos in find_magic_offsets(&carry[search_start..]) {
                let pos = search_start.checked_add(pos).ok_or(R7zError::Parse)?;
                let candidate = base.checked_add(pos as u64).ok_or(R7zError::Parse)?;
                match self.signature_at(candidate)? {
                    SignatureCandidate::Valid(signature) => return Ok((candidate, signature)),
                    SignatureCandidate::BadCrc => saw_bad_signature = true,
                    SignatureCandidate::Incomplete => {}
                }
            }

            if carry.len() >= SEVEN_Z_MAGIC.len() - 1 {
                carry = carry[carry.len() - (SEVEN_Z_MAGIC.len() - 1)..].to_vec();
            }
            offset = offset
                .checked_add(chunk_len as u64)
                .ok_or(R7zError::Parse)?;
        }

        if saw_bad_signature {
            Err(R7zError::Crc)
        } else {
            Err(R7zError::Parse)
        }
    }

    fn signature_at(&self, offset: u64) -> Result<SignatureCandidate, R7zError> {
        if offset.checked_add(32).ok_or(R7zError::Parse)? > self.len()? {
            return Ok(SignatureCandidate::Incomplete);
        }
        let mut signature_bytes = [0u8; 32];
        self.read_exact_at(offset, &mut signature_bytes)?;
        let (_, signature) =
            SignatureHeader::parse(&signature_bytes).map_err(|_| R7zError::Parse)?;
        if signature.signature != *SEVEN_Z_MAGIC {
            return Ok(SignatureCandidate::Incomplete);
        }
        match signature.validate_start_header_crc() {
            Ok(()) => Ok(SignatureCandidate::Valid(signature)),
            Err(R7zError::Crc) => Ok(SignatureCandidate::BadCrc),
            Err(err) => Err(err),
        }
    }
}

enum SignatureCandidate {
    Valid(SignatureHeader),
    BadCrc,
    Incomplete,
}

struct VolumeReader {
    file: std::fs::File,
    start: u64,
    end: u64,
}

struct ArchiveRangeReader<'a> {
    source: &'a ArchiveSource,
    pos: u64,
    end: u64,
}

impl Read for ArchiveRangeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.end || buf.is_empty() {
            return Ok(0);
        }
        let remaining = self.end - self.pos;
        let n = usize::try_from(remaining.min(buf.len() as u64))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "range too large"))?;
        self.source
            .read_exact_at(self.pos, &mut buf[..n])
            .map_err(std::io::Error::other)?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// Metadata extracted from the outer 7z header (`EncodedHeader` only).
#[derive(Debug)]
pub struct ArchiveMetadata {
    pub signature: SignatureHeader,
    pub encoded_header: EncodedHeader,
}

impl ArchiveMetadata {
    /// Parse the outer header of a 7z archive from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Parse`] if the bytes are not a valid `EncodedHeader` archive,
    /// or [`R7zError::Crc`] if the start-header CRC does not match.
    pub fn parse(data: &[u8]) -> Result<ArchiveMetadata, R7zError> {
        let signature_offset = find_signature_in_slice(data)?;
        let archive_data = data.get(signature_offset..).ok_or(R7zError::Parse)?;
        let backing = Bytes::copy_from_slice(archive_data);
        let (input, signature) = SignatureHeader::parse(&backing).map_err(|_| R7zError::Parse)?;
        signature.validate_start_header_crc()?;

        let offset = usize::try_from(signature.next_header_offset).map_err(|_| R7zError::Parse)?;
        let header_start = checked_add_usize(32, offset)?;
        checked_range(archive_data.len(), header_start, signature.next_header_size)?;
        let (input, prop) = find_next_property_id(input, offset).map_err(|_| R7zError::Parse)?;

        match prop {
            Property::EncodedHeader => {
                let (_, encoded_header) =
                    EncodedHeader::parse(input, &backing).map_err(|_| R7zError::Parse)?;
                Ok(ArchiveMetadata {
                    signature,
                    encoded_header,
                })
            }
            _ => Err(R7zError::Parse),
        }
    }
}

/// Fully decoded archive with file listing and extraction support.
pub struct Archive {
    source: ArchiveSource,
    base_offset: u64,
    pub signature: SignatureHeader,
    /// Present for `EncodedHeader` archives; None for uncompressed-header archives.
    pub encoded_header: Option<EncodedHeader>,
    pub header: Header,
}

/// Archive-level and per-entry metadata used for p7zip-style listing output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveListing {
    pub archive_type: &'static str,
    pub physical_size: Option<u64>,
    pub headers_size: Option<u64>,
    pub methods: Vec<String>,
    pub solid: bool,
    pub blocks: usize,
    pub entries: Vec<ArchiveListingEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveListingEntry {
    pub index: usize,
    pub path: String,
    pub kind: ListingEntryKind,
    pub size: Option<u64>,
    pub packed_size: Option<u64>,
    pub modified: Option<SystemTime>,
    pub attributes: Option<u32>,
    pub crc: Option<u32>,
    pub encrypted: bool,
    pub methods: Vec<String>,
    pub block: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListingEntryKind {
    File,
    Directory,
    Symlink,
    Anti,
}

/// High-level metadata for one archive entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveEntryInfo {
    /// Zero-based index in the 7z `FilesInfo` table.
    pub index: usize,
    /// Raw archive entry name as stored in the header.
    pub name: String,
    /// Normalized relative path when the entry name is safe to extract.
    pub safe_name: Option<PathBuf>,
    /// Entry kind derived from 7z empty-stream, anti-item, and mode metadata.
    pub entry_type: EntryType,
}

impl ArchiveEntryInfo {
    fn from_entry<S>(entry: &Entry<'_, S>) -> Self {
        let name = entry.metadata.name();
        let safe_name = safe_archive_name(&name).ok();
        Self {
            index: entry.metadata.index.get(),
            name,
            safe_name,
            entry_type: entry.kind.entry_type(),
        }
    }

    #[must_use]
    pub fn is_file(&self) -> bool {
        matches!(
            self.entry_type,
            EntryType::File | EntryType::EmptyFile | EntryType::Symlink | EntryType::EmptySymlink
        )
    }

    /// Whether this entry owns an archive data stream, independent of its length.
    /// Empty files and empty symlinks have no stream.
    #[must_use]
    pub fn has_data_stream(&self) -> bool {
        matches!(self.entry_type, EntryType::File | EntryType::Symlink)
    }

    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.entry_type == EntryType::Directory
    }

    #[must_use]
    pub fn is_anti(&self) -> bool {
        self.entry_type == EntryType::Anti
    }

    #[must_use]
    pub fn safe_path(&self) -> Option<&Path> {
        self.safe_name.as_deref()
    }
}

/// Iterator returned by [`Archive::entries`].
pub struct ArchiveEntries<'a> {
    entries: Entries<'a>,
}

impl Iterator for ArchiveEntries<'_> {
    type Item = ArchiveEntryInfo;

    fn next(&mut self) -> Option<Self::Item> {
        self.nth(0)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.entries
            .nth(n)
            .map(|entry| ArchiveEntryInfo::from_entry(&entry))
    }
}

impl ExactSizeIterator for ArchiveEntries<'_> {}

/// Forward-only entry reads sharing the current solid-folder decoder.
///
/// Call [`finish`](Self::finish) to verify the last folder. Dropping a session
/// releases its decoder without reading or checking the remaining folder data.
pub struct ArchiveReadSession<'a> {
    files: FileStreams<'a>,
    decoder: FolderDecoder<'a>,
    password: Option<&'a str>,
    count: usize,
}

impl ArchiveReadSession<'_> {
    /// Read an entry whose index is greater than every previously requested index.
    /// Unread entry bytes are drained and checked after the callback returns.
    /// Directories and anti-items return [`R7zError::Directory`]. Empty file-like
    /// entries invoke the callback with an empty reader.
    ///
    /// # Errors
    /// Returns selection, decode, checksum, or callback errors. An invalid index
    /// leaves the session unchanged. A valid request consumes its index even if
    /// it fails. Failed data reads discard the active decoder; later requests
    /// may open a new decoder.
    pub fn read_entry(
        &mut self,
        index: usize,
        callback: impl FnOnce(&mut dyn Read) -> Result<(), R7zError>,
    ) -> Result<(), R7zError> {
        let next_index = self.count - self.files.len();
        if !(next_index..self.count).contains(&index) {
            return Err(R7zError::InvalidOptions(
                "read session requires increasing valid entry indexes",
            ));
        }
        let file = self.files.nth(index - next_index)?.ok_or(R7zError::Parse)?;
        let entry = ArchiveEntryInfo::from_entry(&file);
        match file.kind {
            EntryKind::File(location) | EntryKind::Symlink(location) => {
                self.decoder
                    .read(location, &entry, self.password, |_, reader| {
                        callback(reader)
                    })
            }
            EntryKind::EmptyFile | EntryKind::EmptySymlink => callback(&mut std::io::empty()),
            EntryKind::Directory | EntryKind::Anti => Err(R7zError::Directory),
        }
    }

    /// Copy an entry to a writer while retaining the decoder for subsequent reads.
    ///
    /// # Errors
    /// Returns the errors from [`read_entry`](Self::read_entry), or a writer error.
    pub fn extract_to_writer<W: Write + ?Sized>(
        &mut self,
        index: usize,
        writer: &mut W,
    ) -> Result<u64, R7zError> {
        let mut written = 0;
        self.read_entry(index, |reader| {
            written = copy_entry(reader, writer)?;
            Ok(())
        })?;
        Ok(written)
    }

    /// Complete the current folder and release its decoder. With a folder CRC,
    /// this reads and verifies the remaining data, including unselected entries.
    /// Without a folder CRC, an unselected tail may remain unread.
    ///
    /// # Errors
    /// Returns decoding or checksum errors. The decoder is released on both
    /// success and failure, so independent folders can still be processed.
    pub fn finish_folder(&mut self) -> Result<(), R7zError> {
        self.decoder.finish()
    }

    /// Complete the last folder and close this session.
    ///
    /// # Errors
    /// Returns errors from [`finish_folder`](Self::finish_folder).
    pub fn finish(mut self) -> Result<(), R7zError> {
        self.finish_folder()
    }
}

fn copy_entry(reader: &mut dyn Read, writer: &mut (impl Write + ?Sized)) -> Result<u64, R7zError> {
    std::io::copy(&mut EntryReader(reader), writer).map_err(|error| {
        match error.downcast::<EntryReadError>() {
            Ok(EntryReadError(error)) => error,
            Err(error) => R7zError::Io(error),
        }
    })
}

/// Marks read failures so copying can distinguish them from writer failures.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct EntryReadError(R7zError);

/// Restores source error kinds at the decoded-reader boundary for I/O retries.
struct EntryReader<'a>(&'a mut dyn Read);

impl Read for EntryReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        // Vec writers may offer their entire spare capacity to io::copy.
        let capacity = buffer.len().min(8 * 1024);
        self.0.read(&mut buffer[..capacity]).map_err(|error| {
            let error = match error.kind() {
                std::io::ErrorKind::Interrupted => R7zError::Io(error),
                _ => error
                    .downcast::<R7zError>()
                    .unwrap_or(R7zError::Decompression),
            };
            let kind = match &error {
                R7zError::Io(error) => error.kind(),
                _ => std::io::ErrorKind::Other,
            };
            std::io::Error::new(kind, EntryReadError(error))
        })
    }
}

#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawFolderBlock {
    pub folder_index: usize,
    pub folder_info: Vec<u8>,
    pub packed_streams: Vec<Vec<u8>>,
    pub pack_sizes: Vec<u64>,
    pub coder_unpack_sizes: Vec<u64>,
    pub folder_crc: Option<u32>,
}

impl Archive {
    /// Open and fully decode a 7z archive from disk.
    ///
    /// The file is memory-mapped rather than read into a heap buffer, so the OS
    /// pages in only the regions that are actually accessed.  This avoids loading
    /// the entire archive into RAM when only a few files are extracted.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Io`] if the file cannot be opened or mapped, or a
    /// parse/CRC error if the archive is malformed.
    ///
    /// # Safety
    ///
    /// The underlying `mmap(2)` call is unsafe because another process could
    /// truncate the file while it is mapped, causing a `SIGBUS`.  In practice
    /// this is rarely an issue for archive files, but callers that need
    /// stronger guarantees should use [`Archive::from_reader`] instead.
    pub fn open(path: &Path) -> Result<Archive, R7zError> {
        Self::open_with_options(path, ArchiveOpenOptions::default())
    }

    /// Open a 7z archive from a file path, supplying a password for encrypted archives.
    ///
    /// When the archive has encrypted headers (`-mhe=on`), the password is needed
    /// just to read the file listing.  For archives whose *content* is encrypted
    /// but headers are not, the password is only required at extraction time.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Io`] if the file cannot be opened or mapped,
    /// [`R7zError::PasswordRequired`] if the headers are encrypted and no password
    /// is supplied, or a parse/CRC error if the archive is malformed.
    pub fn open_with_password(path: &Path, password: Option<&str>) -> Result<Archive, R7zError> {
        Self::open_with_password_and_options(path, password, ArchiveOpenOptions::default())
    }

    pub fn open_with_options(
        path: &Path,
        options: ArchiveOpenOptions,
    ) -> Result<Archive, R7zError> {
        Self::open_with_password_and_options(path, None, options)
    }

    pub fn open_with_password_and_options(
        path: &Path,
        password: Option<&str>,
        options: ArchiveOpenOptions,
    ) -> Result<Archive, R7zError> {
        let source = if let Some(source) = ArchiveSource::from_split_first_volume(path)? {
            source
        } else {
            let file = std::fs::File::open(path)?;
            match options.storage_mode {
                ArchiveStorageMode::Mmap => {
                    // SAFETY: The file is opened read-only and we do not mutate the
                    // mapping. A concurrent truncation could cause SIGBUS; callers
                    // that need stronger guarantees can select Seek mode.
                    let mmap = unsafe { Mmap::map(&file)? };
                    ArchiveSource::Bytes(Bytes::from_owner(mmap))
                }
                ArchiveStorageMode::Seek => ArchiveSource::from_reader(file)?,
            }
        };
        Self::from_source_with_password(source, password, options)
    }

    /// Decode a seekable [`Read`] source as a 7z archive.
    ///
    /// The 7z format needs random access: packed streams are near the start,
    /// while the authoritative header is usually near the end. Non-seekable
    /// sources must be spooled by the caller before constructing an [`Archive`].
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Io`] if reading fails, or a parse/CRC error if the
    /// archive is malformed.
    pub fn from_reader<R>(reader: R) -> Result<Archive, R7zError>
    where
        R: Read + Seek + Send + 'static,
    {
        Self::from_reader_with_password(reader, None)
    }

    /// Decode a seekable [`Read`] source as a 7z archive, with a password.
    ///
    /// See [`Archive::from_reader`] and [`Archive::open_with_password`] for details.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Io`] if reading fails, [`R7zError::PasswordRequired`]
    /// if encrypted headers need a password, or a parse/CRC error if malformed.
    pub fn from_reader_with_password<R>(
        reader: R,
        password: Option<&str>,
    ) -> Result<Archive, R7zError>
    where
        R: Read + Seek + Send + 'static,
    {
        Self::from_reader_with_password_and_options(
            reader,
            password,
            ArchiveOpenOptions {
                storage_mode: ArchiveStorageMode::Seek,
                ..ArchiveOpenOptions::default()
            },
        )
    }

    pub fn from_reader_with_options<R>(
        reader: R,
        options: ArchiveOpenOptions,
    ) -> Result<Archive, R7zError>
    where
        R: Read + Seek + Send + 'static,
    {
        Self::from_reader_with_password_and_options(reader, None, options)
    }

    pub fn from_reader_with_password_and_options<R>(
        reader: R,
        password: Option<&str>,
        options: ArchiveOpenOptions,
    ) -> Result<Archive, R7zError>
    where
        R: Read + Seek + Send + 'static,
    {
        Self::from_source_with_password(ArchiveSource::from_reader(reader)?, password, options)
    }

    /// Parse a 7z archive from in-memory bytes.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Parse`] if the bytes are not a valid 7z archive, or
    /// [`R7zError::Crc`] if any CRC check fails.
    pub fn from_bytes(data: Bytes) -> Result<Archive, R7zError> {
        Self::from_bytes_with_password(data, None)
    }

    /// Parse a 7z archive from in-memory bytes, with an optional password.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Parse`] if the bytes are not a valid 7z archive,
    /// [`R7zError::Crc`] if any CRC check fails, or [`R7zError::PasswordRequired`]
    /// if the header is encrypted and no password is supplied.
    pub fn from_bytes_with_password(
        data: Bytes,
        password: Option<&str>,
    ) -> Result<Archive, R7zError> {
        Self::from_source_with_password(
            ArchiveSource::Bytes(data),
            password,
            ArchiveOpenOptions::default(),
        )
    }

    fn from_source_with_password(
        source: ArchiveSource,
        password: Option<&str>,
        options: ArchiveOpenOptions,
    ) -> Result<Archive, R7zError> {
        let source_len = source.len()?;
        let (base_offset, signature) = source.find_signature(DEFAULT_MAX_METADATA_BYTES)?;

        if signature.next_header_size > options.max_metadata_bytes {
            return Err(R7zError::LimitExceeded("metadata"));
        }

        let header_start = checked_add_u64(
            checked_add_u64(base_offset, 32)?,
            signature.next_header_offset,
        )?;
        let header_range = checked_range_u64(source_len, header_start, signature.next_header_size)?;
        let next_header =
            Bytes::from(source.read_range_to_vec(header_range, options.max_metadata_bytes)?);
        if crc32fast::hash(&next_header) != signature.next_header_crc {
            return Err(R7zError::Crc);
        }
        let (header, encoded_header) = match NextHeader::parse(&next_header)? {
            NextHeader::Plain => (
                parse_header_with_external_data(
                    &source,
                    base_offset,
                    &next_header,
                    MetadataBudget::new(options.max_metadata_bytes),
                    password,
                )?,
                None,
            ),
            NextHeader::Encoded(encoded) => {
                let header = decode_encoded_header(
                    &source,
                    base_offset,
                    &encoded,
                    password,
                    MetadataBudget::new(options.max_metadata_bytes)
                        .charge(next_header.len() as u64)?,
                )?;
                (header, Some(*encoded))
            }
        };
        Ok(Archive {
            source,
            base_offset,
            signature,
            encoded_header,
            header,
        })
    }

    /// Number of files (and directories) listed in the archive.
    ///
    /// # Panics
    ///
    /// Panics if `num_files` exceeds `usize::MAX`, which cannot happen on any
    /// realistic platform since 7z archives are limited to far fewer entries.
    #[must_use]
    pub fn num_files(&self) -> usize {
        usize::try_from(self.header.num_files()).unwrap_or(0)
    }

    #[must_use]
    pub fn files_info(&self) -> Option<&FilesInfo> {
        self.header.files_info()
    }

    /// Fallible file metadata access for callers that need malformed-header errors.
    pub fn try_files_info(&self) -> Result<Option<&FilesInfo>, R7zError> {
        self.header.try_files_info()
    }

    /// Return high-level metadata for entry `index`.
    #[must_use]
    pub fn entry(&self, index: usize) -> Option<ArchiveEntryInfo> {
        Entries::new(self.header.files_info(), self.num_files())
            .nth(index)
            .map(|entry| ArchiveEntryInfo::from_entry(&entry))
    }

    /// Iterate high-level entry metadata in archive order.
    #[must_use]
    pub fn entries(&self) -> ArchiveEntries<'_> {
        ArchiveEntries {
            entries: Entries::new(self.header.files_info(), self.num_files()),
        }
    }

    /// Return the normalized safe relative path for entry `index`.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Parse`] when `index` is out of range and
    /// [`R7zError::UnsafePath`] when the stored name is absolute, contains parent
    /// traversal, uses a Windows drive/UNC prefix, or normalizes to an empty path.
    pub fn safe_name(&self, index: usize) -> Result<PathBuf, R7zError> {
        let entry = self.entry(index).ok_or(R7zError::Parse)?;
        safe_archive_name(&entry.name)
    }

    /// Return the normalized safe relative path for entry `index`, or `None` if
    /// the name is unsafe or the index is out of range.
    #[must_use]
    pub fn enclosed_name(&self, index: usize) -> Option<PathBuf> {
        self.safe_name(index).ok()
    }

    #[must_use]
    pub fn streams_info(&self) -> Option<&StreamInfo> {
        self.header.streams_info()
    }

    /// Fallible stream metadata access for callers that need malformed-header errors.
    pub fn try_streams_info(&self) -> Result<Option<&StreamInfo>, R7zError> {
        self.header.try_streams_info()
    }

    /// Build p7zip-style listing metadata without extracting file contents.
    ///
    /// `physical_size` should be the on-disk archive size when known. When it is
    /// not supplied, r7z uses the logical source length.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Parse`] when stream metadata is inconsistent.
    pub fn listing(&self, physical_size: Option<u64>) -> Result<ArchiveListing, R7zError> {
        let physical_size = physical_size.or_else(|| self.source.len().ok());
        let streams = self.try_streams_info()?;
        let pack_total = streams
            .and_then(|streams| streams.pack_info.as_ref())
            .map(|pack_info| {
                pack_info.pack_size.iter().try_fold(0u64, |acc, &size| {
                    acc.checked_add(size).ok_or(R7zError::Parse)
                })
            })
            .transpose()?
            .unwrap_or(0);
        let headers_size = physical_size.and_then(|size| size.checked_sub(pack_total));
        let methods = archive_method_names(streams)?;
        let blocks = streams
            .and_then(|streams| streams.unpack_info.as_ref())
            .map(crate::UnpackInfo::num_folders_usize)
            .unwrap_or(0);
        let solid = archive_is_solid(streams);

        let files_info = self.try_files_info()?;
        let entries = FileStreams::new(files_info, self.num_files(), streams)?
            .map_selected(EntrySelection::All(0..self.num_files()), |file| {
                Ok(Self::listing_entry(file))
            })
            .try_fold(
                Vec::with_capacity(self.num_files()),
                |mut entries, entry| {
                    entries.push(entry?);
                    Ok::<_, R7zError>(entries)
                },
            )?;

        Ok(ArchiveListing {
            archive_type: "7z",
            physical_size,
            headers_size,
            methods,
            solid,
            blocks,
            entries,
        })
    }

    #[doc(hidden)]
    pub fn raw_folder_block(&self, folder_index: usize) -> Result<RawFolderBlock, R7zError> {
        let streams = self.try_streams_info()?.ok_or(R7zError::Parse)?;
        let (_, unpack_info) = streams.packed_folders()?;
        let mut folders = FolderLayouts::for_streams(streams)?;
        let source = PackedSource::new(&self.source, self.base_offset, folders.pack_pos())?;
        let folder = folders.nth(folder_index).ok_or(R7zError::Parse)??;
        let pack_sizes = folder
            .packed_streams()
            .map(|stream| stream.range.end - stream.range.start)
            .collect::<Vec<_>>();
        ensure_packed_folder_buffer_limit(&pack_sizes)?;
        let packed_buffer_limit = codec::MAX_BUFFERED_PACKED_FOLDER_BYTES as u64;
        let packed_streams = folder
            .packed_streams()
            .map(|stream| {
                self.source
                    .read_range_to_vec(source.range(&stream)?, packed_buffer_limit)
            })
            .collect::<Result<Vec<_>, R7zError>>()?;
        Ok(RawFolderBlock {
            folder_index,
            folder_info: unpack_info.folder_bytes(folder_index)?.to_vec(),
            packed_streams,
            pack_sizes,
            coder_unpack_sizes: folder.coder_sizes().to_vec(),
            folder_crc: folder.crc(),
        })
    }

    /// Extract a single file by its index in the `FilesInfo` list to memory.
    ///
    /// Returns zero bytes for zero-byte files and rejects directory/anti entries.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Parse`] if the index is out of range or the archive
    /// structure is inconsistent.
    /// Returns [`R7zError::Directory`] if the entry is a directory or anti-item.
    /// Returns [`R7zError::Decompression`] if decompression fails.
    /// Returns [`R7zError::PasswordRequired`] if the archive is encrypted.
    pub fn extract_to_memory(&self, file_index: usize) -> Result<Vec<u8>, R7zError> {
        self.extract_to_memory_with_password(file_index, None)
    }

    /// Extract a single file by index, supplying a password for encrypted archives.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::PasswordRequired`] if the file is encrypted and no
    /// password is supplied, or [`R7zError::Decompression`] if decryption/
    /// decompression fails (e.g. wrong password).
    pub fn extract_to_memory_with_password(
        &self,
        file_index: usize,
        password: Option<&str>,
    ) -> Result<Vec<u8>, R7zError> {
        let mut bytes = Vec::new();
        self.extract_to_writer_with_password(file_index, &mut bytes, password)?;
        Ok(bytes)
    }

    /// Extract a file selected by entry name to memory.
    ///
    /// Exact header-name matches are preferred. If no exact match exists and
    /// `name` is a safe archive path, r7z also matches against normalized safe
    /// entry names.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::EntryNotFound`] if no entry matches `name`; otherwise
    /// returns the same errors as [`extract_to_memory`](Self::extract_to_memory).
    pub fn extract_to_memory_by_name(&self, name: &str) -> Result<Vec<u8>, R7zError> {
        self.extract_to_memory_by_name_with_password(name, None)
    }

    /// Extract a file selected by entry name to memory, supplying a password for
    /// encrypted archives.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::EntryNotFound`] if no entry matches `name`; otherwise
    /// returns the same errors as
    /// [`extract_to_memory_with_password`](Self::extract_to_memory_with_password).
    pub fn extract_to_memory_by_name_with_password(
        &self,
        name: &str,
        password: Option<&str>,
    ) -> Result<Vec<u8>, R7zError> {
        let index = self.entry_index_by_name(name)?;
        self.extract_to_memory_with_password(index, password)
    }

    /// Extract a single file by index into a writer.
    ///
    /// This streams the decoded folder into `writer` instead of materializing
    /// the whole folder in memory. The returned value is the number of file
    /// bytes written.
    ///
    /// # Errors
    ///
    /// Returns the same archive, codec, and CRC errors as
    /// [`extract_to_memory`](Self::extract_to_memory), plus [`R7zError::Io`] for
    /// writer failures.
    pub fn extract_to_writer<W: Write + ?Sized>(
        &self,
        file_index: usize,
        writer: &mut W,
    ) -> Result<u64, R7zError> {
        self.extract_to_writer_with_password(file_index, writer, None)
    }

    /// Extract a file selected by entry name into a writer.
    ///
    /// Exact header-name matches are preferred. If no exact match exists and
    /// `name` is a safe archive path, r7z also matches against normalized safe
    /// entry names.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::EntryNotFound`] if no entry matches `name`; otherwise
    /// returns the same errors as [`extract_to_writer`](Self::extract_to_writer).
    pub fn extract_by_name<W: Write + ?Sized>(
        &self,
        name: &str,
        writer: &mut W,
    ) -> Result<u64, R7zError> {
        self.extract_by_name_with_password(name, writer, None)
    }

    /// Extract a file selected by entry name into a writer, supplying a password
    /// for encrypted archives.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::EntryNotFound`] if no entry matches `name`; otherwise
    /// returns the same errors as
    /// [`extract_to_writer_with_password`](Self::extract_to_writer_with_password).
    pub fn extract_by_name_with_password<W: Write + ?Sized>(
        &self,
        name: &str,
        writer: &mut W,
        password: Option<&str>,
    ) -> Result<u64, R7zError> {
        let index = self.entry_index_by_name(name)?;
        self.extract_to_writer_with_password(index, writer, password)
    }

    /// Extract a single file by index into a writer, supplying a password for
    /// encrypted archives.
    ///
    /// The decoder stream is drained after the target file has been written
    /// whenever a folder CRC is present, so corruption later in the same solid
    /// block is still detected.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::PasswordRequired`] if the file is encrypted and no
    /// password is supplied, [`R7zError::Crc`] for digest mismatches,
    /// [`R7zError::Decompression`] for codec failures, or [`R7zError::Io`] for
    /// writer failures.
    pub fn extract_to_writer_with_password<W: Write + ?Sized>(
        &self,
        file_index: usize,
        writer: &mut W,
        password: Option<&str>,
    ) -> Result<u64, R7zError> {
        let entry = Entries::new(self.try_files_info()?, self.num_files())
            .nth(file_index)
            .ok_or(R7zError::Parse)?;
        match entry.kind {
            EntryKind::Directory | EntryKind::Anti => return Err(R7zError::Directory),
            EntryKind::EmptyFile | EntryKind::EmptySymlink => return Ok(0),
            EntryKind::File(()) | EntryKind::Symlink(()) => {}
        }

        let mut session = self.read_session(password)?;
        let written = session.extract_to_writer(file_index, writer)?;
        session.finish()?;
        Ok(written)
    }

    /// Start forward-only reads that reuse solid-folder decoders between entries.
    /// No packed data is opened until an entry with a data stream is requested.
    /// Finish the session explicitly to check its final folder CRC.
    ///
    /// # Errors
    /// Returns malformed file/stream layout or packed-source range errors.
    pub fn read_session<'a>(
        &'a self,
        password: Option<&'a str>,
    ) -> Result<ArchiveReadSession<'a>, R7zError> {
        let files = FileStreams::new(
            self.try_files_info()?,
            self.num_files(),
            self.try_streams_info()?,
        )?;
        let decoder = FolderDecoder {
            source: PackedSource::new(&self.source, self.base_offset, files.pack_pos())?,
            current: None,
            mode: CompletionMode::SelectedStreams,
        };
        Ok(ArchiveReadSession {
            files,
            decoder,
            password,
            count: self.num_files(),
        })
    }

    /// Stream every file-like entry through `callback`, decoding each solid
    /// folder at most once.
    ///
    /// Directory and anti entries are skipped. Regular files, symlink entries,
    /// and zero-byte files are passed to the callback with a reader limited to
    /// that entry's contents. If the callback does not fully consume the reader,
    /// r7z drains the rest of the entry so CRC checks and later entries in the
    /// same folder remain valid.
    ///
    /// # Errors
    ///
    /// Returns archive parse, codec, password, CRC, and callback errors.
    pub fn stream_files<F>(&self, callback: F) -> Result<(), R7zError>
    where
        F: FnMut(&ArchiveEntryInfo, &mut dyn Read) -> Result<(), R7zError>,
    {
        self.stream_files_with_password(None, callback)
    }

    /// Stream every file-like entry through `callback`, supplying a password for
    /// encrypted archives.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::PasswordRequired`] if encrypted with no password,
    /// [`R7zError::Crc`] for digest mismatches, [`R7zError::Decompression`] for
    /// codec failures, or any error returned by the callback.
    pub fn stream_files_with_password<F>(
        &self,
        password: Option<&str>,
        callback: F,
    ) -> Result<(), R7zError>
    where
        F: FnMut(&ArchiveEntryInfo, &mut dyn Read) -> Result<(), R7zError>,
    {
        self.stream_files_impl(None, password, callback)
    }

    /// Stream the selected file-like entries through `callback` in archive order,
    /// decoding each selected solid folder at most once.
    ///
    /// Directory and anti entries are skipped. Regular files, symlink entries,
    /// and zero-byte files are passed to the callback. If the callback does not
    /// fully consume an entry, r7z drains the rest of it. A selected folder with
    /// a folder CRC is drained and verified in full, including unselected entries
    /// in that folder. Without a folder CRC, unselected trailing entries are not
    /// decoded. Folders with no selected entries are never opened.
    ///
    /// Duplicate or out-of-range indices return [`R7zError::InvalidOptions`]
    /// before any callback is invoked.
    ///
    /// # Errors
    ///
    /// Returns archive parse, codec, password, CRC, resource-limit, and callback
    /// errors.
    pub fn stream_selected_files<F>(&self, indices: &[usize], callback: F) -> Result<(), R7zError>
    where
        F: FnMut(&ArchiveEntryInfo, &mut dyn Read) -> Result<(), R7zError>,
    {
        self.stream_selected_files_with_password(indices, None, callback)
    }

    /// Stream selected file-like entries, supplying a password for encrypted
    /// archives. Entries are processed in archive order, regardless of the order
    /// of `indices`.
    ///
    /// Returns [`R7zError::InvalidOptions`] for duplicate or out-of-range indices,
    /// [`R7zError::PasswordRequired`] for encrypted data without a password,
    /// [`R7zError::Crc`] for digest mismatches, [`R7zError::Decompression`] for
    /// codec failures, or any error returned by the callback.
    ///
    /// # Errors
    ///
    /// Also returns [`R7zError::InvalidOptions`] for duplicate or out-of-range
    /// indices and [`R7zError::ResourceLimitExceeded`] when a decoder budget is
    /// exceeded.
    pub fn stream_selected_files_with_password<F>(
        &self,
        indices: &[usize],
        password: Option<&str>,
        callback: F,
    ) -> Result<(), R7zError>
    where
        F: FnMut(&ArchiveEntryInfo, &mut dyn Read) -> Result<(), R7zError>,
    {
        self.stream_files_impl(Some(indices), password, callback)
    }

    fn stream_files_impl<F>(
        &self,
        indices: Option<&[usize]>,
        password: Option<&str>,
        callback: F,
    ) -> Result<(), R7zError>
    where
        F: FnMut(&ArchiveEntryInfo, &mut dyn Read) -> Result<(), R7zError>,
    {
        match EntrySelection::new(indices, self.num_files())? {
            EntrySelection::Empty => Ok(()),
            selected @ EntrySelection::All(_) => self.stream_entry_selection(
                selected,
                CompletionMode::WholeFolder,
                password,
                callback,
            ),
            selected @ EntrySelection::Selected { .. } => self.stream_entry_selection(
                selected,
                CompletionMode::SelectedStreams,
                password,
                callback,
            ),
        }
    }

    fn stream_entry_selection(
        &self,
        selected: EntrySelection<'_>,
        mode: CompletionMode,
        password: Option<&str>,
        mut callback: impl FnMut(&ArchiveEntryInfo, &mut dyn Read) -> Result<(), R7zError>,
    ) -> Result<(), R7zError> {
        let files = FileStreams::new(
            self.try_files_info()?,
            self.num_files(),
            self.try_streams_info()?,
        )?;
        let mut decoder = FolderDecoder {
            source: PackedSource::new(&self.source, self.base_offset, files.pack_pos())?,
            current: None,
            mode,
        };
        files
            .map_selected(selected, |file| {
                let entry = ArchiveEntryInfo::from_entry(&file);
                match file.kind {
                    EntryKind::File(location) | EntryKind::Symlink(location) => {
                        decoder.read(location, &entry, password, &mut callback)
                    }
                    EntryKind::EmptyFile | EntryKind::EmptySymlink => {
                        callback(&entry, &mut std::io::empty())
                    }
                    EntryKind::Directory | EntryKind::Anti => Ok(()),
                }
            })
            .collect::<Result<(), _>>()?;
        decoder.finish()
    }

    pub fn symlink_target(&self, file_index: usize) -> Result<Option<String>, R7zError> {
        let Some(entry) = Entries::new(self.try_files_info()?, self.num_files()).nth(file_index)
        else {
            return Ok(None);
        };
        match entry.kind {
            EntryKind::Symlink(()) | EntryKind::EmptySymlink => {}
            _ => return Ok(None),
        }

        let target = self.extract_to_memory(file_index)?;
        String::from_utf8(target)
            .map(Some)
            .map_err(|_| R7zError::Parse)
    }

    fn listing_entry(file: FileStream<'_, '_>) -> ArchiveListingEntry {
        let kind = match file.kind.entry_type() {
            EntryType::File | EntryType::EmptyFile => ListingEntryKind::File,
            EntryType::Symlink | EntryType::EmptySymlink => ListingEntryKind::Symlink,
            EntryType::Directory => ListingEntryKind::Directory,
            EntryType::Anti => ListingEntryKind::Anti,
        };
        let mut entry = ArchiveListingEntry {
            index: file.metadata.index.get(),
            path: file.metadata.name(),
            kind,
            size: None,
            packed_size: None,
            modified: file.metadata.modified.and_then(filetime_to_system_time),
            attributes: file.metadata.attributes,
            crc: None,
            encrypted: false,
            methods: Vec::new(),
            block: None,
        };
        match file.kind {
            EntryKind::File(location) | EntryKind::Symlink(location) => {
                entry.size = Some(location.stream.range.end - location.stream.range.start);
                entry.packed_size = location
                    .stream_index
                    .is_first()
                    .then(|| location.folder.packed_size());
                entry.crc = location.stream.digest;
                entry.methods = folder_method_names(location.folder.folder());
                entry.encrypted = folder_is_encrypted(location.folder.folder());
                entry.block = Some(location.folder_index.get());
            }
            EntryKind::EmptyFile | EntryKind::EmptySymlink => {
                entry.size = Some(0);
                entry.crc = Some(0);
            }
            EntryKind::Directory => entry.size = Some(0),
            EntryKind::Anti => {}
        }
        entry
    }

    fn entry_index_by_name(&self, name: &str) -> Result<usize, R7zError> {
        if let Some(entry) = self.entries().find(|entry| entry.name == name) {
            return Ok(entry.index);
        }

        let requested_safe_name = safe_archive_name(name).ok();
        if let Some(requested_safe_name) = requested_safe_name {
            if let Some(entry) = self
                .entries()
                .find(|entry| entry.safe_name.as_deref() == Some(requested_safe_name.as_path()))
            {
                return Ok(entry.index);
            }
        }

        Err(R7zError::EntryNotFound(name.to_string()))
    }

    #[cfg(test)]
    fn folder_stream_for_file(
        &self,
        file_index: usize,
    ) -> Result<Option<(usize, usize)>, R7zError> {
        let mut files = FileStreams::new(
            self.try_files_info()?,
            self.num_files(),
            self.try_streams_info()?,
        )?;
        Ok(files.nth(file_index)?.and_then(|file| match file.kind {
            EntryKind::File(location) | EntryKind::Symlink(location) => {
                Some((location.folder_index.get(), location.stream_index.get()))
            }
            _ => None,
        }))
    }

    /// Extract all files to a directory.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Io`] if a file or directory cannot be created, or any error
    /// that [`stream_files`](Self::stream_files) can return.
    pub fn extract_all(&self, dest: &Path) -> Result<(), R7zError> {
        self.extract_all_with_password(dest, None)
    }

    /// Extract all files to a directory, supplying a password for encrypted archives.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Io`] if a file or directory cannot be created,
    /// [`R7zError::PasswordRequired`] if encrypted with no password, or any
    /// error that [`stream_files_with_password`](Self::stream_files_with_password) can return.
    pub fn extract_all_with_password(
        &self,
        dest: &Path,
        password: Option<&str>,
    ) -> Result<(), R7zError> {
        for entry in Entries::new(self.try_files_info()?, self.num_files()) {
            if matches!(entry.kind, EntryKind::Directory) {
                let dest_path = dest.join(safe_archive_name(&entry.metadata.name())?);
                std::fs::create_dir_all(&dest_path)?;
            }
        }

        self.stream_files_with_password(password, |entry, reader| {
            let dest_path = dest.join(safe_archive_name(&entry.name)?);
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent).map_err(R7zError::Io)?;
            }
            let file = std::fs::File::create(&dest_path).map_err(R7zError::Io)?;
            let mut writer = BufWriter::new(file);
            std::io::copy(reader, &mut writer).map_err(R7zError::Io)?;
            writer.flush().map_err(R7zError::Io)
        })
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn verify_source_crc(
    source: &ArchiveSource,
    range: Range<u64>,
    expected: u32,
) -> Result<(), R7zError> {
    let mut reader = source.range_reader(range)?;
    let mut hasher = crc32fast::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buffer).map_err(R7zError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    if hasher.finalize() == expected {
        Ok(())
    } else {
        Err(R7zError::Crc)
    }
}

fn decode_encoded_header(
    source: &ArchiveSource,
    base_offset: u64,
    encoded: &EncodedHeader,
    password: Option<&str>,
    budget: MetadataBudget,
) -> Result<Header, R7zError> {
    let folder = encoded.folder(budget.remaining())?;
    let packs = PackedSource::new(source, base_offset, encoded.pack_info.pack_pos)?;
    let decoded = decode_metadata_folder(&packs, folder, password, budget.remaining())?;
    parse_header_with_external_data(source, base_offset, decoded.as_bytes(), budget, password)
}

fn parse_header_with_external_data(
    source: &ArchiveSource,
    base_offset: u64,
    bytes: &Bytes,
    budget: MetadataBudget,
    password: Option<&str>,
) -> Result<Header, R7zError> {
    let budget = budget.charge(bytes.len() as u64)?;
    match Header::resolve_archive(bytes)? {
        HeaderResolution::Complete(header) => {
            verify_additional_stream_crcs(source, base_offset, &header)?;
            Ok(*header)
        }
        HeaderResolution::RequiresExternalFolders(pending) => pending.resolve_with(|additional| {
            decode_additional_folder_data(source, base_offset, additional, budget, password)
        }),
    }
}

fn decode_additional_folder_data(
    source: &ArchiveSource,
    base_offset: u64,
    streams: &StreamInfo,
    budget: MetadataBudget,
    password: Option<&str>,
) -> Result<VerifiedExternalData, R7zError> {
    let plan = ExternalFolderPlan::new(streams, budget)?;
    let packs = PackedSource::new(source, base_offset, plan.pack_pos())?;
    plan.decode(|stream| packs.reader(&stream), password)
}

struct PackedSource<'a> {
    source: &'a ArchiveSource,
    start: u64,
}

impl<'a> PackedSource<'a> {
    fn new(source: &'a ArchiveSource, base_offset: u64, pack_pos: u64) -> Result<Self, R7zError> {
        let start = checked_add_u64(checked_add_u64(base_offset, 32)?, pack_pos)?;
        Ok(Self { source, start })
    }

    fn range(&self, stream: &PackedStream) -> Result<Range<u64>, R7zError> {
        let start = checked_add_u64(self.start, stream.range.start)?;
        let size = stream.range.end - stream.range.start;
        let range = checked_range_u64(self.source.len()?, start, size)?;
        if let Some(expected) = stream.crc {
            verify_source_crc(self.source, range.clone(), expected)?;
        }
        Ok(range)
    }

    fn reader(
        &self,
        stream: &PackedStream,
    ) -> Result<codec::PackedInput<ArchiveRangeReader<'a>>, R7zError> {
        self.source.packed_input(self.range(stream)?)
    }
}

/// Keeps the active decoder for mapped entries selected by the caller.
struct FolderDecoder<'a> {
    source: PackedSource<'a>,
    current: Option<(FolderIndex, ActiveFolder<'a, 'a>)>,
    mode: CompletionMode,
}

impl<'a> FolderDecoder<'a> {
    fn read(
        &mut self,
        location: StreamLocation<'_, 'a>,
        entry: &ArchiveEntryInfo,
        password: Option<&str>,
        callback: impl FnOnce(&ArchiveEntryInfo, &mut dyn Read) -> Result<(), R7zError>,
    ) -> Result<(), R7zError> {
        let active = match self.current.take() {
            Some((index, active)) if index == location.folder_index => active,
            previous => {
                if let Some((_, previous)) = previous {
                    let _completion = previous.finish(self.mode)?;
                }
                location
                    .folder
                    .bind(|stream| self.source.reader(&stream))?
                    .start(password)?
            }
        };
        let active = active
            .skip_to(location.stream_index.get())?
            .read_stream(|reader| callback(entry, reader))?;
        self.current = Some((location.folder_index, active));
        Ok(())
    }

    fn finish(&mut self) -> Result<(), R7zError> {
        if let Some((_, active)) = self.current.take() {
            let _completion = active.finish(self.mode)?;
        }
        Ok(())
    }
}

fn decode_metadata_folder<'a>(
    packs: &PackedSource<'_>,
    folder: FolderLayout<'a>,
    password: Option<&str>,
    metadata_limit: u64,
) -> Result<DecodedFolder<'a>, R7zError> {
    folder
        .bind(|stream| packs.reader(&stream))?
        .collect(password, metadata_limit)
}

fn verify_additional_stream_crcs(
    source: &ArchiveSource,
    base_offset: u64,
    header: &Header,
) -> Result<(), R7zError> {
    header.additional_pack_info()?.map_or(Ok(()), |pack_info| {
        verify_additional_pack_crcs(source, base_offset, pack_info)
    })
}

fn verify_additional_pack_crcs(
    source: &ArchiveSource,
    base_offset: u64,
    pack_info: &crate::PackInfo,
) -> Result<(), R7zError> {
    let data_start = checked_add_u64(checked_add_u64(base_offset, 32)?, pack_info.pack_pos)?;
    let mut pack_offset = 0u64;
    for (index, &pack_size) in pack_info.pack_size.iter().enumerate() {
        let start = checked_add_u64(data_start, pack_offset)?;
        let range = checked_range_u64(source.len()?, start, pack_size)?;
        if let Some(expected_crc) = pack_info.digests.get(index).copied().flatten() {
            verify_source_crc(source, range, expected_crc)?;
        }
        pack_offset = checked_add_u64(pack_offset, pack_size)?;
    }
    Ok(())
}

fn archive_method_names(streams: Option<&StreamInfo>) -> Result<Vec<String>, R7zError> {
    let mut names = Vec::new();
    if let Some(streams) = streams {
        if let Some(unpack) = &streams.unpack_info {
            for idx in 0..unpack.num_folders_usize() {
                let folder = unpack.parse_folder(idx)?;
                for name in folder.coders.iter().map(archive_method_name) {
                    if !names.contains(&name) {
                        names.push(name);
                    }
                }
            }
        }
    }
    Ok(p7zip_method_order(names))
}

fn folder_method_names(folder: &crate::Folder) -> Vec<String> {
    p7zip_method_order(folder.coders.iter().map(entry_method_name).collect())
}

fn p7zip_method_order(names: Vec<String>) -> Vec<String> {
    let (mut regular, crypto): (Vec<_>, Vec<_>) = names
        .into_iter()
        .partition(|name| !is_crypto_method_name(name));
    regular.extend(crypto);
    regular
}

fn is_crypto_method_name(name: &str) -> bool {
    name.starts_with("7zAES") || name.starts_with("AES256CBC")
}

fn archive_method_name(coder: &crate::CoderInfo) -> String {
    match crate::method_from_id(&coder.codec_id) {
        Some(crate::SevenZMethod::Lzma | crate::SevenZMethod::Lzma2) => entry_method_name(coder),
        Some(crate::SevenZMethod::Ppmd) => "PPMD".to_string(),
        Some(crate::SevenZMethod::SevenZAes) => "7zAES".to_string(),
        Some(method) => method.name().to_string(),
        None => format!("{:02X?}", coder.codec_id),
    }
}

fn entry_method_name(coder: &crate::CoderInfo) -> String {
    match crate::method_from_id(&coder.codec_id) {
        Some(crate::SevenZMethod::Lzma) => coder
            .properties
            .as_deref()
            .and_then(lzma_dictionary_bits)
            .map_or_else(|| "LZMA".to_string(), |bits| format!("LZMA:{bits}")),
        Some(crate::SevenZMethod::Lzma2) => coder
            .properties
            .as_deref()
            .and_then(lzma2_dictionary_bits)
            .map_or_else(|| "LZMA2".to_string(), |bits| format!("LZMA2:{bits}")),
        Some(crate::SevenZMethod::Ppmd) => {
            ppmd_method_text(coder).unwrap_or_else(|| "PPMD".to_string())
        }
        Some(crate::SevenZMethod::SevenZAes) => coder
            .properties
            .as_deref()
            .and_then(|props| props.first().map(|byte| byte & 0x3f))
            .map_or_else(|| "7zAES".to_string(), |cycles| format!("7zAES:{cycles}")),
        Some(method) => method.name().to_string(),
        None => format!("{:02X?}", coder.codec_id),
    }
}

fn lzma_dictionary_bits(props: &[u8]) -> Option<u32> {
    if props.len() != 5 {
        return None;
    }
    dictionary_bits(u32::from_le_bytes([props[1], props[2], props[3], props[4]]))
}

fn lzma2_dictionary_bits(props: &[u8]) -> Option<u32> {
    let &[prop] = props else {
        return None;
    };
    let dict_size = match prop {
        0..=39 => {
            let base = 2u32 | (u32::from(prop) & 1);
            base.checked_shl((u32::from(prop) >> 1) + 11)?
        }
        40 => u32::MAX,
        _ => return None,
    };
    dictionary_bits(dict_size)
}

fn dictionary_bits(size: u32) -> Option<u32> {
    if size.is_power_of_two() {
        Some(size.trailing_zeros())
    } else {
        None
    }
}

fn ppmd_method_text(coder: &crate::CoderInfo) -> Option<String> {
    let props = coder.properties.as_deref()?;
    if props.len() != 5 {
        return None;
    }
    let order = props[0];
    let mem_size = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
    let mem_text =
        dictionary_bits(mem_size).map_or_else(|| mem_size.to_string(), |bits| bits.to_string());
    Some(format!("PPMD:o{order}:mem{mem_text}"))
}

fn archive_is_solid(streams: Option<&StreamInfo>) -> bool {
    streams
        .and_then(|streams| streams.substream_info.as_ref())
        .is_some_and(|substreams| {
            substreams
                .num_unpack_streams_per_folder
                .iter()
                .any(|&streams| streams > 1)
        })
}

fn folder_is_encrypted(folder: &crate::Folder) -> bool {
    folder
        .coders
        .iter()
        .any(|coder| coder.codec_id.as_slice() == codec::CODEC_AES_256_SHA_256)
}

fn filetime_to_system_time(filetime: u64) -> Option<SystemTime> {
    const WINDOWS_TO_UNIX_SECS: u64 = 11_644_473_600;
    let secs = filetime / 10_000_000;
    let nanos = (filetime % 10_000_000) * 100;
    if secs < WINDOWS_TO_UNIX_SECS {
        return None;
    }
    Some(UNIX_EPOCH + Duration::new(secs - WINDOWS_TO_UNIX_SECS, nanos as u32))
}

fn checked_add_usize(lhs: usize, rhs: usize) -> Result<usize, R7zError> {
    lhs.checked_add(rhs).ok_or(R7zError::Parse)
}

fn checked_add_u64(lhs: u64, rhs: u64) -> Result<u64, R7zError> {
    lhs.checked_add(rhs).ok_or(R7zError::Parse)
}

fn checked_sub_u64(lhs: u64, rhs: u64) -> Result<u64, R7zError> {
    lhs.checked_sub(rhs).ok_or(R7zError::Parse)
}

fn checked_range(total_len: usize, start: usize, len: u64) -> Result<Range<usize>, R7zError> {
    let len = usize::try_from(len).map_err(|_| R7zError::Parse)?;
    let end = start.checked_add(len).ok_or(R7zError::Parse)?;
    if end <= total_len {
        Ok(start..end)
    } else {
        Err(R7zError::Parse)
    }
}

fn checked_range_u64(total_len: u64, start: u64, len: u64) -> Result<Range<u64>, R7zError> {
    let end = start.checked_add(len).ok_or(R7zError::Parse)?;
    if end <= total_len {
        Ok(start..end)
    } else {
        Err(R7zError::Parse)
    }
}

fn find_signature_in_slice(data: &[u8]) -> Result<usize, R7zError> {
    let mut saw_bad_signature = false;
    for offset in find_magic_offsets(data) {
        let Some(signature_bytes) = data.get(offset..offset.saturating_add(32)) else {
            continue;
        };
        if signature_bytes.len() < 32 {
            continue;
        }
        let (_, signature) =
            SignatureHeader::parse(signature_bytes).map_err(|_| R7zError::Parse)?;
        match signature.validate_start_header_crc() {
            Ok(()) => return Ok(offset),
            Err(R7zError::Crc) => saw_bad_signature = true,
            Err(err) => return Err(err),
        }
    }

    if saw_bad_signature {
        Err(R7zError::Crc)
    } else {
        Err(R7zError::Parse)
    }
}

fn find_magic_offsets(haystack: &[u8]) -> impl Iterator<Item = usize> + '_ {
    haystack
        .windows(SEVEN_Z_MAGIC.len())
        .enumerate()
        .filter_map(|(idx, bytes)| (bytes == SEVEN_Z_MAGIC).then_some(idx))
}

fn is_split_first_volume(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "001")
}

fn split_volume_path(first_volume: &Path, idx: u64) -> PathBuf {
    first_volume.with_extension(format!("{idx:03}"))
}

fn ensure_packed_folder_buffer_limit(pack_sizes: &[u64]) -> Result<(), R7zError> {
    let packed_bytes = pack_sizes.iter().try_fold(0u64, |total, &size| {
        total.checked_add(size).ok_or(R7zError::Parse)
    })?;
    ensure_packed_bytes_limit(packed_bytes)
}

fn ensure_packed_bytes_limit(packed_bytes: u64) -> Result<(), R7zError> {
    let limit =
        u64::try_from(codec::MAX_BUFFERED_PACKED_FOLDER_BYTES).map_err(|_| R7zError::Parse)?;
    if packed_bytes > limit {
        return Err(R7zError::ResourceLimitExceeded {
            resource: "packed folder buffers",
            limit: codec::MAX_BUFFERED_PACKED_FOLDER_BYTES,
        });
    }
    Ok(())
}

/// Normalize an archive entry name into a safe relative path.
///
/// Both `/` and `\` are treated as archive separators. Empty path components
/// and `.` are removed; absolute paths, parent traversal, Windows drive/UNC
/// prefixes, and names that normalize to an empty path are rejected.
///
/// # Errors
///
/// Returns [`R7zError::UnsafePath`] when `name` cannot be safely joined under
/// an extraction directory.
pub fn safe_archive_name(name: &str) -> Result<PathBuf, R7zError> {
    if name.is_empty()
        || name.contains('\0')
        || name.starts_with(['/', '\\'])
        || has_windows_prefix(name)
        || has_parent_component(name)
    {
        return Err(R7zError::UnsafePath(name.to_string()));
    }

    let mut normalized = PathBuf::new();
    for part in name.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                return Err(R7zError::UnsafePath(name.to_string()));
            }
            part => normalized.push(part),
        }
    }

    if normalized.as_os_str().is_empty() {
        Err(R7zError::UnsafePath(name.to_string()))
    } else {
        Ok(normalized)
    }
}

fn has_parent_component(name: &str) -> bool {
    name.split(['/', '\\']).any(|part| part == "..")
}

fn has_windows_prefix(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
        || name.starts_with("\\\\")
}

#[cfg(test)]
mod selected_stream_tests {
    use super::*;
    use crate::{ArchiveBuilder, ArchiveOptions, Codec, CompressionOptions, EntryMeta, SolidMode};
    use std::num::NonZeroU64;

    struct ErrorsThenData {
        errors: std::vec::IntoIter<std::io::Error>,
        data: &'static [u8],
    }

    impl Read for ErrorsThenData {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            match self.errors.next() {
                Some(error) => Err(error),
                None => self.data.read(buffer),
            }
        }
    }

    #[test]
    fn entry_copy_retries_direct_and_wrapped_interruptions() {
        let interrupted = std::io::ErrorKind::Interrupted;
        let mut reader = ErrorsThenData {
            errors: vec![
                interrupted.into(),
                std::io::Error::other(R7zError::Io(interrupted.into())),
            ]
            .into_iter(),
            data: b"payload",
        };
        let mut output = Vec::new();
        assert_eq!(copy_entry(&mut reader, &mut output).unwrap(), 7);
        assert_eq!(output, b"payload");
    }

    #[test]
    fn entry_copy_preserves_wrapped_source_errors() {
        [
            R7zError::Parse,
            R7zError::LimitExceeded("packed source"),
            R7zError::Io(std::io::ErrorKind::PermissionDenied.into()),
        ]
        .into_iter()
        .for_each(|expected| {
            let message = expected.to_string();
            let variant = std::mem::discriminant(&expected);
            let mut reader = ErrorsThenData {
                errors: vec![std::io::Error::other(expected)].into_iter(),
                data: b"unread",
            };
            let mut output = Vec::new();
            let error = copy_entry(&mut reader, &mut output).unwrap_err();
            assert_eq!(std::mem::discriminant(&error), variant);
            assert_eq!(error.to_string(), message);
            assert!(output.is_empty());
        });
    }

    #[test]
    fn entry_copy_classifies_unrecognized_read_errors_as_decompression() {
        let mut reader = ErrorsThenData {
            errors: vec![std::io::ErrorKind::InvalidData.into()].into_iter(),
            data: b"unread",
        };
        assert!(matches!(
            copy_entry(&mut reader, &mut std::io::sink()),
            Err(R7zError::Decompression)
        ));
    }

    #[test]
    fn entry_copy_keeps_writer_errors_as_io_even_when_they_wrap_archive_errors() {
        struct FailedWriter;
        impl Write for FailedWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other(R7zError::LimitExceeded("output")))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let error = copy_entry(&mut &b"payload"[..], &mut FailedWriter).unwrap_err();
        let R7zError::Io(error) = error else {
            panic!("expected writer I/O error")
        };
        assert!(matches!(
            error.downcast::<R7zError>(),
            Ok(R7zError::LimitExceeded("output"))
        ));
    }

    fn three_file_archive() -> Vec<u8> {
        let options = ArchiveOptions {
            codec: Codec::Copy,
            compression: CompressionOptions {
                solid: SolidMode::Limit {
                    max_files: NonZeroU64::new(2),
                    max_bytes: None,
                },
                ..CompressionOptions::default()
            },
            ..ArchiveOptions::default()
        };
        ArchiveBuilder::new()
            .options(options)
            .add_file("first.txt", b"first payload")
            .add_file("second.txt", b"second payload")
            .add_file("later.txt", b"later payload")
            .build()
            .unwrap()
    }

    #[test]
    fn decodes_additional_streams_used_for_external_folder_definitions() {
        let (bytes, _) = archive_with_external_folder_metadata(false);
        let parsed = Archive::from_bytes(bytes).unwrap();
        let main = parsed.header.try_streams_info().unwrap().unwrap();
        assert_eq!(
            main.unpack_info
                .as_ref()
                .unwrap()
                .parse_folder(0)
                .unwrap()
                .coders
                .len(),
            1
        );
    }

    fn archive_with_external_folder_metadata(encoded: bool) -> (Bytes, u64) {
        let header = Bytes::from_static(&[
            0x01, 0x03, // Header + AdditionalStreamsInfo
            0x06, 0x00, 0x01, 0x09, 0x03, 0x00, // one packed stream
            0x07, 0x0b, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0c, 0x03, 0x00, // copy folder
            0x08, 0x00, 0x00, // SubStreamsInfo and AdditionalStreamsInfo end
            0x04, 0x07, 0x0b, 0x01, 0x01, 0x00, 0x0c, 0x03, 0x00, 0x00, // main external ref
            0x05, 0x00, 0x00, 0x00, // empty FilesInfo and Header end
        ]);
        let mut archive = vec![0u8; 32];
        archive[..6].copy_from_slice(b"7z\xbc\xaf'\x1c");
        archive[6] = 0;
        archive[7] = 4;
        archive.extend_from_slice(&[0x01, 0x01, 0x00]);
        archive.extend_from_slice(&header);
        let mut retained = header.len() as u64 + 3 + std::mem::size_of::<Bytes>() as u64;
        let (next_header, offset) = if encoded {
            let size = u8::try_from(header.len()).unwrap();
            assert!(size < 128);
            let descriptor = Bytes::from(vec![
                0x17, // EncodedHeader
                0x06, 0x03, 0x01, 0x09, size, 0x00, // packed header after external bytes
                0x07, 0x0b, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0c, size, 0x00, // copy
                0x00,
            ]);
            retained += descriptor.len() as u64;
            archive.extend_from_slice(&descriptor);
            (descriptor, 3 + header.len() as u64)
        } else {
            (header, 3)
        };
        archive[12..20].copy_from_slice(&offset.to_le_bytes());
        archive[20..28].copy_from_slice(&(next_header.len() as u64).to_le_bytes());
        archive[28..32].copy_from_slice(&crc32fast::hash(&next_header).to_le_bytes());
        let start_crc = crc32fast::hash(&archive[12..32]);
        archive[8..12].copy_from_slice(&start_crc.to_le_bytes());
        (Bytes::from(archive), retained)
    }

    #[test]
    fn metadata_budget_is_shared_by_headers_external_bytes_and_slots() {
        for encoded in [false, true] {
            let (bytes, required) = archive_with_external_folder_metadata(encoded);
            for seekable in [false, true] {
                let open = |limit| {
                    let source = if seekable {
                        ArchiveSource::from_reader(std::io::Cursor::new(bytes.clone())).unwrap()
                    } else {
                        ArchiveSource::Bytes(bytes.clone())
                    };
                    Archive::from_source_with_password(
                        source,
                        None,
                        ArchiveOpenOptions {
                            max_metadata_bytes: limit,
                            ..ArchiveOpenOptions::default()
                        },
                    )
                };
                assert!(
                    open(required).is_ok(),
                    "encoded={encoded}, seekable={seekable}"
                );
                assert!(
                    matches!(open(required - 1), Err(R7zError::LimitExceeded("metadata"))),
                    "encoded={encoded}, seekable={seekable}"
                );
            }
        }
    }

    fn archive_with_many_files(solid: SolidMode) -> (Vec<u8>, Vec<Vec<u8>>) {
        let options = ArchiveOptions {
            codec: Codec::Copy,
            compression: CompressionOptions {
                solid,
                ..CompressionOptions::default()
            },
            ..ArchiveOptions::default()
        };
        let (builder, expected) = (0..128).fold(
            (ArchiveBuilder::new().options(options), Vec::new()),
            |(builder, mut expected), index| {
                let name = format!("entry-{index}.bin");
                let data = format!("payload-{index}").into_bytes();
                expected.push(data.clone());
                (builder.add_file(&name, &data), expected)
            },
        );
        (builder.build().unwrap(), expected)
    }

    fn corruption_offset(bytes: &[u8], file_index: usize, within_stream: bool) -> usize {
        let archive = Archive::from_bytes(Bytes::copy_from_slice(bytes)).unwrap();
        let (folder_index, stream_index) =
            archive.folder_stream_for_file(file_index).unwrap().unwrap();
        let streams = archive.try_streams_info().unwrap().unwrap();
        let mut folders = FolderLayouts::for_streams(streams).unwrap();
        let position = archive.base_offset + 32 + folders.pack_pos();
        let folder = folders.nth(folder_index).unwrap().unwrap();
        let packed_start = folder.packed_streams().next().unwrap().range.start;
        let stream_start = if within_stream {
            folder.substreams().nth(stream_index).unwrap().range.start
        } else {
            0
        };
        usize::try_from(position + packed_start + stream_start).unwrap()
    }

    fn corrupt_file_data(bytes: &mut [u8], file_index: usize) {
        let offset = corruption_offset(bytes, file_index, false);
        bytes[offset] ^= 0xff;
    }

    fn corrupt_stream_data(bytes: &mut [u8], file_index: usize) {
        let offset = corruption_offset(bytes, file_index, true);
        bytes[offset] ^= 0xff;
    }

    #[test]
    fn selected_streams_batch_a_solid_folder_and_skip_unselected_later_folder() {
        let mut bytes = three_file_archive();
        let archive = Archive::from_bytes(Bytes::copy_from_slice(&bytes)).unwrap();
        let folder_for = |index| archive.folder_stream_for_file(index).unwrap().unwrap().0;
        assert_eq!(folder_for(0), folder_for(1));
        assert_ne!(folder_for(1), folder_for(2));
        drop(archive);

        corrupt_file_data(&mut bytes, 2);
        let archive = Archive::from_bytes(bytes.into()).unwrap();
        let mut seen = Vec::new();

        archive
            .stream_selected_files(&[1, 0], |entry, reader| {
                let mut first_byte = [0; 1];
                reader.read_exact(&mut first_byte)?;
                seen.push((entry.index, first_byte[0]));
                Ok(())
            })
            .unwrap();

        assert_eq!(seen, vec![(0, b'f'), (1, b's')]);
    }

    #[test]
    fn selected_stream_traversal_handles_many_folders_and_substreams() {
        let modes = [
            SolidMode::Limit {
                max_files: NonZeroU64::new(1),
                max_bytes: None,
            },
            SolidMode::Solid,
        ];
        for solid in modes {
            let (bytes, expected) = archive_with_many_files(solid);
            let archive = Archive::from_bytes(Bytes::from(bytes)).unwrap();
            let mut indices = (0..expected.len()).collect::<Vec<_>>();
            indices.reverse();
            let mut seen = Vec::new();
            archive
                .stream_selected_files(&indices, |entry, reader| {
                    let mut data = Vec::new();
                    reader.read_to_end(&mut data).map_err(R7zError::Io)?;
                    seen.push((entry.index, data));
                    Ok(())
                })
                .unwrap();

            assert_eq!(seen.len(), expected.len());
            for (index, data) in seen {
                assert_eq!(data, expected[index]);
            }

            let listing = archive.listing(None).unwrap();
            assert_eq!(listing.entries.len(), expected.len());
            for (index, entry) in listing.entries.iter().enumerate() {
                assert_eq!(entry.path, format!("entry-{index}.bin"));
                assert_eq!(entry.size, Some(expected[index].len() as u64));
            }

            let names = archive
                .entries()
                .map(|entry| entry.name)
                .collect::<Vec<_>>();
            assert_eq!(names.len(), expected.len());
            let destination = tempfile::tempdir().unwrap();
            archive.extract_all(destination.path()).unwrap();
            for (index, data) in expected.iter().enumerate() {
                let path = destination.path().join(format!("entry-{index}.bin"));
                assert_eq!(std::fs::read(path).unwrap(), *data);
            }
        }
    }

    #[test]
    fn empty_stream_symlink_does_not_advance_the_data_stream_cursor() {
        let bytes = ArchiveBuilder::new()
            .options(ArchiveOptions {
                codec: Codec::Copy,
                ..ArchiveOptions::default()
            })
            .add_empty_file("empty-link", EntryMeta::symlink())
            .add_file("following.bin", b"payload")
            .build()
            .unwrap();
        let archive = Archive::from_bytes(Bytes::from(bytes)).unwrap();
        let files = archive.files_info().unwrap();
        assert!(files.is_symlink(0));
        assert!(files.is_empty_stream(0));

        let mut seen = Vec::new();
        archive
            .stream_selected_files(&[0, 1], |entry, reader| {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).map_err(R7zError::Io)?;
                seen.push((entry.index, bytes));
                Ok(())
            })
            .unwrap();

        assert_eq!(seen, [(0, Vec::new()), (1, b"payload".to_vec())]);
        let listing = archive.listing(None).unwrap();
        assert_eq!(listing.entries[0].block, None);
        assert_eq!(listing.entries[1].block, Some(0));
        assert_eq!(listing.entries[1].size, Some(7));
        assert_eq!(listing.entries[1].packed_size, Some(7));
    }

    #[test]
    fn selected_stream_does_not_decode_unselected_tail_without_folder_crc() {
        let mut bytes = three_file_archive();
        let original = Archive::from_bytes(Bytes::copy_from_slice(&bytes)).unwrap();
        let selected_index = 0;
        let unselected_index = 1;
        assert_eq!(
            original
                .folder_stream_for_file(selected_index)
                .unwrap()
                .unwrap()
                .0,
            original
                .folder_stream_for_file(unselected_index)
                .unwrap()
                .unwrap()
                .0
        );
        drop(original);
        corrupt_stream_data(&mut bytes, unselected_index);
        let archive = Archive::from_bytes(bytes.into()).unwrap();

        let mut seen = Vec::new();
        archive
            .stream_selected_files(&[selected_index], |_entry, reader| {
                let mut first_byte = [0; 1];
                reader.read_exact(&mut first_byte)?;
                seen.push(first_byte[0]);
                Ok(())
            })
            .unwrap();

        assert_eq!(seen, vec![b'f']);
    }

    #[test]
    fn selected_stream_validates_bounds_and_duplicates_before_callbacks() {
        let archive = Archive::from_bytes(three_file_archive().into()).unwrap();
        let mut calls = 0;
        let mut callback = |_entry: &ArchiveEntryInfo, _reader: &mut dyn Read| {
            calls += 1;
            Ok(())
        };

        assert!(matches!(
            archive.stream_selected_files(&[3], &mut callback),
            Err(R7zError::InvalidOptions(
                "selected entry index out of bounds"
            ))
        ));
        assert!(matches!(
            archive.stream_selected_files(&[1, 1], &mut callback),
            Err(R7zError::InvalidOptions("duplicate selected entry index"))
        ));
        assert_eq!(calls, 0);
    }

    #[test]
    fn file_stream_mapping_rejects_unmatched_file_count_before_traversal() {
        let archive = Archive::from_bytes(three_file_archive().into()).unwrap();
        let cursor = FileStreams::new(archive.files_info(), 0, archive.streams_info());
        assert!(matches!(cursor, Err(R7zError::Parse)));
    }

    #[test]
    fn raw_folder_buffer_budget_is_checked_before_reading() {
        assert!(ensure_packed_folder_buffer_limit(&[256 * 1024 * 1024, 256 * 1024 * 1024]).is_ok());
        assert!(matches!(
            ensure_packed_folder_buffer_limit(&[256 * 1024 * 1024, 256 * 1024 * 1024 + 1]),
            Err(R7zError::ResourceLimitExceeded {
                resource: "packed folder buffers",
                ..
            })
        ));
    }

    #[test]
    fn selected_stream_preserves_empty_files_and_callback_draining() {
        let bytes = ArchiveBuilder::new()
            .add_file("first.txt", b"first payload")
            .add_empty_file("empty.txt", crate::EntryMeta::default())
            .add_file("last.txt", b"last payload")
            .build()
            .unwrap();
        let archive = Archive::from_bytes(bytes.into()).unwrap();
        let mut seen = Vec::new();

        archive
            .stream_selected_files(&[2, 1, 0], |entry, reader| {
                let mut first_byte = [0; 1];
                let n = reader.read(&mut first_byte)?;
                seen.push((entry.index, first_byte[..n].to_vec()));
                Ok(())
            })
            .unwrap();

        assert_eq!(
            seen,
            vec![(0, b"f".to_vec()), (1, Vec::new()), (2, b"l".to_vec())]
        );
    }

    fn mixed_entry_archive() -> Archive {
        let bytes = ArchiveBuilder::new()
            .compression(Codec::Copy)
            .add_directory("directory", EntryMeta::default())
            .add_empty_file("empty", EntryMeta::default())
            .add_empty_file("empty-link", EntryMeta::symlink())
            .add_directory("mode-link", EntryMeta::symlink())
            .add_anti_item("removed", EntryMeta::symlink())
            .add_file("data", b"payload")
            .add_file_entry("link", b"target", EntryMeta::symlink())
            .build()
            .unwrap();
        Archive::from_bytes(bytes.into()).unwrap()
    }

    #[test]
    fn entry_kinds_agree_across_metadata_listing_and_extraction() {
        let archive = mixed_entry_archive();
        let listing = archive.listing(None).unwrap();
        let expected = [
            (EntryType::Directory, ListingEntryKind::Directory, false),
            (EntryType::EmptyFile, ListingEntryKind::File, false),
            (EntryType::EmptySymlink, ListingEntryKind::Symlink, false),
            (EntryType::EmptySymlink, ListingEntryKind::Symlink, false),
            (EntryType::Anti, ListingEntryKind::Anti, false),
            (EntryType::File, ListingEntryKind::File, true),
            (EntryType::Symlink, ListingEntryKind::Symlink, true),
        ];
        let files = archive.files_info().unwrap();
        for ((entry, listing), (kind, listing_kind, has_stream)) in
            archive.entries().zip(&listing.entries).zip(expected)
        {
            assert_eq!(entry.entry_type, kind);
            assert_eq!(files.entry_type(entry.index), kind);
            assert_eq!(files.is_directory(entry.index), entry.is_directory());
            assert_eq!(entry.has_data_stream(), has_stream);
            assert_eq!(listing.kind, listing_kind);
            assert_eq!(listing.path, entry.name);
            assert_eq!(listing.block.is_some(), has_stream);
            assert_eq!(archive.entry(entry.index).unwrap(), entry);
            let extracted = archive.extract_to_memory(entry.index);
            if entry.is_file() {
                assert_eq!(listing.size, Some(extracted.unwrap().len() as u64));
            } else {
                assert!(matches!(extracted, Err(R7zError::Directory)));
            }
        }
        assert_eq!(archive.symlink_target(2).unwrap().as_deref(), Some(""));
        assert_eq!(archive.symlink_target(3).unwrap().as_deref(), Some(""));
        assert_eq!(archive.symlink_target(4).unwrap(), None);
        assert_eq!(
            archive.symlink_target(6).unwrap().as_deref(),
            Some("target")
        );
        assert!(archive.entry(7).is_none());
    }

    #[test]
    fn mixed_entries_preserve_names_and_stream_positions_for_selection_and_extract_all() {
        let archive = mixed_entry_archive();
        let mut seen = Vec::new();
        archive
            .stream_selected_files(&[6, 4, 3, 2, 1, 0, 5], |entry, reader| {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes)?;
                seen.push((entry.index, entry.name.clone(), bytes));
                Ok(())
            })
            .unwrap();
        assert_eq!(
            seen,
            [
                (1, "empty".into(), Vec::new()),
                (2, "empty-link".into(), Vec::new()),
                (3, "mode-link".into(), Vec::new()),
                (5, "data".into(), b"payload".to_vec()),
                (6, "link".into(), b"target".to_vec()),
            ]
        );
        let destination = tempfile::tempdir().unwrap();
        archive.extract_all(destination.path()).unwrap();
        assert!(destination.path().join("directory").is_dir());
        assert!(!destination.path().join("removed").exists());
        for (_, name, data) in seen {
            assert_eq!(std::fs::read(destination.path().join(name)).unwrap(), data);
        }
    }

    #[test]
    fn borrowed_entry_cursor_keeps_names_and_metadata_attached() {
        let modified = UNIX_EPOCH + Duration::from_secs(123456);
        let bytes = ArchiveBuilder::new()
            .compression(Codec::Copy)
            .add_file_entry(
                "first",
                b"a",
                EntryMeta {
                    mtime: Some(modified),
                    attributes: Some(0x20),
                    ..EntryMeta::default()
                },
            )
            .add_empty_file("middle", EntryMeta::default())
            .add_file("last", b"b")
            .build()
            .unwrap();
        let archive = Archive::from_bytes(bytes.into()).unwrap();
        let files = archive.files_info().unwrap();
        let mut entries = Entries::new(Some(files), archive.num_files());
        assert_eq!(entries.stream_count(), 2);
        let first = entries.next().unwrap();
        let raw_name = files.name_slices().next().unwrap().unwrap();
        assert!(std::ptr::eq(
            first.metadata.name.unwrap().as_ptr(),
            raw_name.as_ptr()
        ));
        assert_eq!(first.metadata.name(), "first");
        let listing = archive.listing(None).unwrap();
        assert_eq!(listing.entries[0].modified, Some(modified));
        assert_eq!(listing.entries[0].attributes, Some(0x20));
        assert_eq!(listing.entries[0].crc, Some(crc32fast::hash(b"a")));
        assert_eq!(listing.entries[1].crc, Some(0));
        assert_eq!(listing.entries[2].crc, Some(crc32fast::hash(b"b")));
        assert_eq!(
            entries
                .map(|entry| entry.metadata.name())
                .collect::<Vec<_>>(),
            ["middle", "last"]
        );
    }

    #[test]
    fn entry_iteration_skips_without_losing_names_or_remaining_count() {
        let archive = mixed_entry_archive();
        let mut raw = Entries::new(archive.files_info(), archive.num_files());
        let mut public = archive.entries();
        assert_eq!(raw.len(), 7);
        assert_eq!(public.len(), 7);
        for (skip, index, name) in [(2, 2, "empty-link"), (0, 3, "mode-link"), (1, 5, "data")] {
            let raw_entry = raw.nth(skip).unwrap();
            let public_entry = public.nth(skip).unwrap();
            assert_eq!(raw_entry.metadata.index.get(), index);
            assert_eq!(raw_entry.metadata.name(), name);
            assert_eq!(public_entry.index, index);
            assert_eq!(public_entry.name, name);
            assert_eq!(raw.len(), 6 - index);
            assert_eq!(public.len(), 6 - index);
        }
        assert!(raw.nth(usize::MAX).is_none());
        assert!(public.nth(usize::MAX).is_none());
        assert_eq!(raw.len(), 0);
        assert_eq!(public.len(), 0);
        assert!(raw.next().is_none());
        assert!(public.next().is_none());
        assert!(archive.entry(usize::MAX).is_none());
    }

    #[test]
    fn read_session_reuses_packed_reads_across_solid_entries() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        struct Counted {
            data: std::io::Cursor<Vec<u8>>,
            read: Arc<AtomicUsize>,
        }
        impl Read for Counted {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.data.read(buf)?;
                self.read.fetch_add(n, Ordering::Relaxed);
                Ok(n)
            }
        }
        impl Seek for Counted {
            fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
                self.data.seek(from)
            }
        }
        let count = Arc::new(AtomicUsize::new(0));
        let archive = Archive::from_reader(Counted {
            data: std::io::Cursor::new(three_file_archive()),
            read: count.clone(),
        })
        .unwrap();
        count.store(0, Ordering::Relaxed);
        archive
            .stream_selected_files(&[0, 1], |_, _| Ok(()))
            .unwrap();
        let batched = count.swap(0, Ordering::Relaxed);
        let mut session = archive.read_session(None).unwrap();
        session
            .read_entry(0, |reader| {
                let mut first = [0];
                reader.read_exact(&mut first)?;
                Ok(())
            })
            .unwrap();
        session.read_entry(1, |_| Ok(())).unwrap();
        session.finish().unwrap();
        let reused = count.swap(0, Ordering::Relaxed);
        assert!(reused > 0);
        assert_eq!(reused, batched);
        archive.extract_to_writer(0, &mut std::io::sink()).unwrap();
        archive.extract_to_writer(1, &mut std::io::sink()).unwrap();
        assert!(count.load(Ordering::Relaxed) > reused);
    }

    #[test]
    fn read_session_rejects_invalid_order_without_consuming_valid_requests() {
        let archive = mixed_entry_archive();
        let mut session = archive.read_session(None).unwrap();
        assert!(matches!(
            session.read_entry(usize::MAX, |_| panic!("invalid index")),
            Err(R7zError::InvalidOptions(_))
        ));
        assert!(matches!(
            session.read_entry(0, |_| panic!("directory")),
            Err(R7zError::Directory)
        ));
        for index in [1, 2, 3] {
            assert_eq!(
                session.extract_to_writer(index, &mut Vec::new()).unwrap(),
                0
            );
        }
        assert!(matches!(
            session.read_entry(4, |_| panic!("anti-item")),
            Err(R7zError::Directory)
        ));
        assert!(matches!(
            session.read_entry(3, |_| panic!("backward")),
            Err(R7zError::InvalidOptions(_))
        ));
        let mut data = Vec::new();
        assert_eq!(session.extract_to_writer(5, &mut data).unwrap(), 7);
        assert_eq!(data, b"payload");
        assert!(matches!(
            session.read_entry(5, |_| panic!("repeated")),
            Err(R7zError::InvalidOptions(_))
        ));
        session.extract_to_writer(6, &mut std::io::sink()).unwrap();
        session.finish().unwrap();
    }

    #[test]
    fn read_session_skips_metadata_entries_before_requested_data() {
        let archive = mixed_entry_archive();
        let mut session = archive.read_session(None).unwrap();
        let mut data = Vec::new();
        session.extract_to_writer(5, &mut data).unwrap();
        assert_eq!(data, b"payload");
        assert!(matches!(
            session.read_entry(4, |_| panic!("skipped index")),
            Err(R7zError::InvalidOptions(_))
        ));
        session.extract_to_writer(6, &mut std::io::sink()).unwrap();
        session.finish().unwrap();
    }

    #[test]
    fn read_session_recovers_at_independent_folders_after_decode_or_callback_errors() {
        for corrupt in [false, true] {
            let mut bytes = three_file_archive();
            if corrupt {
                corrupt_file_data(&mut bytes, 0);
            }
            let archive = Archive::from_bytes(bytes.into()).unwrap();
            let mut session = archive.read_session(None).unwrap();
            let result = session.read_entry(0, |reader| {
                if !corrupt {
                    return Err(R7zError::InvalidOptions("callback failure"));
                }
                std::io::copy(reader, &mut std::io::sink()).map_err(R7zError::Io)?;
                Ok(())
            });
            assert!(result.is_err());
            session.finish_folder().unwrap();
            let mut data = Vec::new();
            session.extract_to_writer(2, &mut data).unwrap();
            assert_eq!(data, archive.extract_to_memory(2).unwrap());
            session.finish().unwrap();
        }
    }

    #[test]
    fn read_session_finish_does_not_decode_unselected_tail_without_folder_crc() {
        let mut bytes = three_file_archive();
        corrupt_stream_data(&mut bytes, 1);
        let archive = Archive::from_bytes(bytes.into()).unwrap();
        let mut session = archive.read_session(None).unwrap();
        session.extract_to_writer(0, &mut std::io::sink()).unwrap();
        session.finish().unwrap();
    }

    #[test]
    fn read_session_finishing_reports_folder_crc_failure_after_selected_entry() {
        let data = b"abcd";
        let wrong_crc = crc32fast::hash(data) ^ 1;
        let mut header = vec![
            1, 4, 6, 0, 1, 9, 4, 0, // Header, main streams, packed size
            7, 0x0b, 1, 0, 1, 1, 0, 0x0c, 4, 0x0a, 1, // Copy folder, output size, CRC
        ];
        header.extend_from_slice(&wrong_crc.to_le_bytes());
        header.extend_from_slice(&[0, 8, 0x0d, 2, 9, 2, 0, 0, 5, 2, 0, 0]);
        let mut bytes = b"7z\xbc\xaf'\x1c\x00\x04".to_vec();
        let mut start = Vec::new();
        start.extend_from_slice(&4u64.to_le_bytes());
        start.extend_from_slice(&(header.len() as u64).to_le_bytes());
        start.extend_from_slice(&crc32fast::hash(&header).to_le_bytes());
        bytes.extend_from_slice(&crc32fast::hash(&start).to_le_bytes());
        bytes.extend_from_slice(&start);
        bytes.extend_from_slice(data);
        bytes.extend_from_slice(&header);
        let archive = Archive::from_bytes(bytes.into()).unwrap();
        let mut session = archive.read_session(None).unwrap();
        let mut output = Vec::new();
        session.extract_to_writer(0, &mut output).unwrap();
        assert_eq!(output, b"ab");
        assert!(matches!(session.finish_folder(), Err(R7zError::Crc)));
        session.finish().unwrap();
    }
}
