use crate::{
    EncodedHeader, FilesInfo, Header, Property, R7zError, SignatureHeader, StreamInfo, codec,
    find_next_property_id,
};
use bytes::Bytes;
use memmap2::Mmap;
use std::collections::BTreeSet;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum decompressed size accepted for the compressed archive header (metadata only).
/// A malicious archive could declare an enormous `unpack_size` to cause OOM during header
/// decompression; this cap bounds the allocation to a sane limit. File data extracted
/// via [`Archive::extract_to_memory`] is not subject to this limit.
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

    fn find_signature_offset(&self, limit: u64) -> Result<u64, R7zError> {
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
                    SignatureCandidate::Valid => return Ok(candidate),
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
            Ok(()) => Ok(SignatureCandidate::Valid),
            Err(R7zError::Crc) => Ok(SignatureCandidate::BadCrc),
            Err(err) => Err(err),
        }
    }
}

enum SignatureCandidate {
    Valid,
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
        if source_len < 32 {
            return Err(R7zError::Parse);
        }
        let base_offset = source.find_signature_offset(DEFAULT_MAX_METADATA_BYTES)?;
        let mut signature_bytes = [0u8; 32];
        source.read_exact_at(base_offset, &mut signature_bytes)?;
        let (_, signature) =
            SignatureHeader::parse(&signature_bytes).map_err(|_| R7zError::Parse)?;
        signature.validate_start_header_crc()?;

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
        let (prop_input, prop) = Property::parse(&next_header).map_err(|_| R7zError::Parse)?;

        match prop {
            Property::EncodedHeader => {
                // Parse the EncodedHeader (describes how the full header is compressed)
                let (_, encoded_header) =
                    EncodedHeader::parse(prop_input, &next_header).map_err(|_| R7zError::Parse)?;

                // Decompress the packed header stream
                let pi = &encoded_header.pack_info;
                let ui = &encoded_header.unpack_info;
                let data_start = checked_add_u64(checked_add_u64(base_offset, 32)?, pi.pack_pos)?;
                let pack_size = *pi.pack_size.first().ok_or(R7zError::Parse)?;
                if pack_size > options.max_metadata_bytes {
                    return Err(R7zError::LimitExceeded("metadata"));
                }
                let data_range = checked_range_u64(source_len, data_start, pack_size)?;
                let packed = source.read_range_to_vec(data_range, options.max_metadata_bytes)?;
                let folder = ui.parse_folder(0)?;

                // Find the final output stream's unpack size.
                // For a single coder it's just unpack_sizes[0].
                // For multi-coder (e.g. AES+LZMA2) we need the stream that
                // is NOT bound as an output in any bind pair.
                let unpack_size = {
                    let num_out = folder.total_out_streams();
                    if num_out <= 1 {
                        ui.unpack_sizes.first().copied().ok_or(R7zError::Parse)?
                    } else {
                        let mut final_idx = num_out - 1;
                        for out_idx in 0..num_out {
                            let is_bound = folder
                                .bind_pairs
                                .iter()
                                .any(|&(_, bound_out)| bound_out == out_idx as u64);
                            if !is_bound {
                                final_idx = out_idx;
                                break;
                            }
                        }
                        ui.unpack_sizes
                            .get(final_idx)
                            .copied()
                            .ok_or(R7zError::Parse)?
                    }
                };
                if unpack_size > options.max_metadata_bytes {
                    return Err(R7zError::LimitExceeded("metadata"));
                }
                let decompressed = codec::decompress_folder_with_password_and_sizes(
                    &folder,
                    &packed,
                    unpack_size,
                    &ui.unpack_sizes,
                    password,
                )?;
                let decompressed = Bytes::from(decompressed);

                let (_, header) = Header::parse(&decompressed).map_err(|_| R7zError::Parse)?;

                Ok(Archive {
                    source,
                    base_offset,
                    signature,
                    encoded_header: Some(encoded_header),
                    header,
                })
            }
            Property::Header => {
                // Header is stored uncompressed at next_header_offset (the raw bytes
                // include the 0x01 tag, so we slice from header_start, not header_start+1)
                let (_, header) = Header::parse(&next_header).map_err(|_| R7zError::Parse)?;

                Ok(Archive {
                    source,
                    base_offset,
                    signature,
                    encoded_header: None,
                    header,
                })
            }
            _ => Err(R7zError::Parse),
        }
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

    #[must_use]
    pub fn streams_info(&self) -> Option<&StreamInfo> {
        self.header.streams_info()
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
        let streams = self.streams_info();
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
            .map(|unpack_info| unpack_info.num_folders_usize())
            .unwrap_or(0);
        let solid = archive_is_solid(streams);

        let mut first_entry_for_folder = vec![true; blocks];
        let mut entries = Vec::with_capacity(self.num_files());
        for index in 0..self.num_files() {
            entries.push(self.listing_entry(index, &mut first_entry_for_folder)?);
        }

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
        if file_index >= self.num_files() {
            return Err(R7zError::Parse);
        }

        let fi = self.header.files_info();
        if fi.is_some_and(|f| f.is_anti(file_index) || f.is_directory(file_index)) {
            return Err(R7zError::Directory);
        }
        if fi.is_some_and(|f| f.is_empty_stream(file_index) && f.is_empty_file(file_index)) {
            return Ok(0);
        }

        let location = self.extraction_location(file_index)?;
        let mut reader: Box<dyn Read> = if location.packed_ranges.len() == 1 {
            let packed = self
                .source
                .range_reader(location.packed_ranges[0].clone())?;
            codec::folder_reader_with_sizes_from_reader(
                &location.folder,
                Box::new(packed),
                location.folder_unpack_size,
                &location.coder_unpack_sizes,
                password,
            )?
        } else {
            let mut packed_streams = Vec::with_capacity(location.packed_ranges.len());
            for range in &location.packed_ranges {
                packed_streams.push(self.source.read_range_to_vec(range.clone(), u64::MAX)?);
            }
            codec::folder_reader_with_pack_streams(
                &location.folder,
                packed_streams,
                location.folder_unpack_size,
                &location.coder_unpack_sizes,
                password,
            )?
        };

        let mut folder_hasher = location.folder_digest.map(|_| crc32fast::Hasher::new());
        let mut stream_hasher = location.substream_digest.map(|_| crc32fast::Hasher::new());
        let mut decoded_len = 0u64;
        let mut remaining_skip = location.stream_start;
        let mut remaining_take = location.stream_size;
        let mut written = 0u64;
        let mut buf = [0u8; 8192];

        loop {
            let n = reader.read(&mut buf).map_err(|_| R7zError::Decompression)?;
            if n == 0 {
                break;
            }

            decoded_len = decoded_len.checked_add(n as u64).ok_or(R7zError::Parse)?;

            if let Some(hasher) = folder_hasher.as_mut() {
                hasher.update(&buf[..n]);
            }

            let mut offset = 0usize;
            if remaining_skip > 0 {
                let skip = remaining_skip.min(n);
                remaining_skip -= skip;
                offset += skip;
            }

            if remaining_skip == 0 && remaining_take > 0 && offset < n {
                let take = remaining_take.min(n - offset);
                let bytes = &buf[offset..offset + take];
                writer.write_all(bytes)?;
                if let Some(hasher) = stream_hasher.as_mut() {
                    hasher.update(bytes);
                }
                remaining_take -= take;
                written = written.checked_add(take as u64).ok_or(R7zError::Parse)?;
            }

            if remaining_skip == 0 && remaining_take == 0 && location.folder_digest.is_none() {
                break;
            }
        }

        if remaining_skip > 0 || remaining_take > 0 {
            return Err(R7zError::Decompression);
        }

        if let Some(expected) = location.folder_digest {
            let actual = folder_hasher.ok_or(R7zError::Parse)?.finalize();
            if actual != expected {
                return Err(R7zError::Crc);
            }
        }

        if let Some(expected) = location.substream_digest {
            let actual = stream_hasher.ok_or(R7zError::Parse)?.finalize();
            if actual != expected {
                return Err(R7zError::Crc);
            }
        }

        if decoded_len < location.stream_end_u64()? {
            return Err(R7zError::Decompression);
        }

        Ok(written)
    }

    pub fn symlink_target(&self, file_index: usize) -> Result<Option<String>, R7zError> {
        let Some(fi) = self.files_info() else {
            return Ok(None);
        };
        if !fi.is_symlink(file_index) {
            return Ok(None);
        }
        let target = self.extract_to_memory(file_index)?;
        String::from_utf8(target)
            .map(Some)
            .map_err(|_| R7zError::Parse)
    }

    fn extraction_location(&self, file_index: usize) -> Result<ExtractionLocation, R7zError> {
        let fi = self.header.files_info();
        let streams = self.streams_info().ok_or(R7zError::Parse)?;
        let pack_info = streams.pack_info.as_ref().ok_or(R7zError::Parse)?;
        let unpack_info = streams.unpack_info.as_ref().ok_or(R7zError::Parse)?;
        let substream_info = streams.substream_info.as_ref();

        // Map file_index → (data_stream_index) by skipping empty files
        let data_stream_idx = file_to_data_stream(file_index, fi);
        let data_stream_idx = data_stream_idx.ok_or(R7zError::Parse)?;

        // Find which folder + in-folder offset holds data_stream_idx
        let (folder_idx, stream_in_folder) = data_stream_to_folder(
            data_stream_idx,
            substream_info,
            usize::try_from(unpack_info.num_folders).map_err(|_| R7zError::Parse)?,
        )
        .ok_or(R7zError::Parse)?;

        // Locate the packed bytes for the folder that contains this file stream.
        let folder = unpack_info.parse_folder(folder_idx)?;
        let pack_stream_base = folder_pack_stream_base(folder_idx, unpack_info)?;
        let num_pack_streams = folder_num_pack_streams(&folder)?;
        let prior_pack_sizes = pack_info
            .pack_size
            .get(..pack_stream_base)
            .ok_or(R7zError::Parse)?;
        let mut pack_offset_u64 = prior_pack_sizes.iter().try_fold(0u64, |acc, &size| {
            acc.checked_add(size).ok_or(R7zError::Parse)
        })?;
        let data_start =
            checked_add_u64(checked_add_u64(self.base_offset, 32)?, pack_info.pack_pos)?;
        let pack_sizes = pack_info
            .pack_size
            .get(pack_stream_base..pack_stream_base + num_pack_streams)
            .ok_or(R7zError::Parse)?;
        let mut packed_ranges = Vec::with_capacity(num_pack_streams);
        for &pack_size in pack_sizes {
            let stream_start = checked_add_u64(data_start, pack_offset_u64)?;
            packed_ranges.push(checked_range_u64(
                self.source.len()?,
                stream_start,
                pack_size,
            )?);
            pack_offset_u64 = checked_add_u64(pack_offset_u64, pack_size)?;
        }

        let folder_unpack_size = folder_total_unpack_size(folder_idx, unpack_info, substream_info)?;
        let coder_unpack_sizes = folder_coder_unpack_sizes(folder_idx, unpack_info)?;
        let stream_start =
            stream_offset_in_folder(folder_idx, stream_in_folder, substream_info, unpack_info)?;
        let stream_size =
            stream_size_at(folder_idx, stream_in_folder, substream_info, unpack_info)?;
        let folder_digest = unpack_info.digests.get(folder_idx).copied().flatten();
        let substream_digest = if let Some(si) = substream_info {
            let crc_idx = substream_global_index(folder_idx, stream_in_folder, si)?;
            si.digests.get(crc_idx).copied().flatten()
        } else {
            None
        };

        Ok(ExtractionLocation {
            folder,
            packed_ranges,
            folder_unpack_size,
            coder_unpack_sizes,
            stream_start,
            stream_size,
            folder_digest,
            substream_digest,
        })
    }

    fn listing_entry(
        &self,
        file_index: usize,
        first_entry_for_folder: &mut [bool],
    ) -> Result<ArchiveListingEntry, R7zError> {
        let fi = self.header.files_info();
        let path = fi
            .and_then(|files| files.name(file_index))
            .unwrap_or_else(|| format!("unknown-{file_index}"));
        let Some(files) = fi else {
            return Ok(ArchiveListingEntry {
                index: file_index,
                path,
                kind: ListingEntryKind::File,
                size: None,
                packed_size: None,
                modified: None,
                attributes: None,
                crc: None,
                encrypted: false,
                methods: archive_method_names(self.streams_info())?,
                block: None,
            });
        };

        let kind = if files.is_anti(file_index) {
            ListingEntryKind::Anti
        } else if files.is_directory(file_index) {
            ListingEntryKind::Directory
        } else if files.is_symlink(file_index) {
            ListingEntryKind::Symlink
        } else {
            ListingEntryKind::File
        };

        let modified = files
            .mtimes
            .get(file_index)
            .copied()
            .flatten()
            .and_then(filetime_to_system_time);
        let attributes = files.attributes.get(file_index).copied().flatten();

        if matches!(kind, ListingEntryKind::Directory | ListingEntryKind::Anti)
            || files.is_empty_file(file_index)
        {
            return Ok(ArchiveListingEntry {
                index: file_index,
                path,
                kind,
                size: if matches!(kind, ListingEntryKind::Anti) {
                    None
                } else {
                    Some(0)
                },
                packed_size: None,
                modified,
                attributes,
                crc: files.is_empty_file(file_index).then_some(0),
                encrypted: false,
                methods: Vec::new(),
                block: None,
            });
        }

        let Some((folder_idx, stream_in_folder)) = self.folder_stream_for_file(file_index)? else {
            return Err(R7zError::Parse);
        };
        let streams = self.streams_info().ok_or(R7zError::Parse)?;
        let pack_info = streams.pack_info.as_ref().ok_or(R7zError::Parse)?;
        let unpack_info = streams.unpack_info.as_ref().ok_or(R7zError::Parse)?;
        let substream_info = streams.substream_info.as_ref();
        let folder = unpack_info.parse_folder(folder_idx)?;
        let methods = folder_method_names(&folder);
        let encrypted = folder_is_encrypted(&folder);
        let size = Some(
            u64::try_from(stream_size_at(
                folder_idx,
                stream_in_folder,
                substream_info,
                unpack_info,
            )?)
            .map_err(|_| R7zError::Parse)?,
        );
        let is_first_in_folder = first_entry_for_folder
            .get_mut(folder_idx)
            .ok_or(R7zError::Parse)?;
        let packed_size = if *is_first_in_folder {
            *is_first_in_folder = false;
            Some(folder_packed_size(folder_idx, pack_info, unpack_info)?)
        } else {
            None
        };
        let crc = stream_crc(folder_idx, stream_in_folder, unpack_info, substream_info);

        Ok(ArchiveListingEntry {
            index: file_index,
            path,
            kind,
            size,
            packed_size,
            modified,
            attributes,
            crc,
            encrypted,
            methods,
            block: Some(folder_idx),
        })
    }

    fn folder_stream_for_file(
        &self,
        file_index: usize,
    ) -> Result<Option<(usize, usize)>, R7zError> {
        let fi = self.header.files_info();
        let Some(data_stream_idx) = file_to_data_stream(file_index, fi) else {
            return Ok(None);
        };
        let streams = self.streams_info().ok_or(R7zError::Parse)?;
        let unpack_info = streams.unpack_info.as_ref().ok_or(R7zError::Parse)?;
        Ok(data_stream_to_folder(
            data_stream_idx,
            streams.substream_info.as_ref(),
            usize::try_from(unpack_info.num_folders).map_err(|_| R7zError::Parse)?,
        ))
    }

    /// Extract all files to a directory.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Io`] if a file or directory cannot be created, or any error
    /// that [`extract_to_memory`](Self::extract_to_memory) can return.
    pub fn extract_all(&self, dest: &Path) -> Result<(), R7zError> {
        self.extract_all_with_password(dest, None)
    }

    /// Extract all files to a directory, supplying a password for encrypted archives.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Io`] if a file or directory cannot be created,
    /// [`R7zError::PasswordRequired`] if encrypted with no password, or any
    /// error that [`extract_to_memory_with_password`](Self::extract_to_memory_with_password)
    /// can return.
    pub fn extract_all_with_password(
        &self,
        dest: &Path,
        password: Option<&str>,
    ) -> Result<(), R7zError> {
        let num = self.num_files();
        let fi = self.header.files_info();

        for i in 0..num {
            let name_owned = fi.and_then(|f| f.name(i));
            let name = name_owned.as_deref().unwrap_or("unknown");

            let Some(dest_path) = safe_archive_path(dest, name)? else {
                continue;
            };

            if fi.is_some_and(|f| f.is_anti(i)) {
                continue;
            }

            if fi.is_some_and(|f| f.is_directory(i)) {
                std::fs::create_dir_all(&dest_path)?;
            } else if fi.is_some_and(|f| f.is_empty_stream(i) && f.is_empty_file(i)) {
                if let Some(parent) = dest_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::File::create(&dest_path)?;
            } else {
                if let Some(parent) = dest_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let file = std::fs::File::create(&dest_path)?;
                let mut writer = BufWriter::new(file);
                self.extract_to_writer_with_password(i, &mut writer, password)?;
                writer.flush()?;
            }
        }
        Ok(())
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

struct ExtractionLocation {
    folder: crate::Folder,
    packed_ranges: Vec<Range<u64>>,
    folder_unpack_size: u64,
    coder_unpack_sizes: Vec<u64>,
    stream_start: usize,
    stream_size: usize,
    folder_digest: Option<u32>,
    substream_digest: Option<u32>,
}

impl ExtractionLocation {
    fn stream_end_u64(&self) -> Result<u64, R7zError> {
        let end = self
            .stream_start
            .checked_add(self.stream_size)
            .ok_or(R7zError::Parse)?;
        u64::try_from(end).map_err(|_| R7zError::Parse)
    }
}

fn archive_method_names(streams: Option<&StreamInfo>) -> Result<Vec<String>, R7zError> {
    let mut names = BTreeSet::new();
    if let Some(streams) = streams {
        if let Some(unpack) = &streams.unpack_info {
            for idx in 0..unpack.num_folders_usize() {
                let folder = unpack.parse_folder(idx)?;
                names.extend(folder_method_names(&folder));
            }
        }
    }
    if names.is_empty() {
        Ok(vec!["Copy".to_string()])
    } else {
        Ok(names.into_iter().collect())
    }
}

fn folder_method_names(folder: &crate::Folder) -> Vec<String> {
    folder
        .coders
        .iter()
        .map(|coder| {
            crate::method_from_id(&coder.codec_id).map_or_else(
                || format!("{:02X?}", coder.codec_id),
                |method| method.name().to_string(),
            )
        })
        .collect()
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

fn folder_packed_size(
    folder_idx: usize,
    pack_info: &crate::PackInfo,
    unpack_info: &crate::UnpackInfo,
) -> Result<u64, R7zError> {
    let folder = unpack_info.parse_folder(folder_idx)?;
    let pack_stream_base = folder_pack_stream_base(folder_idx, unpack_info)?;
    let num_pack_streams = folder_num_pack_streams(&folder)?;
    pack_info
        .pack_size
        .get(pack_stream_base..pack_stream_base + num_pack_streams)
        .ok_or(R7zError::Parse)?
        .iter()
        .try_fold(0u64, |acc, &size| {
            acc.checked_add(size).ok_or(R7zError::Parse)
        })
}

fn stream_crc(
    folder_idx: usize,
    stream_in_folder: usize,
    unpack_info: &crate::UnpackInfo,
    substream_info: Option<&crate::SubstreamInfo>,
) -> Option<u32> {
    if let Some(substreams) = substream_info {
        if let Ok(crc_idx) = substream_global_index(folder_idx, stream_in_folder, substreams) {
            return substreams.digests.get(crc_idx).copied().flatten();
        }
        return None;
    }
    unpack_info.digests.get(folder_idx).copied().flatten()
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

fn folder_coder_unpack_sizes(
    folder_idx: usize,
    unpack_info: &crate::UnpackInfo,
) -> Result<Vec<u64>, R7zError> {
    let mut global_base = 0usize;
    for i in 0..folder_idx {
        global_base += unpack_info.parse_folder(i)?.total_out_streams();
    }
    let folder = unpack_info.parse_folder(folder_idx)?;
    let num = folder.total_out_streams();
    unpack_info
        .unpack_sizes
        .get(global_base..global_base + num)
        .map(<[u64]>::to_vec)
        .ok_or(R7zError::Parse)
}

fn folder_pack_stream_base(
    folder_idx: usize,
    unpack_info: &crate::UnpackInfo,
) -> Result<usize, R7zError> {
    let mut base = 0usize;
    for idx in 0..folder_idx {
        let folder = unpack_info.parse_folder(idx)?;
        base = base
            .checked_add(folder_num_pack_streams(&folder)?)
            .ok_or(R7zError::Parse)?;
    }
    Ok(base)
}

fn folder_num_pack_streams(folder: &crate::Folder) -> Result<usize, R7zError> {
    let num_in = folder.coders.iter().try_fold(0u64, |acc, coder| {
        acc.checked_add(coder.num_in_streams).ok_or(R7zError::Parse)
    })?;
    let num_bind_pairs = u64::try_from(folder.bind_pairs.len()).map_err(|_| R7zError::Parse)?;
    let num_packed = num_in.checked_sub(num_bind_pairs).ok_or(R7zError::Parse)?;
    usize::try_from(num_packed).map_err(|_| R7zError::Parse)
}

fn safe_archive_path(dest: &Path, name: &str) -> Result<Option<PathBuf>, R7zError> {
    if name.is_empty() || has_windows_prefix(name) || has_parent_component(name) {
        return Err(R7zError::UnsafePath(name.to_string()));
    }

    let relative = Path::new(name);
    let mut saw_normal = false;
    for component in relative.components() {
        match component {
            Component::Normal(_) => saw_normal = true,
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(R7zError::UnsafePath(name.to_string()));
            }
        }
    }

    if saw_normal {
        Ok(Some(dest.join(relative)))
    } else {
        Err(R7zError::UnsafePath(name.to_string()))
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

/// Map a `FilesInfo` index to a data-stream index (skipping empty-stream entries).
fn file_to_data_stream(file_idx: usize, fi: Option<&FilesInfo>) -> Option<usize> {
    let mut data_idx = 0usize;
    for i in 0..=file_idx {
        let is_empty = fi.is_some_and(|f| f.is_empty_stream(i));
        if i == file_idx {
            if is_empty {
                return None; // caller should have handled empty-stream files
            }
            return Some(data_idx);
        }
        if !is_empty {
            data_idx += 1;
        }
    }
    None
}

/// Map a global data-stream index to (`folder_idx`, `stream_within_folder`).
fn data_stream_to_folder(
    data_idx: usize,
    substream_info: Option<&crate::SubstreamInfo>,
    num_folders: usize,
) -> Option<(usize, usize)> {
    let num_streams: Vec<usize> = if let Some(si) = substream_info {
        si.num_unpack_streams_per_folder
            .iter()
            .map(|&n| usize::try_from(n).expect("num_unpack_streams_per_folder fits in usize"))
            .collect()
    } else {
        vec![1; num_folders]
    };

    let mut global = 0usize;
    for (fi, &n) in num_streams.iter().enumerate() {
        for s in 0..n {
            if global == data_idx {
                return Some((fi, s));
            }
            global += 1;
        }
    }
    None
}

/// Total uncompressed size for a folder (used as the decompression target size).
///
/// This returns the size of the *final* output stream — the one not consumed
/// by any bind pair.  For single-coder folders the index is trivial; for
/// chained coders (e.g. BCJ + LZMA2) we must skip bound output streams.
fn folder_total_unpack_size(
    folder_idx: usize,
    unpack_info: &crate::UnpackInfo,
    substream_info: Option<&crate::SubstreamInfo>,
) -> Result<u64, R7zError> {
    // Compute the global out-stream base for this folder by parsing all
    // preceding folders' total_out_streams.
    let mut global_base: usize = 0;
    for i in 0..folder_idx {
        if let Ok(f) = unpack_info.parse_folder(i) {
            global_base += f.total_out_streams();
        } else {
            global_base += 1; // fallback
        }
    }

    if let Ok(folder) = unpack_info.parse_folder(folder_idx) {
        let num_out = folder.total_out_streams();
        if num_out == 1 {
            // Single coder: direct index
            return unpack_info
                .unpack_sizes
                .get(global_base)
                .copied()
                .ok_or(R7zError::Parse);
        }
        // Multi-coder: find the out-stream NOT bound as an output in any bind pair
        // (the one that produces the final decompressed data).
        for out_idx in 0..num_out {
            let is_bound = folder
                .bind_pairs
                .iter()
                .any(|&(_, bound_out)| bound_out == out_idx as u64);
            if !is_bound {
                return unpack_info
                    .unpack_sizes
                    .get(global_base + out_idx)
                    .copied()
                    .ok_or(R7zError::Parse);
            }
        }
        // Fallback: last out-stream
        return unpack_info
            .unpack_sizes
            .get(global_base + num_out - 1)
            .copied()
            .ok_or(R7zError::Parse);
    }

    // Legacy fallback: try direct index
    if let Some(sz) = unpack_info.unpack_sizes.get(folder_idx) {
        return Ok(*sz);
    }

    // Fallback: sum substream sizes for this folder
    if let Some(si) = substream_info {
        let start: usize = si
            .num_unpack_streams_per_folder
            .get(..folder_idx)
            .ok_or(R7zError::Parse)?
            .iter()
            .try_fold(0usize, |acc, &n| {
                let n = usize::try_from(n).map_err(|_| R7zError::Parse)?;
                acc.checked_add(n).ok_or(R7zError::Parse)
            })?;
        let n = usize::try_from(
            *si.num_unpack_streams_per_folder
                .get(folder_idx)
                .ok_or(R7zError::Parse)?,
        )
        .map_err(|_| R7zError::Parse)?;
        return si
            .unpack_sizes
            .get(start..start + n)
            .ok_or(R7zError::Parse)?
            .iter()
            .try_fold(0u64, |acc, &size| {
                acc.checked_add(size).ok_or(R7zError::Parse)
            });
    }
    Err(R7zError::Parse)
}

/// Byte offset of stream `stream_in_folder` within the decompressed folder data.
fn stream_offset_in_folder(
    folder_idx: usize,
    stream_in_folder: usize,
    substream_info: Option<&crate::SubstreamInfo>,
    _unpack_info: &crate::UnpackInfo,
) -> Result<usize, R7zError> {
    if stream_in_folder == 0 {
        return Ok(0);
    }
    let Some(si) = substream_info else {
        return Ok(0);
    };
    // Global index of the first explicit size for this folder
    let base_global: usize = si.num_unpack_streams_per_folder[..folder_idx]
        .iter()
        .map(|&n| {
            usize::try_from(n)
                .expect("num_unpack_streams_per_folder fits in usize")
                .saturating_sub(1)
        })
        .sum();

    // The explicit sizes stored are for streams 0..n-2; stream n-1 is implicit
    let sizes = si
        .unpack_sizes
        .get(base_global..base_global + stream_in_folder)
        .ok_or(R7zError::Parse)?;
    sizes.iter().try_fold(0usize, |acc, &s| {
        let s = usize::try_from(s).map_err(|_| R7zError::Parse)?;
        acc.checked_add(s).ok_or(R7zError::Parse)
    })
}

/// Size of stream `stream_in_folder` within the decompressed folder data.
fn stream_size_at(
    folder_idx: usize,
    stream_in_folder: usize,
    substream_info: Option<&crate::SubstreamInfo>,
    unpack_info: &crate::UnpackInfo,
) -> Result<usize, R7zError> {
    let n_streams = usize::try_from(
        substream_info
            .and_then(|s| s.num_unpack_streams_per_folder.get(folder_idx))
            .copied()
            .unwrap_or(1),
    )
    .expect("num_unpack_streams_per_folder fits in usize");

    if n_streams == 1 {
        // Single stream: use folder's final unpack size (multi-coder-aware)
        return usize::try_from(folder_total_unpack_size(
            folder_idx,
            unpack_info,
            substream_info,
        )?)
        .map_err(|_| R7zError::Parse);
    }

    let Some(si) = substream_info else {
        return usize::try_from(folder_total_unpack_size(
            folder_idx,
            unpack_info,
            substream_info,
        )?)
        .map_err(|_| R7zError::Parse);
    };

    let base_global: usize = si.num_unpack_streams_per_folder[..folder_idx]
        .iter()
        .map(|&n| {
            usize::try_from(n)
                .expect("num_unpack_streams_per_folder fits in usize")
                .saturating_sub(1)
        })
        .sum();

    if stream_in_folder < n_streams - 1 {
        // Explicit size
        usize::try_from(
            *si.unpack_sizes
                .get(base_global + stream_in_folder)
                .ok_or(R7zError::Parse)?,
        )
        .map_err(|_| R7zError::Parse)
    } else {
        // Last stream: folder_size - sum(explicit_sizes)
        let folder_size = usize::try_from(folder_total_unpack_size(
            folder_idx,
            unpack_info,
            substream_info,
        )?)
        .map_err(|_| R7zError::Parse)?;
        let sizes = si
            .unpack_sizes
            .get(base_global..base_global + n_streams - 1)
            .ok_or(R7zError::Parse)?;
        let explicit_sum = sizes.iter().try_fold(0usize, |acc, &s| {
            let s = usize::try_from(s).map_err(|_| R7zError::Parse)?;
            acc.checked_add(s).ok_or(R7zError::Parse)
        })?;
        folder_size.checked_sub(explicit_sum).ok_or(R7zError::Parse)
    }
}

fn substream_global_index(
    folder_idx: usize,
    stream_in_folder: usize,
    substream_info: &crate::SubstreamInfo,
) -> Result<usize, R7zError> {
    let prior = substream_info
        .num_unpack_streams_per_folder
        .get(..folder_idx)
        .ok_or(R7zError::Parse)?
        .iter()
        .try_fold(0usize, |acc, &n| {
            let n = usize::try_from(n).map_err(|_| R7zError::Parse)?;
            acc.checked_add(n).ok_or(R7zError::Parse)
        })?;
    prior.checked_add(stream_in_folder).ok_or(R7zError::Parse)
}
