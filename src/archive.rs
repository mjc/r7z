use crate::{
    codec, find_next_property_id, EncodedHeader, FilesInfo, Header, Property, R7zError,
    SignatureHeader, StreamInfo,
};
use bytes::Bytes;
use memmap2::Mmap;
use std::io::{BufWriter, Read, Write};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};

/// Maximum decompressed size accepted for the compressed archive header (metadata only).
/// A malicious archive could declare an enormous `unpack_size` to cause OOM during header
/// decompression; this cap bounds the allocation to a sane limit. File data extracted
/// via [`Archive::extract_to_memory`] is not subject to this limit.
const MAX_HEADER_UNPACK_BYTES: u64 = 64 * 1024 * 1024;

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
        if data.len() < 32 {
            return Err(R7zError::Parse);
        }
        // Validate start_header_crc on raw bytes before trusting any parsed fields.
        // input[8..12] = start_header_crc, input[12..32] = the covered region.
        let start_crc = u32::from_le_bytes(data[8..12].try_into().map_err(|_| R7zError::Parse)?);
        if crc32fast::hash(&data[12..32]) != start_crc {
            return Err(R7zError::Crc);
        }
        let backing = Bytes::copy_from_slice(data);
        let (input, signature) = SignatureHeader::parse(&backing).map_err(|_| R7zError::Parse)?;

        let offset = usize::try_from(signature.next_header_offset).map_err(|_| R7zError::Parse)?;
        let header_start = checked_add_usize(32, offset)?;
        checked_range(data.len(), header_start, signature.next_header_size)?;
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
    /// Raw archive bytes (O(1) clone via reference counting).
    data: Bytes,
    pub signature: SignatureHeader,
    /// Present for `EncodedHeader` archives; None for uncompressed-header archives.
    pub encoded_header: Option<EncodedHeader>,
    pub header: Header,
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
        Self::open_with_password(path, None)
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
        let file = std::fs::File::open(path)?;
        // SAFETY: The file is opened read-only and we do not mutate the mapping.
        // A concurrent truncation of the file could cause SIGBUS; callers that
        // need to guard against this should use `from_reader` instead.
        let mmap = unsafe { Mmap::map(&file)? };
        Self::from_bytes_with_password(Bytes::from_owner(mmap), password)
    }

    /// Fully read a [`Read`] source and decode it as a 7z archive.
    ///
    /// Because the 7z format requires random access (the header lives at the
    /// end of the file while the data blocks are near the start), the entire
    /// source is buffered into memory before parsing begins.  For local files
    /// prefer [`Archive::open`], which uses `mmap` to avoid an upfront
    /// allocation.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Io`] if reading fails, or a parse/CRC error if the
    /// archive is malformed.
    pub fn from_reader(reader: impl Read) -> Result<Archive, R7zError> {
        Self::from_reader_with_password(reader, None)
    }

    /// Fully read a [`Read`] source and decode it as a 7z archive, with a password.
    ///
    /// See [`Archive::from_reader`] and [`Archive::open_with_password`] for details.
    pub fn from_reader_with_password(
        mut reader: impl Read,
        password: Option<&str>,
    ) -> Result<Archive, R7zError> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Self::from_bytes_with_password(Bytes::from(buf), password)
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
        if data.len() < 32 {
            return Err(R7zError::Parse);
        }
        // Validate start_header_crc on raw bytes before trusting any parsed fields.
        // data[8..12] = start_header_crc, data[12..32] = the covered region.
        let start_crc = u32::from_le_bytes(data[8..12].try_into().map_err(|_| R7zError::Parse)?);
        if crc32fast::hash(&data[12..32]) != start_crc {
            return Err(R7zError::Crc);
        }
        let (input, signature) = SignatureHeader::parse(&data).map_err(|_| R7zError::Parse)?;

        let offset = usize::try_from(signature.next_header_offset).map_err(|_| R7zError::Parse)?;
        let (input, prop) = find_next_property_id(input, offset).map_err(|_| R7zError::Parse)?;

        // Validate next_header_crc over the raw encoded/header bytes
        let header_start = checked_add_usize(32, offset)?;
        let header_range = checked_range(data.len(), header_start, signature.next_header_size)?;
        let header_raw = &data[header_range.clone()];
        let computed_crc = crc32fast::hash(header_raw);
        if computed_crc != signature.next_header_crc {
            return Err(R7zError::Crc);
        }

        match prop {
            Property::EncodedHeader => {
                // Parse the EncodedHeader (describes how the full header is compressed)
                let (_, encoded_header) =
                    EncodedHeader::parse(input, &data).map_err(|_| R7zError::Parse)?;

                // Decompress the packed header stream
                let pi = &encoded_header.pack_info;
                let ui = &encoded_header.unpack_info;
                let pack_pos = usize::try_from(pi.pack_pos).map_err(|_| R7zError::Parse)?;
                let data_start = checked_add_usize(32, pack_pos)?;
                let pack_size = *pi.pack_size.first().ok_or(R7zError::Parse)?;
                let data_range = checked_range(data.len(), data_start, pack_size)?;
                let packed = &data[data_range];
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
                if unpack_size > MAX_HEADER_UNPACK_BYTES {
                    return Err(R7zError::Parse);
                }
                let decompressed =
                    codec::decompress_folder_with_password(&folder, packed, unpack_size, password)?;
                let decompressed = Bytes::from(decompressed);

                let (_, header) = Header::parse(&decompressed).map_err(|_| R7zError::Parse)?;

                Ok(Archive {
                    data,
                    signature,
                    encoded_header: Some(encoded_header),
                    header,
                })
            }
            Property::Header => {
                // Header is stored uncompressed at next_header_offset (the raw bytes
                // include the 0x01 tag, so we slice from header_start, not header_start+1)
                let header_bytes = data.slice(header_range);
                let (_, header) = Header::parse(&header_bytes).map_err(|_| R7zError::Parse)?;

                Ok(Archive {
                    data,
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
        let packed = &self.data[location.packed_range.clone()];
        let mut reader = codec::folder_reader(
            &location.folder,
            packed,
            location.folder_unpack_size,
            password,
        )?;

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
        let prior_pack_sizes = pack_info
            .pack_size
            .get(..folder_idx)
            .ok_or(R7zError::Parse)?;
        let pack_offset_u64 = prior_pack_sizes.iter().try_fold(0u64, |acc, &size| {
            acc.checked_add(size).ok_or(R7zError::Parse)
        })?;
        let pack_offset = usize::try_from(pack_offset_u64).map_err(|_| R7zError::Parse)?;
        let pack_size = *pack_info.pack_size.get(folder_idx).ok_or(R7zError::Parse)?;
        let pack_pos = usize::try_from(pack_info.pack_pos).map_err(|_| R7zError::Parse)?;
        let data_start = checked_add_usize(checked_add_usize(32, pack_pos)?, pack_offset)?;
        let packed_range = checked_range(self.data.len(), data_start, pack_size)?;

        let folder_unpack_size = folder_total_unpack_size(folder_idx, unpack_info, substream_info)?;
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
            packed_range,
            folder_unpack_size,
            stream_start,
            stream_size,
            folder_digest,
            substream_digest,
        })
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
    packed_range: Range<usize>,
    folder_unpack_size: u64,
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

fn checked_add_usize(lhs: usize, rhs: usize) -> Result<usize, R7zError> {
    lhs.checked_add(rhs).ok_or(R7zError::Parse)
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
        } else {
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
