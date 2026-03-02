use crate::{
    codec, find_next_property_id, EncodedHeader, FilesInfo, Header, Property, R7zError,
    SignatureHeader, StreamInfo,
};
use bytes::Bytes;
use nom::ToUsize;
use std::path::Path;

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
        let (input, signature) = SignatureHeader::parse(data).map_err(|_| R7zError::Parse)?;

        signature.validate_start_header_crc()?;

        let offset = signature.next_header_offset.to_usize();
        let (input, prop) = find_next_property_id(input, offset).map_err(|_| R7zError::Parse)?;

        match prop {
            Property::EncodedHeader => {
                let (_, encoded_header) =
                    EncodedHeader::parse(input).map_err(|_| R7zError::Parse)?;
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
    /// # Errors
    ///
    /// Returns [`R7zError::Io`] if the file cannot be read, or a parse/CRC error if the
    /// archive is malformed.
    pub fn open(path: &Path) -> Result<Archive, R7zError> {
        let data = std::fs::read(path)?;
        Self::from_bytes(Bytes::from(data))
    }

    /// Parse a 7z archive from in-memory bytes.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Parse`] if the bytes are not a valid 7z archive, or
    /// [`R7zError::Crc`] if any CRC check fails.
    pub fn from_bytes(data: Bytes) -> Result<Archive, R7zError> {
        let (input, signature) = SignatureHeader::parse(&data).map_err(|_| R7zError::Parse)?;

        signature.validate_start_header_crc()?;

        let offset = signature.next_header_offset.to_usize();
        let (input, prop) = find_next_property_id(input, offset).map_err(|_| R7zError::Parse)?;

        // Validate next_header_crc over the raw encoded/header bytes
        let header_start = 32 + offset;
        let header_end = header_start
            + usize::try_from(signature.next_header_size).map_err(|_| R7zError::Parse)?;
        let header_raw = &data[header_start..header_end];
        let computed_crc = crc32fast::hash(header_raw);
        if computed_crc != signature.next_header_crc {
            return Err(R7zError::Crc);
        }

        match prop {
            Property::EncodedHeader => {
                // Parse the EncodedHeader (describes how the full header is compressed)
                let (_, encoded_header) =
                    EncodedHeader::parse(input).map_err(|_| R7zError::Parse)?;

                // Decompress the packed header stream
                let pi = &encoded_header.pack_info;
                let ui = &encoded_header.unpack_info;
                let data_start = 32
                    + usize::try_from(pi.pack_pos).map_err(|_| R7zError::Parse)?;
                let data_end = data_start
                    + usize::try_from(pi.pack_size[0]).map_err(|_| R7zError::Parse)?;
                let packed = &data[data_start..data_end];
                let folder = &ui.folders[0];
                let unpack_size = ui.unpack_sizes[0];
                let decompressed = codec::decompress_folder(folder, packed, unpack_size)?;

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
                let (_, header) = Header::parse(header_raw).map_err(|_| R7zError::Parse)?;

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
        self.header
            .files_info
            .as_ref()
            .map_or(0, |f| {
                usize::try_from(f.num_files).expect("num_files fits in usize")
            })
    }

    #[must_use]
    pub fn files_info(&self) -> Option<&FilesInfo> {
        self.header.files_info.as_ref()
    }

    #[must_use]
    pub fn streams_info(&self) -> Option<&StreamInfo> {
        self.header.main_streams_info.as_ref()
    }

    /// Extract a single file by its index in the `FilesInfo` list to memory.
    ///
    /// Skips empty-stream entries (directories, zero-byte files).
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Parse`] if the index is out of range, the file is an
    /// empty-stream entry, or the archive structure is inconsistent.
    /// Returns [`R7zError::Decompression`] if decompression fails.
    pub fn extract_to_memory(&self, file_index: usize) -> Result<Vec<u8>, R7zError> {
        let streams = self.streams_info().ok_or(R7zError::Parse)?;
        let pack_info = streams.pack_info.as_ref().ok_or(R7zError::Parse)?;
        let unpack_info = streams.unpack_info.as_ref().ok_or(R7zError::Parse)?;
        let substream_info = streams.substream_info.as_ref();

        // Map file_index → (data_stream_index) by skipping empty files
        let fi = self.header.files_info.as_ref();
        let data_stream_idx = file_to_data_stream(file_index, fi);
        let data_stream_idx = data_stream_idx.ok_or(R7zError::Parse)?;

        // Find which folder + in-folder offset holds data_stream_idx
        let (folder_idx, stream_in_folder) = data_stream_to_folder(
            data_stream_idx,
            substream_info,
            usize::try_from(unpack_info.num_folders).map_err(|_| R7zError::Parse)?,
        )
        .ok_or(R7zError::Parse)?;

        // Decompress the folder
        let folder = &unpack_info.folders[folder_idx];
        let pack_offset: usize = usize::try_from(
            pack_info.pack_size[..folder_idx].iter().sum::<u64>(),
        )
        .map_err(|_| R7zError::Parse)?;
        let pack_size =
            usize::try_from(pack_info.pack_size[folder_idx]).map_err(|_| R7zError::Parse)?;
        let data_start = 32
            + usize::try_from(pack_info.pack_pos).map_err(|_| R7zError::Parse)?
            + pack_offset;
        let packed = &self.data[data_start..data_start + pack_size];

        // Folder unpack size = sum of all out-stream sizes in the unpack_info
        let folder_unpack_size = folder_total_unpack_size(folder_idx, unpack_info, substream_info);
        let decompressed = codec::decompress_folder(folder, packed, folder_unpack_size)?;

        // Slice the target stream out of the decompressed folder data
        let stream_start =
            stream_offset_in_folder(folder_idx, stream_in_folder, substream_info, unpack_info);
        let stream_size = stream_size_at(folder_idx, stream_in_folder, substream_info, unpack_info);

        Ok(decompressed[stream_start..stream_start + stream_size].to_vec())
    }

    /// Extract all files to a directory.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Io`] if a file or directory cannot be created, or any error
    /// that [`extract_to_memory`](Self::extract_to_memory) can return.
    pub fn extract_all(&self, dest: &Path) -> Result<(), R7zError> {
        let num = self.num_files();
        let fi = self.header.files_info.as_ref();

        for i in 0..num {
            let name_owned = fi.and_then(|f| f.name(i));
            let name = name_owned.as_deref().unwrap_or("unknown");

            let is_empty = fi.is_some_and(|f| f.is_empty_stream(i));

            let dest_path = dest.join(name);
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            if is_empty {
                // Directory or zero-byte file
                if !dest_path.exists() {
                    std::fs::File::create(&dest_path)?;
                }
            } else {
                let bytes = self.extract_to_memory(i)?;
                std::fs::write(&dest_path, &bytes)?;
            }
        }
        Ok(())
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

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
fn folder_total_unpack_size(
    folder_idx: usize,
    unpack_info: &crate::UnpackInfo,
    substream_info: Option<&crate::SubstreamInfo>,
) -> u64 {
    // Use the folder's out-stream unpack_size if available in UnpackInfo
    if let Some(sz) = unpack_info.unpack_sizes.get(folder_idx) {
        return *sz;
    }

    // Fallback: sum substream sizes for this folder
    if let Some(si) = substream_info {
        let start: usize = si.num_unpack_streams_per_folder[..folder_idx]
            .iter()
            .map(|&n| usize::try_from(n).expect("num_unpack_streams_per_folder fits in usize"))
            .sum();
        let n = usize::try_from(si.num_unpack_streams_per_folder[folder_idx])
            .expect("num_unpack_streams_per_folder fits in usize");
        return si.unpack_sizes[start..start + n].iter().sum();
    }
    0
}

/// Byte offset of stream `stream_in_folder` within the decompressed folder data.
fn stream_offset_in_folder(
    folder_idx: usize,
    stream_in_folder: usize,
    substream_info: Option<&crate::SubstreamInfo>,
    _unpack_info: &crate::UnpackInfo,
) -> usize {
    if stream_in_folder == 0 {
        return 0;
    }
    let Some(si) = substream_info else { return 0 };
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
    si.unpack_sizes[base_global..base_global + stream_in_folder]
        .iter()
        .map(|&s| usize::try_from(s).expect("unpack_size fits in usize"))
        .sum()
}

/// Size of stream `stream_in_folder` within the decompressed folder data.
fn stream_size_at(
    folder_idx: usize,
    stream_in_folder: usize,
    substream_info: Option<&crate::SubstreamInfo>,
    unpack_info: &crate::UnpackInfo,
) -> usize {
    let n_streams = usize::try_from(
        substream_info
            .and_then(|s| s.num_unpack_streams_per_folder.get(folder_idx))
            .copied()
            .unwrap_or(1),
    )
    .expect("num_unpack_streams_per_folder fits in usize");

    if n_streams == 1 {
        // Single stream: use folder unpack size
        return usize::try_from(
            unpack_info
                .unpack_sizes
                .get(folder_idx)
                .copied()
                .unwrap_or(0),
        )
        .expect("unpack_size fits in usize");
    }

    let Some(si) = substream_info else {
        return usize::try_from(
            unpack_info
                .unpack_sizes
                .get(folder_idx)
                .copied()
                .unwrap_or(0),
        )
        .expect("unpack_size fits in usize");
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
        usize::try_from(si.unpack_sizes[base_global + stream_in_folder])
            .expect("unpack_size fits in usize")
    } else {
        // Last stream: folder_size - sum(explicit_sizes)
        let folder_size = usize::try_from(
            unpack_info
                .unpack_sizes
                .get(folder_idx)
                .copied()
                .unwrap_or(0),
        )
        .expect("unpack_size fits in usize");
        let explicit_sum: usize = si.unpack_sizes[base_global..base_global + n_streams - 1]
            .iter()
            .map(|&s| usize::try_from(s).expect("unpack_size fits in usize"))
            .sum();
        folder_size - explicit_sum
    }
}
