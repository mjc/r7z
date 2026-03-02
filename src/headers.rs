use crate::files_info::scan_files_info;
use crate::stream_info::scan_stream_info;
use crate::{FilesInfo, PackInfo, Property, R7zError, StreamInfo, UnpackInfo};
use bytes::Bytes;
use nom::IResult;
use std::cell::OnceCell;

/// The outer `EncodedHeader` block that describes where the compressed main header lives.
///
/// Most 7z archives compress their metadata (the `Header`) using LZMA; the
/// `EncodedHeader` provides the [`PackInfo`] and [`UnpackInfo`] needed to locate
/// and decompress it.
#[derive(Debug, PartialEq)]
pub struct EncodedHeader {
    /// Where the compressed header stream is stored.
    pub pack_info: PackInfo,
    /// How to decompress the header stream.
    pub unpack_info: UnpackInfo,
}

impl EncodedHeader {
    /// Parse an `EncodedHeader` block (pack info + unpack info).
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated or malformed.
    pub fn parse<'a>(input: &'a [u8], backing: &Bytes) -> IResult<&'a [u8], EncodedHeader> {
        let (input, pack_info) = PackInfo::parse(input)?;
        let (input, unpack_info) = UnpackInfo::parse(input, backing)?;
        Ok((
            input,
            EncodedHeader {
                pack_info,
                unpack_info,
            },
        ))
    }
}

/// The fully decoded 7z archive header containing stream and file metadata.
///
/// Metadata is validated eagerly during [`parse`](Header::parse) via
/// zero-allocation scanners, but the full [`StreamInfo`] and [`FilesInfo`]
/// structs are constructed lazily on first access.
pub struct Header {
    /// Decompressed header bytes (cheap `Arc`-backed clone of the decode buffer).
    data: Bytes,
    /// Byte offset within `data` where `StreamInfo::parse` should start
    /// (after the `MainStreamsInfo` tag).
    streams_info_start: Option<u32>,
    /// Byte offset within `data` where `FilesInfo::parse` should start
    /// (including the `FilesInfo` tag).
    files_info_start: Option<u32>,
    /// Number of file entries (extracted during scan; avoids a lazy parse just
    /// to read the count).
    num_files: u64,
    /// Lazily-parsed stream descriptor.
    streams_cache: OnceCell<StreamInfo>,
    /// Lazily-parsed file listing.
    files_cache: OnceCell<FilesInfo>,
}

impl std::fmt::Debug for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Header")
            .field("data_len", &self.data.len())
            .field("streams_info_start", &self.streams_info_start)
            .field("files_info_start", &self.files_info_start)
            .field("num_files", &self.num_files)
            .field("streams_cache", &self.streams_cache)
            .field("files_cache", &self.files_cache)
            .finish()
    }
}

impl Header {
    /// Returns the number of file entries in the archive.
    ///
    /// This is extracted during the initial scan and does not trigger
    /// lazy parsing of [`FilesInfo`].
    #[must_use]
    pub fn num_files(&self) -> u64 {
        self.num_files
    }

    /// Access the stream descriptor, parsing it on first call.
    ///
    /// Returns `None` if the header contained no `MainStreamsInfo` block.
    ///
    /// # Panics
    ///
    /// Panics if the pre-validated bytes cannot be parsed (should never happen).
    #[must_use]
    pub fn streams_info(&self) -> Option<&StreamInfo> {
        let off = self.streams_info_start? as usize;
        Some(self.streams_cache.get_or_init(|| {
            let (_, si) = StreamInfo::parse(&self.data[off..], &self.data)
                .expect("pre-validated header");
            si
        }))
    }

    /// Access the file listing, parsing it on first call.
    ///
    /// Returns `None` if the header contained no `FilesInfo` block.
    ///
    /// # Panics
    ///
    /// Panics if the pre-validated bytes cannot be parsed (should never happen).
    #[must_use]
    pub fn files_info(&self) -> Option<&FilesInfo> {
        let off = self.files_info_start? as usize;
        Some(self.files_cache.get_or_init(|| {
            let (_, fi) =
                FilesInfo::parse(&self.data[off..], &self.data).expect("pre-validated header");
            fi
        }))
    }

    /// Parse and validate a decompressed 7z header block.
    ///
    /// The full structure is scanned for correctness (tags, sizes, folder
    /// layout) without allocating any interior collections.  The raw bytes
    /// are stored and the expensive [`StreamInfo`] / [`FilesInfo`] structs
    /// are constructed lazily on first access.
    ///
    /// Expects the input to start with the `Property::Header` (0x01) tag.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated, malformed, or does not start with
    /// the `Header` property tag.
    pub fn parse(backing: &Bytes) -> IResult<&[u8], Header> {
        let input: &[u8] = backing;
        let orig_input = input;
        let (input, tag) = Property::parse(input)?;
        if tag != Property::Header {
            return Err(nom::Err::Failure(nom::error::Error::new(
                orig_input,
                nom::error::ErrorKind::Satisfy,
            )));
        }

        let mut streams_info_start: Option<u32> = None;
        let mut files_info_start: Option<u32> = None;
        let mut num_files: u64 = 0;
        let mut input = input;

        loop {
            let (i, tag) = Property::parse(input)?;
            match tag {
                Property::END => {
                    input = i;
                    break;
                }
                Property::MainStreamsInfo => {
                    // Advance past the tag; record offset for lazy parsing
                    input = i;
                    let off = u32::try_from(backing.len() - input.len()).map_err(|_| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    let (i, ()) = scan_stream_info(input)?;
                    streams_info_start = Some(off);
                    input = i;
                }
                Property::FilesInfo => {
                    // FilesInfo tag is still in `input`; record that offset
                    let off = u32::try_from(backing.len() - input.len()).map_err(|_| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    let (i, nf) = scan_files_info(input)?;
                    files_info_start = Some(off);
                    num_files = nf;
                    input = i;
                }
                Property::ArchiveProperties => {
                    // Skip: size-prefixed block
                    input = i;
                    let (i, size) = crate::sevenzip_varuint64_decode(input)?;
                    let sz = usize::try_from(size).map_err(|_| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    let (i, _) = nom::bytes::complete::take(sz)(i)?;
                    input = i;
                }
                _ => {
                    input = i;
                    let (i, size) = crate::sevenzip_varuint64_decode(input)?;
                    let sz = usize::try_from(size).map_err(|_| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    let (i, _) = nom::bytes::complete::take(sz)(i)?;
                    input = i;
                }
            }
        }

        Ok((
            input,
            Header {
                data: backing.clone(),
                streams_info_start,
                files_info_start,
                num_files,
                streams_cache: OnceCell::new(),
                files_cache: OnceCell::new(),
            },
        ))
    }
}

/// The 32-byte fixed-size header at the start of every 7z archive.
///
/// Contains the magic bytes, format version, and the location and CRC of the
/// next header (either an [`EncodedHeader`] or a plain `Header`).
#[derive(Debug, PartialEq)]
pub struct SignatureHeader {
    /// Magic bytes: `37 7a bc af 27 1c`.
    pub signature: [u8; 6],
    /// Format major version (always `0x00`).
    pub major_version: u8,
    /// Format minor version (typically `0x04`).
    pub minor_version: u8,
    /// CRC32 of the 20-byte start-header fields that follow.
    pub start_header_crc: u32,
    /// Byte offset from the end of this 32-byte header to the next header block.
    pub next_header_offset: u64,
    /// Byte length of the next header block.
    pub next_header_size: u64,
    /// CRC32 of the next header block.
    pub next_header_crc: u32,
}

impl SignatureHeader {
    /// Validate the CRC over the 20-byte `StartHeader` (offset+size+crc).
    ///
    /// The `start_header_crc` field covers:
    /// `[next_header_offset (8), next_header_size (8), next_header_crc (4)]`.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Crc`] if the computed CRC does not match `start_header_crc`.
    pub fn validate_start_header_crc(&self) -> Result<(), R7zError> {
        let mut buf = [0u8; 20];
        buf[..8].copy_from_slice(&self.next_header_offset.to_le_bytes());
        buf[8..16].copy_from_slice(&self.next_header_size.to_le_bytes());
        buf[16..].copy_from_slice(&self.next_header_crc.to_le_bytes());
        let computed = crc32fast::hash(&buf);
        if computed == self.start_header_crc {
            Ok(())
        } else {
            Err(R7zError::Crc)
        }
    }

    /// Parse the 32-byte `SignatureHeader` from the start of a 7z archive.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is shorter than 32 bytes or malformed.
    ///
    /// # Panics
    ///
    /// Never panics; all slice-to-array conversions are guarded by the `len < 32` check above.
    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureHeader> {
        if input.len() < 32 {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Eof,
            )));
        }
        // 7z signature header layout (32 bytes):
        //  [0..6]   magic bytes
        //  [6]      major_version
        //  [7]      minor_version
        //  [8..12]  start_header_crc  (u32 le)
        //  [12..20] next_header_offset (u64 le)
        //  [20..28] next_header_size   (u64 le)
        //  [28..32] next_header_crc   (u32 le)
        let signature: [u8; 6] = input[0..6].try_into().expect("slice is 6 bytes");
        let major_version = input[6];
        let minor_version = input[7];
        let start_header_crc =
            u32::from_le_bytes(input[8..12].try_into().expect("slice is 4 bytes"));
        let next_header_offset =
            u64::from_le_bytes(input[12..20].try_into().expect("slice is 8 bytes"));
        let next_header_size =
            u64::from_le_bytes(input[20..28].try_into().expect("slice is 8 bytes"));
        let next_header_crc =
            u32::from_le_bytes(input[28..32].try_into().expect("slice is 4 bytes"));
        Ok((
            &input[32..],
            SignatureHeader {
                signature,
                major_version,
                minor_version,
                start_header_crc,
                next_header_offset,
                next_header_size,
                next_header_crc,
            },
        ))
    }
}
