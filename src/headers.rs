use crate::{FilesInfo, PackInfo, Property, R7zError, StreamInfo, UnpackInfo};
use nom::{
    multi::count,
    number::streaming::{le_u32, le_u64, le_u8},
    sequence::tuple,
    IResult,
};

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
    pub fn parse(input: &[u8]) -> IResult<&[u8], EncodedHeader> {
        let (input, pack_info) = PackInfo::parse(input)?;
        let (input, unpack_info) = UnpackInfo::parse(input)?;
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
#[derive(Debug)]
pub struct Header {
    /// Stream descriptor for the file data (absent in empty archives).
    pub main_streams_info: Option<StreamInfo>,
    /// File listing with names, timestamps, and attributes.
    pub files_info: Option<FilesInfo>,
}

impl Header {
    /// Parse a decompressed 7z header block.
    ///
    /// Expects the input to start with the `Property::Header` (0x01) tag.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Header> {
        let orig_input = input;
        let (input, tag) = Property::parse(input)?;
        if tag != Property::Header {
            return Err(nom::Err::Failure(nom::error::Error::new(
                orig_input,
                nom::error::ErrorKind::Satisfy,
            )));
        }

        let mut main_streams_info = None;
        let mut files_info = None;
        let mut input = input;

        loop {
            let (i, tag) = Property::parse(input)?;
            match tag {
                Property::END => {
                    input = i;
                    break;
                }
                Property::MainStreamsInfo => {
                    // StreamInfo::parse reads its own sub-tags; consume the outer tag first
                    input = i;
                    let (i, si) = StreamInfo::parse(input)?;
                    main_streams_info = Some(si);
                    input = i;
                }
                Property::FilesInfo => {
                    // FilesInfo::parse reads and validates its own tag byte
                    let (i, fi) = FilesInfo::parse(input)?;
                    files_info = Some(fi);
                    input = i;
                }
                Property::ArchiveProperties => {
                    // Skip: size-prefixed block
                    input = i;
                    let (i, size) = crate::sevenzip_varuint64_decode(input)?;
                    let (i, _) = nom::bytes::streaming::take(size as usize)(i)?;
                    input = i;
                }
                _ => {
                    input = i;
                    let (i, size) = crate::sevenzip_varuint64_decode(input)?;
                    let (i, _) = nom::bytes::streaming::take(size as usize)(i)?;
                    input = i;
                }
            }
        }

        Ok((
            input,
            Header {
                main_streams_info,
                files_info,
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
    pub signature: Vec<u8>,
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
    fn get_file_signature(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        count(le_u8, 6)(input)
    }

    fn get_version(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
        tuple((le_u8, le_u8))(input)
    }

    fn get_next_header_offset(input: &[u8]) -> IResult<&[u8], u64> {
        le_u64(input)
    }

    fn get_next_header_size(input: &[u8]) -> IResult<&[u8], u64> {
        le_u64(input)
    }

    fn get_crc32(input: &[u8]) -> IResult<&[u8], u32> {
        le_u32(input)
    }

    /// Validate the CRC over the 20-byte StartHeader (offset+size+crc).
    ///
    /// The `start_header_crc` field covers:
    /// `[next_header_offset (8), next_header_size (8), next_header_crc (4)]`.
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

    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureHeader> {
        let (input, signature) = Self::get_file_signature(input)?;
        let (input, (major_version, minor_version)) = Self::get_version(input)?;
        let (input, start_header_crc) = Self::get_crc32(input)?;
        let (input, next_header_offset) = Self::get_next_header_offset(input)?;
        let (input, next_header_size) = Self::get_next_header_size(input)?;
        let (input, next_header_crc) = Self::get_crc32(input)?;
        Ok((
            input,
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
