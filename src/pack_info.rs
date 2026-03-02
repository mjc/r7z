use bytes::Bytes;
use nom::{number::complete::le_u8, IResult, ToUsize};
use smallvec::SmallVec;

use crate::{sevenzip_varuint64_decode, usize_cap, Folder, Property};
use crate::folder::scan_folder;
use crate::parsers::scan_digests;

/// Describes where the packed (compressed) data streams live in the archive file.
#[derive(Debug, PartialEq)]
pub struct PackInfo {
    /// Byte offset of the first packed stream, measured from the end of the
    /// 32-byte [`SignatureHeader`](crate::SignatureHeader).
    pub pack_pos: u64,
    /// Number of packed streams.
    pub num_pack_streams: u64,
    /// Compressed size of each packed stream in bytes.
    /// Nearly always length 1; stays on the stack for the common case.
    pub pack_size: SmallVec<[u64; 4]>,
}

impl PackInfo {
    /// Parse a `PackInfo` block from the header stream.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated or does not start with the `PackInfo` tag.
    pub fn parse(input: &[u8]) -> IResult<&[u8], PackInfo> {
        let orig_input = input;
        let (input, property_id) = Property::parse(input)?;
        if property_id != Property::PackInfo {
            return Err(nom::Err::Failure(nom::error::Error::new(
                orig_input,
                nom::error::ErrorKind::Satisfy,
            )));
        }

        let (input, pack_pos) = sevenzip_varuint64_decode(input)?;
        let (input, num_pack_streams) = sevenzip_varuint64_decode(input)?;

        // Property::Size tag
        let (mut input, _size_marker) = le_u8(input)?;

        let mut pack_size: SmallVec<[u64; 4]> =
            SmallVec::with_capacity(usize_cap(num_pack_streams, input.len()));
        for _i in 0..num_pack_streams {
            let (sliced, a_pack_size) = sevenzip_varuint64_decode(input)?;
            pack_size.push(a_pack_size);
            input = sliced;
        }

        // Property::END tag
        let (input, _end_marker) = le_u8(input)?;

        Ok((
            input,
            PackInfo {
                pack_pos,
                num_pack_streams,
                pack_size,
            },
        ))
    }
}

/// Describes the decompression structure: folders, their coders, and output sizes.
///
/// Folder metadata is validated eagerly but parsed lazily: the raw bytes are
/// stored alongside a lightweight index, and full [`Folder`] structs are
/// constructed on demand via [`parse_folder`](UnpackInfo::parse_folder).
#[derive(Debug, Clone)]
pub struct UnpackInfo {
    /// Number of compression folders.
    pub num_folders: u64,
    /// Raw bytes of all folder blocks (validated, not yet parsed).
    /// Arc-backed slice of the original archive `Bytes` — zero copy.
    folder_data: Bytes,
    /// Byte offset of each folder within `folder_data`.
    /// Length = `num_folders + 1` (sentinel at end).
    folder_offsets: Vec<u32>,
    /// Uncompressed (output) size for each coder out-stream across all folders.
    pub unpack_sizes: SmallVec<[u64; 4]>,
    /// Optional CRC32 digest per folder (used to verify decompressed output).
    pub digests: SmallVec<[Option<u32>; 4]>,
}

impl PartialEq for UnpackInfo {
    fn eq(&self, other: &Self) -> bool {
        self.num_folders == other.num_folders
            && self.folder_data == other.folder_data
            && self.folder_offsets == other.folder_offsets
            && self.unpack_sizes == other.unpack_sizes
            && self.digests == other.digests
    }
}

impl UnpackInfo {
    /// Parse a single folder on demand.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError`](crate::R7zError) if the stored bytes are malformed
    /// (should not happen — bytes are validated during [`parse`](UnpackInfo::parse)).
    ///
    /// # Panics
    ///
    /// Panics if `idx >= num_folders`.
    pub fn parse_folder(&self, idx: usize) -> Result<Folder, crate::R7zError> {
        let start = self.folder_offsets[idx] as usize;
        let end = self.folder_offsets[idx + 1] as usize;
        let (_, folder) = Folder::parse(&self.folder_data[start..end])
            .map_err(|_| crate::R7zError::Parse)?;
        Ok(folder)
    }

    /// Number of folders (as `usize`).
    #[must_use]
    pub fn num_folders_usize(&self) -> usize {
        self.folder_offsets.len() - 1
    }
    /// Parse an `UnpackInfo` block from the header stream.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated or does not start with the `UnPackInfo` tag.
    pub fn parse<'a>(input: &'a [u8], backing: &Bytes) -> IResult<&'a [u8], UnpackInfo> {
        let orig_input = input;
        let (input, property_id) = Property::parse(input)?;
        if property_id != Property::UnPackInfo {
            return Err(nom::Err::Failure(nom::error::Error::new(
                orig_input,
                nom::error::ErrorKind::Satisfy,
            )));
        }

        // Folder tag
        let (input, _folder_marker) = le_u8(input)?;
        let (input, num_folders) = sevenzip_varuint64_decode(input)?;
        let (input, is_external) = le_u8(input)?;

        let input = if is_external != 0 {
            let (input, _data_stream_index) = sevenzip_varuint64_decode(input)?;
            input
        } else {
            input
        };

        // Scan and validate each folder — record byte offsets and total_out_streams
        // without building Folder structs.
        let folder_start = input;
        let mut folder_offsets: Vec<u32> =
            Vec::with_capacity(usize_cap(num_folders, input.len()) + 1);
        let mut total_out_streams: usize = 0;
        let mut input = input;
        for _ in 0..num_folders {
            let offset = u32::try_from(folder_start.len() - input.len()).map_err(|_| {
                nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::TooLarge,
                ))
            })?;
            folder_offsets.push(offset);
            let (i, out_streams) = scan_folder(input)?;
            total_out_streams += out_streams;
            input = i;
        }
        // Sentinel offset marking end of last folder
        let end_offset = u32::try_from(folder_start.len() - input.len()).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            ))
        })?;
        folder_offsets.push(end_offset);
        let folder_data = backing.slice_ref(&folder_start[..end_offset as usize]);

        // Property-tag loop for CodersUnPackSize and CRC
        let mut unpack_sizes: SmallVec<[u64; 4]> =
            SmallVec::with_capacity(total_out_streams.min(input.len()));
        let mut digests: SmallVec<[Option<u32>; 4]> = SmallVec::new();

        loop {
            let (i, tag) = Property::parse(input)?;
            input = i;
            match tag {
                Property::END => break,
                Property::CodersUnPackSize => {
                    for _ in 0..total_out_streams {
                        let (i, size) = sevenzip_varuint64_decode(input)?;
                        unpack_sizes.push(size);
                        input = i;
                    }
                }
                Property::CRC => {
                    let (i, crcs) = parse_digests(input, num_folders.to_usize())?;
                    digests = crcs;
                    input = i;
                }
                _ => {
                    // Skip unknown sections (read size + skip)
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let (i, _) =
                        nom::bytes::complete::take(usize::try_from(size).map_err(|_| {
                            nom::Err::Error(nom::error::Error::new(
                                input,
                                nom::error::ErrorKind::TooLarge,
                            ))
                        })?)(i)?;
                    input = i;
                }
            }
        }

        if digests.is_empty() {
            digests.resize(folder_offsets.len() - 1, None);
        }

        Ok((
            input,
            UnpackInfo {
                num_folders,
                folder_data,
                folder_offsets,
                unpack_sizes,
                digests,
            },
        ))
    }
}

/// Walk a `PackInfo` block without allocating.  Used for header validation.
///
/// # Errors
///
/// Returns a nom error if the input is truncated or does not start with the `PackInfo` tag.
pub(crate) fn scan_pack_info(input: &[u8]) -> IResult<&[u8], ()> {
    let orig = input;
    let (input, tag) = Property::parse(input)?;
    if tag != Property::PackInfo {
        return Err(nom::Err::Failure(nom::error::Error::new(
            orig,
            nom::error::ErrorKind::Satisfy,
        )));
    }
    let (input, _pack_pos) = sevenzip_varuint64_decode(input)?;
    let (input, num_pack_streams) = sevenzip_varuint64_decode(input)?;
    let (mut input, _size_marker) = le_u8(input)?;
    for _ in 0..num_pack_streams {
        let (i, _) = sevenzip_varuint64_decode(input)?;
        input = i;
    }
    let (input, _end) = le_u8(input)?;
    Ok((input, ()))
}

/// Walk an `UnpackInfo` block without allocating.  Returns the number of folders.
///
/// Validates the folder layout via [`scan_folder`], then walks the
/// `CodersUnPackSize` and optional `CRC` sections.
///
/// # Errors
///
/// Returns a nom error if the input is truncated or does not start with the
/// `UnPackInfo` tag.
pub(crate) fn scan_unpack_info(input: &[u8]) -> IResult<&[u8], usize> {
    let orig = input;
    let (input, tag) = Property::parse(input)?;
    if tag != Property::UnPackInfo {
        return Err(nom::Err::Failure(nom::error::Error::new(
            orig,
            nom::error::ErrorKind::Satisfy,
        )));
    }

    let (input, _folder_marker) = le_u8(input)?;
    let (input, num_folders) = sevenzip_varuint64_decode(input)?;
    let (input, is_external) = le_u8(input)?;

    let input = if is_external != 0 {
        let (input, _) = sevenzip_varuint64_decode(input)?;
        input
    } else {
        input
    };

    let mut total_out_streams: usize = 0;
    let mut input = input;
    for _ in 0..num_folders {
        let (i, out_streams) = scan_folder(input)?;
        total_out_streams += out_streams;
        input = i;
    }

    let nf = usize::try_from(num_folders).map_err(|_| {
        nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TooLarge,
        ))
    })?;

    loop {
        let (i, tag) = Property::parse(input)?;
        input = i;
        match tag {
            Property::END => break,
            Property::CodersUnPackSize => {
                for _ in 0..total_out_streams {
                    let (i, _) = sevenzip_varuint64_decode(input)?;
                    input = i;
                }
            }
            Property::CRC => {
                let (i, ()) = scan_digests(input, nf)?;
                input = i;
            }
            _ => {
                let (i, size) = sevenzip_varuint64_decode(input)?;
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

    Ok((input, nf))
}

/// Parse CRC digests for `num_streams` streams using `AllAreDefined` + optional bitmap.
fn parse_digests(input: &[u8], num_streams: usize) -> IResult<&[u8], SmallVec<[Option<u32>; 4]>> {
    use nom::number::complete::le_u32;

    let (input, all_defined) = le_u8(input)?;

    let (bitmap, input) = if all_defined == 0 {
        let num_bytes = num_streams.div_ceil(8);
        let (rest, bm) = nom::bytes::complete::take(num_bytes)(input)?;
        (bm, rest)
    } else {
        (&[][..], input)
    };

    let is_defined = |i: usize| -> bool { all_defined != 0 || (bitmap[i / 8] >> (i % 8)) & 1 == 1 };

    (0..num_streams).try_fold(
        (input, SmallVec::with_capacity(num_streams.min(input.len()))),
        |(input, mut crcs), i| {
            if is_defined(i) {
                let (input, crc) = le_u32(input)?;
                crcs.push(Some(crc));
                Ok((input, crcs))
            } else {
                crcs.push(None);
                Ok((input, crcs))
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{scan_pack_info, scan_unpack_info};

    // ── scan_pack_info ──────────────────────────────────────────────

    /// Minimal valid PackInfo: 1 stream, pack_pos=0, size=100.
    #[test]
    fn scan_pack_info_one_stream() {
        // 0x06=PackInfo, pack_pos=0, num_streams=1, 0x09=Size, 100, 0x00=END
        let input = [0x06u8, 0x00, 0x01, 0x09, 0x64, 0x00];
        let (rem, ()) = scan_pack_info(&input).unwrap();
        assert!(rem.is_empty());
    }

    /// Three streams; trailing byte left in remainder.
    #[test]
    fn scan_pack_info_three_streams_trailing() {
        // sizes: 100, 50, 25
        let input = [0x06u8, 0x00, 0x03, 0x09, 0x64, 0x32, 0x19, 0x00, 0xFF];
        let (rem, ()) = scan_pack_info(&input).unwrap();
        assert_eq!(rem, &[0xFF]);
    }

    /// Wrong tag (UnPackInfo) returns a hard Failure.
    #[test]
    fn scan_pack_info_wrong_tag() {
        assert!(scan_pack_info(&[0x07u8]).is_err());
    }

    /// Truncated before sizes returns an error.
    #[test]
    fn scan_pack_info_truncated() {
        let input = [0x06u8, 0x00, 0x01, 0x09]; // missing size + END
        assert!(scan_pack_info(&input).is_err());
    }

    // ── scan_unpack_info ────────────────────────────────────────────

    /// One folder with copy codec → returns num_folders=1.
    #[test]
    fn scan_unpack_info_one_folder() {
        // UnPackInfo, Folder tag, 1 folder, not external,
        // folder=[copy coder], CodersUnPackSize, 100, END
        let input = [0x07u8, 0x0B, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0C, 0x64, 0x00];
        let (rem, nf) = scan_unpack_info(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(nf, 1);
    }

    /// Two folders each with copy codec → returns num_folders=2.
    #[test]
    fn scan_unpack_info_two_folders() {
        let input = [
            0x07u8, 0x0B, 0x02, 0x00,
            // folder 0: copy
            0x01, 0x01, 0x00,
            // folder 1: copy
            0x01, 0x01, 0x00,
            // CodersUnPackSize: 2 out-streams (one per folder)
            0x0C, 0x64, 0x32,
            // END
            0x00,
        ];
        let (rem, nf) = scan_unpack_info(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(nf, 2);
    }

    /// CRC section (all_defined=1, 1 CRC) is skipped correctly.
    #[test]
    fn scan_unpack_info_with_crc() {
        let input = [
            0x07u8, 0x0B, 0x01, 0x00,
            // folder: copy
            0x01, 0x01, 0x00,
            // CodersUnPackSize
            0x0C, 0x64,
            // CRC section: all_defined=1, 1 CRC (4 bytes)
            0x0A, 0x01, 0xAA, 0xBB, 0xCC, 0xDD,
            // END
            0x00,
        ];
        let (rem, nf) = scan_unpack_info(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(nf, 1);
    }

    /// Wrong tag returns an error.
    #[test]
    fn scan_unpack_info_wrong_tag() {
        assert!(scan_unpack_info(&[0x06u8]).is_err());
    }
}
