use nom::{number::complete::le_u8, IResult, ToUsize};
use smallvec::SmallVec;

use crate::{sevenzip_varuint64_decode, Folder, Property};

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
            SmallVec::with_capacity((num_pack_streams as usize).min(input.len()));
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
#[derive(Debug, PartialEq)]
pub struct UnpackInfo {
    /// Number of compression folders.
    pub num_folders: u64,
    /// One [`Folder`] per compression unit.
    /// Nearly always length 1; stays on the stack for typical archives.
    pub folders: SmallVec<[Folder; 4]>,
    /// Uncompressed (output) size for each coder out-stream across all folders.
    pub unpack_sizes: SmallVec<[u64; 4]>,
    /// Optional CRC32 digest per folder (used to verify decompressed output).
    pub digests: SmallVec<[Option<u32>; 4]>,
}

impl UnpackInfo {
    /// Parse an `UnpackInfo` block from the header stream.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated or does not start with the `UnPackInfo` tag.
    pub fn parse(input: &[u8]) -> IResult<&[u8], UnpackInfo> {
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

        // Parse each folder
        let mut folders: SmallVec<[Folder; 4]> =
            SmallVec::with_capacity((num_folders as usize).min(input.len()));
        let mut input = input;
        for _ in 0..num_folders {
            let (i, folder) = Folder::parse(input)?;
            folders.push(folder);
            input = i;
        }

        // Total number of out-streams across all folders
        let total_out_streams: usize = folders
            .iter()
            .map(super::folder::Folder::total_out_streams)
            .sum();

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
            digests.resize(folders.len(), None);
        }

        Ok((
            input,
            UnpackInfo {
                num_folders,
                folders,
                unpack_sizes,
                digests,
            },
        ))
    }
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
