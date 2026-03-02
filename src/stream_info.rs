use crate::{sevenzip_varuint64_decode, PackInfo, Property, UnpackInfo};
use nom::{number::complete::le_u8, IResult, ToUsize};

/// Per-file stream metadata within a solid (multi-file) folder.
#[derive(Debug, PartialEq)]
pub struct SubstreamInfo {
    /// Number of files (data streams) stored in each folder.
    pub num_unpack_streams_per_folder: Vec<u64>,
    /// Explicit uncompressed sizes for each stream except the last per folder.
    /// The last stream's size is implicit: `folder_unpack_size - sum(explicit)`.
    pub unpack_sizes: Vec<u64>,
    /// CRC32 digest per stream (may be absent for some or all streams).
    pub digests: Vec<Option<u32>>,
}

impl SubstreamInfo {
    /// Parse a `SubstreamInfo` block from the header stream.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated or does not start with the
    /// `SubStreamsInfo` property tag.
    ///
    /// # Panics
    ///
    /// Panics if `num_unpack_streams_per_folder` values exceed `usize::MAX`
    /// (impossible in practice).
    pub fn parse(input: &[u8], num_folders: usize) -> IResult<&[u8], SubstreamInfo> {
        let orig_input = input;
        let (input, tag) = Property::parse(input)?;
        if tag != Property::SubStreamsInfo {
            return Err(nom::Err::Failure(nom::error::Error::new(
                orig_input,
                nom::error::ErrorKind::Satisfy,
            )));
        }

        let mut num_unpack_streams_per_folder = vec![1u64; num_folders];
        let mut unpack_sizes = Vec::new();
        let mut digests = Vec::new();
        let mut input = input;

        loop {
            let (i, tag) = Property::parse(input)?;
            input = i;
            match tag {
                Property::END => break,
                Property::NumUnPackStream => {
                    num_unpack_streams_per_folder.clear();
                    for _ in 0..num_folders {
                        let (i, n) = sevenzip_varuint64_decode(input)?;
                        num_unpack_streams_per_folder.push(n);
                        input = i;
                    }
                }
                Property::Size => {
                    // For each folder, store NumUnpackStreams-1 sizes explicitly;
                    // the last stream's size is: folder_unpack_size - sum(explicit_sizes)
                    let sizes_to_read: usize = num_unpack_streams_per_folder
                        .iter()
                        .map(|&n| {
                            usize::try_from(n)
                                .expect("num_unpack_streams_per_folder fits in usize")
                                .saturating_sub(1)
                        })
                        .sum();
                    for _ in 0..sizes_to_read {
                        let (i, size) = sevenzip_varuint64_decode(input)?;
                        unpack_sizes.push(size);
                        input = i;
                    }
                }
                Property::CRC => {
                    let total: usize = num_unpack_streams_per_folder
                        .iter()
                        .map(|&n| n.to_usize())
                        .sum();
                    let (i, crcs) = parse_stream_digests(input, total)?;
                    digests = crcs;
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

        Ok((
            input,
            SubstreamInfo {
                num_unpack_streams_per_folder,
                unpack_sizes,
                digests,
            },
        ))
    }
}

fn parse_stream_digests(input: &[u8], num: usize) -> IResult<&[u8], Vec<Option<u32>>> {
    use nom::number::complete::le_u32;

    let (input, all_defined) = le_u8(input)?;
    let defined: Vec<bool> = if all_defined != 0 {
        vec![true; num]
    } else {
        let num_bytes = num.div_ceil(8);
        let (_, bitmap) = nom::bytes::complete::take(num_bytes)(input)?;
        (0..num)
            .map(|i| (bitmap[i / 8] >> (i % 8)) & 1 == 1)
            .collect()
    };

    let input = if all_defined == 0 {
        &input[num.div_ceil(8)..]
    } else {
        input
    };

    let mut crcs = Vec::new();
    let mut input = input;
    for is_def in &defined {
        if *is_def {
            let (i, crc) = le_u32(input)?;
            crcs.push(Some(crc));
            input = i;
        } else {
            crcs.push(None);
        }
    }

    Ok((input, crcs))
}

/// Ties together [`PackInfo`], [`UnpackInfo`], and optional [`SubstreamInfo`].
///
/// This is the top-level streams descriptor embedded in the 7z `Header`.
#[derive(Debug, PartialEq)]
pub struct StreamInfo {
    /// Location and sizes of packed (compressed) data in the archive file.
    pub pack_info: Option<PackInfo>,
    /// Folder/coder layout and uncompressed sizes.
    pub unpack_info: Option<UnpackInfo>,
    /// Per-file stream breakdown within solid folders (absent for single-file folders).
    pub substream_info: Option<SubstreamInfo>,
}

impl StreamInfo {
    /// Parse a `StreamInfo` block from the header stream.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated or malformed.
    ///
    /// # Panics
    ///
    /// Panics if `num_folders` exceeds `usize::MAX` (impossible in practice).
    pub fn parse(input: &[u8]) -> IResult<&[u8], StreamInfo> {
        let mut pack_info = None;
        let mut unpack_info = None;
        let mut substream_info = None;
        let mut input = input;

        loop {
            let (i, tag) = Property::parse(input)?;
            match tag {
                Property::END => {
                    input = i;
                    break;
                }
                Property::PackInfo => {
                    // The tag was already consumed; push it back by re-parsing from original
                    let (i, pi) = PackInfo::parse(input)?;
                    pack_info = Some(pi);
                    input = i;
                }
                Property::UnPackInfo => {
                    let (i, ui) = UnpackInfo::parse(input)?;
                    unpack_info = Some(ui);
                    input = i;
                }
                Property::SubStreamsInfo => {
                    let num_folders = unpack_info.as_ref().map_or(0, |u| u.folders.len());
                    let (i, si) = SubstreamInfo::parse(input, num_folders)?;
                    substream_info = Some(si);
                    input = i;
                }
                _ => {
                    // Skip unknown section (size-prefixed)
                    input = i;
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

        Ok((
            input,
            StreamInfo {
                pack_info,
                unpack_info,
                substream_info,
            },
        ))
    }
}
