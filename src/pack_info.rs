use nom::{number::streaming::le_u8, IResult, ToUsize};

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
    pub pack_size: Vec<u64>,
}

impl PackInfo {
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

        let mut pack_size = Vec::new();
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
    pub folders: Vec<Folder>,
    /// Uncompressed (output) size for each coder out-stream across all folders.
    pub unpack_sizes: Vec<u64>,
    /// Optional CRC32 digest per folder (used to verify decompressed output).
    pub digests: Vec<Option<u32>>,
}

impl UnpackInfo {
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
        let mut folders = Vec::new();
        let mut input = input;
        for _ in 0..num_folders {
            let (i, folder) = Folder::parse(input)?;
            folders.push(folder);
            input = i;
        }

        // Total number of out-streams across all folders
        let total_out_streams: usize = folders.iter().map(|f| f.total_out_streams()).sum();

        // Property-tag loop for CodersUnPackSize and CRC
        let mut unpack_sizes = Vec::new();
        let mut digests = vec![None; num_folders.to_usize()];

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
                    let (i, _) = nom::bytes::streaming::take(size as usize)(i)?;
                    input = i;
                }
            }
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

/// Parse CRC digests for `num_streams` streams using AllAreDefined + optional bitmap.
fn parse_digests(input: &[u8], num_streams: usize) -> IResult<&[u8], Vec<Option<u32>>> {
    use nom::number::streaming::le_u32;

    let (input, all_defined) = le_u8(input)?;

    let defined: Vec<bool> = if all_defined != 0 {
        vec![true; num_streams]
    } else {
        let num_bytes = num_streams.div_ceil(8);
        let (_, bitmap) = nom::bytes::streaming::take(num_bytes)(input)?;
        (0..num_streams)
            .map(|i| (bitmap[i / 8] >> (i % 8)) & 1 == 1)
            .collect()
    };

    // If all_defined == 0, we consumed bitmap bytes
    let input = if all_defined == 0 {
        let num_bytes = num_streams.div_ceil(8);
        &input[num_bytes..]
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
