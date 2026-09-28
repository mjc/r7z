use crate::pack_info::{scan_pack_info, scan_unpack_info_with_external};
use crate::parsers::{bitmap_is_set, scan_digests};
use crate::{PackInfo, Property, UnpackInfo, sevenzip_varuint64_decode};
use bytes::Bytes;
use nom::{IResult, number::complete::le_u8};

// Keep a single substream digest table within the default 64 MiB metadata budget.
const MAX_SUBSTREAM_DIGESTS: usize = (64 * 1024 * 1024) / std::mem::size_of::<Option<u32>>();

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
                    let sizes_to_read =
                        checked_substream_size_count(input, &num_unpack_streams_per_folder)?;
                    if sizes_to_read > input.len() {
                        return Err(nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::Eof,
                        )));
                    }
                    unpack_sizes.try_reserve(sizes_to_read).map_err(|_| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    for _ in 0..sizes_to_read {
                        let (i, size) = sevenzip_varuint64_decode(input)?;
                        unpack_sizes.push(size);
                        input = i;
                    }
                }
                Property::CRC => {
                    let total = checked_substream_total(input, &num_unpack_streams_per_folder)?;
                    if total > MAX_SUBSTREAM_DIGESTS {
                        return Err(nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        )));
                    }
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

fn checked_substream_total<'a>(
    input: &'a [u8],
    counts: &[u64],
) -> Result<usize, nom::Err<nom::error::Error<&'a [u8]>>> {
    counts.iter().try_fold(0usize, |total, &count| {
        let count = usize::try_from(count).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            ))
        })?;
        total.checked_add(count).ok_or_else(|| {
            nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            ))
        })
    })
}

fn checked_substream_size_count<'a>(
    input: &'a [u8],
    counts: &[u64],
) -> Result<usize, nom::Err<nom::error::Error<&'a [u8]>>> {
    counts.iter().try_fold(0usize, |total, &count| {
        let count = usize::try_from(count)
            .map_err(|_| {
                nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::TooLarge,
                ))
            })?
            .saturating_sub(1);
        total.checked_add(count).ok_or_else(|| {
            nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            ))
        })
    })
}

fn parse_stream_digests(input: &[u8], num: usize) -> IResult<&[u8], Vec<Option<u32>>> {
    use nom::number::complete::le_u32;

    let (input, all_defined) = le_u8(input)?;

    let (bitmap, input) = if all_defined == 0 {
        let num_bytes = num.div_ceil(8);
        let (rest, bm) = nom::bytes::complete::take(num_bytes)(input)?;
        (bm, rest)
    } else {
        (&[][..], input)
    };

    let num_defined = if all_defined != 0 {
        num
    } else {
        (0..num).filter(|&i| bitmap_is_set(bitmap, i)).count()
    };
    let crc_bytes = num_defined
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or_else(|| {
            nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            ))
        })?;
    if crc_bytes > input.len() {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Eof,
        )));
    }

    let is_defined = |i: usize| -> bool { all_defined != 0 || bitmap_is_set(bitmap, i) };
    let mut crcs = Vec::new();
    crcs.try_reserve_exact(num).map_err(|_| {
        nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TooLarge,
        ))
    })?;

    (0..num).try_fold((input, crcs), |(input, mut crcs), i| {
        if is_defined(i) {
            let (input, crc) = le_u32(input)?;
            crcs.push(Some(crc));
            Ok((input, crcs))
        } else {
            crcs.push(None);
            Ok((input, crcs))
        }
    })
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
    pub fn parse<'a>(input: &'a [u8], backing: &Bytes) -> IResult<&'a [u8], StreamInfo> {
        Self::parse_with_external(input, backing, None)
    }

    /// Parse a stream descriptor with decoded external folder definitions.
    pub fn parse_with_external<'a>(
        input: &'a [u8],
        backing: &Bytes,
        external_data: Option<&'a Bytes>,
    ) -> IResult<&'a [u8], StreamInfo> {
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
                    let (i, ui) = UnpackInfo::parse_with_external(input, backing, external_data)?;
                    unpack_info = Some(ui);
                    input = i;
                }
                Property::SubStreamsInfo => {
                    let num_folders = unpack_info
                        .as_ref()
                        .map_or(0, UnpackInfo::num_folders_usize);
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

// ── zero-alloc scanners ──────────────────────────────────────────────────────

/// Walk a `SubstreamInfo` block without allocating.
///
/// # Errors
///
/// Returns a nom error if the input is truncated or does not start with the
/// `SubStreamsInfo` property tag.
fn scan_substream_info(input: &[u8], num_folders: usize) -> IResult<&[u8], ()> {
    let orig = input;
    let (input, tag) = Property::parse(input)?;
    if tag != Property::SubStreamsInfo {
        return Err(nom::Err::Failure(nom::error::Error::new(
            orig,
            nom::error::ErrorKind::Satisfy,
        )));
    }

    let mut sizes_to_read = 0usize;
    let mut total_streams = num_folders; // default: 1 stream per folder
    let mut input = input;

    loop {
        let (i, tag) = Property::parse(input)?;
        input = i;
        match tag {
            Property::END => break,
            Property::NumUnPackStream => {
                sizes_to_read = 0;
                total_streams = 0;
                for _ in 0..num_folders {
                    let (i, n) = sevenzip_varuint64_decode(input)?;
                    let nu = usize::try_from(n).map_err(|_| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    sizes_to_read =
                        sizes_to_read
                            .checked_add(nu.saturating_sub(1))
                            .ok_or_else(|| {
                                nom::Err::Error(nom::error::Error::new(
                                    input,
                                    nom::error::ErrorKind::TooLarge,
                                ))
                            })?;
                    total_streams = total_streams.checked_add(nu).ok_or_else(|| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    input = i;
                }
            }
            Property::Size => {
                if sizes_to_read > input.len() {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Eof,
                    )));
                }
                for _ in 0..sizes_to_read {
                    let (i, _) = sevenzip_varuint64_decode(input)?;
                    input = i;
                }
            }
            Property::CRC => {
                let (i, ()) = scan_digests(input, total_streams)?;
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

    Ok((input, ()))
}

/// Walk a `StreamInfo` block (`PackInfo` + `UnpackInfo` + `SubstreamInfo`)
/// without allocating.  Used for header validation.
///
/// Expects the input to start *after* the `MainStreamsInfo` tag (the caller
/// has already consumed it).
///
/// # Errors
///
/// Returns a nom error if the input is truncated or malformed.
#[cfg(test)]
pub(crate) fn scan_stream_info(input: &[u8]) -> IResult<&[u8], ()> {
    scan_stream_info_with_external(input, None)
}

pub(crate) fn scan_stream_info_with_external<'a>(
    input: &'a [u8],
    external_data: Option<&Bytes>,
) -> IResult<&'a [u8], ()> {
    let mut num_folders = 0usize;
    let mut input = input;

    loop {
        let (i, tag) = Property::parse(input)?;
        match tag {
            Property::END => {
                input = i;
                break;
            }
            Property::PackInfo => {
                // input still includes the PackInfo tag
                let (i, ()) = scan_pack_info(input)?;
                input = i;
            }
            Property::UnPackInfo => {
                let (i, nf) = scan_unpack_info_with_external(input, external_data)?;
                num_folders = nf;
                input = i;
            }
            Property::SubStreamsInfo => {
                let (i, ()) = scan_substream_info(input, num_folders)?;
                input = i;
            }
            _ => {
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

    Ok((input, ()))
}

#[cfg(test)]
mod tests {
    use super::{MAX_SUBSTREAM_DIGESTS, SubstreamInfo, scan_stream_info, scan_substream_info};

    // ── scan_substream_info ────────────────────────────────────────────────────

    /// Minimal: just END immediately.
    #[test]
    fn scan_substream_info_just_end() {
        // SubStreamsInfo tag (0x08), then END (0x00)
        let input = [0x08u8, 0x00];
        let (rem, ()) = scan_substream_info(&input, 1).unwrap();
        assert!(rem.is_empty());
    }

    /// `NumUnPackStream` + `Size`: 2 folders with `[2, 1]` streams → 1 size to skip.
    #[test]
    fn scan_substream_info_num_unpack_stream() {
        // NumUnPackStream (0x0D): folder[0]=2, folder[1]=1
        // sizes_to_read=(2-1)+(1-1)=1, Size (0x09): one varint, END (0x00)
        let input = [0x08u8, 0x0D, 0x02, 0x01, 0x09, 0x64, 0x00];
        let (rem, ()) = scan_substream_info(&input, 2).unwrap();
        assert!(rem.is_empty());
    }

    #[test]
    fn substream_parsers_reject_untrusted_size_counts_without_iterating() {
        let mut input = vec![0x08, 0x0D];
        input.extend(crate::sevenzip_varuint64_encode(u64::MAX));
        input.extend([0x09, 0x00]);

        assert!(SubstreamInfo::parse(&input, 1).is_err());
        assert!(scan_substream_info(&input, 1).is_err());
    }

    #[test]
    fn substream_parser_caps_sparse_digest_expansion() {
        let mut input = vec![0x08, 0x0D];
        input.extend(crate::sevenzip_varuint64_encode(
            u64::try_from(MAX_SUBSTREAM_DIGESTS + 1).unwrap(),
        ));
        input.extend([0x0A, 0x00]);

        assert!(matches!(
            SubstreamInfo::parse(&input, 1),
            Err(nom::Err::Error(nom::error::Error {
                code: nom::error::ErrorKind::TooLarge,
                ..
            }))
        ));
    }

    /// Wrong opening tag returns a hard Failure.
    #[test]
    fn scan_substream_info_wrong_tag() {
        assert!(scan_substream_info(&[0x06u8], 1).is_err());
    }

    // ── scan_stream_info ──────────────────────────────────────────────────────

    /// Just END — empty stream-info block.
    #[test]
    fn scan_stream_info_empty() {
        let input = [0x00u8];
        let (rem, ()) = scan_stream_info(&input).unwrap();
        assert!(rem.is_empty());
    }

    /// `PackInfo` + `UnpackInfo` + `END`.
    #[test]
    fn scan_stream_info_pack_and_unpack() {
        let input: &[u8] = &[
            // PackInfo: pos=0, 1 stream, size=100
            0x06, 0x00, 0x01, 0x09, 0x64, 0x00,
            // UnPackInfo: 1 folder (copy), unpack_size=100
            0x07, 0x0B, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0C, 0x64, 0x00, // END
            0x00,
        ];
        let (rem, ()) = scan_stream_info(input).unwrap();
        assert!(rem.is_empty());
    }

    /// `PackInfo` + `UnpackInfo` + `SubStreamsInfo` + `END`.
    #[test]
    fn scan_stream_info_with_substreams() {
        let input: &[u8] = &[
            // PackInfo
            0x06, 0x00, 0x01, 0x09, 0x64, 0x00, // UnPackInfo (1 folder, copy codec)
            0x07, 0x0B, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0C, 0x64, 0x00,
            // SubStreamsInfo (just END)
            0x08, 0x00, // stream_info END
            0x00,
        ];
        let (rem, ()) = scan_stream_info(input).unwrap();
        assert!(rem.is_empty());
    }

    /// Trailing bytes after END are preserved in the remainder.
    #[test]
    fn scan_stream_info_trailing_bytes() {
        let input: &[u8] = &[0x00, 0xBE, 0xEF];
        let (rem, ()) = scan_stream_info(input).unwrap();
        assert_eq!(rem, &[0xBE, 0xEF]);
    }
}
