use crate::pack_info::{
    FolderLocation, parse_folder_declaration, scan_pack_info, scan_unpack_info_with_external,
};
use crate::parsers::{bitmap_is_set, scan_digests};
use crate::{Folder, PackInfo, Property, R7zError, UnpackInfo, codec, sevenzip_varuint64_decode};
use bytes::Bytes;
use nom::{IResult, number::complete::le_u8};
use smallvec::SmallVec;
use std::ops::Range;

// Keep a single substream digest table within the default 64 MiB metadata budget.
const MAX_SUBSTREAM_DIGESTS: usize = (64 * 1024 * 1024) / std::mem::size_of::<Option<u32>>();

pub(crate) struct PackedStream {
    pub(crate) range: Range<u64>,
    pub(crate) crc: Option<u32>,
}

/// Packed ranges validated during planning, without an owned descriptor list.
struct PackedStreams<'a> {
    sizes: &'a [u64],
    digests: &'a [Option<u32>],
    start: u64,
}

impl PackedStreams<'_> {
    fn iter(&self) -> impl Iterator<Item = PackedStream> {
        self.sizes
            .iter()
            .enumerate()
            .scan(self.start, |offset, (index, &size)| {
                let end = *offset + size;
                let stream = PackedStream {
                    range: *offset..end,
                    crc: self.digests.get(index).copied().flatten(),
                };
                *offset = end;
                Some(stream)
            })
    }
}

/// Additional data streams in the order used by external folder references.
#[derive(Default)]
pub(crate) struct ExternalFolderData(Vec<Bytes>);

impl ExternalFolderData {
    pub(crate) fn reserve(stream_count: usize, metadata_limit: u64) -> Result<Self, R7zError> {
        let slot_bytes = stream_count
            .checked_mul(std::mem::size_of::<Bytes>())
            .and_then(|size| u64::try_from(size).ok())
            .ok_or(R7zError::LimitExceeded("metadata"))?;
        if slot_bytes > metadata_limit {
            return Err(R7zError::LimitExceeded("metadata"));
        }
        let mut streams = Vec::new();
        streams
            .try_reserve_exact(stream_count)
            .map_err(|_| R7zError::LimitExceeded("metadata"))?;
        Ok(Self(streams))
    }

    /// Adapt caller-supplied data at the public parser boundary.
    pub(crate) fn from_supplied(streams: Vec<Bytes>) -> Self {
        Self(streams)
    }

    pub(crate) fn as_slice(&self) -> &[Bytes] {
        &self.0
    }

    pub(crate) fn append(&mut self, folder: DecodedFolder<'_>) -> Result<(), R7zError> {
        for stream in folder.streams() {
            self.0.push(stream?.0);
        }
        Ok(())
    }
}

/// Bytes whose folder and substream checks have passed.
pub(crate) struct DecodedSubstream(Bytes);

/// Validated substream sizes, including the format's implicit final size.
struct FolderStreamLayout<'a> {
    explicit_sizes: &'a [u64],
    final_size: Option<usize>,
    digests: &'a [Option<u32>],
}

impl<'a> FolderStreamLayout<'a> {
    fn new(
        decoded_len: usize,
        stream_count: usize,
        explicit_sizes: &'a [u64],
        digests: &'a [Option<u32>],
    ) -> Result<Self, R7zError> {
        if explicit_sizes.len() != stream_count.saturating_sub(1)
            || (!digests.is_empty() && digests.len() != stream_count)
        {
            return Err(R7zError::Parse);
        }
        let explicit_total = explicit_sizes.iter().try_fold(0usize, |total, &size| {
            let size = usize::try_from(size).map_err(|_| R7zError::Parse)?;
            total.checked_add(size).ok_or(R7zError::Parse)
        })?;
        let remaining = decoded_len
            .checked_sub(explicit_total)
            .ok_or(R7zError::Parse)?;
        Ok(Self {
            explicit_sizes,
            final_size: (stream_count != 0).then_some(remaining),
            digests,
        })
    }

    fn len(&self) -> usize {
        self.explicit_sizes.len() + usize::from(self.final_size.is_some())
    }

    fn ranges(self) -> impl Iterator<Item = (Range<usize>, Option<u32>)> + 'a {
        self.explicit_sizes
            .iter()
            // Construction proves every size and their sum fit usize.
            .map(|&size| usize::try_from(size).expect("validated substream size"))
            .chain(self.final_size)
            .enumerate()
            .scan(0, move |offset, (index, size)| {
                let end = *offset + size;
                let range = *offset..end;
                *offset = end;
                Some((range, self.digests.get(index).copied().flatten()))
            })
    }
}

pub(crate) struct Packed<'a> {
    folder: Folder,
    streams: PackedStreams<'a>,
    coder_sizes: &'a [u64],
    unpack_size: u64,
    decoded_len: usize,
    read_limit: u64,
    crc: Option<u32>,
}

pub(crate) struct Decoded(Bytes);

/// The layout stays attached to its folder across the consuming decode transition.
pub(crate) struct MetadataFolder<'a, State> {
    state: State,
    layout: FolderStreamLayout<'a>,
}

pub(crate) type PackedFolder<'a> = MetadataFolder<'a, Packed<'a>>;
pub(crate) type DecodedFolder<'a> = MetadataFolder<'a, Decoded>;

impl<'a> PackedFolder<'a> {
    pub(crate) fn packed_streams(&self) -> impl Iterator<Item = PackedStream> {
        self.state.streams.iter()
    }

    pub(crate) fn decode<R: std::io::Read>(
        self,
        inputs: SmallVec<[codec::PackedInput<R>; 4]>,
        password: Option<&str>,
    ) -> Result<DecodedFolder<'a>, R7zError> {
        let reader = codec::folder_reader_with_pack_streams(
            &self.state.folder,
            inputs,
            self.state.unpack_size,
            self.state.coder_sizes,
            password,
        )?;
        let bytes = reader.read_bounded_to_vec(self.state.decoded_len, self.state.read_limit)?;
        self.verify_decoded(Bytes::from(bytes))
    }

    fn verify_decoded(self, decoded: Bytes) -> Result<DecodedFolder<'a>, R7zError> {
        if decoded.len() != self.state.decoded_len {
            return Err(R7zError::Decompression);
        }
        if let Some(expected) = self.state.crc
            && crc32fast::hash(&decoded) != expected
        {
            return Err(R7zError::Crc);
        }
        Ok(MetadataFolder {
            state: Decoded(decoded),
            layout: self.layout,
        })
    }
}

impl<'a> DecodedFolder<'a> {
    fn streams(self) -> impl Iterator<Item = Result<DecodedSubstream, R7zError>> + 'a {
        self.layout.ranges().map(move |(range, digest)| {
            let stream = self.state.0.slice(range);
            if digest.is_some_and(|expected| crc32fast::hash(&stream) != expected) {
                return Err(R7zError::Crc);
            }
            Ok(DecodedSubstream(stream))
        })
    }
}

#[derive(Clone)]
struct FolderPlans<'a> {
    pack_info: &'a PackInfo,
    unpack_info: &'a UnpackInfo,
    substream_info: Option<&'a SubstreamInfo>,
    folder_index: usize,
    pack_index: usize,
    output_base: usize,
    pack_offset: u64,
    stream_size_base: usize,
    stream_digest_base: usize,
}

pub(crate) struct PackedFolders<'a> {
    plans: FolderPlans<'a>,
    stream_count: usize,
}

impl PackedFolders<'_> {
    pub(crate) fn pack_pos(&self) -> u64 {
        self.plans.pack_info.pack_pos
    }

    pub(crate) fn stream_count(&self) -> usize {
        self.stream_count
    }
}

impl<'a> Iterator for PackedFolders<'a> {
    type Item = Result<PackedFolder<'a>, R7zError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.plans.next()
    }
}

impl<'a> Iterator for FolderPlans<'a> {
    type Item = Result<PackedFolder<'a>, R7zError>;

    fn next(&mut self) -> Option<Self::Item> {
        (self.folder_index < self.unpack_info.num_folders_usize()).then(|| {
            let result = self.next_folder();
            if result.is_err() {
                self.folder_index = self.unpack_info.num_folders_usize();
            }
            result
        })
    }
}

impl<'a> FolderPlans<'a> {
    fn next_folder(&mut self) -> Result<PackedFolder<'a>, R7zError> {
        let (folder, graph) = self
            .unpack_info
            .parse_folder_with_graph(self.folder_index)?;
        let pack_end = self
            .pack_index
            .checked_add(graph.packed_stream_count())
            .ok_or(R7zError::Parse)?;
        let pack_sizes = self
            .pack_info
            .pack_size
            .get(self.pack_index..pack_end)
            .ok_or(R7zError::Parse)?;
        let output_end = self
            .output_base
            .checked_add(folder.total_out_streams())
            .ok_or(R7zError::Parse)?;
        let coder_sizes = self
            .unpack_info
            .unpack_sizes
            .get(self.output_base..output_end)
            .ok_or(R7zError::Parse)?;
        let unpack_size = *coder_sizes
            .get(graph.final_output().get())
            .ok_or(R7zError::Parse)?;
        let decoded_len =
            usize::try_from(unpack_size).map_err(|_| R7zError::LimitExceeded("metadata"))?;
        let read_limit = u64::try_from(
            decoded_len
                .checked_add(1)
                .ok_or(R7zError::LimitExceeded("metadata"))?,
        )
        .map_err(|_| R7zError::LimitExceeded("metadata"))?;
        let stream_count = self
            .substream_info
            .map(|info| {
                info.num_unpack_streams_per_folder
                    .get(self.folder_index)
                    .copied()
                    .ok_or(R7zError::Parse)
                    .and_then(|count| usize::try_from(count).map_err(|_| R7zError::Parse))
            })
            .transpose()?
            .unwrap_or(1);
        let explicit_count = stream_count.saturating_sub(1);
        let stream_size_end = self
            .stream_size_base
            .checked_add(explicit_count)
            .ok_or(R7zError::Parse)?;
        let explicit_stream_sizes = match self.substream_info {
            Some(info) => info
                .unpack_sizes
                .get(self.stream_size_base..stream_size_end)
                .ok_or(R7zError::Parse)?,
            None => &[],
        };
        let stream_digest_end = self
            .stream_digest_base
            .checked_add(stream_count)
            .ok_or(R7zError::Parse)?;
        let stream_digests = self
            .substream_info
            .filter(|info| !info.digests.is_empty())
            .map(|info| {
                info.digests
                    .get(self.stream_digest_base..stream_digest_end)
                    .ok_or(R7zError::Parse)
            })
            .transpose()?;
        let layout = FolderStreamLayout::new(
            decoded_len,
            stream_count,
            explicit_stream_sizes,
            stream_digests.unwrap_or_default(),
        )?;

        let pack_offset = pack_sizes
            .iter()
            .try_fold(self.pack_offset, |offset, &size| {
                offset.checked_add(size).ok_or(R7zError::Parse)
            })?;
        let streams = PackedStreams {
            sizes: pack_sizes,
            digests: self
                .pack_info
                .digests
                .get(self.pack_index..pack_end.min(self.pack_info.digests.len()))
                .unwrap_or_default(),
            start: self.pack_offset,
        };
        let crc = self
            .unpack_info
            .digests
            .get(self.folder_index)
            .copied()
            .flatten();
        self.folder_index += 1;
        self.pack_index = pack_end;
        self.pack_offset = pack_offset;
        self.output_base = output_end;
        self.stream_size_base = stream_size_end;
        self.stream_digest_base = stream_digest_end;
        Ok(PackedFolder {
            state: Packed {
                folder,
                streams,
                coder_sizes,
                unpack_size,
                decoded_len,
                read_limit,
                crc,
            },
            layout,
        })
    }
}

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
    pub(crate) fn uses_external_folder_data(mut input: &[u8]) -> IResult<&[u8], bool> {
        loop {
            let (after_tag, tag) = Property::parse(input)?;
            match tag {
                Property::END => return Ok((after_tag, false)),
                Property::UnPackInfo => {
                    let (remaining, (_, location)) = parse_folder_declaration(input)?;
                    return Ok((remaining, matches!(location, FolderLocation::External(_))));
                }
                Property::PackInfo => input = scan_pack_info(input)?.0,
                Property::SubStreamsInfo => input = scan_substream_info(input, 0)?.0,
                _ => {
                    let (remaining, size) = sevenzip_varuint64_decode(after_tag)?;
                    let size = usize::try_from(size).map_err(|_| {
                        nom::Err::Failure(nom::error::Error::new(
                            remaining,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    input = nom::bytes::complete::take(size)(remaining)?.0;
                }
            }
        }
    }

    pub(crate) fn packed_folders(&self) -> Result<(&PackInfo, &UnpackInfo), R7zError> {
        match (&self.pack_info, &self.unpack_info) {
            (Some(pack), Some(unpack)) => Ok((pack, unpack)),
            _ => Err(R7zError::Parse),
        }
    }

    pub(crate) fn checked_packed_folders(
        &self,
        metadata_limit: u64,
    ) -> Result<PackedFolders<'_>, R7zError> {
        let (pack, unpack) = self.packed_folders()?;
        let packed_bytes = pack.pack_size.iter().try_fold(0u64, |total, &size| {
            total.checked_add(size).ok_or(R7zError::Parse)
        })?;
        if packed_bytes > metadata_limit {
            return Err(R7zError::LimitExceeded("metadata"));
        }
        let plans = FolderPlans {
            pack_info: pack,
            unpack_info: unpack,
            substream_info: self.substream_info.as_ref(),
            folder_index: 0,
            pack_index: 0,
            output_base: 0,
            pack_offset: 0,
            stream_size_base: 0,
            stream_digest_base: 0,
        };
        let mut preflight = plans.clone();
        let mut output_size = 0u64;
        let mut stream_count = 0usize;
        for folder in preflight.by_ref() {
            let folder = folder?;
            stream_count = stream_count
                .checked_add(folder.layout.len())
                .ok_or(R7zError::Parse)?;
            output_size = output_size
                .checked_add(folder.state.unpack_size)
                .ok_or(R7zError::Parse)?;
            if output_size > metadata_limit {
                return Err(R7zError::LimitExceeded("metadata"));
            }
        }
        let substreams_complete = self.substream_info.as_ref().is_none_or(|info| {
            info.unpack_sizes.len() == preflight.stream_size_base
                && (info.digests.is_empty() || info.digests.len() == stream_count)
        });
        if preflight.pack_index != pack.pack_size.len() || !substreams_complete {
            return Err(R7zError::Parse);
        }
        Ok(PackedFolders {
            plans,
            stream_count,
        })
    }

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
        Self::parse_with_external(input, backing, &[])
    }

    /// Parse a stream descriptor with decoded external folder definitions.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the descriptor or a referenced folder definition is malformed.
    pub fn parse_with_external<'a>(
        input: &'a [u8],
        backing: &Bytes,
        external_data: &[Bytes],
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
    scan_stream_info_with_external(input, &[])
}

pub(crate) fn scan_stream_info_with_external<'a>(
    input: &'a [u8],
    external_data: &[Bytes],
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
    use super::{
        ExternalFolderData, FolderStreamLayout, MAX_SUBSTREAM_DIGESTS, Packed, PackedFolder,
        PackedStreams, SubstreamInfo, scan_stream_info, scan_substream_info,
    };
    use crate::{Folder, R7zError};
    use bytes::Bytes;

    fn packed_folder<'a>(
        decoded_len: usize,
        crc: Option<u32>,
        layout: FolderStreamLayout<'a>,
    ) -> PackedFolder<'a> {
        PackedFolder {
            state: Packed {
                folder: Folder {
                    coders: Default::default(),
                    bind_pairs: Default::default(),
                    packed_indices: Default::default(),
                },
                streams: PackedStreams {
                    sizes: &[],
                    digests: &[],
                    start: 0,
                },
                coder_sizes: &[],
                unpack_size: decoded_len as u64,
                decoded_len,
                read_limit: decoded_len as u64 + 1,
                crc,
            },
            layout,
        }
    }

    #[test]
    fn decoded_folder_requires_expected_length_and_crc() {
        let folder = || {
            packed_folder(
                3,
                Some(crc32fast::hash(b"abc")),
                FolderStreamLayout::new(3, 0, &[], &[]).unwrap(),
            )
        };
        assert!(matches!(
            folder().verify_decoded(Bytes::from_static(b"ab")),
            Err(R7zError::Decompression)
        ));
        assert!(matches!(
            folder().verify_decoded(Bytes::from_static(b"abd")),
            Err(R7zError::Crc)
        ));
        assert!(folder().verify_decoded(Bytes::from_static(b"abc")).is_ok());
    }

    #[test]
    fn split_folder_appends_indexed_substreams_and_checks_their_crcs() {
        let digests = [Some(crc32fast::hash(b"ab")), Some(crc32fast::hash(b"cde"))];
        let folder = || {
            packed_folder(
                5,
                None,
                FolderStreamLayout::new(5, 2, &[2], &digests).unwrap(),
            )
        };
        let decoded = folder()
            .verify_decoded(Bytes::from_static(b"abcde"))
            .unwrap();
        let mut streams = ExternalFolderData::reserve(2, 1024).unwrap();
        streams.append(decoded).unwrap();
        assert_eq!(
            streams.as_slice(),
            [Bytes::from_static(b"ab"), Bytes::from_static(b"cde")]
        );

        let decoded = folder()
            .verify_decoded(Bytes::from_static(b"abXde"))
            .unwrap();
        assert!(matches!(
            ExternalFolderData::reserve(2, 1024)
                .unwrap()
                .append(decoded),
            Err(R7zError::Crc)
        ));
    }

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
