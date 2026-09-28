use crate::stream_info::SubstreamInfo;
use crate::{Folder, PackInfo, R7zError, UnpackInfo, codec};
use bytes::Bytes;
use smallvec::SmallVec;
use std::io::Read;
use std::ops::Range;

/// Remaining capacity for retained header bytes and external metadata.
pub(crate) struct MetadataBudget(u64);

impl MetadataBudget {
    pub(crate) fn new(limit: u64) -> Self {
        Self(limit)
    }

    pub(crate) fn charge(self, bytes: u64) -> Result<Self, R7zError> {
        self.0
            .checked_sub(bytes)
            .map(Self)
            .ok_or(R7zError::LimitExceeded("metadata"))
    }

    pub(crate) fn remaining(&self) -> u64 {
        self.0
    }
}

/// External folders whose decoded bytes and stream slots fit the remaining budget.
pub(crate) struct ExternalFolderPlan<'a> {
    folders: FolderLayouts<'a>,
}

impl<'a> ExternalFolderPlan<'a> {
    pub(crate) fn new(
        streams: &'a crate::StreamInfo,
        budget: MetadataBudget,
    ) -> Result<Self, R7zError> {
        let (pack, unpack) = streams.packed_folders()?;
        let folders = FolderLayouts::new(
            pack,
            unpack,
            streams.substream_info.as_ref(),
            budget.remaining(),
        )?;
        let slot_bytes = external_slot_bytes(folders.stream_count())?;
        let _remaining = budget.charge(slot_bytes)?.charge(folders.output_size)?;
        Ok(Self { folders })
    }

    pub(crate) fn pack_pos(&self) -> u64 {
        self.folders.pack_pos()
    }

    pub(crate) fn decode<R: Read>(
        self,
        mut open: impl FnMut(PackedStream) -> Result<codec::PackedInput<R>, R7zError>,
        password: Option<&str>,
    ) -> Result<VerifiedExternalData, R7zError> {
        let output_limit = self.folders.output_size;
        let mut output = ExternalFolderData::reserve(self.folders.stream_count())?;
        for folder in self.folders {
            let decoded = folder?.bind(&mut open)?.collect(password, output_limit)?;
            output = output.append(decoded)?;
        }
        output.finish()
    }
}

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

struct ExternalFolderCollector {
    data: ExternalFolderData,
    remaining: usize,
}

/// Produced only after all planned external substreams have passed verification.
pub(crate) struct VerifiedExternalData(ExternalFolderData);

impl VerifiedExternalData {
    pub(crate) fn into_data(self) -> ExternalFolderData {
        self.0
    }
}

impl ExternalFolderData {
    fn reserve(stream_count: usize) -> Result<ExternalFolderCollector, R7zError> {
        let mut streams = Vec::new();
        streams
            .try_reserve_exact(stream_count)
            .map_err(|_| R7zError::LimitExceeded("metadata"))?;
        Ok(ExternalFolderCollector {
            data: Self(streams),
            remaining: stream_count,
        })
    }

    /// Adapt caller-supplied data at the public parser boundary.
    pub(crate) fn from_supplied(streams: Vec<Bytes>) -> Self {
        Self(streams)
    }

    pub(crate) fn as_slice(&self) -> &[Bytes] {
        &self.0
    }
}

fn external_slot_bytes(stream_count: usize) -> Result<u64, R7zError> {
    stream_count
        .checked_mul(std::mem::size_of::<Bytes>())
        .and_then(|size| u64::try_from(size).ok())
        .ok_or(R7zError::LimitExceeded("metadata"))
}

impl ExternalFolderCollector {
    pub(crate) fn append(mut self, folder: DecodedFolder<'_>) -> Result<Self, R7zError> {
        self.remaining = self
            .remaining
            .checked_sub(folder.layout.len())
            .ok_or(R7zError::Parse)?;
        for stream in folder.streams() {
            self.data.0.push(stream?.0);
        }
        Ok(self)
    }

    pub(crate) fn finish(self) -> Result<VerifiedExternalData, R7zError> {
        match self.remaining {
            0 => Ok(VerifiedExternalData(self.data)),
            _ => Err(R7zError::Parse),
        }
    }
}

/// Bytes whose folder and substream checks have passed.
pub(crate) struct DecodedSubstream(Bytes);

/// Validated substream sizes, including the format's implicit final size.
#[derive(Clone, Copy)]
struct FolderStreamLayout<'a> {
    explicit_sizes: &'a [u64],
    final_size: Option<u64>,
    digests: &'a [Option<u32>],
}

impl<'a> FolderStreamLayout<'a> {
    fn new(
        decoded_len: u64,
        stream_count: usize,
        explicit_sizes: &'a [u64],
        digests: &'a [Option<u32>],
    ) -> Result<Self, R7zError> {
        if explicit_sizes.len() != stream_count.saturating_sub(1)
            || (!digests.is_empty() && digests.len() != stream_count)
        {
            return Err(R7zError::Parse);
        }
        let explicit_total = explicit_sizes.iter().try_fold(0u64, |total, &size| {
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

    fn streams(self) -> Substreams<'a> {
        Substreams {
            layout: self,
            position: 0,
            offset: 0,
        }
    }
}

pub(crate) struct Substream {
    pub(crate) range: Range<u64>,
    pub(crate) digest: Option<u32>,
}

pub(crate) struct Substreams<'a> {
    layout: FolderStreamLayout<'a>,
    position: usize,
    offset: u64,
}

impl Iterator for Substreams<'_> {
    type Item = Substream;
    fn next(&mut self) -> Option<Self::Item> {
        if self.position == self.layout.len() {
            return None;
        }
        let size = self
            .layout
            .explicit_sizes
            .get(self.position)
            .copied()
            .or(self.layout.final_size)?;
        let end = self.offset + size;
        let stream = Substream {
            range: self.offset..end,
            digest: self.layout.digests.get(self.position).copied().flatten(),
        };
        self.offset = end;
        self.position += 1;
        Some(stream)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.layout.len() - self.position;
        (n, Some(n))
    }
}
impl ExactSizeIterator for Substreams<'_> {}

pub(crate) struct LaidOut<'a> {
    folder: Folder,
    graph: crate::folder::FolderGraph,
    streams: PackedStreams<'a>,
    coder_sizes: &'a [u64],
    unpack_size: u64,
    crc: Option<u32>,
}

pub(crate) struct Decoded(Bytes);

/// The layout stays attached to its folder across the consuming decode transition.
pub(crate) struct FolderState<'a, State> {
    state: State,
    layout: FolderStreamLayout<'a>,
}

pub(crate) type FolderLayout<'a> = FolderState<'a, LaidOut<'a>>;
pub(crate) type DecodedFolder<'a> = FolderState<'a, Decoded>;

impl<'a> FolderLayout<'a> {
    pub(crate) fn coder_sizes(&self) -> &[u64] {
        self.state.coder_sizes
    }
    pub(crate) fn folder(&self) -> &Folder {
        &self.state.folder
    }
    pub(crate) fn crc(&self) -> Option<u32> {
        self.state.crc
    }
    pub(crate) fn packed_size(&self) -> u64 {
        self.state.streams.sizes.iter().sum()
    }

    pub(crate) fn packed_streams(&self) -> impl Iterator<Item = PackedStream> {
        self.state.streams.iter()
    }
    pub(crate) fn substreams(&self) -> Substreams<'a> {
        self.layout.streams()
    }

    pub(crate) fn stream_count(&self) -> usize {
        self.layout.len()
    }

    pub(crate) fn bind<R>(
        self,
        mut open: impl FnMut(PackedStream) -> Result<codec::PackedInput<R>, R7zError>,
    ) -> Result<ReadyFolder<'a, R>, R7zError> {
        let plan = codec::DecoderPlan::compile(
            &self.state.folder,
            &self.state.graph,
            self.state.unpack_size,
            self.state.coder_sizes,
            self.state.streams.sizes,
        )?;
        let inputs = self
            .state
            .streams
            .iter()
            .map(&mut open)
            .collect::<Result<SmallVec<[_; 4]>, _>>()?;
        Ok(ReadyFolder {
            decoder: plan.bind(inputs)?,
            layout: self.layout,
            unpack_size: self.state.unpack_size,
            crc: self.state.crc,
        })
    }

    #[cfg(test)]
    fn verify_decoded(self, bytes: Bytes) -> Result<DecodedFolder<'a>, R7zError> {
        verify_folder_output(self.layout, self.state.unpack_size, self.state.crc, bytes)
    }
}

pub(crate) struct ReadyFolder<'a, R> {
    decoder: codec::ReadyDecoder<R>,
    layout: FolderStreamLayout<'a>,
    unpack_size: u64,
    crc: Option<u32>,
}

impl<'a, R: Read> ReadyFolder<'a, R> {
    pub(crate) fn collect(
        self,
        password: Option<&str>,
        limit: u64,
    ) -> Result<DecodedFolder<'a>, R7zError> {
        let capacity =
            usize::try_from(self.unpack_size).map_err(|_| R7zError::LimitExceeded("metadata"))?;
        let read_limit = self
            .unpack_size
            .checked_add(1)
            .ok_or(R7zError::LimitExceeded("metadata"))?;
        if self.unpack_size > limit {
            return Err(R7zError::LimitExceeded("metadata"));
        }
        let bytes = self
            .decoder
            .start(password)?
            .read_bounded_to_vec(capacity, read_limit)?;
        verify_folder_output(self.layout, self.unpack_size, self.crc, Bytes::from(bytes))
    }

    pub(crate) fn start<'r>(self, password: Option<&str>) -> Result<ActiveFolder<'a, 'r>, R7zError>
    where
        R: 'r,
    {
        Ok(ActiveFolder {
            reader: self.decoder.start(password)?,
            streams: self.layout.streams(),
            digest: DigestState::new(self.crc),
            decoded_len: 0,
            unpack_size: self.unpack_size,
        })
    }
}

fn verify_folder_output(
    layout: FolderStreamLayout<'_>,
    size: u64,
    crc: Option<u32>,
    bytes: Bytes,
) -> Result<DecodedFolder<'_>, R7zError> {
    if bytes.len() as u64 != size {
        return Err(R7zError::Decompression);
    }
    let mut digest = DigestState::new(crc);
    digest.update(&bytes);
    digest.finish()?;
    Ok(FolderState {
        state: Decoded(bytes),
        layout,
    })
}

impl<'a> DecodedFolder<'a> {
    pub(crate) fn as_bytes(&self) -> &Bytes {
        &self.state.0
    }

    fn streams(self) -> impl Iterator<Item = Result<DecodedSubstream, R7zError>> + 'a {
        self.layout.streams().map(move |substream| {
            // Materialization proved the whole folder fits usize before reading.
            let start =
                usize::try_from(substream.range.start).expect("materialized substream start");
            let end = usize::try_from(substream.range.end).expect("materialized substream end");
            let stream = self.state.0.slice(start..end);
            if substream
                .digest
                .is_some_and(|expected| crc32fast::hash(&stream) != expected)
            {
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

pub(crate) struct FolderLayouts<'a> {
    plans: FolderPlans<'a>,
    stream_count: usize,
    output_size: u64,
}

impl<'a> FolderLayouts<'a> {
    pub(crate) fn new(
        pack: &'a PackInfo,
        unpack: &'a UnpackInfo,
        substream_info: Option<&'a SubstreamInfo>,
        metadata_limit: u64,
    ) -> Result<Self, R7zError> {
        Self::validate(pack, unpack, substream_info, Some(metadata_limit))
    }

    pub(crate) fn for_streams(streams: &'a crate::StreamInfo) -> Result<Self, R7zError> {
        let (pack, unpack) = streams.packed_folders()?;
        Self::validate(pack, unpack, streams.substream_info.as_ref(), None)
    }

    fn validate(
        pack: &'a PackInfo,
        unpack: &'a UnpackInfo,
        substream_info: Option<&'a SubstreamInfo>,
        limit: Option<u64>,
    ) -> Result<Self, R7zError> {
        let packed_bytes = pack.pack_size.iter().try_fold(0u64, |total, &size| {
            total.checked_add(size).ok_or(R7zError::Parse)
        })?;
        if limit.is_some_and(|limit| packed_bytes > limit) {
            return Err(R7zError::LimitExceeded("metadata"));
        }
        let plans = FolderPlans {
            pack_info: pack,
            unpack_info: unpack,
            substream_info,
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
            if limit.is_some_and(|limit| output_size > limit) {
                return Err(R7zError::LimitExceeded("metadata"));
            }
        }
        let substreams_complete = substream_info.is_none_or(|info| {
            info.num_unpack_streams_per_folder.len() == unpack.num_folders_usize()
                && info.unpack_sizes.len() == preflight.stream_size_base
                && (info.digests.is_empty() || info.digests.len() == stream_count)
        });
        if preflight.pack_index != pack.pack_size.len()
            || pack.num_pack_streams != pack.pack_size.len() as u64
            || unpack.num_folders != unpack.num_folders_usize() as u64
            || preflight.output_base != unpack.unpack_sizes.len()
            || (!pack.digests.is_empty() && pack.digests.len() != pack.pack_size.len())
            || (!unpack.digests.is_empty() && unpack.digests.len() != unpack.num_folders_usize())
            || !substreams_complete
        {
            return Err(R7zError::Parse);
        }
        Ok(FolderLayouts {
            plans,
            stream_count,
            output_size,
        })
    }
}

impl FolderLayouts<'_> {
    pub(crate) fn pack_pos(&self) -> u64 {
        self.plans.pack_info.pack_pos
    }

    pub(crate) fn stream_count(&self) -> usize {
        self.stream_count
    }
}

impl<'a> Iterator for FolderLayouts<'a> {
    type Item = Result<FolderLayout<'a>, R7zError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.plans.next()
    }
}

impl<'a> Iterator for FolderPlans<'a> {
    type Item = Result<FolderLayout<'a>, R7zError>;

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
    fn next_folder(&mut self) -> Result<FolderLayout<'a>, R7zError> {
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
            unpack_size,
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
        Ok(FolderLayout {
            state: LaidOut {
                folder,
                graph,
                streams,
                coder_sizes,
                unpack_size,
                crc,
            },
            layout,
        })
    }
}

/// Verification scope requested by an output consumer.
#[derive(Clone, Copy)]
pub(crate) enum CompletionMode {
    WholeFolder,
    SelectedStreams,
}

#[must_use]
pub(crate) enum FolderCompletion {
    VerifiedFolder,
    VerifiedSelection,
}

pub(crate) struct ActiveFolder<'a, 'r> {
    reader: codec::FolderReader<'r>,
    streams: Substreams<'a>,
    digest: DigestState,
    decoded_len: u64,
    unpack_size: u64,
}

impl ActiveFolder<'_, '_> {
    pub(crate) fn position(&self) -> usize {
        self.streams.position
    }

    pub(crate) fn skip_to(mut self, position: usize) -> Result<Self, R7zError> {
        if position < self.position() || position > self.streams.layout.len() {
            return Err(R7zError::Parse);
        }
        while self.position() < position {
            self = self.read_stream(|_| Ok(()))?;
        }
        Ok(self)
    }

    pub(crate) fn read_stream(
        mut self,
        consume: impl FnOnce(&mut dyn Read) -> Result<(), R7zError>,
    ) -> Result<Self, R7zError> {
        let stream = self.streams.next().ok_or(R7zError::Parse)?;
        let mut content = SubstreamReader {
            reader: &mut self.reader,
            remaining: stream.range.end - stream.range.start,
            folder_digest: &mut self.digest,
            stream_digest: DigestState::new(stream.digest),
            decoded_len: &mut self.decoded_len,
        };
        consume(&mut content)?;
        std::io::copy(&mut content, &mut std::io::sink()).map_err(|_| R7zError::Decompression)?;
        if content.remaining != 0 {
            return Err(R7zError::Decompression);
        }
        content.stream_digest.finish()?;
        Ok(self)
    }

    pub(crate) fn finish(mut self, mode: CompletionMode) -> Result<FolderCompletion, R7zError> {
        if matches!(mode, CompletionMode::SelectedStreams)
            && matches!(self.digest, DigestState::Absent)
            && self.streams.len() != 0
        {
            return Ok(FolderCompletion::VerifiedSelection);
        }
        while self.streams.len() != 0 {
            self = self.read_stream(|_| Ok(()))?;
        }
        if self.decoded_len != self.unpack_size {
            return Err(R7zError::Decompression);
        }
        let mut extra = [0];
        if self
            .reader
            .read(&mut extra)
            .map_err(|_| R7zError::Decompression)?
            != 0
        {
            return Err(R7zError::Decompression);
        }
        self.digest.finish()?;
        Ok(FolderCompletion::VerifiedFolder)
    }
}

enum DigestState {
    Absent,
    Checking {
        expected: u32,
        hasher: crc32fast::Hasher,
    },
}

impl DigestState {
    fn new(digest: Option<u32>) -> Self {
        match digest {
            None => Self::Absent,
            Some(expected) => Self::Checking {
                expected,
                hasher: crc32fast::Hasher::new(),
            },
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        if let Self::Checking { hasher, .. } = self {
            hasher.update(bytes);
        }
    }
    fn finish(self) -> Result<(), R7zError> {
        match self {
            Self::Absent => Ok(()),
            Self::Checking { expected, hasher } => {
                if expected == hasher.finalize() {
                    Ok(())
                } else {
                    Err(R7zError::Crc)
                }
            }
        }
    }
}

struct SubstreamReader<'a> {
    reader: &'a mut dyn Read,
    remaining: u64,
    folder_digest: &'a mut DigestState,
    stream_digest: DigestState,
    decoded_len: &'a mut u64,
}

impl Read for SubstreamReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let limit = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        if limit == 0 {
            return Ok(0);
        }
        let n = self.reader.read(&mut buf[..limit])?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        self.remaining -= n as u64;
        *self.decoded_len = self
            .decoded_len
            .checked_add(n as u64)
            .ok_or(std::io::ErrorKind::InvalidData)?;
        self.folder_digest.update(&buf[..n]);
        self.stream_digest.update(&buf[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_folder_finish_drains_unselected_tail_when_folder_crc_exists() {
        let active = ActiveFolder {
            reader: codec::FolderReader::Stream(Box::new(std::io::Cursor::new(b"tail"))),
            streams: FolderStreamLayout::new(4, 1, &[], &[]).unwrap().streams(),
            digest: DigestState::new(Some(crc32fast::hash(b"tail"))),
            decoded_len: 0,
            unpack_size: 4,
        };
        assert!(matches!(
            active.finish(CompletionMode::SelectedStreams),
            Ok(FolderCompletion::VerifiedFolder)
        ));
    }

    #[test]
    fn folder_finish_rejects_output_beyond_declared_size() {
        let digest = [Some(crc32fast::hash(b"A"))];
        let active = ActiveFolder {
            reader: codec::FolderReader::Stream(Box::new(std::io::Cursor::new(b"AB"))),
            streams: FolderStreamLayout::new(1, 1, &[], &digest)
                .unwrap()
                .streams(),
            digest: DigestState::new(Some(crc32fast::hash(b"A"))),
            decoded_len: 0,
            unpack_size: 1,
        };
        let active = active
            .read_stream(|reader| {
                let mut byte = [0];
                reader.read_exact(&mut byte).map_err(R7zError::Io)
            })
            .unwrap();
        assert!(matches!(
            active.finish(CompletionMode::WholeFolder),
            Err(R7zError::Decompression)
        ));
    }

    fn packed_folder<'a>(
        decoded_len: usize,
        crc: Option<u32>,
        layout: FolderStreamLayout<'a>,
    ) -> FolderLayout<'a> {
        let folder = Folder::parse(&[1, 1, 0]).unwrap().1;
        let graph = folder.graph().unwrap();
        FolderLayout {
            state: LaidOut {
                folder,
                graph,
                streams: PackedStreams {
                    sizes: &[],
                    digests: &[],
                    start: 0,
                },
                coder_sizes: &[],
                unpack_size: decoded_len as u64,
                crc,
            },
            layout,
        }
    }

    #[test]
    fn substream_layout_handles_empty_single_and_multiple_streams() {
        for (size, count, explicit, expected) in [
            (0, 0, &[][..], vec![]),
            (0, 1, &[][..], vec![(0, 0)]),
            (u64::MAX, 1, &[][..], vec![(0, u64::MAX)]),
            (5, 3, &[2, 0][..], vec![(0, 2), (2, 2), (2, 5)]),
        ] {
            let layout = FolderStreamLayout::new(size, count, explicit, &[]).unwrap();
            let mut streams = layout.streams();
            assert_eq!(streams.len(), count);
            assert_eq!(
                streams
                    .by_ref()
                    .map(|stream| (stream.range.start, stream.range.end))
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(streams.len(), 0);
        }
    }

    #[test]
    fn substream_layout_rejects_inconsistent_tables() {
        for (size, count, explicit, digests) in [
            (1, 2, &[][..], &[][..]),
            (1, 2, &[2][..], &[][..]),
            (u64::MAX, 3, &[u64::MAX, 1][..], &[][..]),
            (1, 1, &[][..], &[None, None][..]),
            (1, usize::MAX, &[][..], &[][..]),
        ] {
            assert!(matches!(
                FolderStreamLayout::new(size, count, explicit, digests),
                Err(R7zError::Parse)
            ));
        }
    }

    fn copy_streams() -> crate::StreamInfo {
        let bytes = Bytes::from_static(&[
            0x06, 0x00, 0x01, 0x09, 0x03, 0x00, // one packed stream
            0x07, 0x0b, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0c, 0x03, 0x00, // copy folder
            0x08, 0x00, 0x00, // one substream
        ]);
        crate::StreamInfo::parse(&bytes, &bytes).unwrap().1
    }

    #[test]
    fn external_plan_admits_bytes_and_slots_together() {
        let mut streams = copy_streams();
        let substreams = streams.substream_info.as_mut().unwrap();
        substreams.num_unpack_streams_per_folder[0] = 2;
        substreams.unpack_sizes = vec![1];
        substreams.digests.clear();
        let required = 3 + 2 * std::mem::size_of::<Bytes>() as u64;
        assert!(matches!(
            ExternalFolderPlan::new(&streams, MetadataBudget::new(required - 1)),
            Err(R7zError::LimitExceeded("metadata"))
        ));
        let plan = ExternalFolderPlan::new(&streams, MetadataBudget::new(required)).unwrap();
        let data = plan
            .decode(
                |_| {
                    Ok(codec::PackedInput {
                        reader: std::io::Cursor::new(b"abc"),
                        size: 3,
                    })
                },
                None,
            )
            .unwrap()
            .into_data();
        assert_eq!(
            data.as_slice(),
            [Bytes::from_static(b"a"), Bytes::from_static(b"bc")]
        );
        assert!(matches!(
            external_slot_bytes(usize::MAX),
            Err(R7zError::LimitExceeded("metadata"))
        ));
    }

    #[test]
    fn folder_layout_rejects_unmatched_tables_before_opening_sources() {
        let mut streams = copy_streams();
        streams
            .substream_info
            .as_mut()
            .unwrap()
            .num_unpack_streams_per_folder[0] = u64::MAX;
        assert!(matches!(
            FolderLayouts::for_streams(&streams),
            Err(R7zError::Parse)
        ));

        let mut streams = copy_streams();
        streams.unpack_info.as_mut().unwrap().unpack_sizes.push(0);
        assert!(matches!(
            FolderLayouts::for_streams(&streams),
            Err(R7zError::Parse)
        ));

        let mut streams = copy_streams();
        streams
            .substream_info
            .as_mut()
            .unwrap()
            .num_unpack_streams_per_folder
            .push(0);
        assert!(matches!(
            FolderLayouts::for_streams(&streams),
            Err(R7zError::Parse)
        ));

        let mut streams = copy_streams();
        streams.pack_info.as_mut().unwrap().num_pack_streams = 2;
        assert!(matches!(
            FolderLayouts::for_streams(&streams),
            Err(R7zError::Parse)
        ));
    }

    #[test]
    fn folder_codec_plan_rejects_bad_properties_before_opening_sources() {
        let streams = copy_streams();
        let mut folder = FolderLayouts::for_streams(&streams)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        folder.state.folder.coders[0].codec_id = [0x21].into_iter().collect(); // LZMA2
        folder.state.folder.coders[0].properties = Some(smallvec::smallvec![41]);
        let result = folder
            .bind::<std::io::Empty>(|_| panic!("invalid properties must precede source reads"));
        assert!(matches!(result, Err(R7zError::Decompression)));
    }

    #[test]
    fn external_collection_requires_all_streams_and_shares_decoded_storage() {
        assert!(matches!(
            ExternalFolderData::reserve(1).unwrap().finish(),
            Err(R7zError::Parse)
        ));
        let bytes = Bytes::from_static(b"abcde");
        let decoded = packed_folder(5, None, FolderStreamLayout::new(5, 2, &[2], &[]).unwrap())
            .verify_decoded(bytes.clone())
            .unwrap();
        let data = ExternalFolderData::reserve(2)
            .unwrap()
            .append(decoded)
            .unwrap()
            .finish()
            .unwrap()
            .into_data();
        assert_eq!(data.as_slice()[0].as_ptr(), bytes.as_ptr());
        assert_eq!(data.as_slice()[1].as_ptr(), bytes[2..].as_ptr());
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
        let streams = ExternalFolderData::reserve(2)
            .unwrap()
            .append(decoded)
            .unwrap();
        assert_eq!(
            streams.finish().unwrap().into_data().as_slice(),
            [Bytes::from_static(b"ab"), Bytes::from_static(b"cde")]
        );

        let decoded = folder()
            .verify_decoded(Bytes::from_static(b"abXde"))
            .unwrap();
        assert!(matches!(
            ExternalFolderData::reserve(2).unwrap().append(decoded),
            Err(R7zError::Crc)
        ));
    }
}
