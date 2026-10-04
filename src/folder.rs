use crate::{
    CoderInfo, R7zError, coder_info::CoderInfoRef, method_from_id, sevenzip_varuint64_decode,
    usize_cap,
};
use nom::IResult;
use smallvec::SmallVec;

const MAX_FOLDER_STREAMS: usize = 16_384;

fn checked_coder_count(
    input: &[u8],
    count: u64,
) -> Result<usize, nom::Err<nom::error::Error<&[u8]>>> {
    let count = usize::try_from(count).map_err(|_| {
        nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TooLarge,
        ))
    })?;
    match count {
        1..=MAX_FOLDER_STREAMS => Ok(count),
        _ => Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TooLarge,
        ))),
    }
}

#[derive(Default)]
struct FolderStreamCounts {
    inputs: u64,
    outputs: u64,
}

impl FolderStreamCounts {
    fn add_coder<'a>(
        &mut self,
        input: &'a [u8],
        num_inputs: u64,
        num_outputs: u64,
    ) -> Result<(), nom::Err<nom::error::Error<&'a [u8]>>> {
        let too_large = || -> nom::Err<nom::error::Error<&'a [u8]>> {
            nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            ))
        };
        self.inputs = self.inputs.checked_add(num_inputs).ok_or_else(too_large)?;
        self.outputs = self
            .outputs
            .checked_add(num_outputs)
            .ok_or_else(too_large)?;
        if self.inputs > MAX_FOLDER_STREAMS as u64 || self.outputs > MAX_FOLDER_STREAMS as u64 {
            return Err(too_large());
        }
        Ok(())
    }

    fn layout<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(u64, u64), nom::Err<nom::error::Error<&'a [u8]>>> {
        let num_bind_pairs = self.outputs.checked_sub(1).ok_or_else(|| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        let num_packed = self.inputs.checked_sub(num_bind_pairs).ok_or_else(|| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        Ok((num_bind_pairs, num_packed))
    }
}

fn checked_stream_index(
    input: &[u8],
    index: u64,
    total: u64,
) -> Result<(), nom::Err<nom::error::Error<&[u8]>>> {
    if index < total {
        Ok(())
    } else {
        Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct CoderIndex(usize);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct InputStreamIndex(usize);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct OutputStreamIndex(usize);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct PackedStreamIndex(usize);

/// A validated view of a folder's global input/output stream graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FolderGraph {
    execution_order: SmallVec<[CoderIndex; 4]>,
    packed_inputs: SmallVec<[(PackedStreamIndex, InputStreamIndex); 4]>,
    final_output: OutputStreamIndex,
    input_owners: Vec<CoderIndex>,
    output_owners: Vec<CoderIndex>,
    input_sources: Vec<Option<OutputStreamIndex>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Bcj2Channel {
    pub(crate) coders: Vec<Bcj2Coder>,
    pub(crate) packed: PackedStreamIndex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Bcj2Coder {
    pub(crate) index: CoderIndex,
    pub(crate) output: OutputStreamIndex,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Bcj2Layout {
    pub(crate) main: Bcj2Channel,
    pub(crate) call: Bcj2Channel,
    pub(crate) jump: Bcj2Channel,
    pub(crate) control: Bcj2Channel,
}

impl CoderIndex {
    pub(crate) const fn get(self) -> usize {
        self.0
    }
}

impl InputStreamIndex {
    fn from_raw(raw: u64, total: usize) -> Result<Self, R7zError> {
        let index = usize::try_from(raw).map_err(|_| R7zError::InvalidFolderGraph)?;
        (index < total)
            .then_some(Self(index))
            .ok_or(R7zError::InvalidFolderGraph)
    }
}

impl OutputStreamIndex {
    fn from_raw(raw: u64, total: usize) -> Result<Self, R7zError> {
        let index = usize::try_from(raw).map_err(|_| R7zError::InvalidFolderGraph)?;
        (index < total)
            .then_some(Self(index))
            .ok_or(R7zError::InvalidFolderGraph)
    }

    pub(crate) const fn get(self) -> usize {
        self.0
    }
}

impl PackedStreamIndex {
    pub(crate) const fn get(self) -> usize {
        self.0
    }
}

impl FolderGraph {
    pub(crate) fn execution_order(&self) -> impl DoubleEndedIterator<Item = CoderIndex> + '_ {
        self.execution_order.iter().copied()
    }

    pub(crate) fn packed_stream_count(&self) -> usize {
        self.packed_inputs.len()
    }

    pub(crate) const fn final_output(&self) -> OutputStreamIndex {
        self.final_output
    }

    pub(crate) fn bcj2_layout(&self, folder: &Folder) -> Result<Option<Bcj2Layout>, R7zError> {
        let mut coders = folder
            .coders
            .iter()
            .enumerate()
            .filter(|(_, coder)| coder.codec_id.as_slice() == crate::CODEC_BCJ2);
        let Some((index, _)) = coders.next() else {
            return Ok(None);
        };
        if coders.next().is_some()
            || self.output_owners.get(self.final_output.0) != Some(&CoderIndex(index))
        {
            return Err(R7zError::InvalidFolderGraph);
        }

        let inputs = self
            .input_owners
            .iter()
            .enumerate()
            .filter_map(|(input, owner)| {
                (*owner == CoderIndex(index)).then_some(InputStreamIndex(input))
            })
            .collect::<SmallVec<[_; 4]>>();
        let [main, call, jump, control] = inputs.as_slice() else {
            return Err(R7zError::InvalidFolderGraph);
        };
        let [main, call, jump, control] = [*main, *call, *jump, *control]
            .map(|input| self.bcj2_channel(folder, CoderIndex(index), input));
        let layout = Bcj2Layout {
            main: main?,
            call: call?,
            jump: jump?,
            control: control?,
        };
        let channel_coders = [&layout.main, &layout.call, &layout.jump, &layout.control]
            .into_iter()
            .flat_map(|channel| channel.coders.iter().map(|coder| coder.index))
            .collect::<SmallVec<[_; 4]>>();
        let unique_coders = channel_coders
            .iter()
            .enumerate()
            .all(|(index, coder)| !channel_coders[..index].contains(coder));
        let all_coders_are_channels = folder
            .coders
            .iter()
            .enumerate()
            .map(|(index, _)| CoderIndex(index))
            .all(|coder| coder == CoderIndex(index) || channel_coders.contains(&coder));
        if !unique_coders || !all_coders_are_channels {
            return Err(R7zError::InvalidFolderGraph);
        }
        Ok(Some(layout))
    }

    fn bcj2_channel(
        &self,
        folder: &Folder,
        bcj2: CoderIndex,
        input: InputStreamIndex,
    ) -> Result<Bcj2Channel, R7zError> {
        let packed_slot = |input| {
            self.packed_inputs
                .iter()
                .find_map(|(slot, candidate)| (*candidate == input).then_some(*slot))
                .ok_or(R7zError::InvalidFolderGraph)
        };
        let mut input = input;
        let mut coders = Vec::new();
        let packed = loop {
            match self
                .input_sources
                .get(input.0)
                .ok_or(R7zError::InvalidFolderGraph)?
            {
                None => break packed_slot(input)?,
                Some(output) => {
                    let coder = *self
                        .output_owners
                        .get(output.0)
                        .ok_or(R7zError::InvalidFolderGraph)?;
                    let info = folder
                        .coders
                        .get(coder.0)
                        .ok_or(R7zError::InvalidFolderGraph)?;
                    let arity = StreamArity::try_from(info)?;
                    if coder == bcj2 || arity.inputs != 1 || arity.outputs != 1 {
                        return Err(R7zError::InvalidFolderGraph);
                    }
                    input = self
                        .input_owners
                        .iter()
                        .position(|owner| *owner == coder)
                        .map(InputStreamIndex)
                        .ok_or(R7zError::InvalidFolderGraph)?;
                    coders.push(Bcj2Coder {
                        index: coder,
                        output: *output,
                    });
                }
            }
        };
        coders.reverse();
        Ok(Bcj2Channel { coders, packed })
    }
}

#[derive(Clone, Copy)]
struct StreamArity {
    inputs: usize,
    outputs: usize,
}

impl TryFrom<&CoderInfo> for StreamArity {
    type Error = R7zError;

    fn try_from(coder: &CoderInfo) -> Result<Self, Self::Error> {
        let actual = (coder.num_in_streams, coder.num_out_streams);
        match method_from_id(&coder.codec_id).map(crate::SevenZMethod::stream_arity) {
            Some(expected) if actual != expected => Err(R7zError::InvalidFolderGraph),
            _ => {
                let inputs = usize::try_from(actual.0).map_err(|_| R7zError::InvalidFolderGraph)?;
                let outputs =
                    usize::try_from(actual.1).map_err(|_| R7zError::InvalidFolderGraph)?;
                match (inputs, outputs) {
                    (1..=MAX_FOLDER_STREAMS, 1..=MAX_FOLDER_STREAMS) => {
                        Ok(Self { inputs, outputs })
                    }
                    _ => Err(R7zError::InvalidFolderGraph),
                }
            }
        }
    }
}

struct StreamOwners {
    inputs: Vec<CoderIndex>,
    outputs: Vec<CoderIndex>,
}

impl StreamOwners {
    fn from_coders(coders: &[CoderInfo]) -> Result<Self, R7zError> {
        let arities = coders
            .iter()
            .map(StreamArity::try_from)
            .collect::<Result<SmallVec<[_; 4]>, _>>()?;
        let totals = arities.iter().try_fold((0usize, 0usize), |totals, arity| {
            let inputs = totals
                .0
                .checked_add(arity.inputs)
                .filter(|&count| count <= MAX_FOLDER_STREAMS)
                .ok_or(R7zError::InvalidFolderGraph)?;
            let outputs = totals
                .1
                .checked_add(arity.outputs)
                .filter(|&count| count <= MAX_FOLDER_STREAMS)
                .ok_or(R7zError::InvalidFolderGraph)?;
            Ok::<_, R7zError>((inputs, outputs))
        })?;

        let mut inputs = Vec::with_capacity(totals.0);
        let mut outputs = Vec::with_capacity(totals.1);
        for (index, arity) in arities.into_iter().enumerate() {
            inputs.extend(std::iter::repeat_n(CoderIndex(index), arity.inputs));
            outputs.extend(std::iter::repeat_n(CoderIndex(index), arity.outputs));
        }
        Ok(Self { inputs, outputs })
    }
}

struct Bindings {
    bound_inputs: Vec<bool>,
    bound_outputs: Vec<bool>,
    input_sources: Vec<Option<OutputStreamIndex>>,
    edges: Vec<SmallVec<[CoderIndex; 2]>>,
    indegree: Vec<usize>,
}

impl Bindings {
    fn new(
        pairs: &[(u64, u64)],
        owners: &StreamOwners,
        coder_count: usize,
    ) -> Result<Self, R7zError> {
        let expected_pairs = owners
            .outputs
            .len()
            .checked_sub(1)
            .ok_or(R7zError::InvalidFolderGraph)?;
        if pairs.len() != expected_pairs {
            return Err(R7zError::InvalidFolderGraph);
        }

        let mut bindings = Self {
            bound_inputs: vec![false; owners.inputs.len()],
            bound_outputs: vec![false; owners.outputs.len()],
            input_sources: vec![None; owners.inputs.len()],
            edges: vec![SmallVec::new(); coder_count],
            indegree: vec![0; coder_count],
        };
        for &(input, output) in pairs {
            bindings.bind(input, output, owners)?;
        }
        Ok(bindings)
    }

    fn bind(&mut self, input: u64, output: u64, owners: &StreamOwners) -> Result<(), R7zError> {
        let input = InputStreamIndex::from_raw(input, owners.inputs.len())?;
        let output = OutputStreamIndex::from_raw(output, owners.outputs.len())?;
        let input_bound = self
            .bound_inputs
            .get_mut(input.0)
            .ok_or(R7zError::InvalidFolderGraph)?;
        let output_bound = self
            .bound_outputs
            .get_mut(output.0)
            .ok_or(R7zError::InvalidFolderGraph)?;
        if *input_bound || *output_bound {
            return Err(R7zError::InvalidFolderGraph);
        }

        let source = *owners
            .outputs
            .get(output.0)
            .ok_or(R7zError::InvalidFolderGraph)?;
        let target = *owners
            .inputs
            .get(input.0)
            .ok_or(R7zError::InvalidFolderGraph)?;
        if source == target {
            return Err(R7zError::InvalidFolderGraph);
        }
        *input_bound = true;
        *output_bound = true;
        *self
            .input_sources
            .get_mut(input.0)
            .ok_or(R7zError::InvalidFolderGraph)? = Some(output);
        self.edges
            .get_mut(source.0)
            .ok_or(R7zError::InvalidFolderGraph)?
            .push(target);
        *self
            .indegree
            .get_mut(target.0)
            .ok_or(R7zError::InvalidFolderGraph)? += 1;
        Ok(())
    }

    fn final_output(&self) -> Result<OutputStreamIndex, R7zError> {
        let mut outputs = self
            .bound_outputs
            .iter()
            .enumerate()
            .filter_map(|(index, &bound)| (!bound).then_some(OutputStreamIndex(index)));
        match (outputs.next(), outputs.next()) {
            (Some(output), None) => Ok(output),
            _ => Err(R7zError::InvalidFolderGraph),
        }
    }

    fn packed_inputs(
        &self,
        explicit: &[u64],
    ) -> Result<SmallVec<[(PackedStreamIndex, InputStreamIndex); 4]>, R7zError> {
        let unbound = self
            .bound_inputs
            .iter()
            .enumerate()
            .filter_map(|(index, &bound)| (!bound).then_some(InputStreamIndex(index)))
            .collect::<SmallVec<[_; 4]>>();
        match explicit {
            [] => match unbound.as_slice() {
                [input] => Ok(smallvec::smallvec![(PackedStreamIndex(0), *input)]),
                _ => Err(R7zError::InvalidFolderGraph),
            },
            indices if indices.len() == unbound.len() => {
                let mut seen = vec![false; self.bound_inputs.len()];
                indices
                    .iter()
                    .enumerate()
                    .map(|(packed, &raw)| {
                        let input = InputStreamIndex::from_raw(raw, self.bound_inputs.len())?;
                        let is_unbound = self.bound_inputs.get(input.0) == Some(&false);
                        let is_new = seen
                            .get_mut(input.0)
                            .is_some_and(|seen| !std::mem::replace(seen, true));
                        (is_unbound && is_new)
                            .then_some((PackedStreamIndex(packed), input))
                            .ok_or(R7zError::InvalidFolderGraph)
                    })
                    .collect()
            }
            _ => Err(R7zError::InvalidFolderGraph),
        }
    }

    fn execution_order(&mut self) -> Result<SmallVec<[CoderIndex; 4]>, R7zError> {
        let mut ready = self
            .indegree
            .iter()
            .enumerate()
            .filter_map(|(index, &degree)| (degree == 0).then_some(CoderIndex(index)))
            .collect::<SmallVec<[_; 4]>>();
        let mut order = SmallVec::with_capacity(self.indegree.len());
        while let Some(node) = ready.pop() {
            order.push(node);
            for &next in self.edges.get(node.0).ok_or(R7zError::InvalidFolderGraph)? {
                let degree = self
                    .indegree
                    .get_mut(next.0)
                    .ok_or(R7zError::InvalidFolderGraph)?;
                *degree = degree.checked_sub(1).ok_or(R7zError::InvalidFolderGraph)?;
                if *degree == 0 {
                    ready.push(next);
                }
            }
        }
        if order.len() == self.indegree.len() {
            Ok(order)
        } else {
            Err(R7zError::InvalidFolderGraph)
        }
    }
}

/// Validate a single folder's bytes without allocating, returning
/// `(remaining_input, total_out_streams)`.
///
/// This walks the exact same byte layout as [`Folder::parse`] — varints,
/// coder blocks, bind pairs, packed indices — and performs identical
/// bounds / overflow checks without allocating owned structs.
///
/// # Errors
///
/// Returns a nom error if the bytes are truncated or malformed.
pub fn scan_folder(input: &[u8]) -> IResult<&[u8], usize> {
    let (mut input, num_coders) = sevenzip_varuint64_decode(input)?;
    let num_coders = checked_coder_count(input, num_coders)?;

    let mut stream_counts = FolderStreamCounts::default();

    for _ in 0..num_coders {
        let (remaining, coder) = CoderInfoRef::parse(input)?;
        stream_counts.add_coder(remaining, coder.num_in_streams, coder.num_out_streams)?;
        input = remaining;
    }

    let (num_bind_pairs, num_packed) = stream_counts.layout(input)?;
    for _ in 0..num_bind_pairs {
        let (i, in_idx) = sevenzip_varuint64_decode(input)?;
        checked_stream_index(i, in_idx, stream_counts.inputs)?;
        let (i, out_idx) = sevenzip_varuint64_decode(i)?;
        checked_stream_index(i, out_idx, stream_counts.outputs)?;
        input = i;
    }

    if num_packed != 1 {
        for _ in 0..num_packed {
            let (i, idx) = sevenzip_varuint64_decode(input)?;
            checked_stream_index(i, idx, stream_counts.inputs)?;
            input = i;
        }
    }

    let total_out = usize::try_from(stream_counts.outputs).map_err(|_| {
        nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TooLarge,
        ))
    })?;

    Ok((input, total_out))
}

/// A compression folder — one or more chained coders applied to a set of streams.
///
/// In the common case a folder contains a single [`CoderInfo`] with no bind pairs.
/// Complex archives may chain multiple coders (e.g. BCJ + LZMA).
#[derive(Debug, PartialEq)]
pub struct Folder {
    /// Ordered list of coders in this folder.
    /// Typically 1 (simple archive) or 2 (e.g. BCJ + LZMA); stays on the stack.
    pub coders: SmallVec<[CoderInfo; 4]>,
    /// Bind pairs connecting coder output streams to coder input streams.
    pub bind_pairs: SmallVec<[(u64, u64); 1]>,
    /// Indices of packed (externally stored) input streams (empty when there is one).
    pub packed_indices: SmallVec<[u64; 1]>,
}

impl Folder {
    /// Total number of output streams across all coders in this folder.
    ///
    /// # Panics
    ///
    /// Panics if `num_out_streams` for any coder exceeds `usize::MAX` (impossible in practice).
    #[must_use]
    pub fn total_out_streams(&self) -> usize {
        self.coders
            .iter()
            .map(|c| usize::try_from(c.num_out_streams).expect("num_out_streams fits in usize"))
            .sum()
    }

    /// Resolve the coder graph into the information required by a decoder.
    pub(crate) fn graph(&self) -> Result<FolderGraph, R7zError> {
        let owners = StreamOwners::from_coders(&self.coders)?;
        let mut bindings = Bindings::new(&self.bind_pairs, &owners, self.coders.len())?;
        let final_output = bindings.final_output()?;
        let packed_inputs = bindings.packed_inputs(&self.packed_indices)?;
        let execution_order = bindings.execution_order()?;
        Ok(FolderGraph {
            execution_order,
            packed_inputs,
            final_output,
            input_owners: owners.inputs,
            output_owners: owners.outputs,
            input_sources: bindings.input_sources,
        })
    }

    /// Parse a single `Folder` block (`num_coders`, coders, bind pairs, packed indices).
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated or malformed.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Folder> {
        let (input, num_coders) = sevenzip_varuint64_decode(input)?;
        let num_coders = checked_coder_count(input, num_coders)?;
        let mut coders: SmallVec<[CoderInfo; 4]> =
            SmallVec::with_capacity(num_coders.min(input.len()));
        let mut input = input;
        let mut stream_counts = FolderStreamCounts::default();
        for _ in 0..num_coders {
            let (i, coder) = CoderInfo::parse(input)?;
            stream_counts.add_coder(i, coder.num_in_streams, coder.num_out_streams)?;
            coders.push(coder);
            input = i;
        }

        let (num_bind_pairs, num_packed) = stream_counts.layout(input)?;

        let mut bind_pairs: SmallVec<[(u64, u64); 1]> =
            SmallVec::with_capacity(usize_cap(num_bind_pairs, input.len()));
        for _ in 0..num_bind_pairs {
            let (i, in_idx) = sevenzip_varuint64_decode(input)?;
            checked_stream_index(i, in_idx, stream_counts.inputs)?;
            let (i, out_idx) = sevenzip_varuint64_decode(i)?;
            checked_stream_index(i, out_idx, stream_counts.outputs)?;
            bind_pairs.push((in_idx, out_idx));
            input = i;
        }

        // NumPackedStreams = NumInStreams_Total - NumBindPairs
        // Only written explicitly when NumPackedStreams != 1
        let mut packed_indices: SmallVec<[u64; 1]> = SmallVec::new();
        if num_packed != 1 {
            packed_indices.reserve_exact(usize_cap(num_packed, input.len()));
            for _ in 0..num_packed {
                let (i, idx) = sevenzip_varuint64_decode(input)?;
                checked_stream_index(i, idx, stream_counts.inputs)?;
                packed_indices.push(idx);
                input = i;
            }
        }

        Ok((
            input,
            Folder {
                coders,
                bind_pairs,
                packed_indices,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CoderIndex, Folder, InputStreamIndex, OutputStreamIndex, PackedStreamIndex, scan_folder,
    };
    use crate::{CoderInfo, SevenZMethod};
    use arrayvec::ArrayVec;
    use smallvec::{SmallVec, smallvec};

    fn copy_coder() -> CoderInfo {
        CoderInfo {
            codec_id: ArrayVec::<u8, 15>::from_iter([0x00]),
            num_in_streams: 1,
            num_out_streams: 1,
            properties: None,
        }
    }

    fn simple_chain(bind_pairs: &[(u64, u64)]) -> Folder {
        Folder {
            coders: smallvec![copy_coder(), copy_coder()],
            bind_pairs: SmallVec::from_slice(bind_pairs),
            packed_indices: SmallVec::new(),
        }
    }

    /// Single copy coder (`id_size=1`, not complex, no props).
    #[test]
    fn scan_folder_copy_codec() {
        // num_coders=1, flags=0x01 (id_size=1, simple, no props), codec_id=[0x00]
        let input = [0x01u8, 0x01, 0x00];
        let (rem, out) = scan_folder(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(out, 1);
    }

    /// Single LZMA coder with properties (mirrors `LZMA_CODER_BYTES` from coder tests).
    #[test]
    fn scan_folder_lzma_with_props() {
        // num_coders=1, flags=0x23 (id_size=3, simple, has_props)
        // codec_id=[0x03,0x01,0x01], prop_size=5, props=[5d,00,10,00,00]
        let input = [
            0x01u8, 0x23, 0x03, 0x01, 0x01, 0x05, 0x5d, 0x00, 0x10, 0x00, 0x00,
        ];
        let (rem, out) = scan_folder(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(out, 1);
    }

    /// Trailing bytes after a valid folder are left in the remainder.
    #[test]
    fn scan_folder_trailing_bytes() {
        let input = [0x01u8, 0x01, 0x00, 0xDE, 0xAD];
        let (rem, out) = scan_folder(&input).unwrap();
        assert_eq!(rem, &[0xDE, 0xAD]);
        assert_eq!(out, 1);
    }

    /// Complex coder (`is_complex` flag): 2 in-streams, 1 out-stream → 2 packed indices.
    #[test]
    fn scan_folder_complex_two_in_one_out() {
        // num_coders=1, flags=0x12 (id_size=2, is_complex, no props)
        // codec_id=[0x21,0x00], n_in=2, n_out=1
        // bind_pairs=0 (out-1=0), num_packed=2 → two packed-index varints
        let input = [0x01u8, 0x12, 0x21, 0x00, 0x02, 0x01, 0x00, 0x01];
        let (rem, out) = scan_folder(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(out, 1);
    }

    /// Truncated mid-coder returns an error.
    #[test]
    fn scan_folder_truncated() {
        // num_coders=1 but no coder bytes
        assert!(scan_folder(&[0x01u8]).is_err());
    }

    #[test]
    fn folder_parser_and_scanner_agree_on_coder_layouts() {
        let copy = [0x01u8, 0x01, 0x00];
        let lzma = [
            0x01u8, 0x23, 0x03, 0x01, 0x01, 0x05, 0x5d, 0x00, 0x10, 0x00, 0x00,
        ];
        let multiple_packed = [0x01u8, 0x12, 0x21, 0x00, 0x02, 0x01, 0x00, 0x01];
        let chained = [
            0x02u8, 0x11, 0x00, 0x01, 0x01, 0x11, 0x00, 0x01, 0x01, 0x00, 0x00,
        ];

        for folder in [&copy[..], &lzma[..], &multiple_packed[..], &chained[..]] {
            for end in 0..=folder.len() {
                assert_folder_parser_and_scanner_agree(&folder[..end]);
            }

            let mut trailing = folder.to_vec();
            trailing.extend_from_slice(&[0xde, 0xad]);
            assert_folder_parser_and_scanner_agree(&trailing);
        }
    }

    fn assert_folder_parser_and_scanner_agree(input: &[u8]) {
        match (scan_folder(input), Folder::parse(input)) {
            (Ok((scan_rest, out_streams)), Ok((parse_rest, folder))) => {
                assert_eq!(scan_rest.len(), parse_rest.len());
                assert_eq!(out_streams, folder.total_out_streams());
            }
            (Err(_), Err(_)) => {}
            (scan, parse) => {
                panic!("scanner/parser disagree for {input:02x?}: scan={scan:?}, parse={parse:?}")
            }
        }
    }

    /// Empty input returns an error.
    #[test]
    fn scan_folder_empty() {
        assert!(scan_folder(&[]).is_err());
    }

    #[test]
    fn folder_parser_and_scanner_reject_invalid_coder_counts_consistently() {
        let too_many =
            crate::sevenzip_varuint64_encode(u64::try_from(super::MAX_FOLDER_STREAMS + 1).unwrap());

        for input in [&[0][..], too_many.as_slice()] {
            for result in [
                Folder::parse(input).map(|_| ()),
                scan_folder(input).map(|_| ()),
            ] {
                assert!(matches!(
                    result,
                    Err(nom::Err::Failure(nom::error::Error {
                        code: nom::error::ErrorKind::TooLarge,
                        ..
                    }))
                ));
            }
        }
    }

    #[test]
    fn folder_parser_and_scanner_reject_excessive_stream_counts_consistently() {
        let mut input = vec![0x01u8, 0x11, 0x00];
        input.extend(crate::sevenzip_varuint64_encode(
            u64::try_from(super::MAX_FOLDER_STREAMS + 1).unwrap(),
        ));
        input.push(0x01);

        for result in [
            Folder::parse(&input).map(|_| ()),
            scan_folder(&input).map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(nom::Err::Failure(nom::error::Error {
                    code: nom::error::ErrorKind::TooLarge,
                    ..
                }))
            ));
        }

        let mut truncated_after_limit = vec![0x02u8, 0x11, 0x00];
        truncated_after_limit.extend(crate::sevenzip_varuint64_encode(
            u64::try_from(super::MAX_FOLDER_STREAMS + 1).unwrap(),
        ));
        truncated_after_limit.push(0x01);

        for result in [
            Folder::parse(&truncated_after_limit).map(|_| ()),
            scan_folder(&truncated_after_limit).map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(nom::Err::Failure(nom::error::Error {
                    code: nom::error::ErrorKind::TooLarge,
                    ..
                }))
            ));
        }
    }

    #[test]
    fn folder_parser_and_scanner_reject_out_of_range_stream_indices() {
        let invalid_bind_input = [0x01u8, 0x12, 0x21, 0x00, 0x02, 0x02, 0x02, 0x00];
        let invalid_bind_output = [0x01u8, 0x12, 0x21, 0x00, 0x02, 0x02, 0x00, 0x02];
        let invalid_packed = [0x01u8, 0x12, 0x21, 0x00, 0x02, 0x01, 0x02, 0x00];

        for input in [
            &invalid_bind_input[..],
            &invalid_bind_output[..],
            &invalid_packed[..],
        ] {
            assert!(
                Folder::parse(input).is_err(),
                "parser accepted {input:02x?}"
            );
            assert!(scan_folder(input).is_err(), "scanner accepted {input:02x?}");
        }
    }

    #[test]
    fn graph_resolves_global_streams_for_both_coder_orders() {
        let normal = simple_chain(&[(1, 0)]).graph().unwrap();
        let normal_order: SmallVec<[CoderIndex; 4]> = smallvec![CoderIndex(0), CoderIndex(1)];
        assert_eq!(normal.execution_order, normal_order);
        let one_packed: SmallVec<[(PackedStreamIndex, InputStreamIndex); 4]> =
            smallvec![(PackedStreamIndex(0), InputStreamIndex(0))];
        assert_eq!(normal.packed_inputs, one_packed);
        assert_eq!(normal.final_output, OutputStreamIndex(1));

        let reversed = simple_chain(&[(0, 1)]).graph().unwrap();
        let reversed_order: SmallVec<[CoderIndex; 4]> = smallvec![CoderIndex(1), CoderIndex(0)];
        assert_eq!(reversed.execution_order, reversed_order);
        assert_eq!(reversed.final_output, OutputStreamIndex(0));
    }

    #[test]
    fn graph_rejects_cycles_duplicate_connections_and_bad_indices() {
        let mut cycle = Folder {
            coders: smallvec![copy_coder(), copy_coder(), copy_coder()],
            bind_pairs: smallvec![(1, 0), (0, 1)],
            packed_indices: SmallVec::new(),
        };
        assert!(cycle.graph().is_err());

        cycle.bind_pairs = smallvec![(0, 0), (0, 1)];
        cycle.packed_indices = smallvec![1, 2];
        assert!(cycle.graph().is_err());

        let mut bad_index = simple_chain(&[(1, 0)]);
        bad_index.bind_pairs[0] = (1, 2);
        assert!(bad_index.graph().is_err());
    }

    #[test]
    fn graph_checks_known_coder_arities() {
        let mut bcj2 = copy_coder();
        bcj2.codec_id = ArrayVec::from_iter(SevenZMethod::Bcj2.id().iter().copied());
        bcj2.num_in_streams = 1;
        bcj2.num_out_streams = 1;
        let folder = Folder {
            coders: smallvec![bcj2],
            bind_pairs: SmallVec::new(),
            packed_indices: SmallVec::new(),
        };
        assert!(folder.graph().is_err());
    }

    #[test]
    fn graph_maps_supported_bcj2_channels_from_connections() {
        let bcj2_coder = || {
            let mut coder = copy_coder();
            coder.codec_id = ArrayVec::from_iter(SevenZMethod::Bcj2.id().iter().copied());
            coder.num_in_streams = 4;
            coder
        };
        let layouts = [
            (
                Folder {
                    coders: smallvec![copy_coder(), bcj2_coder()],
                    bind_pairs: smallvec![(1, 0)],
                    packed_indices: smallvec![0, 2, 3, 4],
                },
                [
                    (vec![CoderIndex(0)], PackedStreamIndex(0)),
                    (vec![], PackedStreamIndex(1)),
                    (vec![], PackedStreamIndex(2)),
                    (vec![], PackedStreamIndex(3)),
                ],
            ),
            (
                Folder {
                    coders: smallvec![copy_coder(), copy_coder(), copy_coder(), bcj2_coder()],
                    bind_pairs: smallvec![(5, 0), (4, 1), (3, 2)],
                    packed_indices: smallvec![2, 6, 1, 0],
                },
                [
                    (vec![CoderIndex(2)], PackedStreamIndex(0)),
                    (vec![CoderIndex(1)], PackedStreamIndex(2)),
                    (vec![CoderIndex(0)], PackedStreamIndex(3)),
                    (vec![], PackedStreamIndex(1)),
                ],
            ),
        ];
        for (folder, expected) in layouts {
            let graph = folder.graph().unwrap();
            let layout = graph.bcj2_layout(&folder).unwrap().unwrap();
            let actual =
                [&layout.main, &layout.call, &layout.jump, &layout.control].map(|channel| {
                    (
                        channel
                            .coders
                            .iter()
                            .map(|coder| coder.index)
                            .collect::<Vec<_>>(),
                        channel.packed,
                    )
                });
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn graph_collects_chained_bcj2_channel_coders_in_execution_order() {
        let bcj2_coder = || {
            let mut coder = copy_coder();
            coder.codec_id = ArrayVec::from_iter(SevenZMethod::Bcj2.id().iter().copied());
            coder.num_in_streams = 4;
            coder
        };
        let chained_main = Folder {
            coders: smallvec![copy_coder(), copy_coder(), bcj2_coder()],
            bind_pairs: smallvec![(1, 0), (2, 1)],
            packed_indices: smallvec![0, 3, 4, 5],
        };
        let graph = chained_main.graph().unwrap();
        let layout = graph.bcj2_layout(&chained_main).unwrap().unwrap();
        assert_eq!(
            layout
                .main
                .coders
                .iter()
                .map(|coder| (coder.index, coder.output))
                .collect::<Vec<_>>(),
            vec![
                (CoderIndex(0), OutputStreamIndex(0)),
                (CoderIndex(1), OutputStreamIndex(1)),
            ]
        );
        assert_eq!(layout.main.packed, PackedStreamIndex(0));
    }
}
