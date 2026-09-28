use crate::{CoderInfo, SevenZMethod, method_from_id, sevenzip_varuint64_decode, usize_cap};
use nom::IResult;
use smallvec::SmallVec;

const MAX_FOLDER_STREAMS: u64 = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CoderIndex(pub usize);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct InputStreamIndex(pub usize);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct OutputStreamIndex(pub usize);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PackedStreamIndex(pub usize);

/// A validated view of a folder's global input/output stream graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FolderGraph {
    pub execution_order: SmallVec<[CoderIndex; 4]>,
    pub packed_inputs: SmallVec<[(PackedStreamIndex, InputStreamIndex); 4]>,
    pub final_output: OutputStreamIndex,
}

/// Validate a single folder's bytes without allocating, returning
/// `(remaining_input, total_out_streams)`.
///
/// This walks the exact same byte layout as [`Folder::parse`] — varints,
/// coder blocks, bind pairs, packed indices — and performs identical
/// bounds / overflow checks, but builds no structs.
///
/// # Errors
///
/// Returns a nom error if the bytes are truncated or malformed.
pub fn scan_folder(input: &[u8]) -> IResult<&[u8], usize> {
    let (mut input, num_coders) = sevenzip_varuint64_decode(input)?;

    if num_coders == 0 || num_coders > MAX_FOLDER_STREAMS {
        return Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TooLarge,
        )));
    }

    let mut num_in_total: u64 = 0;
    let mut num_out_total: u64 = 0;

    for _ in 0..num_coders {
        let (i, flags) = nom::number::complete::le_u8(input)?;
        let codec_id_size = usize::from(flags & 0x0f);
        let is_complex = (flags & 0x10) != 0;
        let has_attributes = (flags & 0x20) != 0;

        let (i, _codec_id) = nom::bytes::complete::take(codec_id_size)(i)?;

        let (i, n_in, n_out) = if is_complex {
            let (i, n_in) = sevenzip_varuint64_decode(i)?;
            let (i, n_out) = sevenzip_varuint64_decode(i)?;
            (i, n_in, n_out)
        } else {
            (i, 1u64, 1u64)
        };

        num_in_total = num_in_total.checked_add(n_in).ok_or_else(|| {
            nom::Err::Failure(nom::error::Error::new(i, nom::error::ErrorKind::TooLarge))
        })?;
        num_out_total = num_out_total.checked_add(n_out).ok_or_else(|| {
            nom::Err::Failure(nom::error::Error::new(i, nom::error::ErrorKind::TooLarge))
        })?;
        if num_in_total > MAX_FOLDER_STREAMS || num_out_total > MAX_FOLDER_STREAMS {
            return Err(nom::Err::Failure(nom::error::Error::new(
                i,
                nom::error::ErrorKind::TooLarge,
            )));
        }

        input = if has_attributes {
            let (i, prop_size) = sevenzip_varuint64_decode(i)?;
            let sz = usize::try_from(prop_size).map_err(|_| {
                nom::Err::Error(nom::error::Error::new(i, nom::error::ErrorKind::TooLarge))
            })?;
            let (i, _props) = nom::bytes::complete::take(sz)(i)?;
            i
        } else {
            i
        };
    }

    let num_bind_pairs = num_out_total.checked_sub(1).ok_or_else(|| {
        nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
    })?;
    if num_bind_pairs > num_in_total {
        return Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
    for _ in 0..num_bind_pairs {
        let (i, _in_idx) = sevenzip_varuint64_decode(input)?;
        let (i, _out_idx) = sevenzip_varuint64_decode(i)?;
        input = i;
    }

    let num_packed = num_in_total.checked_sub(num_bind_pairs).ok_or_else(|| {
        nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
    })?;
    if num_packed != 1 {
        for _ in 0..num_packed {
            let (i, _idx) = sevenzip_varuint64_decode(input)?;
            input = i;
        }
    }

    let total_out = usize::try_from(num_out_total).map_err(|_| {
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

    /// Validate coder arities and bind pairs, returning the coder execution graph.
    pub fn checked_graph(&self) -> Result<FolderGraph, crate::R7zError> {
        let invalid = || crate::R7zError::InvalidFolderGraph;
        if self.coders.is_empty() || self.coders.len() > MAX_FOLDER_STREAMS as usize {
            return Err(invalid());
        }

        let mut in_bases = Vec::with_capacity(self.coders.len());
        let mut out_bases = Vec::with_capacity(self.coders.len());
        let mut total_in = 0usize;
        let mut total_out = 0usize;
        for coder in &self.coders {
            in_bases.push(total_in);
            out_bases.push(total_out);
            let expected = match method_from_id(&coder.codec_id) {
                Some(SevenZMethod::Bcj2) => Some((4, 1)),
                Some(_) => Some((1, 1)),
                None => None,
            };
            if expected
                .is_some_and(|(i, o)| coder.num_in_streams != i || coder.num_out_streams != o)
            {
                return Err(invalid());
            }
            total_in = total_in
                .checked_add(usize::try_from(coder.num_in_streams).map_err(|_| invalid())?)
                .filter(|&n| n <= MAX_FOLDER_STREAMS as usize)
                .ok_or_else(invalid)?;
            total_out = total_out
                .checked_add(usize::try_from(coder.num_out_streams).map_err(|_| invalid())?)
                .filter(|&n| n <= MAX_FOLDER_STREAMS as usize)
                .ok_or_else(invalid)?;
        }
        if total_in == 0 || total_out == 0 || self.bind_pairs.len() != total_out - 1 {
            return Err(invalid());
        }

        let mut input_owners = vec![0usize; total_in];
        let mut output_owners = vec![0usize; total_out];
        for (coder_idx, coder) in self.coders.iter().enumerate() {
            let in_start = in_bases[coder_idx];
            let in_end = in_start + usize::try_from(coder.num_in_streams).map_err(|_| invalid())?;
            input_owners[in_start..in_end].fill(coder_idx);
            let out_start = out_bases[coder_idx];
            let out_end =
                out_start + usize::try_from(coder.num_out_streams).map_err(|_| invalid())?;
            output_owners[out_start..out_end].fill(coder_idx);
        }
        let mut bound_inputs = vec![false; total_in];
        let mut bound_outputs = vec![false; total_out];
        let mut edges = vec![SmallVec::<[usize; 2]>::new(); self.coders.len()];
        let mut indegree = vec![0usize; self.coders.len()];
        for &(input, output) in &self.bind_pairs {
            let input = usize::try_from(input).map_err(|_| invalid())?;
            let output = usize::try_from(output).map_err(|_| invalid())?;
            if input >= total_in
                || output >= total_out
                || bound_inputs[input]
                || bound_outputs[output]
            {
                return Err(invalid());
            }
            bound_inputs[input] = true;
            bound_outputs[output] = true;
            let source = output_owners[output];
            let target = input_owners[input];
            if source == target {
                return Err(invalid());
            }
            edges[source].push(target);
            indegree[target] += 1;
        }

        let finals: SmallVec<[OutputStreamIndex; 2]> = bound_outputs
            .iter()
            .enumerate()
            .filter_map(|(i, bound)| (!bound).then_some(OutputStreamIndex(i)))
            .collect();
        if finals.len() != 1 {
            return Err(invalid());
        }
        let unbound_inputs: SmallVec<[InputStreamIndex; 4]> = bound_inputs
            .iter()
            .enumerate()
            .filter_map(|(i, bound)| (!bound).then_some(InputStreamIndex(i)))
            .collect();
        let explicit = !self.packed_indices.is_empty();
        let packed_inputs: SmallVec<[(PackedStreamIndex, InputStreamIndex); 4]> = if explicit {
            if self.packed_indices.len() != unbound_inputs.len() {
                return Err(invalid());
            }
            let mut seen = vec![false; total_in];
            self.packed_indices
                .iter()
                .enumerate()
                .map(|(packed_idx, &raw)| {
                    let idx = usize::try_from(raw).map_err(|_| invalid())?;
                    if idx >= total_in || bound_inputs[idx] || seen[idx] {
                        return Err(invalid());
                    }
                    seen[idx] = true;
                    Ok((PackedStreamIndex(packed_idx), InputStreamIndex(idx)))
                })
                .collect::<Result<_, _>>()?
        } else {
            if unbound_inputs.len() != 1 {
                return Err(invalid());
            }
            smallvec::smallvec![(PackedStreamIndex(0), unbound_inputs[0])]
        };

        let mut ready: SmallVec<[CoderIndex; 4]> = (0..self.coders.len())
            .filter(|&i| indegree[i] == 0)
            .map(CoderIndex)
            .collect();
        let mut order = SmallVec::with_capacity(self.coders.len());
        while let Some(CoderIndex(node)) = ready.pop() {
            order.push(CoderIndex(node));
            for &next in &edges[node] {
                indegree[next] -= 1;
                if indegree[next] == 0 {
                    ready.push(CoderIndex(next));
                }
            }
        }
        if order.len() != self.coders.len() {
            return Err(invalid());
        }
        Ok(FolderGraph {
            execution_order: order,
            packed_inputs,
            final_output: finals[0],
        })
    }

    /// Parse a single `Folder` block (`num_coders`, coders, bind pairs, packed indices).
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated or malformed.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Folder> {
        let (input, num_coders) = sevenzip_varuint64_decode(input)?;
        let mut coders: SmallVec<[CoderInfo; 4]> =
            SmallVec::with_capacity(usize_cap(num_coders, input.len()));
        let mut input = input;
        for _ in 0..num_coders {
            let (i, coder) = CoderInfo::parse(input)?;
            coders.push(coder);
            input = i;
        }

        let num_in_total = coders
            .iter()
            .try_fold(0u64, |sum, c| sum.checked_add(c.num_in_streams))
            .ok_or_else(|| {
                nom::Err::Failure(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::TooLarge,
                ))
            })?;
        let num_out_total = coders
            .iter()
            .try_fold(0u64, |sum, c| sum.checked_add(c.num_out_streams))
            .ok_or_else(|| {
                nom::Err::Failure(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::TooLarge,
                ))
            })?;
        if num_in_total > MAX_FOLDER_STREAMS || num_out_total > MAX_FOLDER_STREAMS {
            return Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            )));
        }
        let num_bind_pairs = num_out_total.checked_sub(1).ok_or_else(|| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        if num_bind_pairs > num_in_total {
            return Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }

        let mut bind_pairs: SmallVec<[(u64, u64); 1]> =
            SmallVec::with_capacity(usize_cap(num_bind_pairs, input.len()));
        for _ in 0..num_bind_pairs {
            let (i, in_idx) = sevenzip_varuint64_decode(input)?;
            let (i, out_idx) = sevenzip_varuint64_decode(i)?;
            bind_pairs.push((in_idx, out_idx));
            input = i;
        }

        // NumPackedStreams = NumInStreams_Total - NumBindPairs
        // Only written explicitly when NumPackedStreams != 1
        let num_packed = num_in_total.checked_sub(num_bind_pairs).ok_or_else(|| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        let mut packed_indices: SmallVec<[u64; 1]> = SmallVec::new();
        if num_packed != 1 {
            packed_indices.reserve_exact(usize_cap(num_packed, input.len()));
            for _ in 0..num_packed {
                let (i, idx) = sevenzip_varuint64_decode(input)?;
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

    /// Empty input returns an error.
    #[test]
    fn scan_folder_empty() {
        assert!(scan_folder(&[]).is_err());
    }

    #[test]
    fn checked_graph_resolves_global_streams_for_both_coder_orders() {
        let normal = simple_chain(&[(1, 0)]).checked_graph().unwrap();
        let normal_order: SmallVec<[CoderIndex; 4]> = smallvec![CoderIndex(0), CoderIndex(1)];
        assert_eq!(normal.execution_order, normal_order);
        let one_packed: SmallVec<[(PackedStreamIndex, InputStreamIndex); 4]> =
            smallvec![(PackedStreamIndex(0), InputStreamIndex(0))];
        assert_eq!(normal.packed_inputs, one_packed);
        assert_eq!(normal.final_output, OutputStreamIndex(1));

        let reversed = simple_chain(&[(0, 1)]).checked_graph().unwrap();
        let reversed_order: SmallVec<[CoderIndex; 4]> = smallvec![CoderIndex(1), CoderIndex(0)];
        assert_eq!(reversed.execution_order, reversed_order);
        assert_eq!(reversed.final_output, OutputStreamIndex(0));
    }

    #[test]
    fn checked_graph_rejects_cycles_duplicate_connections_and_bad_indices() {
        let mut cycle = Folder {
            coders: smallvec![copy_coder(), copy_coder(), copy_coder()],
            bind_pairs: smallvec![(1, 0), (0, 1)],
            packed_indices: SmallVec::new(),
        };
        assert!(cycle.checked_graph().is_err());

        cycle.bind_pairs = smallvec![(0, 0), (0, 1)];
        cycle.packed_indices = smallvec![1, 2];
        assert!(cycle.checked_graph().is_err());

        let mut bad_index = simple_chain(&[(1, 0)]);
        bad_index.bind_pairs[0] = (1, 2);
        assert!(bad_index.checked_graph().is_err());
    }

    #[test]
    fn checked_graph_checks_known_coder_arities() {
        let mut bcj2 = copy_coder();
        bcj2.codec_id = ArrayVec::from_iter(SevenZMethod::Bcj2.id().iter().copied());
        bcj2.num_in_streams = 1;
        bcj2.num_out_streams = 1;
        let folder = Folder {
            coders: smallvec![bcj2],
            bind_pairs: SmallVec::new(),
            packed_indices: SmallVec::new(),
        };
        assert!(folder.checked_graph().is_err());
    }
}
