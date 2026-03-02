use crate::{sevenzip_varuint64_decode, CoderInfo};
use nom::IResult;

/// A compression folder — one or more chained coders applied to a set of streams.
///
/// In the common case a folder contains a single [`CoderInfo`] with no bind pairs.
/// Complex archives may chain multiple coders (e.g. BCJ + LZMA).
#[derive(Debug, PartialEq)]
pub struct Folder {
    /// Ordered list of coders in this folder.
    pub coders: Vec<CoderInfo>,
    /// Bind pairs connecting coder output streams to coder input streams.
    pub bind_pairs: Vec<(u64, u64)>,
    /// Indices of packed (externally stored) input streams (empty when there is one).
    pub packed_indices: Vec<u64>,
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

    /// Parse a single `Folder` block (`num_coders`, coders, bind pairs, packed indices).
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated or malformed.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Folder> {
        let (input, num_coders) = sevenzip_varuint64_decode(input)?;
        let mut coders = Vec::new();
        let mut input = input;
        for _ in 0..num_coders {
            let (i, coder) = CoderInfo::parse(input)?;
            coders.push(coder);
            input = i;
        }

        let num_in_total: u64 = coders.iter().map(|c| c.num_in_streams).sum();
        let num_out_total: u64 = coders.iter().map(|c| c.num_out_streams).sum();
        let num_bind_pairs = num_out_total.saturating_sub(1);

        let mut bind_pairs = Vec::new();
        for _ in 0..num_bind_pairs {
            let (i, in_idx) = sevenzip_varuint64_decode(input)?;
            let (i, out_idx) = sevenzip_varuint64_decode(i)?;
            bind_pairs.push((in_idx, out_idx));
            input = i;
        }

        // NumPackedStreams = NumInStreams_Total - NumBindPairs
        // Only written explicitly when NumPackedStreams != 1
        let num_packed = num_in_total - num_bind_pairs;
        let mut packed_indices = Vec::new();
        if num_packed != 1 {
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
