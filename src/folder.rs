use crate::{CoderInfo, sevenzip_varuint64_decode, usize_cap};
use nom::IResult;
use smallvec::SmallVec;

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

        num_in_total += n_in;
        num_out_total += n_out;

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

    let num_bind_pairs = num_out_total.saturating_sub(1);
    for _ in 0..num_bind_pairs {
        let (i, _in_idx) = sevenzip_varuint64_decode(input)?;
        let (i, _out_idx) = sevenzip_varuint64_decode(i)?;
        input = i;
    }

    let num_packed = num_in_total - num_bind_pairs;
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

        let num_in_total: u64 = coders.iter().map(|c| c.num_in_streams).sum();
        let num_out_total: u64 = coders.iter().map(|c| c.num_out_streams).sum();
        let num_bind_pairs = num_out_total.saturating_sub(1);

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
        let num_packed = num_in_total - num_bind_pairs;
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
    use super::scan_folder;

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
}
