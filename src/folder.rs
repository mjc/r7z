use crate::{sevenzip_varuint64_decode, CoderInfo};
use nom::IResult;

#[derive(Debug, PartialEq)]
pub struct Folder {
    pub coders: Vec<CoderInfo>,
    pub bind_pairs: Vec<(u64, u64)>,
    pub packed_indices: Vec<u64>,
}

impl Folder {
    pub fn total_out_streams(&self) -> usize {
        self.coders.iter().map(|c| c.num_out_streams as usize).sum()
    }

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
