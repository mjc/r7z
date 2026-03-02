use crate::sevenzip_varuint64_decode;
use nom::{bytes::streaming::take, number::streaming::le_u8, IResult};

/// A single coder (codec) within a [`Folder`](crate::Folder).
///
/// Each `CoderInfo` identifies a codec by its ID bytes and carries optional
/// codec-specific properties (e.g. LZMA dictionary/mode settings).
#[derive(Debug, PartialEq)]
pub struct CoderInfo {
    /// Codec identifier bytes (e.g. `[0x03, 0x01, 0x01]` = LZMA, `[0x21]` = LZMA2).
    pub codec_id: Vec<u8>,
    /// Number of input streams consumed by this coder.
    pub num_in_streams: u64,
    /// Number of output streams produced by this coder.
    pub num_out_streams: u64,
    /// Codec-specific properties (e.g. 5 bytes for LZMA, 1 byte for LZMA2).
    pub properties: Option<Vec<u8>>,
}

impl CoderInfo {
    pub fn parse(input: &[u8]) -> IResult<&[u8], CoderInfo> {
        let (input, flags) = le_u8(input)?;
        let codec_id_size = (flags & 0x0f) as usize;
        let is_complex = (flags & 0x10) != 0;
        let has_attributes = (flags & 0x20) != 0;

        let (input, codec_id_bytes) = take(codec_id_size)(input)?;
        let codec_id = codec_id_bytes.to_vec();

        let (input, num_in_streams, num_out_streams) = if is_complex {
            let (input, n_in) = sevenzip_varuint64_decode(input)?;
            let (input, n_out) = sevenzip_varuint64_decode(input)?;
            (input, n_in, n_out)
        } else {
            (input, 1u64, 1u64)
        };

        let (input, properties) = if has_attributes {
            let (input, prop_size) = sevenzip_varuint64_decode(input)?;
            let (input, prop_bytes) = take(prop_size as usize)(input)?;
            (input, Some(prop_bytes.to_vec()))
        } else {
            (input, None)
        };

        Ok((
            input,
            CoderInfo {
                codec_id,
                num_in_streams,
                num_out_streams,
                properties,
            },
        ))
    }
}
