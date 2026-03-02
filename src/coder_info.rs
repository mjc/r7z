use crate::sevenzip_varuint64_decode;
use arrayvec::ArrayVec;
use nom::{bytes::complete::take, number::complete::le_u8, IResult};
use smallvec::SmallVec;

/// A single coder (codec) within a [`Folder`](crate::Folder).
///
/// Each `CoderInfo` identifies a codec by its ID bytes and carries optional
/// codec-specific properties (e.g. LZMA dictionary/mode settings).
#[derive(Debug, PartialEq)]
pub struct CoderInfo {
    /// Codec identifier bytes (e.g. `[0x03, 0x01, 0x01]` = LZMA, `[0x21]` = LZMA2).
    /// The 7z format encodes the length in a 4-bit field, so this is at most 15 bytes,
    /// fitting entirely on the stack.
    pub codec_id: ArrayVec<u8, 15>,
    /// Number of input streams consumed by this coder.
    pub num_in_streams: u64,
    /// Number of output streams produced by this coder.
    pub num_out_streams: u64,
    /// Codec-specific properties (e.g. 5 bytes for LZMA, 1 byte for LZMA2).
    /// Stored inline for all common codecs; spills to heap only for exotic ones.
    pub properties: Option<SmallVec<[u8; 16]>>,
}

impl CoderInfo {
    /// Parse a single `CoderInfo` block from the input.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated or malformed.
    pub fn parse(input: &[u8]) -> IResult<&[u8], CoderInfo> {
        let (input, flags) = le_u8(input)?;
        let codec_id_size = (flags & 0x0f) as usize;
        let is_complex = (flags & 0x10) != 0;
        let has_attributes = (flags & 0x20) != 0;

        let (input, codec_id_bytes) = take(codec_id_size)(input)?;
        let codec_id: ArrayVec<u8, 15> = ArrayVec::try_from(codec_id_bytes).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            ))
        })?;

        let (input, num_in_streams, num_out_streams) = if is_complex {
            let (input, n_in) = sevenzip_varuint64_decode(input)?;
            let (input, n_out) = sevenzip_varuint64_decode(input)?;
            (input, n_in, n_out)
        } else {
            (input, 1u64, 1u64)
        };

        let (input, properties) = if has_attributes {
            let (input, prop_size) = sevenzip_varuint64_decode(input)?;
            let sz = usize::try_from(prop_size).map_err(|_| {
                nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::TooLarge,
                ))
            })?;
            let (input, prop_bytes) = take(sz)(input)?;
            (input, Some(SmallVec::from_slice(prop_bytes)))
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
