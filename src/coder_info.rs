use crate::sevenzip_varuint64_decode;
use arrayvec::ArrayVec;
use nom::{IResult, bytes::complete::take, number::complete::le_u8};
use smallvec::SmallVec;

/// A single coder (codec) within a [`Folder`](crate::Folder).
///
/// Each `CoderInfo` identifies a codec by its ID bytes and carries optional
/// codec-specific properties (e.g. LZMA dictionary/mode settings).
#[derive(Debug, PartialEq, Eq)]
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

/// Borrowed fields from a parsed coder block, used by scanners that retain no data.
pub(crate) struct CoderInfoRef<'a> {
    pub(crate) codec_id: &'a [u8],
    pub(crate) num_in_streams: u64,
    pub(crate) num_out_streams: u64,
    pub(crate) properties: Option<&'a [u8]>,
}

impl<'a> CoderInfoRef<'a> {
    pub(crate) fn parse(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (input, flags) = le_u8(input)?;
        let codec_id_size = usize::from(flags & 0x0f);
        let is_complex = (flags & 0x10) != 0;
        let has_attributes = (flags & 0x20) != 0;

        let (input, codec_id) = take(codec_id_size)(input)?;
        let (input, num_in_streams, num_out_streams) = if is_complex {
            let (input, num_in) = sevenzip_varuint64_decode(input)?;
            let (input, num_out) = sevenzip_varuint64_decode(input)?;
            (input, num_in, num_out)
        } else {
            (input, 1, 1)
        };
        let (input, properties) = if has_attributes {
            let (input, prop_size) = sevenzip_varuint64_decode(input)?;
            let size = usize::try_from(prop_size).map_err(|_| {
                nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::TooLarge,
                ))
            })?;
            let (input, properties) = take(size)(input)?;
            (input, Some(properties))
        } else {
            (input, None)
        };

        Ok((
            input,
            Self {
                codec_id,
                num_in_streams,
                num_out_streams,
                properties,
            },
        ))
    }
}

impl CoderInfo {
    /// Parse a single `CoderInfo` block from the input.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated or malformed.
    pub fn parse(input: &[u8]) -> IResult<&[u8], CoderInfo> {
        let (input, parsed) = CoderInfoRef::parse(input)?;
        let codec_id: ArrayVec<u8, 15> = ArrayVec::try_from(parsed.codec_id).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            ))
        })?;
        let properties = parsed.properties.map(SmallVec::from_slice);

        Ok((
            input,
            CoderInfo {
                codec_id,
                num_in_streams: parsed.num_in_streams,
                num_out_streams: parsed.num_out_streams,
                properties,
            },
        ))
    }
}
