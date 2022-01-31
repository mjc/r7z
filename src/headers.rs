use crate::{PackInfo, Property, StreamInfo, UnpackInfo};
use nom::{
    multi::count,
    number::streaming::{le_u32, le_u64, le_u8},
    sequence::tuple,
    IResult,
};

pub struct EncodedHeader {
    pack_info: PackInfo,
    unpack_info: UnpackInfo,
}

impl EncodedHeader {
    pub fn parse(input: &[u8]) -> IResult<&[u8], EncodedHeader> {
        let (input, property) = Property::parse(input)?;
        assert!(property == Property::EncodedHeader);
        let (input, (pack_info, unpack_info)) = tuple((PackInfo::parse, UnpackInfo::parse))(input)?;
        Ok((
            input,
            EncodedHeader {
                pack_info,
                unpack_info,
            },
        ))
    }
}

pub struct Header {
    property_id: Property,
    main_stream_info: Vec<StreamInfo>,
}

// TODO: getters, setters, constructor, etc.
#[derive(Debug, PartialEq)]
pub struct SignatureHeader {
    pub signature: Vec<u8>, // always b'7z\xbc\xaf\x27\x1c'
    pub major_version: u8,  // always b'\x00'
    pub minor_version: u8,  // always b'\x04'
    pub start_header_crc: u32,
    pub next_header_offset: u64,
    pub next_header_size: u64,
    pub next_header_crc: u32,
}

impl SignatureHeader {
    // this shouldn't ned to allocate
    fn get_file_signature(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        count(le_u8, 6)(input)
    }

    fn get_version(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
        tuple((le_u8, le_u8))(input)
    }

    fn get_next_header_offset(input: &[u8]) -> IResult<&[u8], u64> {
        le_u64(input)
    }

    fn get_next_header_size(input: &[u8]) -> IResult<&[u8], u64> {
        le_u64(input)
    }

    fn get_crc32(input: &[u8]) -> IResult<&[u8], u32> {
        le_u32(input)
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureHeader> {
        let (input, signature) = Self::get_file_signature(input)?;
        let (input, (major_version, minor_version)) = Self::get_version(input)?;
        let (input, start_header_crc) = Self::get_crc32(input)?;
        let (input, next_header_offset) = Self::get_next_header_offset(input)?;
        let (input, next_header_size) = Self::get_next_header_size(input)?;
        let (input, next_header_crc) = Self::get_crc32(input)?;
        Ok((
            input,
            SignatureHeader {
                signature,
                major_version,
                minor_version,
                start_header_crc,
                next_header_offset,
                next_header_size,
                next_header_crc,
            },
        ))
    }
}
