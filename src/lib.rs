use std::io::Read;
use std::io::Seek;

use nom::bytes;
use nom::multi::count;
use nom::number;
use nom::number::streaming::le_u32;
use nom::number::streaming::le_u64;
use nom::number::streaming::le_u8;
use nom::sequence::tuple;
use nom::streaming;
use nom::IResult;

mod constants;

/*
Data types in file and Rust equivalent:
    byte: u8
    bytearray: [u8, usize]
    utf8_string: str::from_utf8(bytearray)
    utf16_string: str::from_utf16(bytearray) (not sure if lossy is ok)
    uint32: u32,
    uint64: u64,
    number: varuint?
    bitfield: bitflags
    booleanlist: Vec<(bool, bitflags)>
    crc32 format: ITU-T V.42


    My understanding of the simplest layout:
    SignatureHeader
        (data block
            (packed stream)
                packed substream
            (packed stream)
                (packed substream)
            (...))
        (packed stream for header
        header encoding information)
        header

*/

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

fn get_next_header_crc32(input: &[u8]) -> IResult<&[u8], u32> {
    le_u32(input)
}

fn get_crc32(input: &[u8]) -> IResult<&[u8], u32> {
    le_u32(input)
}

pub fn parse_signature_header(input: &[u8]) -> IResult<&[u8], SignatureHeader> {
    let (input, signature) = get_file_signature(input)?;
    let (input, (major_version, minor_version)) = get_version(input)?;
    let (input, start_header_crc) = get_crc32(input)?;
    let (input, next_header_offset) = get_next_header_offset(input)?;
    let (input, next_header_size) = get_next_header_size(input)?;
    let (input, next_header_crc) = get_next_header_crc32(input)?;
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
