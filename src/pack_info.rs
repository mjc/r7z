use nom::{
    multi::count,
    number::streaming::{le_u32, le_u64, le_u8},
    IResult, ToUsize,
};

use crate::{sevenzip_varuint64_decode, Digest, Folder, Property};

#[derive(Debug, PartialEq)]
pub struct PackInfo {
    pack_pos: u64,
    num_pack_streams: u64,
    size_marker: u8,
    pack_size: Vec<u64>,
    end_marker: u8,
    pack_streams_crc: Vec<u32>,
}

impl PackInfo {
    pub fn parse(input: &[u8]) -> IResult<&[u8], PackInfo> {
        println!("packinfo::parse");
        let (input, property_id) = Property::parse(input)?;
        assert!(property_id == Property::PackInfo);

        let (input, pack_pos) = sevenzip_varuint64_decode(&input);
        let (input, num_pack_streams) = sevenzip_varuint64_decode(input);

        let (mut input, size_marker) = le_u8(input)?;

        let mut pack_size = Vec::new();
        // array of SZvaruint64
        for i in 0..(num_pack_streams - 1) {
            let (sliced, a_pack_size) = sevenzip_varuint64_decode(input);
            pack_size.push(a_pack_size);

            input = sliced;
        }

        let (input, pack_streams_crc) = count(le_u32, num_pack_streams.to_usize())(input)?;
        let (input, end_marker) = le_u8(input)?;
        Ok((
            input,
            PackInfo {
                pack_pos,
                num_pack_streams,
                size_marker,
                pack_size,
                end_marker,
                pack_streams_crc,
            },
        ))
    }
}
#[derive(Debug, PartialEq)]
pub struct UnpackInfo {
    folder_marker: u8,
    num_folders: u64,
    is_external: u8,
    folders: Vec<Folder>,
    unpacksize_marker: u8,
    unpacksizes: Vec<u64>,
    digests: Vec<Digest>,
    defined: u8, // bitfield
}

impl UnpackInfo {
    pub fn parse(input: &[u8]) -> IResult<&[u8], UnpackInfo> {
        let (input, folder_marker) = le_u8(input)?;
        let (input, num_folders) = sevenzip_varuint64_decode(input);
        let (input, is_external) = le_u8(input)?;
        let (input, folders) = count(Folder::parse, num_folders.to_usize())(input)?;
        let (input, unpacksize_marker) = le_u8(input)?;
        let (input, unpacksizes) = count(le_u64, num_folders.to_usize())(input)?;
        let (input, digests) = count(Digest::parse, num_folders.to_usize())(input)?;
        let (input, defined) = le_u8(input)?;
        Ok((
            input,
            UnpackInfo {
                folder_marker,
                num_folders,
                is_external,
                folders,
                unpacksize_marker,
                unpacksizes,
                digests,
                defined,
            },
        ))
    }
}
