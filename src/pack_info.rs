use nom::{
    multi::count,
    number::streaming::{le_u32, le_u64, le_u8},
    IResult,
};

use crate::{Digest, Folder};

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
        let (input, pack_pos) = le_u64(input)?;
        let (input, num_pack_streams) = le_u64(input)?;
        let (input, size_marker) = le_u8(input)?;
        let (input, pack_size) = count(le_u64, num_pack_streams.try_into().unwrap())(input)?;
        let (input, pack_streams_crc) = count(le_u32, num_pack_streams.try_into().unwrap())(input)?;
        let (input, end_marker) = le_u8(input)?;
        Ok((
            input,
            PackInfo {
                pack_pos: pack_pos,
                num_pack_streams: num_pack_streams,
                size_marker: size_marker,
                pack_size: pack_size,
                end_marker: end_marker,
                pack_streams_crc: pack_streams_crc,
            },
        ))
    }
}

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
        let (input, num_folders) = le_u64(input)?;
        let (input, is_external) = le_u8(input)?;
        let (input, folders) = count(Folder::parse, num_folders.try_into().unwrap())(input)?;
        let (input, unpacksize_marker) = le_u8(input)?;
        let (input, unpacksizes) = count(le_u64, num_folders.try_into().unwrap())(input)?;
        let (input, digests) = count(Digest::parse, num_folders.try_into().unwrap())(input)?;
        let (input, defined) = le_u8(input)?;
        Ok((
            input,
            UnpackInfo {
                folder_marker: folder_marker,
                num_folders: num_folders,
                is_external: is_external,
                folders: folders,
                unpacksize_marker: unpacksize_marker,
                unpacksizes: unpacksizes,
                digests: digests,
                defined: defined,
            },
        ))
    }
}
