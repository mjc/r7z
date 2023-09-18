use nom::{
    multi::count,
    number::streaming::{le_u32, le_u64},
    IResult, ToUsize,
};
use nom_varint::take_varint;

pub struct FoldersInfo {
    num_folders: u64,
    data_stream_index: u64,
    unpack_sizes: Vec<u64>,
    unpack_digests: Vec<u32>,
}

impl FoldersInfo {
    pub fn parse(input: &[u8]) -> IResult<&[u8], FoldersInfo> {
        let (input, num_folders) = le_u64(input)?;
        let (input, data_stream_index) = le_u64(input)?;
        let (input, unpack_sizes) = count(le_u64, num_folders.to_usize())(input)?;
        let (input, unpack_digests) = count(le_u32, num_folders.to_usize())(input)?;
        Ok((
            input,
            FoldersInfo {
                num_folders: num_folders,
                data_stream_index: data_stream_index,
                unpack_sizes: unpack_sizes,
                unpack_digests: unpack_digests,
            },
        ))
    }
}

#[derive(Debug, PartialEq)]
pub struct Folder {
    num_coders: usize,
    // coders: Vec<CoderInfo>,
}

impl Folder {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Folder> {
        let (input, num_coders) = take_varint(input)?;
        let (input, _coders) = le_u64(input)?;
        Ok((
            input,
            Folder {
                num_coders: num_coders,
                // coders
            },
        ))
    }
}
