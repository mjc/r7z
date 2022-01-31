extern crate num;
#[macro_use]
extern crate num_derive;

mod coder_info;
mod folder;
mod headers;
mod pack_info;
mod property;
mod stream_info;

pub use coder_info::CoderInfo;
pub use folder::{Folder, FoldersInfo};
pub use headers::{EncodedHeader, Header, SignatureHeader};
pub use pack_info::{PackInfo, UnpackInfo};
pub use property::{find_next_property_id, Property};
pub use stream_info::{StreamInfo, SubstreamInfo};

/*
https://github.com/google/omaha/blob/master/third_party/lzma/files/7zFormat.txt
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

/*
Everything is little endian
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
*/

pub struct Digest {}
