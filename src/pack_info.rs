use crate::{Digest, Folder};

pub struct PackInfo {
    pack_pos: u64,
    num_pack_streams: u64,
    size_marker: u8,
    pack_size: Vec<u64>,
    end_marker: u8,
    pack_streams_crc: Vec<u32>,
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
