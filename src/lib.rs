extern crate num;
#[macro_use]
extern crate num_derive;

mod signature_header;
pub use signature_header::*;

mod property;
pub use property::Property;

/*
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

struct Header<'sevenzipfile> {
    property_id: Property,
    main_stream_info: Vec<StreamInfo<'sevenzipfile>>,
}

struct SubstreamInfo {}

struct PackInfo<'packinfo> {
    property_id: Property,
    pos: u64,
    pack_streams_count: u64,
    pack_streams_size: &'packinfo [u64],
    pack_streams_crc: &'packinfo [u32],
}

struct CoderInfo {
    property_id: Property,
    folders_info: FoldersInfo,
}

struct FoldersInfo {
    property_id: Property,
    num_folders: u64,
    data_stream_index: u64,
    unpack_sizes: Vec<u64>,
    unpack_digests: Vec<u32>,
}

struct Folder {
    count: u64,
}

struct EncodedHeader {}

struct StreamInfo<'sevenzipfile> {
    property_id: Property,
    pack_info: PackInfo<'sevenzipfile>,
    coder_info: CoderInfo,
    substream_info: SubstreamInfo,
}

fn get_header_at_offset(input: &[u8], offset: u64, size: u64) -> Result<&[u8], &[u8]> {
    unimplemented!()
}
