pub struct PackInfo {
    pack_pos: u64,
    num_pack_streams: u64,
    size_marker: u8,
    pack_size: Vec<u64>,
    end_marker: u8,
    pack_streams_crc: Vec<u32>,
}
