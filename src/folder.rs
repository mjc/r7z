pub struct FoldersInfo {
    num_folders: u64,
    data_stream_index: u64,
    unpack_sizes: Vec<u64>,
    unpack_digests: Vec<u32>,
}

pub struct Folder {
    num_coders: u64,
    count: u64,
}
