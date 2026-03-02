use crate::{codec, parsers::sevenzip_varuint64_encode, R7zError};

/// Codec selection for [`ArchiveBuilder`].
#[derive(Clone, Copy, Default)]
pub enum Codec {
    /// Classic LZMA (id `[0x03, 0x01, 0x01]`). Widely supported; lzma-rs exposes
    /// the 5-byte properties directly from its LZMA_ALONE output.
    #[default]
    Lzma,
    /// LZMA2 (id `[0x21]`). Modern default in p7zip/7-Zip; slightly better
    /// compression ratio and supports multi-threading on the encode side.
    Lzma2,
}

/// Builds a 7z archive in memory from one or more files.
///
/// # Example
/// ```rust,no_run
/// let bytes = r7z::ArchiveBuilder::new()
///     .add_file("hello.txt", b"Hello, world!")
///     .build()
///     .unwrap();
/// std::fs::write("out.7z", bytes).unwrap();
/// ```
pub struct ArchiveBuilder {
    files: Vec<(String, Vec<u8>)>,
    codec: Codec,
}

impl Default for ArchiveBuilder {
    fn default() -> Self {
        ArchiveBuilder::new()
    }
}

impl ArchiveBuilder {
    pub fn new() -> Self {
        ArchiveBuilder {
            files: Vec::new(),
            codec: Codec::default(),
        }
    }

    pub fn add_file(mut self, name: &str, data: &[u8]) -> Self {
        self.files.push((name.to_string(), data.to_vec()));
        self
    }

    pub fn compression(mut self, codec: Codec) -> Self {
        self.codec = codec;
        self
    }

    /// Build the 7z archive, returning the raw bytes.
    pub fn build(self) -> Result<Vec<u8>, R7zError> {
        if self.files.is_empty() {
            return Err(R7zError::Parse);
        }
        build_archive(&self.files, self.codec)
    }
}

fn build_archive(files: &[(String, Vec<u8>)], codec: Codec) -> Result<Vec<u8>, R7zError> {
    // Solid compression: concatenate all file data into one stream.
    let mut all_data: Vec<u8> = Vec::new();
    for (_, data) in files {
        all_data.extend_from_slice(data);
    }

    let (coder_flags_and_id_and_props, compressed) = match codec {
        Codec::Lzma => {
            let (props, compressed) = codec::compress_lzma(&all_data)?;
            (encode_coder_info_lzma(&props), compressed)
        }
        Codec::Lzma2 => {
            let (props_byte, compressed) = codec::compress_lzma2(&all_data)?;
            (encode_coder_info_lzma2(props_byte), compressed)
        }
    };

    let pack_size = compressed.len() as u64;
    let folder_unpack_size = all_data.len() as u64;

    let header = build_header(
        files,
        &coder_flags_and_id_and_props,
        pack_size,
        folder_unpack_size,
    );

    // Layout: [32-byte SignatureHeader][compressed data][header]
    let mut archive: Vec<u8> = vec![0u8; 32];
    archive.extend_from_slice(&compressed);
    let next_header_offset = compressed.len() as u64;
    archive.extend_from_slice(&header);

    // Compute and fill in the signature.
    let next_header_size = header.len() as u64;
    let next_header_crc = crc32fast::hash(&header);

    let mut start_header = [0u8; 20];
    start_header[..8].copy_from_slice(&next_header_offset.to_le_bytes());
    start_header[8..16].copy_from_slice(&next_header_size.to_le_bytes());
    start_header[16..].copy_from_slice(&next_header_crc.to_le_bytes());
    let start_header_crc = crc32fast::hash(&start_header);

    archive[..6].copy_from_slice(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
    archive[6] = 0x00; // major version
    archive[7] = 0x04; // minor version
    archive[8..12].copy_from_slice(&start_header_crc.to_le_bytes());
    archive[12..20].copy_from_slice(&next_header_offset.to_le_bytes());
    archive[20..28].copy_from_slice(&next_header_size.to_le_bytes());
    archive[28..32].copy_from_slice(&next_header_crc.to_le_bytes());

    Ok(archive)
}

/// Encode a CoderInfo block for LZMA (codec_id = [0x03,0x01,0x01], 5-byte properties).
fn encode_coder_info_lzma(props: &[u8]) -> Vec<u8> {
    // flags byte: id_size=3 (bits 0-3), is_complex=0 (bit 4), has_attrs=1 (bit 5) → 0x23
    let mut bytes = vec![0x23u8, 0x03, 0x01, 0x01];
    bytes.extend_from_slice(&sevenzip_varuint64_encode(5)); // props_size
    bytes.extend_from_slice(props);
    bytes
}

/// Encode a CoderInfo block for LZMA2 (codec_id = [0x21], 1-byte properties).
///
/// The properties byte encodes the dictionary size hint:
/// `dict_size = 1 << (props_byte / 2 + 11)` for even values.
/// We claim 32 MB (prop = 0x1c) which covers lzma-rs's default dictionary.
fn encode_coder_info_lzma2(props_byte: u8) -> Vec<u8> {
    // flags byte: id_size=1 (bits 0-3), is_complex=0 (bit 4), has_attrs=1 (bit 5) → 0x21
    let mut bytes = vec![0x21u8, 0x21];
    bytes.extend_from_slice(&sevenzip_varuint64_encode(1)); // props_size
    bytes.push(props_byte);
    bytes
}

/// Serialize the uncompressed 7z Header block.
///
/// Layout:
/// ```text
/// 0x01  Header
///   0x04  MainStreamsInfo
///     PackInfo   UnpackInfo   [SubstreamsInfo]
///   0x00  END StreamInfo
///   0x05  FilesInfo
///   ...
///   0x00  END FilesInfo
/// 0x00  END Header
/// ```
fn build_header(
    files: &[(String, Vec<u8>)],
    coder_info_bytes: &[u8],
    pack_size: u64,
    folder_unpack_size: u64,
) -> Vec<u8> {
    let mut h: Vec<u8> = Vec::new();

    h.push(0x01); // Header tag

    // MainStreamsInfo
    h.push(0x04); // MainStreamsInfo tag (consumed by Header loop; StreamInfo::parse starts after)

    // PackInfo (0x06): pack_pos=0, num_streams=1, one size
    h.push(0x06);
    h.extend_from_slice(&sevenzip_varuint64_encode(0)); // pack_pos
    h.extend_from_slice(&sevenzip_varuint64_encode(1)); // num_pack_streams
    h.push(0x09); // Size tag
    h.extend_from_slice(&sevenzip_varuint64_encode(pack_size));
    h.push(0x00); // END PackInfo

    // UnpackInfo (0x07)
    h.push(0x07);
    h.push(0x0b); // Folder tag
    h.extend_from_slice(&sevenzip_varuint64_encode(1)); // num_folders = 1
    h.push(0x00); // external = 0

    // Folder: num_coders=1, CoderInfo, no bind pairs (single coder → 0 bind pairs)
    h.extend_from_slice(&sevenzip_varuint64_encode(1)); // num_coders
    h.extend_from_slice(coder_info_bytes);
    // bind_pairs count = total_out_streams - 1 = 1 - 1 = 0 (nothing to write)
    // num_packed = num_in_total - bind_pairs = 1 - 0 = 1 (skip explicit packed_indices)

    h.push(0x0c); // CodersUnPackSize tag
    h.extend_from_slice(&sevenzip_varuint64_encode(folder_unpack_size));
    h.push(0x00); // END UnpackInfo

    // SubstreamsInfo — only needed for solid multi-file archives
    if files.len() > 1 {
        h.push(0x08); // SubstreamsInfo tag (also re-read by SubstreamInfo::parse)

        // NumUnPackStream: one entry per folder
        h.push(0x0d);
        h.extend_from_slice(&sevenzip_varuint64_encode(files.len() as u64));

        // Size: n-1 explicit sizes (last stream size is implicit)
        h.push(0x09);
        for (_, data) in &files[..files.len() - 1] {
            h.extend_from_slice(&sevenzip_varuint64_encode(data.len() as u64));
        }

        // CRC: one per stream
        h.push(0x0a);
        h.push(0x01); // all_defined = 1
        for (_, data) in files {
            let crc = crc32fast::hash(data);
            h.extend_from_slice(&crc.to_le_bytes());
        }

        h.push(0x00); // END SubstreamsInfo
    }

    h.push(0x00); // END StreamInfo

    // FilesInfo — the 0x05 tag is read by both the Header loop (for dispatch) and
    // FilesInfo::parse (for validation), both from the same byte position.
    h.push(0x05); // FilesInfo tag
    h.extend_from_slice(&sevenzip_varuint64_encode(files.len() as u64));

    // Name property
    h.push(0x11); // Name tag
    let name_data = encode_utf16le_names(files);
    let name_block_size = 1 + name_data.len() as u64; // +1 for the external byte
    h.extend_from_slice(&sevenzip_varuint64_encode(name_block_size));
    h.push(0x00); // external = 0
    h.extend_from_slice(&name_data);

    h.push(0x00); // END FilesInfo

    h.push(0x00); // END Header

    h
}

/// Encode file names as concatenated null-terminated UTF-16LE strings.
fn encode_utf16le_names(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, _) in files {
        for unit in name.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.push(0);
        out.push(0); // UTF-16LE null terminator
    }
    out
}
