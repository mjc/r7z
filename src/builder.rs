use crate::{codec, parsers::sevenzip_varuint64_encode, R7zError};
use std::io::{Read, Seek, SeekFrom, Write};

/// Codec selection for [`ArchiveBuilder`].
#[derive(Clone, Copy, Default)]
pub enum Codec {
    /// Classic LZMA (id `\[0x03, 0x01, 0x01\]`). Widely supported; lzma-rs exposes
    /// the 5-byte properties directly from its `LZMA_ALONE` output.
    #[default]
    Lzma,
    /// LZMA2 (id `\[0x21\]`). Modern default in p7zip/7-Zip; slightly better
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
    #[must_use]
    pub fn new() -> Self {
        ArchiveBuilder {
            files: Vec::new(),
            codec: Codec::default(),
        }
    }

    #[must_use]
    pub fn add_file(mut self, name: &str, data: &[u8]) -> Self {
        self.files.push((name.to_string(), data.to_vec()));
        self
    }

    #[must_use]
    pub fn compression(mut self, codec: Codec) -> Self {
        self.codec = codec;
        self
    }

    /// Build the 7z archive, returning the raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Parse`] if no files have been added, or any compression
    /// error encountered while building the archive.
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

/// Counts bytes written through it.
struct CountWriter<W: Write> {
    inner: W,
    count: u64,
}

impl<W: Write> CountWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, count: 0 }
    }
}

impl<W: Write> Write for CountWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Hashes and counts bytes as they are read.
struct HashRead<R: Read> {
    inner: R,
    hasher: crc32fast::Hasher,
    count: u64,
}

impl<R: Read> HashRead<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: crc32fast::Hasher::new(),
            count: 0,
        }
    }

    fn finish(self) -> (u32, u64) {
        (self.hasher.finalize(), self.count)
    }
}

impl<R: Read> Read for HashRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
            self.count += n as u64;
        }
        Ok(n)
    }
}

/// Build a solid LZMA2 7z archive from an iterator of `(name, reader)` pairs, writing
/// directly into `out` (a file or any `Write + Seek`).
///
/// Neither all input data nor all compressed output is held in memory simultaneously —
/// each file is piped from `reader` through the compressor into `out` as it goes.
///
/// # Errors
///
/// Returns [`R7zError`] on I/O or compression failure.
pub fn build_streaming<W, I, R>(entries: I, mut out: W) -> Result<(), R7zError>
where
    W: Write + Seek,
    I: IntoIterator<Item = (String, R)>,
    R: Read,
{
    // Reserve 32 bytes for the signature header (filled in at the end via seek).
    out.write_all(&[0u8; 32]).map_err(|_| R7zError::Parse)?;

    // Wrap the output so we can count how many compressed bytes are written.
    let count_writer = CountWriter::new(&mut out);
    let mut lzma2 = lzma_rust2::Lzma2Writer::new(count_writer, lzma_rust2::Lzma2Options::default());

    let mut file_meta: Vec<(String, u64, u32)> = Vec::new(); // (name, unpack_size, crc)

    for (name, reader) in entries {
        let mut hr = HashRead::new(reader);
        std::io::copy(&mut hr, &mut lzma2).map_err(|_| R7zError::Parse)?;
        let (crc, size) = hr.finish();
        file_meta.push((name, size, crc));
    }

    if file_meta.is_empty() {
        return Err(R7zError::Parse);
    }

    // Finish the LZMA2 stream. Block-scope releases the &mut out borrow naturally.
    let pack_size = {
        let cw = lzma2.finish().map_err(|_| R7zError::Parse)?;
        cw.count
    };

    let folder_unpack_size: u64 = file_meta.iter().map(|(_, s, _)| s).sum();
    let props_byte = 0x1c_u8;
    let coder_info = encode_coder_info_lzma2(props_byte);

    let header = build_header_from_meta(&file_meta, &coder_info, pack_size, folder_unpack_size);

    out.write_all(&header).map_err(|_| R7zError::Parse)?;

    let next_header_offset = pack_size;
    let next_header_size = header.len() as u64;
    let next_header_crc = crc32fast::hash(&header);

    let mut start_header = [0u8; 20];
    start_header[..8].copy_from_slice(&next_header_offset.to_le_bytes());
    start_header[8..16].copy_from_slice(&next_header_size.to_le_bytes());
    start_header[16..].copy_from_slice(&next_header_crc.to_le_bytes());
    let start_header_crc = crc32fast::hash(&start_header);

    out.seek(SeekFrom::Start(0)).map_err(|_| R7zError::Parse)?;
    let mut sig = [0u8; 32];
    sig[..6].copy_from_slice(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
    sig[6] = 0x00;
    sig[7] = 0x04;
    sig[8..12].copy_from_slice(&start_header_crc.to_le_bytes());
    sig[12..20].copy_from_slice(&next_header_offset.to_le_bytes());
    sig[20..28].copy_from_slice(&next_header_size.to_le_bytes());
    sig[28..32].copy_from_slice(&next_header_crc.to_le_bytes());
    out.write_all(&sig).map_err(|_| R7zError::Parse)?;
    out.flush().map_err(|_| R7zError::Parse)?;
    Ok(())
}

/// Variant of [`build_header`] that takes pre-computed per-file metadata instead of owned data.
fn build_header_from_meta(
    file_meta: &[(String, u64, u32)],
    coder_info_bytes: &[u8],
    pack_size: u64,
    folder_unpack_size: u64,
) -> Vec<u8> {
    let mut h: Vec<u8> = Vec::new();

    h.push(0x01); // Header tag
    h.push(0x04); // MainStreamsInfo tag

    // PackInfo
    h.push(0x06);
    h.extend_from_slice(&sevenzip_varuint64_encode(0));
    h.extend_from_slice(&sevenzip_varuint64_encode(1));
    h.push(0x09);
    h.extend_from_slice(&sevenzip_varuint64_encode(pack_size));
    h.push(0x00);

    // UnpackInfo
    h.push(0x07);
    h.push(0x0b);
    h.extend_from_slice(&sevenzip_varuint64_encode(1));
    h.push(0x00);
    h.extend_from_slice(&sevenzip_varuint64_encode(1));
    h.extend_from_slice(coder_info_bytes);
    h.push(0x0c);
    h.extend_from_slice(&sevenzip_varuint64_encode(folder_unpack_size));
    h.push(0x00);

    // SubstreamsInfo (only needed for multi-file solid archives)
    if file_meta.len() > 1 {
        h.push(0x08);
        h.push(0x0d);
        h.extend_from_slice(&sevenzip_varuint64_encode(file_meta.len() as u64));
        h.push(0x09);
        for (_, size, _) in &file_meta[..file_meta.len() - 1] {
            h.extend_from_slice(&sevenzip_varuint64_encode(*size));
        }
        h.push(0x0a);
        h.push(0x01); // all_defined
        for (_, _, crc) in file_meta {
            h.extend_from_slice(&crc.to_le_bytes());
        }
        h.push(0x00);
    }

    h.push(0x00); // END StreamInfo

    h.push(0x05);
    h.extend_from_slice(&sevenzip_varuint64_encode(file_meta.len() as u64));

    h.push(0x11);
    let name_data: Vec<u8> = {
        let mut nd = Vec::new();
        for (name, _, _) in file_meta {
            for unit in name.encode_utf16() {
                nd.extend_from_slice(&unit.to_le_bytes());
            }
            nd.push(0);
            nd.push(0);
        }
        nd
    };
    let name_block_size = 1 + name_data.len() as u64;
    h.extend_from_slice(&sevenzip_varuint64_encode(name_block_size));
    h.push(0x00);
    h.extend_from_slice(&name_data);

    h.push(0x00); // END FilesInfo
    h.push(0x00); // END Header
    h
}

/// Encode a `CoderInfo` block for LZMA (`codec_id` = \[0x03,0x01,0x01\], 5-byte properties).
fn encode_coder_info_lzma(props: &[u8]) -> Vec<u8> {
    // flags byte: id_size=3 (bits 0-3), is_complex=0 (bit 4), has_attrs=1 (bit 5) → 0x23
    let mut bytes = vec![0x23u8, 0x03, 0x01, 0x01];
    bytes.extend_from_slice(&sevenzip_varuint64_encode(5)); // props_size
    bytes.extend_from_slice(props);
    bytes
}

/// Encode a `CoderInfo` block for LZMA2 (`codec_id` = \[0x21\], 1-byte properties).
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
