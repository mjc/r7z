use crate::R7zError;
use lzma_rust2::{Lzma2Reader, Lzma2Writer, LzmaOptions, LzmaReader, LzmaWriter};
use smallvec::SmallVec;
use std::io::{Cursor, Read, Write};

/// Compress `data` with LZMA, returning `(properties, compressed_stream)`.
///
/// `properties` is the 5-byte LZMA properties block to store in `CoderInfo`.
/// `compressed_stream` is the raw compressed bytes (no `LZMA_ALONE` header).
pub fn compress_lzma(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), R7zError> {
    let options = LzmaOptions::with_preset(6);
    let dict_size = options.dict_size;
    let buf = Vec::new();
    let mut writer =
        LzmaWriter::new_no_header(buf, &options, false).map_err(|_| R7zError::Decompression)?;
    writer
        .write_all(data)
        .map_err(|_| R7zError::Decompression)?;
    let props_byte = writer.props();
    let compressed = writer.finish().map_err(|_| R7zError::Decompression)?;

    // 5-byte props block: 1-byte properties + 4-byte dict size LE
    let mut props = Vec::with_capacity(5);
    props.push(props_byte);
    props.extend_from_slice(&dict_size.to_le_bytes());
    Ok((props, compressed))
}

/// Codec ID for LZMA (classic, used in older 7z archives and header streams).
pub const CODEC_LZMA: &[u8] = &[0x03, 0x01, 0x01];
/// Codec ID for LZMA2 (used in modern 7z archives).
pub const CODEC_LZMA2: &[u8] = &[0x21];
/// Codec ID for the x86 BCJ (Branch/Call/Jump) filter.
pub const CODEC_BCJ_X86: &[u8] = &[0x03, 0x03, 0x01, 0x03];
/// Codec ID for the no-op copy codec (uncompressed).
pub const CODEC_COPY: &[u8] = &[0x00];
/// Codec ID for AES-256-SHA-256 encryption (7zAES).
pub const CODEC_AES_256_SHA_256: &[u8] = &[0x06, 0xF1, 0x07, 0x01];

/// Compress `data` with LZMA2, returning `(properties_byte, compressed_stream)`.
///
/// The properties byte encodes the maximum dictionary size needed for decompression.
/// We advertise 32 MB (0x1c), which matches the default preset dictionary.
/// p7zip uses this only for memory estimation — the LZMA2 stream is self-describing.
pub fn compress_lzma2(data: &[u8]) -> Result<(u8, Vec<u8>), R7zError> {
    let buf = Vec::new();
    let mut writer = Lzma2Writer::new(buf, lzma_rust2::Lzma2Options::default());
    writer
        .write_all(data)
        .map_err(|_| R7zError::Decompression)?;
    let compressed = writer.finish().map_err(|_| R7zError::Decompression)?;
    // 0x1c → dict_size = 1 << (0x1c/2 + 11) = 1 << 25 = 32 MB
    Ok((0x1c, compressed))
}

/// Decompress `input` using the given codec, returning the decompressed bytes.
///
/// * `codec_id`   — codec identifier bytes from `CoderInfo`
/// * `properties` — optional codec properties from `CoderInfo`
/// * `input`      — compressed data (not including any `LZMA_ALONE` header)
/// * `unpack_size`— expected output size (used to build LZMA header)
pub fn decompress(
    codec_id: &[u8],
    properties: Option<&[u8]>,
    input: &[u8],
    unpack_size: u64,
) -> Result<Vec<u8>, R7zError> {
    if codec_id == CODEC_COPY {
        return Ok(input.to_vec());
    }

    if codec_id == CODEC_LZMA {
        return decompress_lzma(properties, input, unpack_size);
    }

    if codec_id == CODEC_LZMA2 {
        return decompress_lzma2(properties, input);
    }

    if codec_id == CODEC_BCJ_X86 {
        // BCJ is applied in-place as a post-processing step after a prior
        // decompressor.  When called standalone, clone the input and decode.
        let mut buf = input.to_vec();
        crate::bcj::bcj_x86_decode(&mut buf);
        return Ok(buf);
    }

    if codec_id == CODEC_AES_256_SHA_256 {
        // AES requires a password — when called through the simple decompress
        // path without one, signal that a password is needed.
        return Err(R7zError::PasswordRequired);
    }

    Err(R7zError::UnsupportedCodec(codec_id.to_vec()))
}

/// Decompress or decrypt a single coder, with optional password for AES.
fn decompress_coder(
    coder: &crate::CoderInfo,
    input: &[u8],
    unpack_size: u64,
    password: Option<&str>,
) -> Result<Vec<u8>, R7zError> {
    if *coder.codec_id == *CODEC_AES_256_SHA_256 {
        let pwd = password.ok_or(R7zError::PasswordRequired)?;
        let props_bytes = coder.properties.as_deref().ok_or(R7zError::Decompression)?;
        let props = crate::aes::AesProperties::parse(props_bytes)?;
        let key = crate::aes::derive_key(pwd, &props.salt, props.num_cycles_power);
        return crate::aes::decrypt_aes256_cbc(input, &key, &props.iv);
    }
    decompress(
        &coder.codec_id,
        coder.properties.as_deref(),
        input,
        unpack_size,
    )
}

fn decompress_lzma(
    properties: Option<&[u8]>,
    input: &[u8],
    unpack_size: u64,
) -> Result<Vec<u8>, R7zError> {
    let props = properties.ok_or(R7zError::Decompression)?;
    if props.len() != 5 {
        return Err(R7zError::Decompression);
    }
    let props_byte = props[0];
    let dict_size = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);

    let mut reader =
        LzmaReader::new_with_props(Cursor::new(input), unpack_size, props_byte, dict_size, None)
            .map_err(|_| R7zError::Decompression)?;
    let mut output = Vec::with_capacity(usize::try_from(unpack_size).unwrap_or(0));
    reader
        .read_to_end(&mut output)
        .map_err(|_| R7zError::Decompression)?;
    Ok(output)
}

fn decompress_lzma2(properties: Option<&[u8]>, input: &[u8]) -> Result<Vec<u8>, R7zError> {
    let dict_size = lzma2_dict_size(properties);
    let mut reader = Lzma2Reader::new(Cursor::new(input), dict_size, None);
    let mut output = Vec::new();
    reader
        .read_to_end(&mut output)
        .map_err(|_| R7zError::Decompression)?;
    Ok(output)
}

/// Decode the LZMA2 dictionary size from the 7z properties byte.
///
/// The 7z spec encodes: `dict_size = (2 | (p & 1)) << ((p >> 1) + 11)` for p < 40,
/// and `u32::MAX` for p == 40 (meaning "as large as needed").
fn lzma2_dict_size(props: Option<&[u8]>) -> u32 {
    let p = props.and_then(|b| b.first().copied()).unwrap_or(40);
    if p >= 40 {
        u32::MAX
    } else {
        (2u32 | (u32::from(p) & 1)) << ((u32::from(p) >> 1) + 11)
    }
}

/// Decompress all folders in a Folder chain and return the concatenated output.
///
/// For simple single-coder folders this just calls `decompress` once.
/// BCJ+LZMA chaining (bind pairs) is resolved in order.
///
/// # Errors
///
/// Returns [`R7zError::Decompression`] if decompression fails, or
/// [`R7zError::UnsupportedCodec`] if a coder uses an unrecognised codec ID.
pub fn decompress_folder(
    folder: &crate::Folder,
    packed_data: &[u8],
    unpack_size: u64,
) -> Result<Vec<u8>, R7zError> {
    decompress_folder_with_password(folder, packed_data, unpack_size, None)
}

/// Decompress a folder, optionally decrypting with `password` if AES-encrypted.
///
/// # Errors
///
/// Returns [`R7zError::PasswordRequired`] if the folder uses AES but no password
/// was supplied, or [`R7zError::Decompression`] / [`R7zError::UnsupportedCodec`]
/// for other failures.
pub fn decompress_folder_with_password(
    folder: &crate::Folder,
    packed_data: &[u8],
    unpack_size: u64,
    password: Option<&str>,
) -> Result<Vec<u8>, R7zError> {
    if folder.coders.len() == 1 {
        let coder = &folder.coders[0];
        return decompress_coder(coder, packed_data, unpack_size, password);
    }

    // Multi-coder chain: resolve bind-pair ordering so that each coder's
    // output feeds the next one's input.
    //
    // In a BCJ+LZMA folder: coder[0]=LZMA, coder[1]=BCJ, bind_pair=(1,0)
    // meaning BCJ's in-stream (1) ← LZMA's out-stream (0).
    // Execution order: LZMA first (produces decompressed bytes), then BCJ.
    //
    // We build a topological order by figuring out which coder receives the
    // packed stream (starts first) and following the bind pairs.
    let order = coder_execution_order(folder)?;

    let mut data = packed_data.to_vec();
    for (i, &coder_idx) in order.iter().enumerate() {
        let coder = &folder.coders[coder_idx];
        // For chained coders we don't know intermediate sizes; use 0 to signal "unknown".
        let size = if i == order.len() - 1 { unpack_size } else { 0 };
        data = decompress_coder(coder, &data, size, password)?;
    }
    Ok(data)
}

/// Determine the order in which coders should be executed for decompression.
///
/// The packed (compressed) stream enters one coder first, its output feeds the
/// next via bind pairs, and so on.  We return coder indices in execution order.
fn coder_execution_order(folder: &crate::Folder) -> Result<SmallVec<[usize; 4]>, R7zError> {
    let n = folder.coders.len();
    if n <= 1 {
        return Ok((0..n).collect());
    }

    if folder
        .coders
        .iter()
        .any(|coder| coder.num_in_streams != 1 || coder.num_out_streams != 1)
    {
        return Err(R7zError::Parse);
    }

    if folder.bind_pairs.len() != n - 1 {
        return Err(R7zError::Parse);
    }

    // Find which coder's input stream is NOT bound to any other coder's output.
    // That coder receives the packed data and runs first.
    //
    // Bind pairs: (in_index, out_index) — in_index is a global input stream
    // index, out_index is a global output stream index.
    //
    // For a 2-coder folder:
    //   coder 0: in_stream 0, out_stream 0
    //   coder 1: in_stream 1, out_stream 1
    //   bind_pair (1, 0) means: in_stream 1 ← out_stream 0
    //   So coder 1's input comes from coder 0's output.
    //   The packed data goes to the stream NOT appearing as any bind_pair's in_index.
    //   Stream 0 (coder 0) is not bound as input → coder 0 runs first.

    // Build a set of bound input streams.
    let bound_in: SmallVec<[u64; 4]> = folder
        .bind_pairs
        .iter()
        .map(|&(in_idx, _)| in_idx)
        .collect();

    for &(in_idx, out_idx) in &folder.bind_pairs {
        if in_idx >= n as u64 || out_idx >= n as u64 {
            return Err(R7zError::Parse);
        }
    }

    let start_stream = if folder.packed_indices.is_empty() {
        let starts: SmallVec<[u64; 2]> = (0..n as u64)
            .filter(|stream| !bound_in.contains(stream))
            .collect();
        if starts.len() != 1 {
            return Err(R7zError::Parse);
        }
        starts[0]
    } else if folder.packed_indices.len() == 1 {
        let start = folder.packed_indices[0];
        if start >= n as u64 || bound_in.contains(&start) {
            return Err(R7zError::Parse);
        }
        start
    } else {
        return Err(R7zError::Parse);
    };

    // Map global stream index → coder index
    // For simple 1-in/1-out coders: stream i belongs to coder i.
    // For complex coders we'd need cumulative sums, but 7z BCJ uses simple coders.
    let mut order = SmallVec::with_capacity(n);

    // Find the first coder (the one whose input stream is not bound)
    let mut current_stream = start_stream;
    order.push(usize::try_from(start_stream).map_err(|_| R7zError::Parse)?);

    // Follow the chain: find bind pair where out_index == current_stream,
    // then the coder that owns in_index is next.
    while order.len() < n {
        let matches: SmallVec<[(u64, u64); 2]> = folder
            .bind_pairs
            .iter()
            .copied()
            .filter(|&(_, out_idx)| out_idx == current_stream)
            .collect();
        if matches.len() != 1 {
            return Err(R7zError::Parse);
        }
        let (in_idx, _) = matches[0];
        let coder_idx = usize::try_from(in_idx).map_err(|_| R7zError::Parse)?;
        if order.contains(&coder_idx) {
            return Err(R7zError::Parse);
        }
        order.push(coder_idx);
        current_stream = in_idx;
    }

    Ok(order)
}
