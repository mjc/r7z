use crate::R7zError;
use std::io::{BufReader, Cursor};

/// Compress `data` with LZMA, returning `(properties, compressed_stream)`.
///
/// `properties` is the 5-byte LZMA properties block to store in `CoderInfo`.
/// `compressed_stream` is the raw compressed bytes (`LZMA_ALONE` header stripped).
pub fn compress_lzma(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), R7zError> {
    let mut alone: Vec<u8> = Vec::new();
    let mut reader = BufReader::new(Cursor::new(data));
    lzma_rs::lzma_compress(&mut reader, &mut alone).map_err(|_| R7zError::Decompression)?;
    // LZMA_ALONE layout: 5-byte props | 8-byte unpack_size | compressed bytes
    if alone.len() < 13 {
        return Err(R7zError::Decompression);
    }
    let props = alone[..5].to_vec();
    let compressed = alone[13..].to_vec();
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

/// Compress `data` with LZMA2, returning `(properties_byte, compressed_stream)`.
///
/// The properties byte encodes the maximum dictionary size needed for decompression.
/// We advertise 32 MB (0x1c), which is sufficient for lzma-rs's default dictionary.
/// p7zip uses this only for memory estimation — the LZMA2 stream is self-describing.
pub fn compress_lzma2(data: &[u8]) -> Result<(u8, Vec<u8>), R7zError> {
    let mut compressed: Vec<u8> = Vec::new();
    let mut reader = BufReader::new(Cursor::new(data));
    lzma_rs::lzma2_compress(&mut reader, &mut compressed).map_err(|_| R7zError::Decompression)?;
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
        return decompress_lzma2(input);
    }

    Err(R7zError::UnsupportedCodec(codec_id.to_vec()))
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

    // Build an LZMA_ALONE stream: 5-byte props + 8-byte uncompressed size + data
    let mut stream = Vec::with_capacity(13 + input.len());
    stream.extend_from_slice(props);
    stream.extend_from_slice(&unpack_size.to_le_bytes());
    stream.extend_from_slice(input);

    let mut reader = BufReader::new(Cursor::new(stream));
    let mut output = Vec::with_capacity(usize::try_from(unpack_size).unwrap_or(0));
    lzma_rs::lzma_decompress(&mut reader, &mut output).map_err(|_| R7zError::Decompression)?;
    Ok(output)
}

fn decompress_lzma2(input: &[u8]) -> Result<Vec<u8>, R7zError> {
    let mut reader = BufReader::new(Cursor::new(input));
    let mut output = Vec::new();
    lzma_rs::lzma2_decompress(&mut reader, &mut output).map_err(|_| R7zError::Decompression)?;
    Ok(output)
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
    if folder.coders.len() == 1 {
        let coder = &folder.coders[0];
        return decompress(
            &coder.codec_id,
            coder.properties.as_deref(),
            packed_data,
            unpack_size,
        );
    }

    // Multi-coder chain: execute coders in order (simple linear chain assumed).
    // Full bind-pair resolution is left for Phase 3.5.
    let mut data = packed_data.to_vec();
    for (i, coder) in folder.coders.iter().enumerate() {
        // For chained coders we don't know intermediate sizes; use 0 to signal "unknown".
        let size = if i == folder.coders.len() - 1 {
            unpack_size
        } else {
            0
        };
        data = decompress(&coder.codec_id, coder.properties.as_deref(), &data, size)?;
    }
    Ok(data)
}
