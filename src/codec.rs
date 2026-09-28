mod plan;
use crate::{Folder, R7zError};
use bzip2_rs::DecoderReader as Bzip2Decoder;
use deflate64::Deflate64Decoder;
use flate2::read::DeflateDecoder;
use lzma_rust2::{
    Lzma2Reader, Lzma2Writer, LzmaOptions, LzmaReader, LzmaWriter, filter::bcj::BcjReader,
};
pub(crate) use plan::{DecoderPlan, ReadyDecoder};
use ppmd_rust::Ppmd7Decoder;
use smallvec::SmallVec;
use std::io::{Cursor, Read, Write};

const MAX_LZMA_DICTIONARY_BYTES: u32 = 256 * 1024 * 1024;
const MAX_LZMA2_PROBABILITY_BYTES: usize = 24 * 1024;
const MAX_PPMD_MEMORY_BYTES: u32 = 256 * 1024 * 1024;
// AES decryption holds both encrypted and decrypted copies, each capped here.
const MAX_BUFFERED_AES_BYTES: usize = 256 * 1024 * 1024;
const MAX_MATERIALIZED_OUTPUT_BYTES: usize = 512 * 1024 * 1024;
const MAX_BCJ2_OUTPUT_BYTES: usize = 256 * 1024 * 1024;
const MAX_DECODER_WORKING_SET_BYTES: usize = 512 * 1024 * 1024;
const OTHER_CODER_WORKING_SET_BYTES: usize = 2 * 1024 * 1024;
const DECODER_OVERHEAD_BYTES: usize = 128 * 1024;
const MAX_FOLDER_CODERS: usize = 64;
// Remaining buffered paths use this cap for packed folder bytes.
pub(crate) const MAX_BUFFERED_PACKED_FOLDER_BYTES: usize = 512 * 1024 * 1024;
const MAX_BCJ2_WORKING_BYTES: usize = 512 * 1024 * 1024;

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
/// Codec ID for the BCJ2 multi-stream x86 branch filter.
pub const CODEC_BCJ2: &[u8] = &[0x03, 0x03, 0x01, 0x1B];
/// Codec ID for the ARM branch filter.
pub const CODEC_BCJ_ARM: &[u8] = &[0x03, 0x03, 0x05, 0x01];
/// Codec ID for the ARM64 branch filter.
pub const CODEC_BCJ_ARM64: &[u8] = &[0x0A];
/// Codec ID for the ARM Thumb branch filter.
pub const CODEC_BCJ_ARM_THUMB: &[u8] = &[0x03, 0x03, 0x07, 0x01];
/// Codec ID for the IA-64 branch filter.
pub const CODEC_BCJ_IA64: &[u8] = &[0x03, 0x03, 0x04, 0x01];
/// Codec ID for the PowerPC branch filter.
pub const CODEC_BCJ_PPC: &[u8] = &[0x03, 0x03, 0x02, 0x05];
/// Codec ID for the SPARC branch filter.
pub const CODEC_BCJ_SPARC: &[u8] = &[0x03, 0x03, 0x08, 0x05];
/// Codec ID for the RISC-V branch filter.
pub const CODEC_BCJ_RISCV: &[u8] = &[0x0B];
/// Codec ID for the no-op copy codec (uncompressed).
pub const CODEC_COPY: &[u8] = &[0x00];
/// Codec ID for AES-256-SHA-256 encryption (7zAES).
pub const CODEC_AES_256_SHA_256: &[u8] = &[0x06, 0xF1, 0x07, 0x01];
/// Codec ID for raw Deflate streams.
pub const CODEC_DEFLATE: &[u8] = &[0x04, 0x01, 0x08];
/// Codec ID for `BZip2` streams.
pub const CODEC_BZIP2: &[u8] = &[0x04, 0x02, 0x02];
/// Codec ID for `PPMd7` streams.
pub const CODEC_PPMD: &[u8] = &[0x03, 0x04, 0x01];
/// Codec ID for Deflate64 streams.
pub const CODEC_DEFLATE64: &[u8] = &[0x04, 0x01, 0x09];
/// Codec ID for the Delta filter.
pub const CODEC_DELTA: &[u8] = &[0x03];
/// Codec ID for the 2-byte swap filter.
pub const CODEC_SWAP2: &[u8] = &[0x02, 0x03, 0x02];
/// Codec ID for the 4-byte swap filter.
pub const CODEC_SWAP4: &[u8] = &[0x02, 0x03, 0x04];

/// Compress `data` with LZMA2, returning `(properties_byte, compressed_stream)`.
///
/// The properties byte encodes the maximum dictionary size needed for decompression.
/// We advertise 32 MB (0x1c), which matches the default preset dictionary.
/// p7zip uses this only for memory estimation — the LZMA2 stream is self-describing.
#[allow(dead_code)]
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

/// Decode the LZMA2 dictionary size from the 7z properties byte.
///
/// The 7z spec encodes: `dict_size = (2 | (p & 1)) << ((p >> 1) + 11)` for p < 40,
/// and `u32::MAX` for p == 40 (meaning "as large as needed").
fn lzma2_dict_size(props: Option<&[u8]>) -> Result<u32, R7zError> {
    let Some(props) = props else {
        return Err(resource_limit(
            "LZMA dictionary",
            MAX_LZMA_DICTIONARY_BYTES as usize,
        ));
    };
    if props.len() != 1 {
        return Err(R7zError::Decompression);
    }

    let p = props[0];
    match p.cmp(&40) {
        std::cmp::Ordering::Greater => Err(R7zError::Decompression),
        std::cmp::Ordering::Equal => Err(resource_limit(
            "LZMA dictionary",
            MAX_LZMA_DICTIONARY_BYTES as usize,
        )),
        std::cmp::Ordering::Less => {
            let dict_size = (2u32 | (u32::from(p) & 1)) << ((u32::from(p) >> 1) + 11);
            if dict_size > MAX_LZMA_DICTIONARY_BYTES {
                Err(resource_limit(
                    "LZMA dictionary",
                    MAX_LZMA_DICTIONARY_BYTES as usize,
                ))
            } else {
                Ok(dict_size)
            }
        }
    }
}

fn branch_start_pos(props: Option<&[u8]>, alignment: u32) -> Result<usize, R7zError> {
    let props = props.unwrap_or_default();
    let pos = match props {
        [] => 0,
        [a, b, c, d] => u32::from_le_bytes([*a, *b, *c, *d]),
        _ => return Err(R7zError::Decompression),
    };
    if pos % alignment != 0 {
        return Err(R7zError::Decompression);
    }
    Ok(pos as usize)
}

#[cfg(test)]
fn decompress_lzma2(properties: Option<&[u8]>, input: &[u8]) -> Result<Vec<u8>, R7zError> {
    let dict_size = lzma2_dict_size(properties)?;
    let mut reader = Lzma2Reader::new(Cursor::new(input), dict_size, None);
    let mut output = Vec::new();
    let available = MAX_MATERIALIZED_OUTPUT_BYTES
        .checked_sub(dict_size as usize)
        .ok_or_else(|| resource_limit("decoder working set", MAX_MATERIALIZED_OUTPUT_BYTES))?;
    let max_output = growth_safe_output_limit(available);
    read_to_end_bounded(&mut reader, &mut output, max_output, "materialized output")?;
    Ok(output)
}

/// Decompress all folders in a Folder chain and return the concatenated output.
///
/// This is the compatibility wrapper around the internal folder reader: it
/// builds the reader chain for the folder, drains it, and returns the decoded
/// bytes.
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
    folder: &Folder,
    packed_data: &[u8],
    unpack_size: u64,
    password: Option<&str>,
) -> Result<Vec<u8>, R7zError> {
    decompress_folder_with_password_and_sizes(folder, packed_data, unpack_size, &[], password)
}

pub fn decompress_folder_with_password_and_sizes(
    folder: &Folder,
    packed_data: &[u8],
    unpack_size: u64,
    coder_unpack_sizes: &[u64],
    password: Option<&str>,
) -> Result<Vec<u8>, R7zError> {
    prepare_folder_decoder(
        folder,
        smallvec::smallvec![PackedInput {
            reader: Cursor::new(packed_data),
            size: packed_data.len()
        }],
        unpack_size,
        coder_unpack_sizes,
    )?
    .materialize(password)
}

pub(crate) struct PackedInput<R> {
    pub(crate) reader: R,
    pub(crate) size: usize,
}

pub(crate) enum FolderReader<'a> {
    Stream(Box<dyn Read + 'a>),
    Buffered(Cursor<Vec<u8>>),
}

impl Read for FolderReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Stream(reader) => reader.read(buf),
            Self::Buffered(reader) => reader.read(buf),
        }
    }
}

impl FolderReader<'_> {
    pub(crate) fn read_bounded_to_vec(
        self,
        capacity_hint: usize,
        read_limit: u64,
    ) -> Result<Vec<u8>, R7zError> {
        match self {
            Self::Stream(reader) => {
                let mut output = Vec::with_capacity(capacity_hint.min(64 * 1024));
                reader
                    .take(read_limit)
                    .read_to_end(&mut output)
                    .map_err(R7zError::Io)?;
                Ok(output)
            }
            Self::Buffered(reader) => {
                let position = usize::try_from(reader.position()).unwrap_or(usize::MAX);
                let mut output = reader.into_inner();
                drop(output.drain(..position.min(output.len())));
                output.truncate(usize::try_from(read_limit).unwrap_or(usize::MAX));
                Ok(output)
            }
        }
    }
}

fn prepare_folder_decoder<R: Read>(
    folder: &Folder,
    packed_streams: SmallVec<[PackedInput<R>; 4]>,
    unpack_size: u64,
    coder_unpack_sizes: &[u64],
) -> Result<ReadyDecoder<R>, R7zError> {
    let graph = folder.graph()?;
    let mut sizes = SmallVec::<[u64; 4]>::from_slice(coder_unpack_sizes);
    // Public adapters historically allow omitted intermediate output sizes.
    // Resolve that convention here; the executable plan always has a complete table.
    sizes.resize(folder.total_out_streams(), 0);
    if coder_unpack_sizes.len() <= graph.final_output().get() {
        *sizes
            .get_mut(graph.final_output().get())
            .ok_or(R7zError::InvalidFolderGraph)? = unpack_size;
    }
    let packed_sizes = packed_streams
        .iter()
        .map(|input| input.size as u64)
        .collect::<SmallVec<[_; 4]>>();
    DecoderPlan::compile(folder, &graph, unpack_size, &sizes, &packed_sizes)?.bind(packed_streams)
}

fn aes_coder_reader<'a>(
    props: crate::aes::AesProperties,
    mut input: Box<dyn Read + 'a>,
    unpack_size: u64,
    password: Option<&str>,
) -> Result<Box<dyn Read + 'a>, R7zError> {
    let password = password.ok_or(R7zError::PasswordRequired)?;
    let key = crate::aes::derive_key(password, &props.salt, props.num_cycles_power)?;
    let mut encrypted = Vec::new();
    read_to_end_bounded(
        &mut input,
        &mut encrypted,
        MAX_BUFFERED_AES_BYTES,
        "AES encrypted input",
    )?;
    drop(input);
    let mut decrypted = crate::aes::decrypt_aes256_cbc(&encrypted, &key, &props.iv)?;
    if unpack_size > 0 {
        truncate_to(&mut decrypted, unpack_size)?;
    }
    Ok(Box::new(Cursor::new(decrypted)))
}

fn ppmd_properties(props: &[u8]) -> Result<(u32, u32), R7zError> {
    if props.len() != 5 {
        return Err(R7zError::Decompression);
    }

    let order = u32::from(props[0]);
    let mem_size = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
    if mem_size > MAX_PPMD_MEMORY_BYTES {
        return Err(resource_limit(
            "PPMd memory",
            MAX_PPMD_MEMORY_BYTES as usize,
        ));
    }
    Ok((order, mem_size))
}

fn resource_limit(resource: &'static str, limit: usize) -> R7zError {
    R7zError::ResourceLimitExceeded { resource, limit }
}

fn growth_safe_output_limit(available: usize) -> usize {
    // Vec growth can briefly keep both the old and replacement allocations alive.
    available / 2
}

fn validate_folder_coder_count(folder: &crate::Folder) -> Result<(), R7zError> {
    if folder.coders.len() > MAX_FOLDER_CODERS {
        return Err(R7zError::LimitExceeded("folder coder count"));
    }
    Ok(())
}

struct ExactSizeReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> ExactSizeReader<R> {
    fn new(inner: R, size: u64) -> Self {
        Self {
            inner,
            remaining: size,
        }
    }
}

impl<R: Read> Read for ExactSizeReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }

        let limit = usize::try_from(self.remaining)
            .ok()
            .map_or(buf.len(), |remaining| remaining.min(buf.len()));
        let n = self.inner.read(&mut buf[..limit])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "decoder ended before declared unpack size",
            ));
        }

        self.remaining -= u64::try_from(n).expect("read length fits in u64");
        Ok(n)
    }
}

enum DecoderTopology {
    Chain,
    Bcj2,
}

impl DecoderTopology {
    fn from_folder(folder: &Folder) -> Result<Self, R7zError> {
        match folder.coders.last() {
            Some(coder) if coder.codec_id.as_slice() == CODEC_BCJ2 => Ok(Self::Bcj2),
            _ if folder
                .coders
                .iter()
                .all(|coder| coder.num_in_streams == 1 && coder.num_out_streams == 1) =>
            {
                Ok(Self::Chain)
            }
            _ => {
                let unsupported = folder
                    .coders
                    .iter()
                    .find(|coder| crate::method_from_id(&coder.codec_id).is_none());
                Err(unsupported.map_or(R7zError::InvalidFolderGraph, |coder| {
                    R7zError::UnsupportedCodec(coder.codec_id.to_vec())
                }))
            }
        }
    }
}

fn read_to_end_bounded(
    input: &mut dyn Read,
    output: &mut Vec<u8>,
    max_len: usize,
    resource: &'static str,
) -> Result<(), R7zError> {
    let mut buf = [0u8; 8192];
    loop {
        let n = input.read(&mut buf).map_err(|_| R7zError::Decompression)?;
        if n == 0 {
            return Ok(());
        }
        let new_len = output.len().checked_add(n).ok_or(R7zError::Decompression)?;
        if new_len > max_len {
            return Err(resource_limit(resource, max_len));
        }
        if new_len > output.capacity() {
            let target_capacity = output
                .capacity()
                .max(buf.len())
                .saturating_mul(2)
                .max(new_len)
                .min(max_len);
            output
                .try_reserve_exact(target_capacity - output.len())
                .map_err(|_| resource_limit(resource, max_len))?;
        }
        if output.capacity() > max_len {
            return Err(resource_limit(resource, max_len));
        }
        output.extend_from_slice(&buf[..n]);
    }
}

#[cfg(test)]
mod bounded_reader_tests {
    use super::*;

    #[test]
    fn buffered_and_streamed_outputs_share_cursor_and_limit_semantics() {
        for limit in [0, 3, u64::MAX] {
            for mut reader in [
                FolderReader::Stream(Box::new(Cursor::new(b"abcdef"))),
                FolderReader::Buffered(Cursor::new(b"abcdef".to_vec())),
            ] {
                reader.read_exact(&mut [0; 2]).unwrap();
                let output = reader.read_bounded_to_vec(4, limit).unwrap();
                let expected = &b"cdef"[..usize::try_from(limit.min(4)).unwrap()];
                assert_eq!(output, expected);
            }
        }
    }

    #[test]
    fn bcj2_layouts_map_packed_inputs_to_named_streams() {
        let copy = || crate::CoderInfo::parse(&[1, 0]).unwrap().1;
        let bcj2 = || {
            crate::CoderInfo::parse(&[0x14, 3, 3, 1, 0x1b, 4, 1])
                .unwrap()
                .1
        };
        let main: &[u8] = &[0xe8];
        let call: &[u8] = &9u32.to_be_bytes();
        let control: &[u8] = &[0, 0x7f, 0xff, 0xfc, 0];
        let layouts = [
            (
                Folder {
                    coders: smallvec::smallvec![copy(), bcj2()],
                    packed_indices: smallvec::smallvec![0, 2, 3, 4],
                    bind_pairs: smallvec::smallvec![(1, 0)],
                },
                [main, call, &[][..], control],
                &[1, 5][..],
            ),
            (
                Folder {
                    coders: smallvec::smallvec![copy(), copy(), copy(), bcj2()],
                    packed_indices: smallvec::smallvec![2, 6, 1, 0],
                    bind_pairs: smallvec::smallvec![(5, 0), (4, 1), (3, 2)],
                },
                [main, control, call, &[][..]],
                &[0, 4, 1, 5][..],
            ),
        ];
        for (folder, inputs, sizes) in layouts {
            let inputs = inputs
                .into_iter()
                .map(|bytes| PackedInput {
                    reader: Cursor::new(bytes),
                    size: bytes.len(),
                })
                .collect();
            let output = prepare_folder_decoder(&folder, inputs, 5, sizes)
                .unwrap()
                .start(None)
                .unwrap()
                .read_bounded_to_vec(5, 6)
                .unwrap();
            assert_eq!(output, [0xe8, 4, 0, 0, 0]);
        }
    }

    #[test]
    fn bounded_reader_grows_geometrically_for_large_outputs() {
        let input = vec![0x5a; 4 * 1024 * 1024];
        let mut reader = Cursor::new(input.as_slice());
        let mut output = Vec::new();

        read_to_end_bounded(&mut reader, &mut output, input.len(), "test output").unwrap();

        assert_eq!(output, input);
        assert!(output.capacity() <= 4 * 1024 * 1024);
    }
}

fn bcj2_output_size(unpack_size: u64) -> Result<usize, R7zError> {
    let output_size = usize::try_from(unpack_size).map_err(|_| R7zError::Parse)?;
    if output_size > MAX_BCJ2_OUTPUT_BYTES {
        return Err(resource_limit("BCJ2 output", MAX_BCJ2_OUTPUT_BYTES));
    }
    Ok(output_size)
}

fn ensure_bcj2_working_budget(output_size: usize, decoder_memory: usize) -> Result<(), R7zError> {
    let committed = output_size
        .checked_add(decoder_memory)
        .ok_or(R7zError::Decompression)?;
    if committed > MAX_BCJ2_WORKING_BYTES {
        return Err(resource_limit(
            "BCJ2 working buffers",
            MAX_BCJ2_WORKING_BYTES,
        ));
    }
    Ok(())
}

fn truncate_to(data: &mut Vec<u8>, size: u64) -> Result<(), R7zError> {
    let size = usize::try_from(size).map_err(|_| R7zError::Parse)?;
    if data.len() < size {
        return Err(R7zError::Decompression);
    }
    data.truncate(size);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ExactSizeReader, compress_lzma, decompress_lzma2, lzma2_dict_size, ppmd_properties,
    };
    use crate::R7zError;
    use std::io::{Cursor, ErrorKind, Read};

    #[test]
    fn lzma_property_block_is_exactly_five_bytes() {
        let (props, _) = compress_lzma(b"property block").unwrap();
        assert_eq!(props.len(), 5);
    }

    #[test]
    fn lzma2_dict_size_decodes_p7zip_property_values() {
        assert_eq!(lzma2_dict_size(Some(&[8])).unwrap(), 64 * 1024);
        assert_eq!(lzma2_dict_size(Some(&[16])).unwrap(), 1024 * 1024);
        assert_eq!(lzma2_dict_size(Some(&[24])).unwrap(), 16 * 1024 * 1024);
        assert_eq!(lzma2_dict_size(Some(&[28])).unwrap(), 64 * 1024 * 1024);
        assert!(matches!(
            lzma2_dict_size(Some(&[40])),
            Err(R7zError::ResourceLimitExceeded { .. })
        ));
    }

    #[test]
    fn lzma2_dictionary_properties_above_the_resource_cap_are_rejected() {
        assert_eq!(lzma2_dict_size(Some(&[32])).unwrap(), 256 * 1024 * 1024);
        assert!(matches!(
            lzma2_dict_size(Some(&[40])),
            Err(R7zError::ResourceLimitExceeded {
                resource: "LZMA dictionary",
                ..
            })
        ));
        assert!(matches!(
            lzma2_dict_size(Some(&[33])),
            Err(R7zError::ResourceLimitExceeded { .. })
        ));
        assert!(matches!(
            lzma2_dict_size(None),
            Err(R7zError::ResourceLimitExceeded { .. })
        ));
    }

    #[test]
    fn lzma2_property_values_zero_through_twenty_four_decode_empty_stream() {
        for prop in 0u8..=24 {
            let decoded = decompress_lzma2(Some(&[prop]), &[0x00]).unwrap();
            assert!(decoded.is_empty(), "property {prop} decoded non-empty data");
        }
    }

    #[test]
    fn unsupported_lzma2_property_shapes_return_decompression_errors() {
        for props in [&[][..], &[0x1c, 0x00][..], &[41][..]] {
            let err = lzma2_dict_size(Some(props)).unwrap_err();
            assert!(matches!(err, R7zError::Decompression));

            let err = decompress_lzma2(Some(props), &[0x00]).unwrap_err();
            assert!(matches!(err, R7zError::Decompression));
        }
    }

    #[test]
    fn ppmd_property_block_is_exactly_five_bytes() {
        assert_eq!(
            ppmd_properties(&[6, 0x00, 0x00, 0x10, 0x00]).unwrap(),
            (6, 1024 * 1024)
        );

        for props in [
            &[][..],
            &[6, 0x00, 0x00, 0x10][..],
            &[6, 0, 0, 0x10, 0, 0][..],
        ] {
            let err = ppmd_properties(props).unwrap_err();
            assert!(matches!(err, R7zError::Decompression));
        }
    }

    #[test]
    fn ppmd_memory_properties_above_the_resource_cap_are_rejected() {
        let props = [6, 0, 0, 0, 0x40]; // 1 GiB
        assert!(matches!(
            ppmd_properties(&props),
            Err(R7zError::ResourceLimitExceeded {
                resource: "PPMd memory",
                ..
            })
        ));
    }

    #[test]
    fn coder_reader_rejects_oversized_lzma_and_ppmd_properties_before_decode() {
        let lzma =
            crate::CoderInfo::parse(&[0x23, 0x03, 0x01, 0x01, 5, 0x5d, 0xff, 0xff, 0xff, 0xff])
                .unwrap()
                .1;
        assert!(matches!(
            super::plan::CoderPlan::compile(&lzma, 0),
            Err(R7zError::ResourceLimitExceeded {
                resource: "LZMA dictionary",
                ..
            })
        ));

        let lzma2 = crate::CoderInfo::parse(&[0x21, 0x21, 1, 40]).unwrap().1;
        assert!(matches!(
            super::plan::CoderPlan::compile(&lzma2, 0),
            Err(R7zError::ResourceLimitExceeded {
                resource: "LZMA dictionary",
                ..
            })
        ));

        let ppmd = crate::CoderInfo::parse(&[0x23, 0x03, 0x04, 0x01, 5, 6, 0, 0, 0, 0x40])
            .unwrap()
            .1;
        assert!(matches!(
            super::plan::CoderPlan::compile(&ppmd, 0),
            Err(R7zError::ResourceLimitExceeded {
                resource: "PPMd memory",
                ..
            })
        ));
    }

    #[test]
    fn bcj2_declared_final_output_is_capped_before_allocation() {
        let err = super::bcj2_output_size(u64::MAX).unwrap_err();
        assert!(matches!(
            err,
            R7zError::ResourceLimitExceeded {
                resource: "BCJ2 output",
                ..
            }
        ));
    }

    #[test]
    fn bcj2_budget_counts_output_and_live_decoders() {
        assert!(super::ensure_bcj2_working_budget(400, 100).is_ok());
        assert!(matches!(
            super::ensure_bcj2_working_budget(512 * 1024 * 1024, 1),
            Err(R7zError::ResourceLimitExceeded {
                resource: "BCJ2 working buffers",
                ..
            })
        ));
    }

    #[test]
    fn exact_size_reader_rejects_early_eof() {
        let mut reader = ExactSizeReader::new(Cursor::new(b"ab"), 3);
        let mut out = Vec::new();

        let err = reader.read_to_end(&mut out).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(out, b"ab");
    }
}
