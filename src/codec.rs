mod plan;
mod sizes;
pub use crate::method::{
    CODEC_AES_256_SHA_256, CODEC_BCJ_ARM, CODEC_BCJ_ARM_THUMB, CODEC_BCJ_ARM64, CODEC_BCJ_IA64,
    CODEC_BCJ_PPC, CODEC_BCJ_RISCV, CODEC_BCJ_SPARC, CODEC_BCJ_X86, CODEC_BCJ2, CODEC_BZIP2,
    CODEC_COPY, CODEC_DEFLATE, CODEC_DEFLATE64, CODEC_DELTA, CODEC_LZMA, CODEC_LZMA2, CODEC_PPMD,
    CODEC_SWAP2, CODEC_SWAP4,
};
use crate::resources::{KdfCycles, OperationBudget, ResourceLimits};
use crate::{Folder, R7zError};
use bzip2_rs::DecoderReader as Bzip2Decoder;
use deflate64::Deflate64Decoder;
use flate2::read::DeflateDecoder;
use lzma_rust2::{
    Lzma2Reader, Lzma2Writer, LzmaOptions, LzmaReader, LzmaWriter, filter::bcj::BcjReader,
};
pub(crate) use plan::{DecoderPlan, ReadyDecoder};
use ppmd_rust::Ppmd7Decoder;
use sizes::{CoderOutputSizes, OutputSize};
use smallvec::SmallVec;
use std::io::{Cursor, Read, Write};

const MAX_LZMA_DICTIONARY_BYTES: u32 = 256 * 1024 * 1024;
const MAX_LZMA2_PROBABILITY_BYTES: usize = 24 * 1024;
const MAX_PPMD_MEMORY_BYTES: u32 = 256 * 1024 * 1024;
const MAX_MATERIALIZED_OUTPUT_BYTES: usize = 512 * 1024 * 1024;
const MAX_BCJ2_OUTPUT_BYTES: usize = 256 * 1024 * 1024;
pub(crate) const MAX_DECODER_WORKING_SET_BYTES: usize = 512 * 1024 * 1024;
const OTHER_CODER_WORKING_SET_BYTES: usize = 2 * 1024 * 1024;
const DECODER_OVERHEAD_BYTES: usize = 128 * 1024;
const AES_CBC_WORKING_SET_BYTES: usize = 1024;
// lzma-rust2's BcjReader owns a 4 KiB filter buffer; DeltaReader owns 256 bytes.
pub(super) const BCJ_READER_WORKING_SET_BYTES: usize = 4096;
pub(super) const DELTA_READER_WORKING_SET_BYTES: usize = 256;
// lzma-rust2's Bcj2Reader owns four 256 KiB channel buffers.
pub(super) const BCJ2_READER_WORKING_SET_BYTES: usize = 4 * 256 * 1024;
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

/// Decode using coder output sizes in the folder's output-stream order.
///
/// Supplied zeroes mean empty outputs. Omitted entries are inferred through
/// length-preserving filters where possible; codecs requiring a size reject
/// unresolved entries. A supplied final size must agree with `unpack_size`.
///
/// # Errors
///
/// Returns errors for invalid folder layouts or sizes, unsupported codecs,
/// missing passwords, decoder failures, or resource limits.
pub fn decompress_folder_with_password_and_sizes(
    folder: &Folder,
    packed_data: &[u8],
    unpack_size: u64,
    coder_unpack_sizes: &[u64],
    password: Option<&str>,
) -> Result<Vec<u8>, R7zError> {
    let mut budget = OperationBudget::new(ResourceLimits::default());
    prepare_folder_decoder(
        folder,
        smallvec::smallvec![PackedInput {
            reader: Cursor::new(packed_data),
            size: packed_data.len()
        }],
        unpack_size,
        coder_unpack_sizes,
        &mut budget,
    )?
    .materialize(password, &mut budget)
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
    budget: &mut OperationBudget,
) -> Result<ReadyDecoder<R>, R7zError> {
    let graph = folder.graph()?;
    let sizes = CoderOutputSizes::partial(folder, &graph, unpack_size, coder_unpack_sizes)?;
    let packed_sizes = packed_streams
        .iter()
        .map(|input| input.size as u64)
        .collect::<SmallVec<[_; 4]>>();
    DecoderPlan::with_output_sizes(folder, &graph, unpack_size, sizes, &packed_sizes, budget)?
        .bind(packed_streams)
}

fn aes_coder_reader<'a>(
    props: &crate::aes::AesProperties,
    input: Box<dyn Read + 'a>,
    input_size: OutputSize,
    unpack_size: OutputSize,
    password: Option<&str>,
    budget: &mut OperationBudget,
) -> Result<crate::aes::Aes256CbcDecryptReader<Box<dyn Read + 'a>>, R7zError> {
    let password = password.ok_or(R7zError::PasswordRequired)?;
    let cycles = match props.num_cycles_power {
        0x3F => 0,
        power if power <= crate::aes::MAX_AES_NUM_CYCLES_POWER => 1u64 << power,
        _ => return Err(R7zError::Decompression),
    };
    budget.charge_kdf_cycles(KdfCycles::new(cycles))?;
    let key = zeroize::Zeroizing::new(crate::aes::derive_key_with_control(
        password,
        &props.salt,
        props.num_cycles_power,
        budget.monitor.control(),
    )?);
    let ciphertext_size = match input_size {
        OutputSize::Known(size) => Some(size),
        OutputSize::Unknown => None,
    };
    let plaintext_size = match unpack_size {
        OutputSize::Known(size) => Some(size),
        OutputSize::Unknown => None,
    };
    crate::aes::Aes256CbcDecryptReader::new(input, &key, &props.iv, ciphertext_size, plaintext_size)
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
    R7zError::ResourceLimitExceeded {
        resource,
        limit: limit as u64,
    }
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
    end: OutputEnd,
}

enum OutputEnd {
    /// The declared size ends the stream (`PPMd` may decode entropy padding).
    Sized,
    /// The underlying codec must also report EOF at the declared size.
    Terminated,
}

impl<R> ExactSizeReader<R> {
    fn sized(inner: R, size: u64) -> Self {
        Self {
            inner,
            remaining: size,
            end: OutputEnd::Sized,
        }
    }
    fn terminated(inner: R, size: u64) -> Self {
        Self {
            inner,
            remaining: size,
            end: OutputEnd::Terminated,
        }
    }
}

impl<R: Read> Read for ExactSizeReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            return match self.end {
                OutputEnd::Sized => Ok(0),
                OutputEnd::Terminated => match self.inner.read(&mut [0])? {
                    0 => Ok(0),
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "decoder exceeded declared unpack size",
                    )),
                },
            };
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
            let mut budget = OperationBudget::new(ResourceLimits::default());
            let output = prepare_folder_decoder(&folder, inputs, 5, sizes, &mut budget)
                .unwrap()
                .start(None, &mut budget)
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

#[cfg(test)]
mod tests {
    use super::{
        ExactSizeReader, compress_lzma, decompress_lzma2, lzma2_dict_size, ppmd_properties,
    };
    use crate::R7zError;
    use crate::resources::{OperationBudget, ResourceLimits};
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
            super::plan::CoderPlan::compile(&lzma, super::OutputSize::Known(0)),
            Err(R7zError::ResourceLimitExceeded {
                resource: "LZMA dictionary",
                ..
            })
        ));

        let lzma2 = crate::CoderInfo::parse(&[0x21, 0x21, 1, 40]).unwrap().1;
        assert!(matches!(
            super::plan::CoderPlan::compile(&lzma2, super::OutputSize::Known(0)),
            Err(R7zError::ResourceLimitExceeded {
                resource: "LZMA dictionary",
                ..
            })
        ));

        let ppmd = crate::CoderInfo::parse(&[0x23, 0x03, 0x04, 0x01, 5, 6, 0, 0, 0, 0x40])
            .unwrap()
            .1;
        assert!(matches!(
            super::plan::CoderPlan::compile(&ppmd, super::OutputSize::Known(0)),
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
        let mut reader = ExactSizeReader::sized(Cursor::new(b"ab"), 3);
        let mut out = Vec::new();

        let err = reader.read_to_end(&mut out).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(out, b"ab");
    }

    #[test]
    fn terminated_reader_checks_exact_short_long_and_empty_outputs() {
        for (bytes, size, expected) in [
            (&b"abc"[..], 3, None),
            (&b"ab"[..], 3, Some(ErrorKind::UnexpectedEof)),
            (&b"abcd"[..], 3, Some(ErrorKind::InvalidData)),
            (&b""[..], 0, None),
            (&b"a"[..], 0, Some(ErrorKind::InvalidData)),
        ] {
            let mut reader = ExactSizeReader::terminated(Cursor::new(bytes), size);
            assert_eq!(reader.read(&mut []).unwrap(), 0);
            let result = reader.read_to_end(&mut Vec::new());
            assert_eq!(result.err().map(|error| error.kind()), expected);
        }
    }

    #[test]
    fn sized_reader_does_not_decode_entropy_padding() {
        let mut input = Cursor::new(b"abcPADDING");
        let mut output = Vec::new();
        ExactSizeReader::sized(&mut input, 3)
            .read_to_end(&mut output)
            .unwrap();
        assert_eq!(output, b"abc");
        assert_eq!(input.position(), 3);
    }

    #[test]
    fn aes_distinguishes_known_empty_output_from_omitted_size() {
        use super::{OutputSize, aes_coder_reader};
        let key = crate::aes::derive_key("password", &[], 0).unwrap();
        let encrypted = crate::aes::encrypt_aes256_cbc_zero_pad(&[], &key, &[0; 16]).unwrap();
        let mut budget = OperationBudget::new(ResourceLimits::default());
        for (output_size, expected) in [(OutputSize::Known(0), 0), (OutputSize::Unknown, 16)] {
            let props = crate::aes::AesProperties::parse(&[0, 0]).unwrap();
            let mut reader = aes_coder_reader(
                &props,
                Box::new(Cursor::new(&encrypted)),
                OutputSize::Known(encrypted.len() as u64),
                output_size,
                Some("password"),
                &mut budget,
            )
            .unwrap();
            let mut output = Vec::new();
            reader.read_to_end(&mut output).unwrap();
            assert_eq!(output, vec![0; expected]);
        }
    }

    #[test]
    fn aes_coders_share_the_operation_kdf_limit() {
        use super::{OutputSize, aes_coder_reader};

        let mut budget = OperationBudget::new(ResourceLimits {
            max_total_kdf_cycles: Some(1),
            ..ResourceLimits::default()
        });
        let open = |budget: &mut OperationBudget| {
            aes_coder_reader(
                &crate::aes::AesProperties::parse(&[0, 0]).unwrap(),
                Box::new(Cursor::new([0; 16])),
                OutputSize::Known(16),
                OutputSize::Known(16),
                Some("password"),
                budget,
            )
        };

        drop(open(&mut budget).unwrap());
        assert!(matches!(
            open(&mut budget),
            Err(R7zError::ResourceLimitExceeded {
                resource: "AES KDF cycles",
                limit: 1,
            })
        ));
    }

    #[test]
    fn aes_coder_reader_streams_inputs_over_256_mib() {
        use super::{OutputSize, aes_coder_reader};

        let size = 256 * 1024 * 1024 + 16;
        let props = crate::aes::AesProperties::parse(&[0, 0]).unwrap();
        let mut budget = OperationBudget::new(ResourceLimits::default());
        let mut reader = aes_coder_reader(
            &props,
            Box::new(std::io::repeat(0).take(size)),
            OutputSize::Known(size),
            OutputSize::Known(size),
            Some("password"),
            &mut budget,
        )
        .unwrap();
        let mut output = [0; 8192];
        let mut read = 0;
        loop {
            let n = reader.read(&mut output).unwrap();
            if n == 0 {
                break;
            }
            read += n as u64;
        }

        assert_eq!(read, size);
    }
}
