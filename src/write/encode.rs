use super::header::{
    CoderSpec, build_encoded_header_descriptor, build_header, encode_coder_info_aes_then,
    encode_coder_info_bcj_lzma2, encode_coder_info_copy, encode_coder_info_lzma,
    encode_coder_info_lzma2, encode_coder_info_ppmd,
};
use super::lzma2;
use super::model::{
    ArchiveOptions, Codec, CompletedFolder, CompressionLevel, CompressionOptions, EncoderThreads,
    EncryptionOptions, HeaderMode, LzmaAlgorithm, MatchFinder, PreparedFolder, SolidMode,
    WriteEntry, WriteEntryIndex,
};
use crate::resources::{KdfCycles, OperationBudget, WriterOperation};
use crate::{R7zError, aes, bcj, codec};
use lzma_rust2::{EncodeMode, Lzma2Options, LzmaOptions, LzmaWriter, MfType};
use ppmd_rust::{
    PPMD7_MAX_MEM_SIZE, PPMD7_MAX_ORDER, PPMD7_MIN_MEM_SIZE, PPMD7_MIN_ORDER, Ppmd7Encoder,
};
use std::io::{Seek, SeekFrom, Write};
use std::{
    collections::BTreeMap,
    num::{NonZeroU32, NonZeroU64},
};

struct PackedBytes(Vec<u8>);

impl PackedBytes {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

struct CoderInfo(Vec<u8>);

impl CoderInfo {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

struct UnpackSizes(Vec<u64>);

impl UnpackSizes {
    fn as_slice(&self) -> &[u64] {
        &self.0
    }

    fn into_vec(self) -> Vec<u64> {
        self.0
    }
}

struct EncodedPayload {
    packed: PackedBytes,
    coder_info: CoderInfo,
    unpack_sizes: UnpackSizes,
    coders: Vec<CoderSpec>,
}

struct EncodedHeader {
    packed: PackedBytes,
    coder_info: CoderInfo,
    unpack_sizes: UnpackSizes,
}
pub(crate) const DEFAULT_LZMA2_CHUNK_SIZE: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_LZMA2_CHUNK_SIZE: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub(super) struct PreparedSettings {
    pub(super) aes: AesSettings,
    pub(super) codec: PreparedCodec,
}

pub(super) struct PreparedArchiveOptions {
    archive: SensitiveArchiveOptions,
    settings: PreparedSettings,
}

struct SensitiveArchiveOptions(ArchiveOptions);

impl std::ops::Deref for SensitiveArchiveOptions {
    type Target = ArchiveOptions;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveArchiveOptions {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(encryption) = &mut self.0.encryption {
            encryption.password.zeroize();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EncoderWorkingSetBytes(u64);

impl PreparedArchiveOptions {
    pub(super) fn archive(&self) -> &ArchiveOptions {
        &self.archive
    }

    pub(super) fn settings(&self) -> PreparedSettings {
        self.settings
    }

    pub(super) fn encryption(&self) -> Option<PreparedEncryption<'_>> {
        self.archive
            .encryption
            .as_ref()
            .map(|options| PreparedEncryption {
                options,
                settings: self.settings.aes,
            })
    }

    pub(super) fn validate_encoder_working_set(&self) -> Result<(), R7zError> {
        let Some(limit) = self
            .archive
            .streaming
            .resource_limits
            .max_encoder_working_set_bytes
        else {
            return Ok(());
        };

        let estimate = match self.settings.codec {
            PreparedCodec::Lzma => EncoderWorkingSetBytes(
                u64::from(lzma_options(&self.archive.compression).get_memory_usage())
                    .checked_mul(1024)
                    .ok_or(R7zError::LimitExceeded("encoder memory"))?,
            ),
            PreparedCodec::Ppmd(PpmdSettings { memory_size, .. }) => {
                EncoderWorkingSetBytes(u64::from(memory_size))
            }
            PreparedCodec::Copy | PreparedCodec::Lzma2(_) | PreparedCodec::Lzma2Bcj(_) => {
                return Ok(());
            }
        };

        if estimate.0 > limit {
            return Err(R7zError::LimitExceeded("encoder memory"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct PreparedEncryption<'a> {
    options: &'a EncryptionOptions,
    settings: AesSettings,
}

impl PreparedEncryption<'_> {
    pub(super) fn encrypt_header(&self) -> bool {
        self.options.encrypt_header
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct AesSettings {
    pub(super) cycles_power: u8,
    pub(super) salt_len: u8,
    pub(super) iv_len: u8,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PpmdSettings {
    pub(super) order: u8,
    pub(super) memory_size: u32,
}

#[derive(Clone, Copy, Debug)]
enum CodecSettings {
    Copy,
    Lzma,
    Lzma2,
    Ppmd(PpmdSettings),
    Lzma2Bcj,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum PreparedCodec {
    Copy,
    Lzma,
    Lzma2(ThreadRequest),
    Ppmd(PpmdSettings),
    Lzma2Bcj(ThreadRequest),
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ThreadRequest {
    Auto,
    Single,
    Fixed(NonZeroU32),
}

pub(crate) fn build_archive(
    entries: &[WriteEntry],
    options: &ArchiveOptions,
) -> Result<Vec<u8>, R7zError> {
    let prepared = prepare_archive_options(options.clone())?;
    if let Some(control) = &options.streaming.control {
        control.check()?;
    }
    let budget = OperationBudget::new(options.streaming.resource_limits)
        .with_control(options.streaming.control.clone());
    let mut operation = budget.into_writer_budgets().operation;
    build_archive_with_settings(entries, &prepared, &mut operation)
}

pub(super) fn build_archive_with_settings(
    entries: &[WriteEntry],
    prepared: &PreparedArchiveOptions,
    budget: &mut WriterOperation,
) -> Result<Vec<u8>, R7zError> {
    let mut folders = Vec::new();
    let mut by_folder: BTreeMap<super::model::WriteFolderId, Vec<WriteEntryIndex>> =
        BTreeMap::new();
    for (idx, entry) in entries.iter().enumerate() {
        if entry.stream.has_stream() {
            by_folder
                .entry(entry.folder_id)
                .or_default()
                .push(WriteEntryIndex::from_index(idx));
        }
    }

    for file_indices in by_folder.into_values() {
        let folder = encode_folder(entries, file_indices, prepared, budget)?;
        folders.push(folder);
    }

    build_archive_from_prepared(entries, &folders, prepared, budget)
}

pub(crate) fn build_archive_from_prepared(
    entries: &[WriteEntry],
    folders: &[PreparedFolder],
    prepared: &PreparedArchiveOptions,
    budget: &mut WriterOperation,
) -> Result<Vec<u8>, R7zError> {
    let options = &prepared.archive;
    let mut packed_data = Vec::new();
    for folder in folders {
        for stream in &folder.packed_streams {
            packed_data.extend_from_slice(stream);
        }
    }
    let folder_metadata = folders
        .iter()
        .map(|folder| folder.metadata.clone())
        .collect::<Vec<_>>();

    let raw_header = build_header(entries, &folder_metadata);
    let should_encode = match options.header_mode {
        HeaderMode::Plain => false,
        HeaderMode::Encoded => true,
        HeaderMode::P7zipDefault => {
            entries.len() > 1
                || options.encryption.is_some()
                || options
                    .encryption
                    .as_ref()
                    .is_some_and(|enc| enc.encrypt_header)
        }
    };

    let (next_header, next_header_offset) = if should_encode {
        let encoded = encode_header_stream(&raw_header, prepared, budget)?;
        let pack_pos = packed_data.len() as u64;
        packed_data.extend_from_slice(encoded.packed.as_slice());
        let descriptor = build_encoded_header_descriptor(
            pack_pos,
            encoded.packed.len() as u64,
            encoded.coder_info.as_slice(),
            encoded.unpack_sizes.as_slice(),
        );
        (descriptor, packed_data.len() as u64)
    } else {
        (raw_header, packed_data.len() as u64)
    };

    let mut archive = vec![0u8; 32];
    archive.extend_from_slice(&packed_data);
    archive.extend_from_slice(&next_header);
    write_signature(&mut archive, next_header_offset, &next_header);
    Ok(archive)
}

pub(crate) fn validate_archive_options(
    options: &ArchiveOptions,
) -> Result<PreparedSettings, R7zError> {
    let codec_settings = validate_compression_options(options)?;
    let requested_threads = options.compression.threads;
    if matches!(requested_threads, EncoderThreads::Fixed(0)) {
        return Err(R7zError::InvalidOptions(
            "encoder thread count must be positive",
        ));
    }
    if !matches!(options.codec, Codec::Lzma2 | Codec::Lzma2Bcj)
        && matches!(requested_threads, EncoderThreads::Fixed(_))
    {
        return Err(R7zError::InvalidOptions(
            "multiple encoder threads require LZMA2",
        ));
    }
    let threads = match requested_threads {
        EncoderThreads::Auto => ThreadRequest::Auto,
        EncoderThreads::Single => ThreadRequest::Single,
        EncoderThreads::Fixed(count) if count > lzma2::MAX_WORKERS => {
            return Err(R7zError::InvalidOptions(
                "encoder thread count must be <= 256",
            ));
        }
        EncoderThreads::Fixed(count) => {
            ThreadRequest::Fixed(NonZeroU32::new(count).expect("validated worker count is nonzero"))
        }
    };
    let codec = match codec_settings {
        CodecSettings::Copy => PreparedCodec::Copy,
        CodecSettings::Lzma => PreparedCodec::Lzma,
        CodecSettings::Lzma2 => PreparedCodec::Lzma2(threads),
        CodecSettings::Ppmd(settings) => PreparedCodec::Ppmd(settings),
        CodecSettings::Lzma2Bcj => PreparedCodec::Lzma2Bcj(threads),
    };
    let aes = match options.encryption.as_ref() {
        Some(enc) => {
            if enc.num_cycles_power > aes::MAX_AES_NUM_CYCLES_POWER {
                return Err(R7zError::InvalidOptions(
                    "AES num_cycles_power must be <= 24",
                ));
            }
            if enc.salt_len > 16 {
                return Err(R7zError::InvalidOptions("AES salt_len must be <= 16"));
            }
            if enc.iv_len > 16 {
                return Err(R7zError::InvalidOptions("AES iv_len must be <= 16"));
            }
            if enc.encrypt_header && options.header_mode == HeaderMode::Plain {
                return Err(R7zError::InvalidOptions(
                    "encrypt_header requires encoded headers",
                ));
            }
            AesSettings {
                cycles_power: enc.num_cycles_power,
                salt_len: enc.salt_len,
                iv_len: enc.iv_len,
            }
        }
        None => AesSettings {
            cycles_power: 0,
            salt_len: 0,
            iv_len: 0,
        },
    };
    Ok(PreparedSettings { aes, codec })
}

pub(super) fn prepare_archive_options(
    archive: ArchiveOptions,
) -> Result<PreparedArchiveOptions, R7zError> {
    let archive = SensitiveArchiveOptions(archive);
    let settings = validate_archive_options(&archive)?;
    Ok(PreparedArchiveOptions { archive, settings })
}

fn validate_compression_options(options: &ArchiveOptions) -> Result<CodecSettings, R7zError> {
    let methods: &[crate::SevenZMethod] = match options.codec {
        Codec::Copy => &[crate::SevenZMethod::Copy],
        Codec::Lzma => &[crate::SevenZMethod::Lzma],
        Codec::Lzma2 => &[crate::SevenZMethod::Lzma2],
        Codec::Ppmd => &[crate::SevenZMethod::Ppmd],
        Codec::Lzma2Bcj => &[crate::SevenZMethod::Lzma2, crate::SevenZMethod::Bcj],
    };
    if methods.iter().any(|method| !method.support().can_encode()) {
        return Err(R7zError::InvalidOptions(
            "selected codec is not supported for writing",
        ));
    }
    if options.streaming.buffer_size == 0 {
        return Err(R7zError::InvalidOptions(
            "streaming buffer_size must be greater than zero",
        ));
    }
    if options.codec == Codec::Copy
        && (options.compression.dictionary_size.is_some()
            || options.compression.fast_bytes.is_some()
            || options.compression.literal_context_bits.is_some()
            || options.compression.literal_position_bits.is_some()
            || options.compression.position_bits.is_some()
            || options.compression.match_finder.is_some()
            || options.compression.lzma_algorithm.is_some()
            || options.compression.match_cycles.is_some()
            || options.compression.lzma2_chunk_size.is_some())
    {
        return Err(R7zError::InvalidOptions(
            "Copy codec does not support compression tuning",
        ));
    }
    if let Some(dict) = options.compression.dictionary_size {
        let min_dict = if options.codec == Codec::Ppmd {
            PPMD7_MIN_MEM_SIZE
        } else {
            4096
        };
        if dict < min_dict {
            return Err(R7zError::InvalidOptions(
                "dictionary_size is too small for selected codec",
            ));
        }
    }
    let ppmd_order = match options.codec {
        Codec::Ppmd => Some(ppmd_order(&options.compression)?),
        Codec::Copy | Codec::Lzma | Codec::Lzma2 | Codec::Lzma2Bcj => {
            if options
                .compression
                .fast_bytes
                .is_some_and(|fast_bytes| !(8..=273).contains(&fast_bytes))
            {
                return Err(R7zError::InvalidOptions("fast_bytes must be in 8..=273"));
            }
            None
        }
    };
    if options.codec == Codec::Ppmd && options.compression.lzma2_chunk_size.is_some() {
        return Err(R7zError::InvalidOptions(
            "PPMd does not support lzma2_chunk_size",
        ));
    }
    if options.codec == Codec::Ppmd
        && (options.compression.literal_context_bits.is_some()
            || options.compression.literal_position_bits.is_some()
            || options.compression.position_bits.is_some()
            || options.compression.match_finder.is_some()
            || options.compression.lzma_algorithm.is_some()
            || options.compression.match_cycles.is_some())
    {
        return Err(R7zError::InvalidOptions(
            "PPMd does not support LZMA-specific tuning",
        ));
    }
    validate_lzma_property_bits(&options.compression)?;
    validate_match_cycles(&options.compression)?;
    validate_lzma2_chunk_size(options)?;
    if let SolidMode::Limit {
        max_files: None,
        max_bytes: None,
    } = &options.compression.solid
    {
        return Err(R7zError::InvalidOptions(
            "solid limit requires max_files or max_bytes",
        ));
    }
    match (options.codec, ppmd_order) {
        (Codec::Copy, _) => Ok(CodecSettings::Copy),
        (Codec::Lzma, _) => Ok(CodecSettings::Lzma),
        (Codec::Lzma2, _) => Ok(CodecSettings::Lzma2),
        (Codec::Ppmd, Some(order)) => {
            ppmd_settings(&options.compression, order).map(CodecSettings::Ppmd)
        }
        (Codec::Ppmd, None) => Err(R7zError::Parse),
        (Codec::Lzma2Bcj, _) => Ok(CodecSettings::Lzma2Bcj),
    }
}

fn validate_lzma2_chunk_size(options: &ArchiveOptions) -> Result<(), R7zError> {
    if matches!(options.codec, Codec::Lzma2 | Codec::Lzma2Bcj) {
        let dict = lzma_options(&options.compression).dict_size;
        if u64::from(dict) > MAX_LZMA2_CHUNK_SIZE {
            return Err(R7zError::InvalidOptions(
                "dictionary_size must be <= 1g for LZMA2",
            ));
        }
    }
    if let Some(chunk_size) = options.compression.lzma2_chunk_size {
        if chunk_size.get() > MAX_LZMA2_CHUNK_SIZE {
            return Err(R7zError::InvalidOptions("lzma2_chunk_size must be <= 1g"));
        }
        let dict = lzma_options(&options.compression).dict_size;
        if chunk_size.get() < u64::from(dict) {
            return Err(R7zError::InvalidOptions(
                "lzma2_chunk_size must be at least dictionary_size",
            ));
        }
    }
    Ok(())
}

fn validate_match_cycles(compression: &CompressionOptions) -> Result<(), R7zError> {
    if let Some(match_cycles) = compression.match_cycles {
        i32::try_from(match_cycles)
            .map(|_| ())
            .map_err(|_| R7zError::InvalidOptions("match_cycles is too large"))?;
    }
    Ok(())
}

fn validate_lzma_property_bits(compression: &CompressionOptions) -> Result<(), R7zError> {
    let lc = compression.literal_context_bits.unwrap_or(3);
    let lp = compression.literal_position_bits.unwrap_or(0);
    let pb = compression.position_bits.unwrap_or(2);
    if lc > 8 {
        return Err(R7zError::InvalidOptions(
            "literal_context_bits must be in 0..=8",
        ));
    }
    if lp > 4 {
        return Err(R7zError::InvalidOptions(
            "literal_position_bits must be in 0..=4",
        ));
    }
    if pb > 4 {
        return Err(R7zError::InvalidOptions("position_bits must be in 0..=4"));
    }
    if lc + lp > 4 {
        return Err(R7zError::InvalidOptions(
            "literal_context_bits + literal_position_bits must be <= 4",
        ));
    }
    Ok(())
}

pub(crate) fn finish_streamed_archive<W: Write + Seek>(
    mut out: W,
    entries: &[WriteEntry],
    folders: &[CompletedFolder],
    prepared: &PreparedArchiveOptions,
    budget: &mut WriterOperation,
) -> Result<W, R7zError> {
    budget.monitor.check()?;
    let options = &prepared.archive;
    let packed_size = folders.iter().try_fold(0u64, |acc, folder| {
        let folder_size = folder.pack_sizes.iter().try_fold(0u64, |acc, &size| {
            acc.checked_add(size).ok_or(R7zError::Parse)
        })?;
        acc.checked_add(folder_size).ok_or(R7zError::Parse)
    })?;
    let raw_header = build_header(entries, folders);
    let should_encode = match options.header_mode {
        HeaderMode::Plain => false,
        HeaderMode::Encoded => true,
        HeaderMode::P7zipDefault => entries.len() > 1 || options.encryption.is_some(),
    };

    let (next_header, next_header_offset) = if should_encode {
        let encoded = encode_header_stream(&raw_header, prepared, budget)?;
        out.seek(SeekFrom::Start(32 + packed_size))?;
        out.write_all(encoded.packed.as_slice())?;
        let descriptor = build_encoded_header_descriptor(
            packed_size,
            encoded.packed.len() as u64,
            encoded.coder_info.as_slice(),
            encoded.unpack_sizes.as_slice(),
        );
        (descriptor, packed_size + encoded.packed.len() as u64)
    } else {
        (raw_header, packed_size)
    };

    out.seek(SeekFrom::Start(32 + next_header_offset))?;
    out.write_all(&next_header)?;
    let signature = signature_bytes(next_header_offset, &next_header);
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&signature)?;
    out.flush()?;
    budget.monitor.check()?;
    Ok(out)
}

pub(crate) fn encode_folder(
    entries: &[WriteEntry],
    file_indices: Vec<WriteEntryIndex>,
    prepared: &PreparedArchiveOptions,
    budget: &mut WriterOperation,
) -> Result<PreparedFolder, R7zError> {
    let mut data = Vec::new();
    let mut file_sizes = Vec::new();
    let mut file_crcs = Vec::new();
    for &idx in &file_indices {
        let bytes = entries[idx.index()]
            .stream
            .buffered_data()
            .ok_or(R7zError::Parse)?;
        file_sizes.push(bytes.len() as u64);
        file_crcs.push(Some(crc32fast::hash(bytes)));
        data.extend_from_slice(bytes);
    }

    let mut encoded = encode_payload_with_options(&data, prepared)?;

    if let Some(encryption) = prepared.encryption() {
        let aes = make_aes_material(encryption, budget)?;
        let before_padding = encoded.packed.len() as u64;
        encoded.packed = PackedBytes(aes::encrypt_aes256_cbc_zero_pad(
            encoded.packed.as_slice(),
            &aes.key,
            &aes.iv,
        )?);
        encoded.coder_info = CoderInfo(encode_coder_info_aes_then(&encoded.coders, &aes.props));
        let mut sizes = vec![before_padding];
        sizes.extend(encoded.unpack_sizes.into_vec());
        encoded.unpack_sizes = UnpackSizes(sizes);
    }

    let pack_size = encoded.packed.len() as u64;
    Ok(PreparedFolder {
        metadata: CompletedFolder {
            file_indices,
            pack_sizes: vec![pack_size],
            coder_info: encoded.coder_info.into_vec(),
            coder_unpack_sizes: encoded.unpack_sizes.into_vec(),
            folder_crc: None,
            file_sizes,
            file_crcs,
        },
        packed_streams: vec![encoded.packed.into_vec()],
    })
}

fn encode_payload_with_options(
    data: &[u8],
    prepared: &PreparedArchiveOptions,
) -> Result<EncodedPayload, R7zError> {
    prepared.validate_encoder_working_set()?;
    let options = &prepared.archive;
    let compression = &options.compression;
    match prepared.settings.codec {
        PreparedCodec::Copy => Ok(EncodedPayload {
            packed: PackedBytes(data.to_vec()),
            coder_info: CoderInfo(encode_coder_info_copy()),
            unpack_sizes: UnpackSizes(vec![data.len() as u64]),
            coders: vec![CoderSpec::Copy],
        }),
        PreparedCodec::Lzma => {
            let (props, compressed) = compress_lzma(data, compression)?;
            Ok(EncodedPayload {
                packed: PackedBytes(compressed),
                coder_info: CoderInfo(encode_coder_info_lzma(&props)),
                unpack_sizes: UnpackSizes(vec![data.len() as u64]),
                coders: vec![CoderSpec::Lzma(props)],
            })
        }
        PreparedCodec::Lzma2(threads) => {
            let (prop, compressed) = compress_lzma2(data, compression, threads)?;
            Ok(EncodedPayload {
                packed: PackedBytes(compressed),
                coder_info: CoderInfo(encode_coder_info_lzma2(prop)),
                unpack_sizes: UnpackSizes(vec![data.len() as u64]),
                coders: vec![CoderSpec::Lzma2(prop)],
            })
        }
        PreparedCodec::Ppmd(ppmd) => {
            let (props, compressed) = compress_ppmd(data, ppmd)?;
            Ok(EncodedPayload {
                packed: PackedBytes(compressed),
                coder_info: CoderInfo(encode_coder_info_ppmd(&props)),
                unpack_sizes: UnpackSizes(vec![data.len() as u64]),
                coders: vec![CoderSpec::Ppmd(props)],
            })
        }
        PreparedCodec::Lzma2Bcj(threads) => {
            let mut filtered = data.to_vec();
            bcj::bcj_x86_encode(&mut filtered);
            let (prop, compressed) = compress_lzma2(&filtered, compression, threads)?;
            Ok(EncodedPayload {
                packed: PackedBytes(compressed),
                coder_info: CoderInfo(encode_coder_info_bcj_lzma2(prop)),
                unpack_sizes: UnpackSizes(vec![data.len() as u64, data.len() as u64]),
                coders: vec![CoderSpec::Lzma2(prop), CoderSpec::Bcj],
            })
        }
    }
}

fn encode_header_stream(
    raw_header: &[u8],
    prepared: &PreparedArchiveOptions,
    budget: &mut WriterOperation,
) -> Result<EncodedHeader, R7zError> {
    let (props, compressed) = codec::compress_lzma(raw_header)?;
    let coder_info = encode_coder_info_lzma(&props);
    let sizes = vec![raw_header.len() as u64];

    let Some(encryption) = prepared
        .encryption()
        .filter(PreparedEncryption::encrypt_header)
    else {
        return Ok(EncodedHeader {
            packed: PackedBytes(compressed),
            coder_info: CoderInfo(coder_info),
            unpack_sizes: UnpackSizes(sizes),
        });
    };

    let aes = make_aes_material(encryption, budget)?;
    let before_padding = compressed.len() as u64;
    let encrypted = aes::encrypt_aes256_cbc_zero_pad(&compressed, &aes.key, &aes.iv)?;
    let coder_info = encode_coder_info_aes_then(&[CoderSpec::Lzma(props)], &aes.props);
    Ok(EncodedHeader {
        packed: PackedBytes(encrypted),
        coder_info: CoderInfo(coder_info),
        unpack_sizes: UnpackSizes(vec![before_padding, raw_header.len() as u64]),
    })
}

pub(crate) fn lzma_options(compression: &CompressionOptions) -> LzmaOptions {
    let mut options = LzmaOptions::with_preset(compression_level_preset(compression.level));
    // Match the pinned p7zip defaults. lzma-rust2 only offers HC4 at fast
    // levels, where p7zip uses HC5, so HC4 remains the closest available finder.
    match compression.level {
        CompressionLevel::Fastest => {
            options.dict_size = 256 << 10;
            options.nice_len = 32;
            options.depth_limit = 16;
        }
        CompressionLevel::Fast => {
            options.dict_size = 4 << 20;
            options.nice_len = 32;
            options.depth_limit = 16;
        }
        CompressionLevel::Normal => {
            options.dict_size = 16 << 20;
            options.nice_len = 32;
            options.depth_limit = 32;
        }
        CompressionLevel::Maximum => {
            options.dict_size = 32 << 20;
            options.nice_len = 64;
            options.depth_limit = 48;
        }
        CompressionLevel::Ultra => {
            options.dict_size = 64 << 20;
            options.nice_len = 64;
            options.depth_limit = 48;
        }
        CompressionLevel::Store => {}
    }
    if let Some(dict_size) = compression.dictionary_size {
        options.dict_size = dict_size;
    }
    if let Some(fast_bytes) = compression.fast_bytes {
        options.nice_len = fast_bytes;
    }
    if let Some(lc) = compression.literal_context_bits {
        options.lc = lc;
    }
    if let Some(lp) = compression.literal_position_bits {
        options.lp = lp;
    }
    if let Some(pb) = compression.position_bits {
        options.pb = pb;
    }
    if let Some(match_finder) = compression.match_finder {
        options.mf = match match_finder {
            MatchFinder::Hc4 => MfType::Hc4,
            MatchFinder::Bt4 => MfType::Bt4,
        };
    }
    if let Some(algorithm) = compression.lzma_algorithm {
        options.mode = match algorithm {
            LzmaAlgorithm::Fast => EncodeMode::Fast,
            LzmaAlgorithm::Normal => EncodeMode::Normal,
        };
    }
    if let Some(match_cycles) = compression.match_cycles {
        options.depth_limit =
            i32::try_from(match_cycles).expect("validate_match_cycles rejects too-large values");
    }
    options
}

pub(crate) fn lzma2_options(compression: &CompressionOptions) -> Lzma2Options {
    let mut options = Lzma2Options {
        lzma_options: lzma_options(compression),
        chunk_size: None,
    };
    options.set_chunk_size(Some(effective_lzma2_chunk_size(compression)));
    options
}

fn effective_lzma2_chunk_size(compression: &CompressionOptions) -> NonZeroU64 {
    let dict = u64::from(lzma_options(compression).dict_size);
    let size = compression.lzma2_chunk_size.map_or_else(
        || DEFAULT_LZMA2_CHUNK_SIZE.max(dict).min(MAX_LZMA2_CHUNK_SIZE),
        NonZeroU64::get,
    );
    NonZeroU64::new(size).expect("LZMA2 chunk size constants are non-zero")
}

pub(crate) fn lzma2_property_byte(compression: &CompressionOptions) -> Result<u8, R7zError> {
    encode_lzma2_dict_size(lzma_options(compression).dict_size)
}

fn compression_level_preset(level: CompressionLevel) -> u32 {
    match level {
        CompressionLevel::Store => 0,
        CompressionLevel::Fastest => 1,
        CompressionLevel::Fast => 3,
        CompressionLevel::Normal => 5,
        CompressionLevel::Maximum => 7,
        CompressionLevel::Ultra => 9,
    }
}

fn compress_lzma(
    data: &[u8],
    compression: &CompressionOptions,
) -> Result<(Vec<u8>, Vec<u8>), R7zError> {
    let options = lzma_options(compression);
    let dict_size = options.dict_size;
    let mut writer = LzmaWriter::new_no_header(Vec::new(), &options, false)
        .map_err(|_| R7zError::Decompression)?;
    writer
        .write_all(data)
        .map_err(|_| R7zError::Decompression)?;
    let props_byte = writer.props();
    let compressed = writer.finish().map_err(|_| R7zError::Decompression)?;
    let mut props = Vec::with_capacity(5);
    props.push(props_byte);
    props.extend_from_slice(&dict_size.to_le_bytes());
    Ok((props, compressed))
}

fn compress_lzma2(
    data: &[u8],
    compression: &CompressionOptions,
    threads: ThreadRequest,
) -> Result<(u8, Vec<u8>), R7zError> {
    let options = lzma2_options(compression);
    let prop = encode_lzma2_dict_size(options.lzma_options.dict_size)?;
    let mut writer =
        lzma2::Encoder::new(Vec::new(), compression, Some(data.len() as u64), threads)?;
    writer.write_all(data)?;
    let compressed = writer.finish()?;
    Ok((prop, compressed))
}

fn compress_ppmd(data: &[u8], settings: PpmdSettings) -> Result<(Vec<u8>, Vec<u8>), R7zError> {
    let PpmdSettings { order, memory_size } = settings;
    let mut writer =
        Ppmd7Encoder::new(Vec::new(), u32::from(order), memory_size).map_err(|_| {
            R7zError::InvalidOptions("PPMd order or memory size is outside supported range")
        })?;
    writer
        .write_all(data)
        .map_err(|_| R7zError::Decompression)?;
    let compressed = writer.finish(false).map_err(|_| R7zError::Decompression)?;

    let mut props = Vec::with_capacity(5);
    props.push(order);
    props.extend_from_slice(&memory_size.to_le_bytes());
    Ok((props, compressed))
}

fn ppmd_order(compression: &CompressionOptions) -> Result<u8, R7zError> {
    let order = compression.fast_bytes.unwrap_or(6);
    if !(PPMD7_MIN_ORDER..=PPMD7_MAX_ORDER).contains(&order) {
        return Err(R7zError::InvalidOptions("PPMd order must be in 2..=64"));
    }
    u8::try_from(order).map_err(|_| R7zError::InvalidOptions("PPMd order is too large"))
}

fn ppmd_settings(compression: &CompressionOptions, order: u8) -> Result<PpmdSettings, R7zError> {
    let mem_size = compression
        .dictionary_size
        .unwrap_or_else(|| ppmd_memory_size_preset(compression.level));
    if !(PPMD7_MIN_MEM_SIZE..=PPMD7_MAX_MEM_SIZE).contains(&mem_size) {
        return Err(R7zError::InvalidOptions(
            "PPMd memory size is outside supported range",
        ));
    }

    Ok(PpmdSettings {
        order,
        memory_size: mem_size,
    })
}

const fn ppmd_memory_size_preset(level: CompressionLevel) -> u32 {
    match level {
        CompressionLevel::Store | CompressionLevel::Fastest => 1 << 20,
        CompressionLevel::Fast => 4 << 20,
        CompressionLevel::Normal => 16 << 20,
        CompressionLevel::Maximum => 32 << 20,
        CompressionLevel::Ultra => 64 << 20,
    }
}

fn encode_lzma2_dict_size(dict_size: u32) -> Result<u8, R7zError> {
    if dict_size < 4096 {
        return Err(R7zError::InvalidOptions(
            "dictionary_size must be at least 4096 bytes",
        ));
    }
    if dict_size == u32::MAX {
        return Ok(40);
    }
    for prop in 0u8..40 {
        let base = 2u32 | (u32::from(prop) & 1);
        let size = base
            .checked_shl((u32::from(prop) >> 1) + 11)
            .ok_or(R7zError::InvalidOptions("dictionary_size is too large"))?;
        if size >= dict_size {
            return Ok(prop);
        }
    }
    Err(R7zError::InvalidOptions("dictionary_size is too large"))
}

pub(super) struct AesMaterial {
    pub(super) key: zeroize::Zeroizing<[u8; 32]>,
    pub(super) iv: [u8; 16],
    pub(super) props: Vec<u8>,
}

pub(super) fn make_aes_material(
    encryption: PreparedEncryption<'_>,
    budget: &mut WriterOperation,
) -> Result<AesMaterial, R7zError> {
    let PreparedEncryption { options, settings } = encryption;
    let mut salt = vec![0u8; usize::from(settings.salt_len)];
    let mut iv_bytes = vec![0u8; usize::from(settings.iv_len)];
    if !salt.is_empty() {
        getrandom::fill(&mut salt).map_err(|_| R7zError::Parse)?;
    }
    if !iv_bytes.is_empty() {
        getrandom::fill(&mut iv_bytes).map_err(|_| R7zError::Parse)?;
    }
    let mut iv = [0u8; 16];
    let iv_copy_len = iv_bytes.len().min(16);
    iv[..iv_copy_len].copy_from_slice(&iv_bytes[..iv_copy_len]);
    let cycles = 1u64
        .checked_shl(u32::from(settings.cycles_power))
        .ok_or(R7zError::Decompression)?;
    budget.monitor.check()?;
    budget.kdf.charge(KdfCycles::new(cycles))?;
    let key = aes::derive_key_with_control(
        &options.password,
        &salt,
        settings.cycles_power,
        budget.monitor.control(),
    )?;
    let props = aes::encode_aes_properties(settings.cycles_power, &salt, &iv_bytes);
    Ok(AesMaterial {
        key: zeroize::Zeroizing::new(key),
        iv,
        props,
    })
}

fn write_signature(archive: &mut [u8], next_header_offset: u64, next_header: &[u8]) {
    archive[..32].copy_from_slice(&signature_bytes(next_header_offset, next_header));
}

fn signature_bytes(next_header_offset: u64, next_header: &[u8]) -> [u8; 32] {
    let next_header_size = next_header.len() as u64;
    let next_header_crc = crc32fast::hash(next_header);
    let mut start_header = [0u8; 20];
    start_header[..8].copy_from_slice(&next_header_offset.to_le_bytes());
    start_header[8..16].copy_from_slice(&next_header_size.to_le_bytes());
    start_header[16..].copy_from_slice(&next_header_crc.to_le_bytes());
    let start_header_crc = crc32fast::hash(&start_header);

    let mut signature = [0u8; 32];
    signature[..6].copy_from_slice(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
    signature[6] = 0x00;
    signature[7] = 0x04;
    signature[8..12].copy_from_slice(&start_header_crc.to_le_bytes());
    signature[12..20].copy_from_slice(&next_header_offset.to_le_bytes());
    signature[20..28].copy_from_slice(&next_header_size.to_le_bytes());
    signature[28..32].copy_from_slice(&next_header_crc.to_le_bytes());
    signature
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_lzma2_options_match_p7zip_level_five() {
        let options = lzma2_options(&CompressionOptions::default()).lzma_options;

        assert_eq!(options.dict_size, 16 << 20);
        assert_eq!(options.nice_len, 32);
        assert!(matches!(options.mf, MfType::Bt4));
        assert!(matches!(options.mode, EncodeMode::Normal));
    }

    #[test]
    fn lzma2_level_defaults_match_p7zip_levels_one_three_seven_and_nine() {
        let cases = [
            (
                CompressionLevel::Fastest,
                256 << 10,
                32,
                16,
                12,
                MfType::Hc4,
                EncodeMode::Fast,
            ),
            (
                CompressionLevel::Fast,
                4 << 20,
                32,
                16,
                20,
                MfType::Hc4,
                EncodeMode::Fast,
            ),
            (
                CompressionLevel::Maximum,
                32 << 20,
                64,
                48,
                26,
                MfType::Bt4,
                EncodeMode::Normal,
            ),
            (
                CompressionLevel::Ultra,
                64 << 20,
                64,
                48,
                28,
                MfType::Bt4,
                EncodeMode::Normal,
            ),
        ];

        for (level, dict_size, nice_len, depth_limit, property_byte, mf, mode) in cases {
            let compression = CompressionOptions {
                level,
                ..Default::default()
            };
            let options = lzma2_options(&compression).lzma_options;

            assert_eq!(options.dict_size, dict_size, "{level:?} dictionary");
            assert_eq!(options.nice_len, nice_len, "{level:?} fast bytes");
            assert_eq!(options.depth_limit, depth_limit, "{level:?} match cycles");
            assert_eq!(options.mf, mf, "{level:?} match finder");
            assert_eq!(options.mode, mode, "{level:?} algorithm");
            assert_eq!(
                lzma2_property_byte(&compression).unwrap(),
                property_byte,
                "{level:?} encoded dictionary property"
            );
        }
    }

    #[test]
    fn lzma2_level_defaults_preserve_explicit_overrides() {
        let compression = CompressionOptions {
            level: CompressionLevel::Fast,
            dictionary_size: Some(8 << 20),
            fast_bytes: Some(48),
            match_finder: Some(MatchFinder::Bt4),
            match_cycles: Some(8),
            ..Default::default()
        };
        let options = lzma2_options(&compression).lzma_options;

        assert_eq!(options.dict_size, 8 << 20);
        assert_eq!(options.nice_len, 48);
        assert_eq!(options.depth_limit, 8);
        assert!(matches!(options.mf, MfType::Bt4));
    }

    #[test]
    fn lzma2_options_uses_bounded_default_chunk_size() {
        let compression = CompressionOptions::default();
        let options = lzma2_options(&compression);

        assert_eq!(
            options.chunk_size.map(NonZeroU64::get),
            Some(DEFAULT_LZMA2_CHUNK_SIZE)
        );
    }

    #[test]
    fn validate_lzma2_rejects_oversized_chunk_size() {
        let options = ArchiveOptions {
            codec: Codec::Lzma2,
            compression: CompressionOptions {
                lzma2_chunk_size: NonZeroU64::new(MAX_LZMA2_CHUNK_SIZE + 1),
                ..Default::default()
            },
            ..Default::default()
        };

        let err = validate_archive_options(&options).unwrap_err();
        assert!(err.to_string().contains("lzma2_chunk_size"));
    }

    #[test]
    fn validate_lzma2_rejects_fixed_worker_count_above_the_limit() {
        let options = ArchiveOptions {
            codec: Codec::Lzma2,
            compression: CompressionOptions {
                threads: EncoderThreads::Fixed(257),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(matches!(
            validate_archive_options(&options),
            Err(R7zError::InvalidOptions(
                "encoder thread count must be <= 256"
            ))
        ));
    }
}
