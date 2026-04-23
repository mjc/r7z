use super::header::{
    CoderSpec, build_encoded_header_descriptor, build_header, encode_coder_info_aes_then,
    encode_coder_info_bcj_lzma2, encode_coder_info_copy, encode_coder_info_lzma,
    encode_coder_info_lzma2, encode_coder_info_ppmd,
};
use super::model::{
    ArchiveOptions, Codec, CompletedFolder, CompressionLevel, CompressionOptions,
    EncryptionOptions, HeaderMode, PreparedFolder, SolidMode, WriteEntry,
};
use crate::{R7zError, aes, bcj, codec};
use lzma_rust2::{Lzma2Options, Lzma2Writer, LzmaOptions, LzmaWriter};
use ppmd_rust::{
    PPMD7_MAX_MEM_SIZE, PPMD7_MAX_ORDER, PPMD7_MIN_MEM_SIZE, PPMD7_MIN_ORDER, Ppmd7Encoder,
};
use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};

type PayloadEncoding = (Vec<u8>, Vec<u8>, Vec<u64>, Vec<CoderSpec>);
type HeaderEncoding = (Vec<u8>, Vec<u8>, Vec<u64>);

pub(crate) fn build_archive(
    entries: &[WriteEntry],
    options: &ArchiveOptions,
) -> Result<Vec<u8>, R7zError> {
    validate_archive_options(options)?;

    let mut folders = Vec::new();
    let mut by_folder: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (idx, entry) in entries.iter().enumerate() {
        if entry.has_stream {
            by_folder.entry(entry.folder_id).or_default().push(idx);
        }
    }

    for file_indices in by_folder.into_values() {
        let folder = encode_folder(entries, file_indices, options)?;
        folders.push(folder);
    }

    build_archive_from_prepared(entries, &folders, options)
}

pub(crate) fn build_archive_from_prepared(
    entries: &[WriteEntry],
    folders: &[PreparedFolder],
    options: &ArchiveOptions,
) -> Result<Vec<u8>, R7zError> {
    validate_archive_options(options)?;

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
        let (pack, coder_info, coder_unpack_sizes) =
            encode_header_stream(&raw_header, options.encryption.as_ref())?;
        let pack_pos = packed_data.len() as u64;
        packed_data.extend_from_slice(&pack);
        let descriptor = build_encoded_header_descriptor(
            pack_pos,
            pack.len() as u64,
            &coder_info,
            &coder_unpack_sizes,
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

pub(crate) fn validate_archive_options(options: &ArchiveOptions) -> Result<(), R7zError> {
    validate_compression_options(options)?;
    let Some(enc) = &options.encryption else {
        return Ok(());
    };
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
    Ok(())
}

fn validate_compression_options(options: &ArchiveOptions) -> Result<(), R7zError> {
    if options.streaming.buffer_size == 0 {
        return Err(R7zError::InvalidOptions(
            "streaming buffer_size must be greater than zero",
        ));
    }
    if options.codec == Codec::Copy
        && (options.compression.dictionary_size.is_some()
            || options.compression.fast_bytes.is_some()
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
    if let Some(fast_bytes) = options.compression.fast_bytes {
        if options.codec == Codec::Ppmd {
            if !(PPMD7_MIN_ORDER..=PPMD7_MAX_ORDER).contains(&fast_bytes) {
                return Err(R7zError::InvalidOptions("PPMd order must be in 2..=64"));
            }
        } else if !(8..=273).contains(&fast_bytes) {
            return Err(R7zError::InvalidOptions("fast_bytes must be in 8..=273"));
        }
    }
    if options.codec == Codec::Ppmd && options.compression.lzma2_chunk_size.is_some() {
        return Err(R7zError::InvalidOptions(
            "PPMd does not support lzma2_chunk_size",
        ));
    }
    if let Some(chunk_size) = options.compression.lzma2_chunk_size {
        let dict = lzma_options(&options.compression).dict_size;
        if chunk_size.get() < u64::from(dict) {
            return Err(R7zError::InvalidOptions(
                "lzma2_chunk_size must be at least dictionary_size",
            ));
        }
    }
    if let SolidMode::Limit {
        max_files: None,
        max_bytes: None,
    } = &options.compression.solid
    {
        return Err(R7zError::InvalidOptions(
            "solid limit requires max_files or max_bytes",
        ));
    }
    Ok(())
}

pub(crate) fn finish_streamed_archive<W: Write + Seek>(
    mut out: W,
    entries: &[WriteEntry],
    folders: &[CompletedFolder],
    options: &ArchiveOptions,
) -> Result<W, R7zError> {
    if entries.is_empty() {
        return Err(R7zError::Parse);
    }
    validate_archive_options(options)?;

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
        HeaderMode::P7zipDefault => entries.len() > 1,
    };

    let (next_header, next_header_offset) = if should_encode {
        let (pack, coder_info, coder_unpack_sizes) = encode_header_stream(&raw_header, None)?;
        out.seek(SeekFrom::Start(32 + packed_size))?;
        out.write_all(&pack)?;
        let descriptor = build_encoded_header_descriptor(
            packed_size,
            pack.len() as u64,
            &coder_info,
            &coder_unpack_sizes,
        );
        (descriptor, packed_size + pack.len() as u64)
    } else {
        (raw_header, packed_size)
    };

    out.seek(SeekFrom::Start(32 + next_header_offset))?;
    out.write_all(&next_header)?;
    let signature = signature_bytes(next_header_offset, &next_header);
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&signature)?;
    out.flush()?;
    Ok(out)
}

fn encode_folder(
    entries: &[WriteEntry],
    file_indices: Vec<usize>,
    options: &ArchiveOptions,
) -> Result<PreparedFolder, R7zError> {
    let mut data = Vec::new();
    let mut file_sizes = Vec::new();
    let mut file_crcs = Vec::new();
    for &idx in &file_indices {
        let bytes = entries[idx].data.as_ref().ok_or(R7zError::Parse)?;
        file_sizes.push(bytes.len() as u64);
        file_crcs.push(Some(crc32fast::hash(bytes)));
        data.extend_from_slice(bytes);
    }

    let (mut pack, mut coder_info, mut coder_unpack_sizes, specs) =
        encode_payload_with_options(&data, options.codec, &options.compression)?;

    if let Some(enc) = &options.encryption {
        let aes = make_aes_material(enc)?;
        let before_padding = pack.len() as u64;
        pack = aes::encrypt_aes256_cbc_zero_pad(&pack, &aes.key, &aes.iv)?;
        coder_info = encode_coder_info_aes_then(&specs, &aes.props);
        let mut sizes = vec![before_padding];
        sizes.append(&mut coder_unpack_sizes);
        coder_unpack_sizes = sizes;
    }

    let pack_size = pack.len() as u64;
    Ok(PreparedFolder {
        metadata: CompletedFolder {
            file_indices,
            pack_sizes: vec![pack_size],
            coder_info,
            coder_unpack_sizes,
            folder_crc: None,
            file_sizes,
            file_crcs,
        },
        packed_streams: vec![pack],
    })
}

fn encode_payload_with_options(
    data: &[u8],
    method: Codec,
    compression: &CompressionOptions,
) -> Result<PayloadEncoding, R7zError> {
    match method {
        Codec::Copy => Ok((
            data.to_vec(),
            encode_coder_info_copy(),
            vec![data.len() as u64],
            vec![CoderSpec::Copy],
        )),
        Codec::Lzma => {
            let (props, compressed) = compress_lzma(data, compression)?;
            Ok((
                compressed,
                encode_coder_info_lzma(&props),
                vec![data.len() as u64],
                vec![CoderSpec::Lzma(props)],
            ))
        }
        Codec::Lzma2 => {
            let (prop, compressed) = compress_lzma2(data, compression)?;
            Ok((
                compressed,
                encode_coder_info_lzma2(prop),
                vec![data.len() as u64],
                vec![CoderSpec::Lzma2(prop)],
            ))
        }
        Codec::Ppmd => {
            let (props, compressed) = compress_ppmd(data, compression)?;
            Ok((
                compressed,
                encode_coder_info_ppmd(&props),
                vec![data.len() as u64],
                vec![CoderSpec::Ppmd(props)],
            ))
        }
        Codec::Lzma2Bcj => {
            let mut filtered = data.to_vec();
            bcj::bcj_x86_encode(&mut filtered);
            let (prop, compressed) = compress_lzma2(&filtered, compression)?;
            Ok((
                compressed,
                encode_coder_info_bcj_lzma2(prop),
                vec![data.len() as u64, data.len() as u64],
                vec![CoderSpec::Lzma2(prop), CoderSpec::Bcj],
            ))
        }
    }
}

fn encode_header_stream(
    raw_header: &[u8],
    encryption: Option<&EncryptionOptions>,
) -> Result<HeaderEncoding, R7zError> {
    let (props, compressed) = codec::compress_lzma(raw_header)?;
    let coder_info = encode_coder_info_lzma(&props);
    let sizes = vec![raw_header.len() as u64];

    let Some(enc) = encryption.filter(|enc| enc.encrypt_header) else {
        return Ok((compressed, coder_info, sizes));
    };

    let aes = make_aes_material(enc)?;
    let before_padding = compressed.len() as u64;
    let encrypted = aes::encrypt_aes256_cbc_zero_pad(&compressed, &aes.key, &aes.iv)?;
    let coder_info = encode_coder_info_aes_then(&[CoderSpec::Lzma(props)], &aes.props);
    Ok((
        encrypted,
        coder_info,
        vec![before_padding, raw_header.len() as u64],
    ))
}

pub(crate) fn lzma_options(compression: &CompressionOptions) -> LzmaOptions {
    let mut options = LzmaOptions::with_preset(compression_level_preset(compression.level));
    if let Some(dict_size) = compression.dictionary_size {
        options.dict_size = dict_size;
    }
    if let Some(fast_bytes) = compression.fast_bytes {
        options.nice_len = fast_bytes;
    }
    options
}

pub(crate) fn lzma2_options(compression: &CompressionOptions) -> Lzma2Options {
    let mut options = Lzma2Options {
        lzma_options: lzma_options(compression),
        chunk_size: None,
    };
    options.set_chunk_size(compression.lzma2_chunk_size);
    options
}

pub(crate) fn lzma2_property_byte(compression: &CompressionOptions) -> Result<u8, R7zError> {
    encode_lzma2_dict_size(lzma_options(compression).dict_size)
}

fn compression_level_preset(level: CompressionLevel) -> u32 {
    match level {
        CompressionLevel::Store => 0,
        CompressionLevel::Fastest => 1,
        CompressionLevel::Fast => 3,
        CompressionLevel::Normal => 6,
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
) -> Result<(u8, Vec<u8>), R7zError> {
    let options = lzma2_options(compression);
    let prop = encode_lzma2_dict_size(options.lzma_options.dict_size)?;
    let mut writer = Lzma2Writer::new(Vec::new(), options);
    writer
        .write_all(data)
        .map_err(|_| R7zError::Decompression)?;
    let compressed = writer.finish().map_err(|_| R7zError::Decompression)?;
    Ok((prop, compressed))
}

fn compress_ppmd(
    data: &[u8],
    compression: &CompressionOptions,
) -> Result<(Vec<u8>, Vec<u8>), R7zError> {
    let (order, mem_size) = ppmd_options(compression)?;
    let mut writer = Ppmd7Encoder::new(Vec::new(), u32::from(order), mem_size).map_err(|_| {
        R7zError::InvalidOptions("PPMd order or memory size is outside supported range")
    })?;
    writer
        .write_all(data)
        .map_err(|_| R7zError::Decompression)?;
    let compressed = writer.finish(false).map_err(|_| R7zError::Decompression)?;

    let mut props = Vec::with_capacity(5);
    props.push(order);
    props.extend_from_slice(&mem_size.to_le_bytes());
    Ok((props, compressed))
}

fn ppmd_options(compression: &CompressionOptions) -> Result<(u8, u32), R7zError> {
    let order = compression.fast_bytes.unwrap_or(6);
    if !(PPMD7_MIN_ORDER..=PPMD7_MAX_ORDER).contains(&order) {
        return Err(R7zError::InvalidOptions("PPMd order must be in 2..=64"));
    }

    let mem_size = compression
        .dictionary_size
        .unwrap_or_else(|| ppmd_memory_size_preset(compression.level));
    if !(PPMD7_MIN_MEM_SIZE..=PPMD7_MAX_MEM_SIZE).contains(&mem_size) {
        return Err(R7zError::InvalidOptions(
            "PPMd memory size is outside supported range",
        ));
    }

    Ok((
        u8::try_from(order).map_err(|_| R7zError::InvalidOptions("PPMd order is too large"))?,
        mem_size,
    ))
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

struct AesMaterial {
    key: [u8; 32],
    iv: [u8; 16],
    props: Vec<u8>,
}

fn make_aes_material(options: &EncryptionOptions) -> Result<AesMaterial, R7zError> {
    if options.num_cycles_power > aes::MAX_AES_NUM_CYCLES_POWER {
        return Err(R7zError::InvalidOptions(
            "AES num_cycles_power must be <= 24",
        ));
    }
    if options.salt_len > 16 {
        return Err(R7zError::InvalidOptions("AES salt_len must be <= 16"));
    }
    if options.iv_len > 16 {
        return Err(R7zError::InvalidOptions("AES iv_len must be <= 16"));
    }

    let mut salt = vec![0u8; usize::from(options.salt_len)];
    let mut iv_bytes = vec![0u8; usize::from(options.iv_len)];
    if !salt.is_empty() {
        getrandom::fill(&mut salt).map_err(|_| R7zError::Parse)?;
    }
    if !iv_bytes.is_empty() {
        getrandom::fill(&mut iv_bytes).map_err(|_| R7zError::Parse)?;
    }
    let mut iv = [0u8; 16];
    let iv_copy_len = iv_bytes.len().min(16);
    iv[..iv_copy_len].copy_from_slice(&iv_bytes[..iv_copy_len]);
    let key = aes::derive_key(&options.password, &salt, options.num_cycles_power)?;
    let props = aes::encode_aes_properties(options.num_cycles_power, &salt, &iv_bytes);
    Ok(AesMaterial { key, iv, props })
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
