use super::header::{
    build_encoded_header_descriptor, build_header, encode_coder_info_aes_then,
    encode_coder_info_bcj_lzma2, encode_coder_info_copy, encode_coder_info_lzma,
    encode_coder_info_lzma2, CoderSpec,
};
use super::model::{
    ArchiveOptions, Codec, CompletedFolder, EncryptionOptions, HeaderMode, WriteEntry,
};
use crate::{aes, bcj, codec, R7zError};
use std::collections::BTreeMap;

type PayloadEncoding = (Vec<u8>, Vec<u8>, Vec<u64>, Vec<CoderSpec>);
type HeaderEncoding = (Vec<u8>, Vec<u8>, Vec<u64>);

pub(crate) fn build_archive(
    entries: &[WriteEntry],
    options: &ArchiveOptions,
) -> Result<Vec<u8>, R7zError> {
    if entries.is_empty() {
        return Err(R7zError::Parse);
    }

    let mut packed_data = Vec::new();
    let mut folders = Vec::new();
    let mut by_folder: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (idx, entry) in entries.iter().enumerate() {
        if entry.data.is_some() {
            by_folder.entry(entry.folder_id).or_default().push(idx);
        }
    }

    for file_indices in by_folder.into_values() {
        let (folder, pack) = encode_folder(entries, file_indices, options)?;
        packed_data.extend_from_slice(&pack);
        folders.push(folder);
    }

    let raw_header = build_header(entries, &folders);
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

fn encode_folder(
    entries: &[WriteEntry],
    file_indices: Vec<usize>,
    options: &ArchiveOptions,
) -> Result<(CompletedFolder, Vec<u8>), R7zError> {
    let mut data = Vec::new();
    let mut file_sizes = Vec::new();
    let mut file_crcs = Vec::new();
    for &idx in &file_indices {
        let bytes = entries[idx].data.as_ref().ok_or(R7zError::Parse)?;
        file_sizes.push(bytes.len() as u64);
        file_crcs.push(crc32fast::hash(bytes));
        data.extend_from_slice(bytes);
    }

    let (mut pack, mut coder_info, mut coder_unpack_sizes, specs) =
        encode_payload(&data, options.codec)?;

    if let Some(enc) = &options.encryption {
        let aes = make_aes_material(enc)?;
        let before_padding = pack.len() as u64;
        pack = aes::encrypt_aes256_cbc_zero_pad(&pack, &aes.key, &aes.iv)?;
        coder_info = encode_coder_info_aes_then(&specs, &aes.props);
        let mut sizes = vec![before_padding];
        sizes.append(&mut coder_unpack_sizes);
        coder_unpack_sizes = sizes;
    }

    Ok((
        CompletedFolder {
            file_indices,
            pack_size: pack.len() as u64,
            coder_info,
            coder_unpack_sizes,
            file_sizes,
            file_crcs,
        },
        pack,
    ))
}

fn encode_payload(data: &[u8], method: Codec) -> Result<PayloadEncoding, R7zError> {
    match method {
        Codec::Copy => Ok((
            data.to_vec(),
            encode_coder_info_copy(),
            vec![data.len() as u64],
            vec![CoderSpec::Copy],
        )),
        Codec::Lzma => {
            let (props, compressed) = codec::compress_lzma(data)?;
            Ok((
                compressed,
                encode_coder_info_lzma(&props),
                vec![data.len() as u64],
                vec![CoderSpec::Lzma(props)],
            ))
        }
        Codec::Lzma2 => {
            let (prop, compressed) = codec::compress_lzma2(data)?;
            Ok((
                compressed,
                encode_coder_info_lzma2(prop),
                vec![data.len() as u64],
                vec![CoderSpec::Lzma2(prop)],
            ))
        }
        Codec::Lzma2Bcj => {
            let mut filtered = data.to_vec();
            bcj::bcj_x86_encode(&mut filtered);
            let (prop, compressed) = codec::compress_lzma2(&filtered)?;
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

struct AesMaterial {
    key: [u8; 32],
    iv: [u8; 16],
    props: Vec<u8>,
}

fn make_aes_material(options: &EncryptionOptions) -> Result<AesMaterial, R7zError> {
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
    let next_header_size = next_header.len() as u64;
    let next_header_crc = crc32fast::hash(next_header);
    let mut start_header = [0u8; 20];
    start_header[..8].copy_from_slice(&next_header_offset.to_le_bytes());
    start_header[8..16].copy_from_slice(&next_header_size.to_le_bytes());
    start_header[16..].copy_from_slice(&next_header_crc.to_le_bytes());
    let start_header_crc = crc32fast::hash(&start_header);

    archive[..6].copy_from_slice(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
    archive[6] = 0x00;
    archive[7] = 0x04;
    archive[8..12].copy_from_slice(&start_header_crc.to_le_bytes());
    archive[12..20].copy_from_slice(&next_header_offset.to_le_bytes());
    archive[20..28].copy_from_slice(&next_header_size.to_le_bytes());
    archive[28..32].copy_from_slice(&next_header_crc.to_le_bytes());
}
