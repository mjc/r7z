mod support;

use arrayvec::ArrayVec;
use smallvec::{SmallVec, smallvec};

use std::io::{Read, Write};
use support::create_p7zip_archive;

fn branch_folder(method: &[u8], properties: Option<&[u8]>) -> r7z::raw::Folder {
    r7z::raw::Folder {
        coders: smallvec![r7z::raw::CoderInfo {
            codec_id: coder_id(method),
            num_in_streams: 1,
            num_out_streams: 1,
            properties: properties.map(SmallVec::from_slice),
        }],
        bind_pairs: SmallVec::new(),
        packed_indices: SmallVec::new(),
    }
}

fn branch_payload(arm64: bool) -> Vec<u8> {
    let instruction_bytes: &[u8] = if arm64 {
        &[
            0x01, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x14, 0x1f, 0x20,
            0x03, 0xd5,
        ]
    } else {
        &[
            0xef, 0x00, 0x00, 0x00, 0x97, 0x02, 0x00, 0x00, 0xe7, 0x80, 0x02, 0x00, 0x6f, 0x00,
            0x00, 0x00, 0x01, 0x00,
        ]
    };
    instruction_bytes.repeat(if arm64 { 768 } else { 560 })
}

#[test]
fn branch_method_ids_and_names_are_registered() {
    for (id, name, method) in [
        (r7z::CODEC_BCJ_ARM64, "ARM64", r7z::SevenZMethod::Arm64),
        (r7z::CODEC_BCJ_RISCV, "RISC-V", r7z::SevenZMethod::Riscv),
    ] {
        assert_eq!(r7z::method_from_id(id), Some(method));
        assert_eq!(r7z::method_from_name(name), Some(method));
        assert_eq!(method.kind(), r7z::MethodKind::Filter);
        assert!(method.supported_by_r7z());
    }
}

#[test]
fn official_7zip_2603_branch_archives_extract() {
    for (name, method, arm64, offset) in [
        ("arm64.7z", r7z::CODEC_BCJ_ARM64, true, 0_u32),
        ("arm64_offset4.7z", r7z::CODEC_BCJ_ARM64, true, 4),
        ("riscv.7z", r7z::CODEC_BCJ_RISCV, false, 0),
        ("riscv_offset2.7z", r7z::CODEC_BCJ_RISCV, false, 2),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/corpus/7z/generated")
            .join(name);
        let archive = r7z::Archive::open(&path).unwrap();
        let folder = archive
            .raw_streams_info()
            .unwrap()
            .unpack_info
            .as_ref()
            .unwrap()
            .parse_folder(0)
            .unwrap();
        let coder = folder
            .coders
            .iter()
            .find(|coder| coder.codec_id.as_slice() == method)
            .unwrap();
        let expected_properties = if offset == 0 {
            None
        } else {
            Some(offset.to_le_bytes().to_vec())
        };
        assert_eq!(
            coder.properties.as_deref(),
            expected_properties.as_deref(),
            "{name}"
        );
        assert_eq!(
            archive
                .extract_to_memory(r7z::ArchiveEntryIndex::new(0))
                .unwrap(),
            branch_payload(arm64),
            "{name}"
        );
    }
}

#[test]
fn branch_filter_properties_validate_length_and_alignment() {
    for (method, alignment) in [(r7z::CODEC_BCJ_ARM64, 4u32), (r7z::CODEC_BCJ_RISCV, 2)] {
        for bad in [
            &[0][..],
            &[0, 0][..],
            &[0, 0, 0][..],
            &[0; 5][..],
            &[1, 0, 0, 0][..],
        ] {
            let folder = branch_folder(method, Some(bad));
            assert!(
                matches!(
                    r7z::raw::decompress_folder(&folder, &[], 0),
                    Err(r7z::R7zError::Decompression)
                ),
                "{method:?} {bad:?}"
            );
        }
        if alignment == 4 {
            let folder = branch_folder(method, Some(&[2, 0, 0, 0]));
            assert!(matches!(
                r7z::raw::decompress_folder(&folder, &[], 0),
                Err(r7z::R7zError::Decompression)
            ));
        }
        for valid in [None, Some(&[][..]), Some(&[0, 0, 0, 0][..])] {
            let folder = branch_folder(method, valid);
            assert_eq!(r7z::raw::decompress_folder(&folder, &[], 0).unwrap(), []);
        }
    }
}

struct OneByteReader(std::io::Cursor<Vec<u8>>);

impl Read for OneByteReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = buf.len().min(1);
        self.0.read(&mut buf[..len])
    }
}

#[test]
fn branch_filters_handle_instruction_boundaries_across_reads_and_short_inputs() {
    use lzma_rust2::filter::bcj::{BcjReader, BcjWriter};

    for arm64 in [true, false] {
        let payload = branch_payload(arm64);
        let mut writer = if arm64 {
            BcjWriter::new_arm64(Vec::new(), 4)
        } else {
            BcjWriter::new_riscv(Vec::new(), 2)
        };
        writer.write_all(&payload).unwrap();
        let encoded = writer.finish().unwrap();
        let input = OneByteReader(std::io::Cursor::new(encoded));
        let mut reader = if arm64 {
            BcjReader::new_arm64(input, 4)
        } else {
            BcjReader::new_riscv(input, 2)
        };
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, payload);

        for len in 0..8 {
            let short = &payload[..len];
            let input = OneByteReader(std::io::Cursor::new(short.to_vec()));
            let mut reader = if arm64 {
                BcjReader::new_arm64(input, 0)
            } else {
                BcjReader::new_riscv(input, 0)
            };
            let mut output = Vec::new();
            reader.read_to_end(&mut output).unwrap();
            assert_eq!(output, short);
        }
    }
}

#[test]
fn r7z_decodes_all_branch_filters_through_lzma_rust2() {
    use lzma_rust2::filter::bcj::BcjWriter;

    for method in [
        r7z::CODEC_BCJ_X86,
        r7z::CODEC_BCJ_ARM,
        r7z::CODEC_BCJ_ARM_THUMB,
        r7z::CODEC_BCJ_IA64,
        r7z::CODEC_BCJ_PPC,
        r7z::CODEC_BCJ_SPARC,
        r7z::CODEC_BCJ_ARM64,
        r7z::CODEC_BCJ_RISCV,
    ] {
        let payload = branch_filter_payload(method);
        let encoded = match method {
            r7z::CODEC_BCJ_X86 => {
                let mut writer = BcjWriter::new_x86(Vec::new(), 0);
                writer.write_all(&payload).unwrap();
                writer.finish().unwrap()
            }
            r7z::CODEC_BCJ_ARM => {
                let mut writer = BcjWriter::new_arm(Vec::new(), 0);
                writer.write_all(&payload).unwrap();
                writer.finish().unwrap()
            }
            r7z::CODEC_BCJ_ARM_THUMB => {
                let mut writer = BcjWriter::new_arm_thumb(Vec::new(), 0);
                writer.write_all(&payload).unwrap();
                writer.finish().unwrap()
            }
            r7z::CODEC_BCJ_IA64 => {
                let mut writer = BcjWriter::new_ia64(Vec::new(), 0);
                writer.write_all(&payload).unwrap();
                writer.finish().unwrap()
            }
            r7z::CODEC_BCJ_PPC => {
                let mut writer = BcjWriter::new_ppc(Vec::new(), 0);
                writer.write_all(&payload).unwrap();
                writer.finish().unwrap()
            }
            r7z::CODEC_BCJ_SPARC => {
                let mut writer = BcjWriter::new_sparc(Vec::new(), 0);
                writer.write_all(&payload).unwrap();
                writer.finish().unwrap()
            }
            r7z::CODEC_BCJ_ARM64 => {
                let mut writer = BcjWriter::new_arm64(Vec::new(), 0);
                writer.write_all(&payload).unwrap();
                writer.finish().unwrap()
            }
            r7z::CODEC_BCJ_RISCV => {
                let mut writer = BcjWriter::new_riscv(Vec::new(), 0);
                writer.write_all(&payload).unwrap();
                writer.finish().unwrap()
            }
            _ => unreachable!(),
        };
        let folder = branch_folder(method, None);
        assert_eq!(
            r7z::raw::decompress_folder(&folder, &encoded, payload.len() as u64).unwrap(),
            payload,
            "{method:?}"
        );
    }
}

#[test]
fn delta_method_uses_7z_distance_properties() {
    let folder = branch_folder(r7z::CODEC_DELTA, Some(&[1]));
    let encoded = [10, 20, 1, 2, 1];
    assert_eq!(
        r7z::raw::decompress_folder(&folder, &encoded, 5).unwrap(),
        [10, 20, 11, 22, 12],
    );
}

fn branch_filter_payload(method: &[u8]) -> Vec<u8> {
    if method == r7z::CODEC_BCJ_ARM64 {
        return branch_payload(true);
    }
    if method == r7z::CODEC_BCJ_RISCV {
        return branch_payload(false);
    }

    let mut data = vec![0; 256];
    for pos in (0..data.len()).step_by(16) {
        match method {
            r7z::CODEC_BCJ_X86 => {
                data[pos] = 0xE8;
                data[pos + 4] = 0;
            }
            r7z::CODEC_BCJ_ARM => {
                data[pos + 3] = 0xEB;
            }
            r7z::CODEC_BCJ_ARM_THUMB => {
                data[pos..pos + 4].copy_from_slice(&[0x00, 0xF0, 0x00, 0xF8]);
            }
            r7z::CODEC_BCJ_IA64 => {
                data[pos] = 0x16;
                data[pos + 5] = 0x14;
            }
            r7z::CODEC_BCJ_PPC => data[pos..pos + 4].copy_from_slice(&[0x48, 0, 0, 1]),
            r7z::CODEC_BCJ_SPARC => data[pos..pos + 4].copy_from_slice(&[0x40, 0, 0, 0]),
            _ => unreachable!(),
        }
    }
    data
}

fn coder_id(id: &[u8]) -> ArrayVec<u8, 15> {
    let mut out = ArrayVec::new();
    out.try_extend_from_slice(id).unwrap();
    out
}

fn single_lzma2_folder(properties: &[u8]) -> r7z::raw::Folder {
    r7z::raw::Folder {
        coders: smallvec![r7z::raw::CoderInfo {
            codec_id: coder_id(r7z::CODEC_LZMA2),
            num_in_streams: 1,
            num_out_streams: 1,
            properties: Some(SmallVec::from_slice(properties)),
        }],
        bind_pairs: SmallVec::new(),
        packed_indices: SmallVec::new(),
    }
}

#[test]
fn lzma_property_block_from_archive_builder_is_exactly_five_bytes() {
    let bytes = r7z::ArchiveBuilder::new()
        .compression(r7z::Codec::Lzma)
        .add_file("payload.txt", b"payload")
        .build()
        .expect("build failed");
    let archive = r7z::Archive::from_bytes(bytes.into()).expect("from_bytes failed");
    let ui = archive
        .raw_streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap();
    let folder = ui.parse_folder(0).unwrap();

    assert_eq!(folder.coders[0].codec_id.as_slice(), r7z::CODEC_LZMA);
    assert_eq!(folder.coders[0].properties.as_ref().unwrap().len(), 5);
}

#[test]
fn p7zip_lzma2_property_values_extract_with_r7z() {
    for (dict_arg, len) in [
        ("-md=64K", 128 * 1024),
        ("-md=1M", 2 * 1024 * 1024),
        ("-md=16M", 3 * 1024 * 1024),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let payload: Vec<u8> = (0u8..=251).cycle().take(len).collect();
        std::fs::write(dir.join("payload.bin"), &payload).unwrap();

        let archive_path = dir.join(format!("lzma2_dict_{len}.7z"));
        create_p7zip_archive(
            dir,
            &archive_path,
            &["payload.bin"],
            &["-m0=lzma2", dict_arg],
        );

        let archive = r7z::Archive::open(&archive_path).unwrap();
        let ui = archive
            .raw_streams_info()
            .unwrap()
            .unpack_info
            .as_ref()
            .unwrap();
        let folder = ui.parse_folder(0).unwrap();
        let lzma2 = folder
            .coders
            .iter()
            .find(|coder| coder.codec_id.as_slice() == r7z::CODEC_LZMA2)
            .expect("expected LZMA2 coder");
        let properties = lzma2.properties.as_ref().unwrap();
        assert_eq!(properties.len(), 1);
        assert!(
            properties[0] <= 40,
            "p7zip emitted unsupported LZMA2 property {} for {dict_arg}",
            properties[0]
        );
        assert_eq!(
            archive
                .extract_to_memory(r7z::ArchiveEntryIndex::new(0))
                .unwrap(),
            payload
        );
    }
}

#[test]
fn lzma2_property_values_within_the_default_cap_decode_empty_stream() {
    for prop in 0u8..=24 {
        let folder = single_lzma2_folder(&[prop]);
        let result = std::panic::catch_unwind(|| r7z::raw::decompress_folder(&folder, &[0x00], 0));
        assert!(result.is_ok(), "LZMA2 property {prop} panicked");
        assert_eq!(result.unwrap().unwrap(), Vec::<u8>::new());
    }

    for prop in [33, 40] {
        let folder = single_lzma2_folder(&[prop]);
        let result = r7z::raw::decompress_folder(&folder, &[0x00], 0);
        assert!(matches!(
            result,
            Err(r7z::R7zError::ResourceLimitExceeded {
                resource: "LZMA dictionary",
                ..
            })
        ));
    }
}

#[test]
fn unsupported_lzma2_property_shapes_return_r7z_errors() {
    for properties in [&[][..], &[0x1c, 0x00][..], &[41][..]] {
        let folder = single_lzma2_folder(properties);
        let result = std::panic::catch_unwind(|| r7z::raw::decompress_folder(&folder, &[0x00], 0));
        assert!(
            result.is_ok(),
            "LZMA2 properties {properties:?} panicked instead of returning an error"
        );
        let err = result.unwrap().unwrap_err();
        assert!(
            matches!(err, r7z::R7zError::Decompression | r7z::R7zError::Parse),
            "expected Decompression or Parse for {properties:?}, got {err:?}"
        );
    }
}
