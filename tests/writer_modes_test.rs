use std::{io::Cursor, num::NonZeroU64};

use r7z::{
    Archive, ArchiveBuilder, ArchiveOptions, ArchiveWriter, Codec, EncoderThreads,
    EncryptionOptions, EntryMeta, HeaderMode, SolidMode,
};

const CODECS: [Codec; 5] = [
    Codec::Copy,
    Codec::Lzma,
    Codec::Lzma2,
    Codec::Lzma2Bcj,
    Codec::Ppmd,
];
const FIRST: &[u8] = b"first file: abcabcabcabcabcabc\xe8\x12\0\0\0";
const SECOND: &[u8] = b"second file: abcabcabcabcabcabc\xe9\x12\0\0\0";

fn options(codec: Codec, encrypted: bool) -> ArchiveOptions {
    let mut options = ArchiveOptions {
        codec,
        header_mode: HeaderMode::Plain,
        ..ArchiveOptions::default()
    };
    options.compression.threads = EncoderThreads::Single;
    if codec != Codec::Copy {
        options.compression.dictionary_size = Some(4096);
    }
    if encrypted {
        let mut encryption = EncryptionOptions::default_for_password("secret");
        // Deterministic test fixture; production encryption uses random salt and IV.
        encryption.num_cycles_power = 0;
        encryption.salt_len = 0;
        encryption.iv_len = 0;
        options.encryption = Some(encryption);
    }
    options
}

fn write_files(options: ArchiveOptions, explicit_boundaries: bool) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new()), options).unwrap();
    writer.new_folder().unwrap();
    writer
        .append_directory("dir", EntryMeta::default())
        .unwrap();
    writer.append("empty", &[][..]).unwrap();
    writer.append("first", FIRST).unwrap();
    if explicit_boundaries {
        writer.new_folder().unwrap();
        writer.new_folder().unwrap();
    }
    writer
        .append_empty_file("empty2", EntryMeta::default())
        .unwrap();
    writer.append("second", SECOND).unwrap();
    writer.new_folder().unwrap();
    writer
        .append_anti_item("deleted", EntryMeta::default())
        .unwrap();
    writer.finish().unwrap().into_inner()
}

#[test]
fn archive_bytes_preserve_each_writer_mode() {
    // CRCs captured from the writer before its mode/state refactor.
    let expected = [
        [579_042_107, 3_491_593_456],
        [1_215_624_127, 1_358_248_528],
        [512_371_686, 2_158_045_044],
        [1_989_869_444, 2_958_504_880],
        [117_985_710, 281_716_578],
    ];
    for (codec, expected) in CODECS.into_iter().zip(expected) {
        for (encrypted, expected) in [false, true].into_iter().zip(expected) {
            let bytes = write_files(options(codec, encrypted), true);
            assert_eq!(
                crc32fast::hash(&bytes),
                expected,
                "{codec:?}, encrypted={encrypted}"
            );
            let archive = Archive::from_bytes_with_password(bytes.into(), Some("secret")).unwrap();
            for (index, expected) in [(1, &[][..]), (2, FIRST), (3, &[][..]), (4, SECOND)] {
                assert_eq!(
                    archive
                        .extract_to_memory_with_password(index, Some("secret"))
                        .unwrap(),
                    expected
                );
            }
        }
    }
}

#[test]
fn streaming_writer_encrypts_encoded_headers() {
    let mut options = options(Codec::Lzma2, true);
    options.header_mode = HeaderMode::Encoded;
    options.encryption.as_mut().unwrap().encrypt_header = true;
    let bytes = write_files(options, false);
    let archive = Archive::from_bytes_with_password(bytes.into(), Some("secret")).unwrap();

    for (index, expected) in [(1, &[][..]), (2, FIRST), (3, &[][..]), (4, SECOND)] {
        assert_eq!(
            archive
                .extract_to_memory_with_password(index, Some("secret"))
                .unwrap(),
            expected
        );
    }
}

#[test]
fn copy_builder_and_streaming_writer_emit_the_same_archive() {
    let options = options(Codec::Copy, false);
    let streaming = write_files(options.clone(), false);
    let built = ArchiveBuilder::new()
        .options(options)
        .add_directory("dir", EntryMeta::default())
        .add_empty_file("empty", EntryMeta::default())
        .add_file("first", FIRST)
        .add_empty_file("empty2", EntryMeta::default())
        .add_file("second", SECOND)
        .add_anti_item("deleted", EntryMeta::default())
        .build()
        .unwrap();

    assert_eq!(built, streaming);
}

#[test]
fn copy_builder_preserves_preplanned_byte_limit_folders() {
    let mut options = options(Codec::Copy, false);
    options.compression.solid = SolidMode::Limit {
        max_files: None,
        max_bytes: NonZeroU64::new(10),
    };
    let bytes = ArchiveBuilder::new()
        .options(options)
        .add_file("first", b"123456")
        .add_file("second", b"abcdef")
        .build()
        .unwrap();
    let archive = Archive::from_bytes(bytes.into()).unwrap();
    let unpack = archive
        .raw_streams_info()
        .unwrap()
        .unpack_info
        .as_ref()
        .unwrap();

    assert_eq!(unpack.num_folders, 2);
}

#[test]
fn builder_lzma2_admission_uses_the_planned_folder_size() {
    for codec in [Codec::Lzma2, Codec::Lzma2Bcj] {
        let mut options = options(codec, false);
        options.compression.threads = EncoderThreads::Fixed(4);
        options.compression.encoder_memory_limit = Some(256 * 1024 * 1024);
        let bytes = ArchiveBuilder::new()
            .options(options)
            .add_file("small", b"small folder")
            .build()
            .unwrap();
        let archive = Archive::from_bytes(bytes.into()).unwrap();
        assert_eq!(archive.extract_to_memory(0).unwrap(), b"small folder");
    }
}

#[test]
fn builders_preserve_empty_symlink_streams_before_non_solid_files() {
    for codec in [Codec::Copy, Codec::Lzma, Codec::Lzma2, Codec::Lzma2Bcj] {
        let mut options = options(codec, false);
        options.compression.solid = SolidMode::NonSolid;
        let bytes = ArchiveBuilder::new()
            .options(options)
            .add_symlink("empty-link", "", EntryMeta::default())
            .add_file("after", b"data")
            .build()
            .unwrap();
        let archive = Archive::from_bytes(bytes.into()).unwrap();
        let files = archive.raw_files_info().unwrap();

        assert_eq!(files.entry_type(0), r7z::EntryType::Symlink, "{codec:?}");
        assert_eq!(
            archive.symlink_target(0).unwrap().as_deref(),
            Some(""),
            "{codec:?}"
        );
        assert_eq!(archive.extract_to_memory(1).unwrap(), b"data", "{codec:?}");
        assert_eq!(
            archive
                .raw_streams_info()
                .unwrap()
                .unpack_info
                .as_ref()
                .unwrap()
                .num_folders,
            2,
            "{codec:?}"
        );
    }
}

#[test]
fn automatic_folder_boundaries_match_explicit_boundaries() {
    for codec in CODECS {
        for encrypted in [false, true] {
            let expected = write_files(options(codec, encrypted), true);
            for solid in [
                SolidMode::NonSolid,
                SolidMode::Limit {
                    max_files: NonZeroU64::new(1),
                    max_bytes: None,
                },
                SolidMode::Limit {
                    max_files: None,
                    max_bytes: NonZeroU64::new(FIRST.len() as u64),
                },
            ] {
                let mut options = options(codec, encrypted);
                options.compression.solid = solid;
                assert_eq!(
                    write_files(options, false),
                    expected,
                    "{codec:?}, encrypted={encrypted}"
                );
            }
        }
    }
}

#[test]
fn codec_selection_before_data_preserves_metadata_and_selects_the_new_mode() {
    for initial in CODECS {
        for selected in CODECS {
            for encrypted in [false, true] {
                let mut initial_options = options(initial, encrypted);
                initial_options.compression.dictionary_size = None;
                initial_options.compression.level = r7z::CompressionLevel::Fastest;
                let mut selected_options = initial_options.clone();
                selected_options.codec = selected;
                let mut writer =
                    ArchiveWriter::new(Cursor::new(Vec::new()), initial_options).unwrap();
                writer
                    .append_directory("dir", EntryMeta::default())
                    .unwrap();
                writer.append("empty", &[][..]).unwrap();
                writer.new_folder().unwrap();
                writer.set_compression(selected).unwrap();
                writer.append("file", FIRST).unwrap();
                let actual = writer.finish().unwrap().into_inner();

                let mut direct =
                    ArchiveWriter::new(Cursor::new(Vec::new()), selected_options).unwrap();
                direct
                    .append_directory("dir", EntryMeta::default())
                    .unwrap();
                direct.append("empty", &[][..]).unwrap();
                direct.append("file", FIRST).unwrap();
                assert_eq!(
                    actual,
                    direct.finish().unwrap().into_inner(),
                    "{initial:?} -> {selected:?}, encrypted={encrypted}"
                );
            }
        }
    }
}

#[test]
fn codec_selection_revalidates_codec_specific_options() {
    let tuned_lzma = options(Codec::Lzma, false);
    let mut ppmd_order = options(Codec::Ppmd, false);
    ppmd_order.compression.fast_bytes = Some(4);
    let mut lzma_fast_bytes = options(Codec::Lzma, false);
    lzma_fast_bytes.compression.fast_bytes = Some(100);
    let mut threaded = options(Codec::Lzma2, false);
    threaded.compression.threads = EncoderThreads::Fixed(2);
    for (options, codec, expected) in [
        (
            tuned_lzma,
            Codec::Copy,
            "Copy codec does not support compression tuning",
        ),
        (ppmd_order, Codec::Lzma, "fast_bytes must be in 8..=273"),
        (lzma_fast_bytes, Codec::Ppmd, "PPMd order must be in 2..=64"),
        (
            threaded,
            Codec::Lzma,
            "multiple encoder threads require LZMA2",
        ),
    ] {
        let mut writer = ArchiveWriter::new(Cursor::new(Vec::new()), options.clone()).unwrap();
        assert!(
            matches!(writer.set_compression(codec), Err(r7z::R7zError::InvalidOptions(message)) if message == expected)
        );
        writer.append("file", FIRST).unwrap();

        let mut unchanged = ArchiveWriter::new(Cursor::new(Vec::new()), options).unwrap();
        unchanged.append("file", FIRST).unwrap();
        assert_eq!(
            writer.finish().unwrap().into_inner(),
            unchanged.finish().unwrap().into_inner()
        );
    }
}

#[test]
fn codec_selection_is_locked_after_data_including_closed_folders() {
    for codec in CODECS {
        for encrypted in [false, true] {
            for close_folder in [false, true] {
                let mut writer =
                    ArchiveWriter::new(Cursor::new(Vec::new()), options(codec, encrypted)).unwrap();
                writer.append("file", FIRST).unwrap();
                if close_folder {
                    writer.new_folder().unwrap();
                }
                assert!(matches!(
                    writer.set_compression(Codec::Lzma2),
                    Err(r7z::R7zError::InvalidOptions(
                        "cannot change compression after appending nonempty file data"
                    ))
                ));
                writer.append("second", SECOND).unwrap();
                let bytes = writer.finish().unwrap().into_inner();
                let archive =
                    Archive::from_bytes_with_password(bytes.into(), Some("secret")).unwrap();
                for (index, expected) in [FIRST, SECOND].into_iter().enumerate() {
                    assert_eq!(
                        archive
                            .extract_to_memory_with_password(index, Some("secret"))
                            .unwrap(),
                        expected
                    );
                }
            }
        }
    }
}

#[test]
fn empty_and_metadata_only_archives_match_the_builder() {
    for codec in CODECS {
        for encrypted in [false, true] {
            for header_mode in [
                HeaderMode::Plain,
                HeaderMode::Encoded,
                HeaderMode::P7zipDefault,
            ] {
                for metadata in [false, true] {
                    let mut options = options(codec, encrypted);
                    options.header_mode = header_mode;
                    let mut writer =
                        ArchiveWriter::new(Cursor::new(Vec::new()), options.clone()).unwrap();
                    let mut builder = r7z::ArchiveBuilder::new().options(options);
                    if metadata {
                        writer.append("empty", &[][..]).unwrap();
                        writer
                            .append_directory("dir", EntryMeta::default())
                            .unwrap();
                        writer
                            .append_anti_item("deleted", EntryMeta::default())
                            .unwrap();
                        builder = builder
                            .add_empty_file("empty", EntryMeta::default())
                            .add_directory("dir", EntryMeta::default())
                            .add_anti_item("deleted", EntryMeta::default());
                    }
                    writer.new_folder().unwrap();
                    writer.new_folder().unwrap();
                    assert_eq!(
                        writer.finish().unwrap().into_inner(),
                        builder.build().unwrap()
                    );
                }
            }
        }
    }
}

#[test]
fn tiny_input_buffers_preserve_solid_streams_and_checksums() {
    for codec in CODECS {
        let expected = write_files(options(codec, false), false);
        for buffer_size in [1, 3, 17] {
            let mut options = options(codec, false);
            options.streaming.buffer_size = buffer_size;
            assert_eq!(
                write_files(options, false),
                expected,
                "{codec:?}, buffer_size={buffer_size}"
            );
        }
    }
}

struct FailingReader;

impl std::io::Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("input failed"))
    }
}

#[test]
fn input_failure_before_data_prevents_reusing_the_writer() {
    for codec in CODECS {
        let mut writer =
            ArchiveWriter::new(Cursor::new(Vec::new()), options(codec, false)).unwrap();
        let error = writer.append("file", FailingReader).unwrap_err();
        assert!(matches!(error, r7z::R7zError::Io(error) if error.to_string() == "input failed"));
        assert!(writer.append("another", SECOND).is_err());
        assert!(writer.finish().is_err());
    }
}

#[test]
fn partial_input_failure_prevents_finishing_or_reusing_the_writer() {
    use std::io::Read;

    for codec in CODECS {
        let mut writer =
            ArchiveWriter::new(Cursor::new(Vec::new()), options(codec, false)).unwrap();
        let error = writer
            .append("file", FIRST.chain(FailingReader))
            .unwrap_err();
        assert!(matches!(error, r7z::R7zError::Io(error) if error.to_string() == "input failed"));
        assert!(matches!(
            writer.set_compression(Codec::Copy),
            Err(r7z::R7zError::InvalidOptions(
                "archive writer cannot be reused after an I/O or encoder failure"
            ))
        ));
        assert!(writer.append("another", SECOND).is_err());
        assert!(writer.append("empty", &[][..]).is_err());
        assert!(
            writer
                .append_directory("dir", EntryMeta::default())
                .is_err()
        );
        assert!(writer.new_folder().is_err());
        assert!(writer.finish().is_err());
    }
}

#[test]
fn encoder_memory_limit_failure_prevents_reusing_the_writer() {
    let mut limited = options(Codec::Lzma2, false);
    limited.compression.encoder_memory_limit = Some(1);
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new()), limited).unwrap();

    assert!(matches!(
        writer.append("file", FIRST),
        Err(r7z::R7zError::LimitExceeded("encoder memory"))
    ));
    assert!(writer.append("another", SECOND).is_err());
    assert!(writer.finish().is_err());

    let mut next =
        ArchiveWriter::new(Cursor::new(Vec::new()), options(Codec::Lzma2, false)).unwrap();
    next.append("file", FIRST).unwrap();
    next.finish().unwrap();
}

struct ControlledOutput {
    bytes: Cursor<Vec<u8>>,
    fail: std::rc::Rc<std::cell::Cell<bool>>,
    max_write: usize,
}

impl std::io::Write for ControlledOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.fail.get() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "output failed",
            ));
        }
        self.bytes.write(&bytes[..bytes.len().min(self.max_write)])
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Seek for ControlledOutput {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        self.bytes.seek(position)
    }
}

struct FailAfterBytes {
    bytes: Cursor<Vec<u8>>,
    remaining: usize,
}

impl std::io::Write for FailAfterBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "output failed",
            ));
        }
        let written = bytes.len().min(self.remaining);
        let written = self.bytes.write(&bytes[..written])?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Seek for FailAfterBytes {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        self.bytes.seek(position)
    }
}

#[test]
fn short_output_writes_preserve_file_checksums() {
    for codec in CODECS {
        let out = ControlledOutput {
            bytes: Cursor::new(Vec::new()),
            fail: Default::default(),
            max_write: 3,
        };
        let mut writer = ArchiveWriter::new(out, options(codec, false)).unwrap();
        writer.append("file", FIRST).unwrap();
        let bytes = writer.finish().unwrap().bytes.into_inner();
        let archive = Archive::from_bytes(bytes.into()).unwrap();
        assert_eq!(archive.extract_to_memory(0).unwrap(), FIRST);
    }
}

#[test]
fn folder_finalization_failure_prevents_reusing_the_writer() {
    for codec in [Codec::Lzma, Codec::Lzma2, Codec::Lzma2Bcj, Codec::Ppmd] {
        let fail = std::rc::Rc::new(std::cell::Cell::new(false));
        let out = ControlledOutput {
            bytes: Cursor::new(Vec::new()),
            fail: fail.clone(),
            max_write: usize::MAX,
        };
        let mut writer = ArchiveWriter::new(out, options(codec, false)).unwrap();
        writer.append("file", FIRST).unwrap();
        fail.set(true);
        assert!(
            matches!(writer.new_folder(), Err(r7z::R7zError::Io(error))
            if error.kind() == std::io::ErrorKind::BrokenPipe && error.to_string() == "output failed"),
            "{codec:?}"
        );
        fail.set(false);
        assert!(writer.append("another", SECOND).is_err());
        assert!(writer.finish().is_err());
    }
}

#[test]
fn encrypted_payload_write_failure_prevents_finishing_or_reusing_the_writer() {
    let out = FailAfterBytes {
        bytes: Cursor::new(Vec::new()),
        remaining: 8192,
    };
    let mut writer = ArchiveWriter::new(out, options(Codec::Copy, true)).unwrap();
    let input = vec![0xA5; 64 * 1024];
    assert!(matches!(
        writer.append("file", input.as_slice()),
        Err(r7z::R7zError::Io(error)) if error.kind() == std::io::ErrorKind::BrokenPipe
    ));
    assert!(writer.append("another", SECOND).is_err());
    assert!(writer.finish().is_err());
}

#[test]
fn parallel_lzma2_write_failure_drops_the_folder_and_allows_a_new_writer() {
    let mut options = options(Codec::Lzma2, false);
    options.compression.threads = EncoderThreads::Fixed(2);
    options.compression.lzma2_chunk_size = NonZeroU64::new(4096);

    let out = FailAfterBytes {
        bytes: Cursor::new(Vec::new()),
        remaining: 96,
    };
    let mut writer = ArchiveWriter::new(out, options.clone()).unwrap();
    let input = vec![0xA5; 64 * 1024];

    assert!(matches!(
        writer.append("file", input.as_slice()),
        Err(r7z::R7zError::Io(error)) if error.kind() == std::io::ErrorKind::BrokenPipe
    ));
    assert!(writer.append("another", SECOND).is_err());
    assert!(writer.finish().is_err());

    let mut next = ArchiveWriter::new(Cursor::new(Vec::new()), options).unwrap();
    next.append("file", input.as_slice()).unwrap();
    let archive = Archive::from_bytes(next.finish().unwrap().into_inner().into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), input);
}

#[test]
fn archive_finalization_preserves_output_errors() {
    for codec in [Codec::Lzma, Codec::Lzma2, Codec::Lzma2Bcj, Codec::Ppmd] {
        let fail = std::rc::Rc::new(std::cell::Cell::new(false));
        let out = ControlledOutput {
            bytes: Cursor::new(Vec::new()),
            fail: fail.clone(),
            max_write: usize::MAX,
        };
        let mut writer = ArchiveWriter::new(out, options(codec, false)).unwrap();
        writer.append("file", FIRST).unwrap();
        fail.set(true);
        assert!(
            matches!(writer.finish(), Err(r7z::R7zError::Io(error))
            if error.kind() == std::io::ErrorKind::BrokenPipe && error.to_string() == "output failed"),
            "{codec:?}"
        );
    }
}
