use std::io::{self, Cursor, Seek, SeekFrom, Write};

use r7z::{
    Archive, ArchiveBuilder, ArchiveEntryIndex, ArchiveOptions, ArchiveWriter, Codec,
    EncoderThreads, EncryptionOptions, EntryMeta, HeaderMode, R7zError,
};

const DICTIONARY: u32 = 1024 * 1024;
const OUTPUT_BUFFER_BYTES: u64 = 64 * 1024;
const CODECS: [Codec; 2] = [Codec::Lzma, Codec::Ppmd];

#[derive(Default)]
struct CountedOutput {
    inner: Cursor<Vec<u8>>,
    writes: usize,
    reject_payload: bool,
}

impl Write for CountedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.reject_payload && self.inner.position() >= 32 {
            return Err(io::Error::other("payload write failed"));
        }
        self.writes += 1;
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for CountedOutput {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

fn options(codec: Codec, encrypted: bool) -> ArchiveOptions {
    let mut options = ArchiveOptions {
        codec,
        header_mode: HeaderMode::Plain,
        ..Default::default()
    };
    options.compression.dictionary_size = Some(DICTIONARY);
    options.compression.threads = EncoderThreads::Single;
    if encrypted {
        let mut encryption = EncryptionOptions::default_for_password("secret");
        encryption.num_cycles_power = 0;
        options.encryption = Some(encryption);
    }
    options
}

fn random_input() -> Vec<u8> {
    let mut state = 0x1234_5678_9abc_def0_u64;
    (0..256 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

#[test]
fn range_encoders_batch_payload_output() {
    let data = random_input();
    for codec in CODECS {
        let mut writer = ArchiveWriter::new(CountedOutput::default(), options(codec, false))
            .unwrap()
            .start();
        writer.append("payload", data.as_slice()).unwrap();
        let output = writer.finish().unwrap();
        assert!(output.writes < 128, "{codec:?}: {} writes", output.writes);
        let archive = Archive::from_bytes(output.inner.into_inner().into()).unwrap();
        assert_eq!(
            archive
                .extract_to_memory(ArchiveEntryIndex::new(0))
                .unwrap(),
            data
        );
    }
}

#[test]
fn buffered_payloads_finish_before_encryption_and_folder_headers() {
    let data = random_input();
    for codec in CODECS {
        for encrypted in [false, true] {
            let mut writer = ArchiveWriter::new(Cursor::new(Vec::new()), options(codec, encrypted))
                .unwrap()
                .start();
            writer.append("large", data.as_slice()).unwrap();
            writer.new_folder().unwrap();
            writer
                .append("tail", b"a final partial buffer".as_slice())
                .unwrap();
            let bytes = writer.finish().unwrap().into_inner();
            let archive = Archive::from_bytes_with_password(bytes.into(), Some("secret")).unwrap();
            for (index, expected) in [
                (0, data.as_slice()),
                (1, b"a final partial buffer".as_slice()),
            ] {
                assert_eq!(
                    archive
                        .extract_to_memory_with_password(
                            ArchiveEntryIndex::new(index),
                            Some("secret")
                        )
                        .unwrap(),
                    expected,
                    "{codec:?}, encrypted={encrypted}"
                );
            }
        }
    }
}

#[test]
fn final_buffer_write_errors_are_returned() {
    for codec in CODECS {
        let output = CountedOutput {
            reject_payload: true,
            ..Default::default()
        };
        let mut writer = ArchiveWriter::new(output, options(codec, false))
            .unwrap()
            .start();
        writer
            .append("payload", b"small final buffer".as_slice())
            .unwrap();
        assert!(
            matches!(writer.finish(), Err(R7zError::Io(error)) if error.to_string() == "payload write failed")
        );
    }
}

#[test]
fn encoder_memory_admission_includes_output_buffer() {
    for codec in CODECS {
        let codec_memory = match codec {
            Codec::Lzma => {
                let mut options = lzma_rust2::LzmaOptions::with_preset(5);
                options.dict_size = DICTIONARY;
                u64::from(options.get_memory_usage()) * 1024
            }
            Codec::Ppmd => u64::from(DICTIONARY),
            _ => unreachable!(),
        };
        let required = codec_memory + OUTPUT_BUFFER_BYTES;
        for (limit, admitted) in [(required - 1, false), (required, true)] {
            let mut options = options(codec, false);
            options
                .streaming
                .resource_limits
                .max_encoder_working_set_bytes = Some(limit);
            let result = ArchiveBuilder::new()
                .options(options.clone())
                .add_file("payload", b"budget")
                .build();
            assert_eq!(result.is_ok(), admitted, "{codec:?}, limit={limit}");
            if !admitted {
                assert!(matches!(
                    result,
                    Err(R7zError::LimitExceeded("encoder memory"))
                ));
            }
            let mut writer = ArchiveWriter::new(Cursor::new(Vec::new()), options)
                .unwrap()
                .start();
            let result = writer.append_file("payload", b"budget".as_slice(), EntryMeta::default());
            assert_eq!(
                result.is_ok(),
                admitted,
                "streaming {codec:?}, limit={limit}"
            );
            if admitted {
                writer.finish().unwrap();
            } else {
                assert!(matches!(
                    result,
                    Err(R7zError::LimitExceeded("encoder memory"))
                ));
            }
        }
    }
}

#[test]
fn encrypted_output_errors_during_buffer_flush_are_returned() {
    let data = random_input();
    for codec in CODECS {
        for size in [16 * 1024, data.len()] {
            let output = CountedOutput {
                reject_payload: true,
                ..Default::default()
            };
            let mut writer = ArchiveWriter::new(output, options(codec, true))
                .unwrap()
                .start();
            let result = writer
                .append("payload", &data[..size])
                .and_then(|()| writer.finish().map(drop));
            assert!(
                matches!(result, Err(R7zError::Io(error)) if error.to_string() == "payload write failed"),
                "{codec:?}, input size={size}"
            );
        }
    }
}
