use lzma_rust2::{Lzma2Options, Lzma2Reader, Lzma2Writer};
use std::io::{Read, Write};

fn input(size: usize, repetitive: bool) -> Vec<u8> {
    let mut state = 0x1234_5678_u32;
    (0..size)
        .map(|position| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            if repetitive {
                u8::try_from(position % 251).unwrap()
            } else {
                state.to_le_bytes()[0]
            }
        })
        .collect()
}

fn encode(data: &[u8], parallel: bool, fragment: usize, flush: bool) -> Vec<u8> {
    let mut options = Lzma2Options::with_preset(5);
    options.lzma_options.dict_size = 64 * 1024;
    options.set_chunk_size(std::num::NonZeroU64::new(256 * 1024));
    let mut writer = if parallel {
        Lzma2Writer::new_parallel_match_finder(Vec::new(), options).unwrap()
    } else {
        Lzma2Writer::new(Vec::new(), options)
    };
    for chunk in data.chunks(fragment) {
        writer.write_all(chunk).unwrap();
        if flush {
            writer.flush().unwrap();
        }
    }
    writer.finish().unwrap()
}

#[test]
fn pipelined_match_finding_preserves_output_across_window_moves_and_resets() {
    for repetitive in [false, true] {
        let data = input(1024 * 1024 + 31, repetitive);
        for fragment in [4097, 64 * 1024] {
            let expected = encode(&data, false, fragment, false);
            let actual = encode(&data, true, fragment, false);
            assert!(
                actual == expected,
                "repetitive={repetitive}, fragment={fragment}, sizes={}/{}, first mismatch={:?}",
                actual.len(),
                expected.len(),
                actual.iter().zip(&expected).position(|(a, b)| a != b)
            );
            let mut decoded = Vec::new();
            Lzma2Reader::new(actual.as_slice(), 64 * 1024, None)
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, data);
        }
    }
}

#[test]
fn pipelined_match_finding_preserves_fragmented_flushes() {
    let data = input(8193, true);
    for fragment in [1, 13, 4097] {
        assert_eq!(
            encode(&data, true, fragment, true),
            encode(&data, false, fragment, true)
        );
    }
}

#[test]
fn tiny_unflushed_writes_do_not_fill_the_result_queue() {
    let data = input(16 * 1024 + 31, false);
    for fragment in [1, 13, 100] {
        assert_eq!(
            encode(&data, true, fragment, false),
            encode(&data, false, fragment, false)
        );
    }
}

#[test]
fn a_large_single_write_preserves_compressed_output() {
    let data = input(2 * 1024 * 1024, false);
    assert_eq!(
        encode(&data, true, data.len(), false),
        encode(&data, false, data.len(), false)
    );
}

#[test]
fn pipelined_match_finding_rejects_preset_dictionaries_before_starting_a_worker() {
    let mut options = Lzma2Options::with_preset(5);
    options.lzma_options.preset_dict = Some(b"preset dictionary".to_vec());
    let result = Lzma2Writer::new_parallel_match_finder(Vec::new(), options);
    assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::InvalidInput));
}

struct FailingSink {
    fail_flush: bool,
    writes: usize,
}

impl Write for FailingSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.writes += 1;
        if self.fail_flush {
            Ok(bytes.len())
        } else {
            Err(std::io::Error::other("injected write failure"))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("injected flush failure"))
    }
}

#[test]
fn output_errors_stop_the_pipeline_and_make_the_writer_terminal() {
    for fail_flush in [false, true] {
        let sink = FailingSink {
            fail_flush,
            writes: 0,
        };
        let mut options = Lzma2Options::with_preset(5);
        options.lzma_options.dict_size = 64 * 1024;
        let mut writer = Lzma2Writer::new_parallel_match_finder(sink, options).unwrap();
        let data = input(512 * 1024, false);
        let error = writer
            .write_all(&data)
            .and_then(|()| writer.flush())
            .unwrap_err();
        assert!(error.to_string().starts_with("injected"));
        let attempts = writer.inner().writes;
        assert_eq!(
            writer.write_all(b"retry").unwrap_err().to_string(),
            "encoder has failed"
        );
        assert_eq!(
            writer.flush().unwrap_err().to_string(),
            "encoder has failed"
        );
        assert_eq!(writer.inner().writes, attempts);
        assert!(writer.finish().is_err());
    }
}
