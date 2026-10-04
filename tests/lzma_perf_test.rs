use sha2::{Digest, Sha256};
/// Head-to-head comparison: `lzma_rust2` (pure Rust) vs C liblzma (via xz2).
///
/// Uses LZMA-alone format for both so the underlying algorithm is identical
/// and framing differences are negligible.
///
/// Run with:  cargo test --release `lzma_perf` -- --nocapture --ignored
use std::io::{Cursor, Read, Write};
use std::num::NonZeroU64;
use std::time::Instant;

const ITERS: u32 = 5;

/// 1 MB payload — repeating counter cycle, same as the benchmark fixtures.
fn payload() -> Vec<u8> {
    (0..1_048_576u32).map(|i| i.to_le_bytes()[0]).collect()
}

/// Pseudo-random 1 MB — poor compressibility (xorshift32).
fn pseudo_random_payload(size: usize) -> Vec<u8> {
    let mut state: u32 = 0xDEAD_BEEF;
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state & 0xFF) as u8
        })
        .collect()
}

/// Text-like data — repeating English-ish words. Moderate compressibility.
fn text_like_payload(size: usize) -> Vec<u8> {
    let words = "the quick brown fox jumps over the lazy dog and then runs back again to fetch a bone from the yard where the old tree stands quietly in the breeze ";
    words
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(size)
        .collect()
}

// ── lzma_rust2 (pure Rust) ─────────────────────────────────────────────────

fn rust_compress(data: &[u8]) -> Vec<u8> {
    let opts = lzma_rust2::LzmaOptions::with_preset(6);
    let dict_size = opts.dict_size;
    let mut w = lzma_rust2::LzmaWriter::new_no_header(Vec::new(), &opts, false).unwrap();
    w.write_all(data).unwrap();
    let props_byte = w.props();
    let compressed = w.finish().unwrap();

    // Package as LZMA-alone: 5 bytes props + 8 bytes uncompressed size LE + stream
    let mut out = Vec::with_capacity(13 + compressed.len());
    out.push(props_byte);
    out.extend_from_slice(&dict_size.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&compressed);
    out
}

fn rust_decompress(alone: &[u8]) -> Vec<u8> {
    let props_byte = alone[0];
    let dict_size = u32::from_le_bytes([alone[1], alone[2], alone[3], alone[4]]);
    let unpack_size = u64::from_le_bytes(alone[5..13].try_into().unwrap());
    let stream = &alone[13..];

    let mut r = lzma_rust2::LzmaReader::new_with_props(
        Cursor::new(stream),
        unpack_size,
        props_byte,
        dict_size,
        None,
    )
    .unwrap();
    let mut out = Vec::with_capacity(usize::try_from(unpack_size).unwrap());
    r.read_to_end(&mut out).unwrap();
    out
}

// ── C liblzma (via xz2) ───────────────────────────────────────────────────

fn c_compress(data: &[u8]) -> Vec<u8> {
    // LZMA-alone encoder with preset 6
    let opts = xz2::stream::LzmaOptions::new_preset(6).unwrap();
    let stream = xz2::stream::Stream::new_lzma_encoder(&opts).unwrap();
    let mut encoder = xz2::read::XzEncoder::new_stream(Cursor::new(data), stream);
    let mut out = Vec::new();
    encoder.read_to_end(&mut out).unwrap();
    out
}

fn c_decompress(alone: &[u8]) -> Vec<u8> {
    let stream = xz2::stream::Stream::new_lzma_decoder(u64::MAX).unwrap();
    let mut decoder = xz2::read::XzDecoder::new_stream(Cursor::new(alone), stream);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).unwrap();
    out
}

// ── Benchmark driver ───────────────────────────────────────────────────────

fn bench<F: Fn() -> R, R>(label: &str, iters: u32, f: F) -> std::time::Duration {
    // Warm-up
    let _ = f();

    let start = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(f());
    }
    let elapsed = start.elapsed();
    let per_iter = elapsed / iters;
    println!("  {label}: {per_iter:?} / iter  ({iters} iters, total {elapsed:?})");
    per_iter
}

#[test]
#[ignore = "manual Rust and liblzma performance comparison"]
fn lzma_rust_vs_c_performance() {
    let data = payload();
    println!(
        "\n=== LZMA Rust-vs-C comparison ({} bytes payload) ===\n",
        data.len()
    );

    // ── Compress ───────────────────────────────────────────────────────────
    println!("Compression (preset 6):");
    let rust_comp_time = bench("lzma_rust2", ITERS, || rust_compress(&data));
    let c_comp_time = bench("C liblzma ", ITERS, || c_compress(&data));
    let comp_ratio = rust_comp_time.as_secs_f64() / c_comp_time.as_secs_f64();
    println!("  → Rust/C ratio: {comp_ratio:.2}x\n");

    // Pre-compress for decompression benchmarks
    let rust_compressed = rust_compress(&data);
    let c_compressed = c_compress(&data);
    println!(
        "Compressed sizes: rust={} bytes, C={} bytes\n",
        rust_compressed.len(),
        c_compressed.len()
    );

    // ── Decompress ─────────────────────────────────────────────────────────
    println!("Decompression:");
    let rust_dec_time = bench("lzma_rust2", ITERS, || rust_decompress(&rust_compressed));
    let c_dec_time = bench("C liblzma ", ITERS, || c_decompress(&c_compressed));
    let dec_ratio = rust_dec_time.as_secs_f64() / c_dec_time.as_secs_f64();
    println!("  → Rust/C ratio: {dec_ratio:.2}x\n");

    // Verify correctness
    assert_eq!(rust_decompress(&rust_compressed), data);
    assert_eq!(c_decompress(&c_compressed), data);
    println!("✓ Both produce identical output");

    // ── Less-compressible data (pseudo-random) ─────────────────────────────
    println!("\n=== LZMA Rust-vs-C comparison (1 MB pseudo-random payload) ===\n");
    let random_data = pseudo_random_payload(1_048_576);

    println!("Compression (preset 6):");
    let rust_comp_time2 = bench("lzma_rust2", ITERS, || rust_compress(&random_data));
    let c_comp_time2 = bench("C liblzma ", ITERS, || c_compress(&random_data));
    let comp_ratio2 = rust_comp_time2.as_secs_f64() / c_comp_time2.as_secs_f64();
    println!("  → Rust/C ratio: {comp_ratio2:.2}x\n");

    let rust_rand_compressed = rust_compress(&random_data);
    let c_rand_compressed = c_compress(&random_data);
    println!(
        "Compressed sizes: rust={} bytes, C={} bytes\n",
        rust_rand_compressed.len(),
        c_rand_compressed.len()
    );

    println!("Decompression:");
    let rust_dec_time2 = bench("lzma_rust2", ITERS, || {
        rust_decompress(&rust_rand_compressed)
    });
    let c_dec_time2 = bench("C liblzma ", ITERS, || c_decompress(&c_rand_compressed));
    let dec_ratio2 = rust_dec_time2.as_secs_f64() / c_dec_time2.as_secs_f64();
    println!("  → Rust/C ratio: {dec_ratio2:.2}x\n");

    assert_eq!(rust_decompress(&rust_rand_compressed), random_data);
    assert_eq!(c_decompress(&c_rand_compressed), random_data);
    println!("✓ Both produce identical output");

    // ── Realistic text-like data ───────────────────────────────────────────
    println!("\n=== LZMA Rust-vs-C comparison (1 MB text-like payload) ===\n");
    let text_data = text_like_payload(1_048_576);

    println!("Compression (preset 6):");
    let rust_comp_time3 = bench("lzma_rust2", ITERS, || rust_compress(&text_data));
    let c_comp_time3 = bench("C liblzma ", ITERS, || c_compress(&text_data));
    let comp_ratio3 = rust_comp_time3.as_secs_f64() / c_comp_time3.as_secs_f64();
    println!("  → Rust/C ratio: {comp_ratio3:.2}x\n");

    let rust_text_compressed = rust_compress(&text_data);
    let c_text_compressed = c_compress(&text_data);
    println!(
        "Compressed sizes: rust={} bytes, C={} bytes\n",
        rust_text_compressed.len(),
        c_text_compressed.len()
    );

    println!("Decompression:");
    let rust_dec_time3 = bench("lzma_rust2", ITERS, || {
        rust_decompress(&rust_text_compressed)
    });
    let c_dec_time3 = bench("C liblzma ", ITERS, || c_decompress(&c_text_compressed));
    let dec_ratio3 = rust_dec_time3.as_secs_f64() / c_dec_time3.as_secs_f64();
    println!("  → Rust/C ratio: {dec_ratio3:.2}x\n");

    assert_eq!(rust_decompress(&rust_text_compressed), text_data);
    assert_eq!(c_decompress(&c_text_compressed), text_data);
    println!("✓ Both produce identical output");
}

#[test]
#[ignore = "large manual encoder comparison"]
fn large_lzma2_matched_input_vs_liblzma() {
    let zeros = vec![0u8; 64 * 1024 * 1024];
    bench_matched_lzma2(&zeros, "64 MiB zeros");

    let random = pseudo_random_payload(16 * 1024 * 1024);
    bench_matched_lzma2(&random, "16 MiB pseudo-random");
}

#[test]
#[ignore = "large"]
fn large_lzma2_mt_candidate() {
    let input_path = std::env::var("R7Z_BENCH_INPUT").expect("set R7Z_BENCH_INPUT");
    let workers = std::env::var("R7Z_BENCH_WORKERS")
        .expect("set R7Z_BENCH_WORKERS")
        .parse::<u32>()
        .unwrap();
    let chunk_size = NonZeroU64::new(
        std::env::var("R7Z_BENCH_CHUNK_SIZE")
            .unwrap_or_else(|_| (64 * 1024 * 1024).to_string())
            .parse::<u64>()
            .unwrap(),
    )
    .unwrap();
    let input_path = std::path::Path::new(&input_path);
    let input_size = std::fs::metadata(input_path).unwrap().len();
    let mut input_hash = Sha256::new();
    let mut input = std::fs::File::open(input_path).unwrap();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        input_hash.update(&buffer[..read]);
    }
    let expected_hash = input_hash.finalize();

    let mut options = lzma_rust2::Lzma2Options::with_preset(5);
    options.lzma_options.dict_size = 16 << 20;
    options.lzma_options.nice_len = 32;
    options.lzma_options.depth_limit = 32;
    options.set_chunk_size(Some(chunk_size));

    let output = Vec::new();
    let start = Instant::now();
    let mut input = std::fs::File::open(input_path).unwrap();
    let output = if workers == 1 {
        let mut writer = lzma_rust2::Lzma2Writer::new(output, options.clone());
        std::io::copy(&mut input, &mut writer).unwrap();
        writer.finish().unwrap()
    } else {
        let mut writer = lzma_rust2::Lzma2WriterMt::new(output, options.clone(), workers).unwrap();
        std::io::copy(&mut input, &mut writer).unwrap();
        writer.finish().unwrap()
    };
    let elapsed = start.elapsed();
    println!(
        "workers={workers}, chunk_size={}, input_bytes={input_size}, packed_bytes={}, elapsed={elapsed:?}",
        chunk_size.get(),
        output.len()
    );

    let mut decoder =
        lzma_rust2::Lzma2Reader::new(output.as_slice(), options.lzma_options.dict_size, None);
    let mut decoded_output = Sha256Sink::default();
    std::io::copy(&mut decoder, &mut decoded_output).unwrap();
    assert_eq!(decoded_output.len, input_size);
    assert_eq!(decoded_output.hasher.finalize(), expected_hash);
}

#[derive(Default)]
struct Sha256Sink {
    hasher: Sha256,
    len: u64,
}

impl Write for Sha256Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(bytes);
        self.len += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bench_matched_lzma2(data: &[u8], label: &str) {
    let size = data.len();

    let mut rust_options = lzma_rust2::Lzma2Options::with_preset(5);
    rust_options.lzma_options.dict_size = 16 << 20;
    rust_options.set_chunk_size(Some(NonZeroU64::new(size as u64).unwrap()));

    let mut c_options = xz2::stream::LzmaOptions::new_preset(5).unwrap();
    c_options
        .dict_size(16 << 20)
        .nice_len(32)
        .mode(xz2::stream::Mode::Normal)
        .match_finder(xz2::stream::MatchFinder::BinaryTree4)
        .depth(0);

    let rust_encode = |chunk_size: usize| {
        let mut writer = lzma_rust2::Lzma2Writer::new(Vec::new(), rust_options.clone());
        for chunk in data.chunks(chunk_size) {
            writer.write_all(chunk).unwrap();
        }
        writer.finish().unwrap()
    };
    let c_encode = |chunk_size: usize| {
        let mut filters = xz2::stream::Filters::new();
        filters.lzma2(&c_options);
        let stream =
            xz2::stream::Stream::new_stream_encoder(&filters, xz2::stream::Check::None).unwrap();
        let mut writer = xz2::write::XzEncoder::new_stream(Vec::new(), stream);
        for chunk in data.chunks(chunk_size) {
            writer.write_all(chunk).unwrap();
        }
        writer.finish().unwrap()
    };

    let rust_output = rust_encode(size);
    let mut rust_decoded = Vec::new();
    lzma_rust2::Lzma2Reader::new(rust_output.as_slice(), 16 << 20, None)
        .read_to_end(&mut rust_decoded)
        .unwrap();
    assert_eq!(rust_decoded, data);

    let c_output = c_encode(size);
    let mut c_decoded = Vec::new();
    xz2::read::XzDecoder::new(c_output.as_slice())
        .read_to_end(&mut c_decoded)
        .unwrap();
    assert_eq!(c_decoded, data);

    println!("{label}, preset 5, 16 MiB dict, 32 fast bytes, BT4");
    println!(
        "compressed bytes: Rust={}, liblzma/XZ={}",
        rust_output.len(),
        c_output.len()
    );
    bench("Rust one write", 2, || rust_encode(size));
    bench("liblzma one write", 2, || c_encode(size));
    bench("Rust 8 KiB writes", 2, || rust_encode(8192));
    bench("liblzma 8 KiB writes", 2, || c_encode(8192));
}
