/// Head-to-head comparison: lzma_rust2 (pure Rust) vs C liblzma (via xz2).
///
/// Uses LZMA-alone format for both so the underlying algorithm is identical
/// and framing differences are negligible.
///
/// Run with:  cargo test --release lzma_perf -- --nocapture --ignored
use std::io::{Cursor, Read, Write};
use std::time::Instant;

const ITERS: u32 = 5;

/// 1 MB payload — repeating counter cycle, same as the benchmark fixtures.
fn payload() -> Vec<u8> {
    (0..1_048_576u32).map(|i| (i % 256) as u8).collect()
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
    words.as_bytes().iter().copied().cycle().take(size).collect()
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

    let mut r =
        lzma_rust2::LzmaReader::new_with_props(Cursor::new(stream), unpack_size, props_byte, dict_size, None)
            .unwrap();
    let mut out = Vec::with_capacity(unpack_size as usize);
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
#[ignore] // run explicitly with --ignored
fn lzma_rust_vs_c_performance() {
    let data = payload();
    println!("\n=== LZMA Rust-vs-C comparison ({} bytes payload) ===\n", data.len());

    // ── Compress ───────────────────────────────────────────────────────────
    println!("Compression (preset 6):");
    let rust_comp_time = bench("lzma_rust2", ITERS, || rust_compress(&data));
    let c_comp_time = bench("C liblzma ", ITERS, || c_compress(&data));
    let comp_ratio = rust_comp_time.as_nanos() as f64 / c_comp_time.as_nanos() as f64;
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
    let dec_ratio = rust_dec_time.as_nanos() as f64 / c_dec_time.as_nanos() as f64;
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
    let comp_ratio2 = rust_comp_time2.as_nanos() as f64 / c_comp_time2.as_nanos() as f64;
    println!("  → Rust/C ratio: {comp_ratio2:.2}x\n");

    let rust_rand_compressed = rust_compress(&random_data);
    let c_rand_compressed = c_compress(&random_data);
    println!(
        "Compressed sizes: rust={} bytes, C={} bytes\n",
        rust_rand_compressed.len(),
        c_rand_compressed.len()
    );

    println!("Decompression:");
    let rust_dec_time2 = bench("lzma_rust2", ITERS, || rust_decompress(&rust_rand_compressed));
    let c_dec_time2 = bench("C liblzma ", ITERS, || c_decompress(&c_rand_compressed));
    let dec_ratio2 = rust_dec_time2.as_nanos() as f64 / c_dec_time2.as_nanos() as f64;
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
    let comp_ratio3 = rust_comp_time3.as_nanos() as f64 / c_comp_time3.as_nanos() as f64;
    println!("  → Rust/C ratio: {comp_ratio3:.2}x\n");

    let rust_text_compressed = rust_compress(&text_data);
    let c_text_compressed = c_compress(&text_data);
    println!(
        "Compressed sizes: rust={} bytes, C={} bytes\n",
        rust_text_compressed.len(),
        c_text_compressed.len()
    );

    println!("Decompression:");
    let rust_dec_time3 = bench("lzma_rust2", ITERS, || rust_decompress(&rust_text_compressed));
    let c_dec_time3 = bench("C liblzma ", ITERS, || c_decompress(&c_text_compressed));
    let dec_ratio3 = rust_dec_time3.as_nanos() as f64 / c_dec_time3.as_nanos() as f64;
    println!("  → Rust/C ratio: {dec_ratio3:.2}x\n");

    assert_eq!(rust_decompress(&rust_text_compressed), text_data);
    assert_eq!(c_decompress(&c_text_compressed), text_data);
    println!("✓ Both produce identical output");
}
