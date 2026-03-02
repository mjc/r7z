use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::path::Path;

fn fixture_bytes() -> Vec<u8> {
    std::fs::read("tests/fixtures/test_1.7z").expect("test fixture missing")
}

fn bench_signature_parse(c: &mut Criterion) {
    let data = fixture_bytes();
    c.bench_function("SignatureHeader::parse", |b| {
        b.iter(|| r7z::SignatureHeader::parse(black_box(&data)).unwrap())
    });
}

fn bench_archive_open(c: &mut Criterion) {
    let path = Path::new("tests/fixtures/test_1.7z");
    c.bench_function("Archive::open", |b| {
        b.iter(|| r7z::Archive::open(black_box(path)).unwrap())
    });
}

fn bench_archive_from_bytes(c: &mut Criterion) {
    let data = fixture_bytes();
    c.bench_function("Archive::from_bytes", |b| {
        b.iter(|| r7z::Archive::from_bytes(black_box(data.clone())).unwrap())
    });
}

fn bench_extract_to_memory(c: &mut Criterion) {
    let archive = r7z::Archive::open(Path::new("tests/fixtures/test_1.7z")).unwrap();
    // Find the first non-empty file index
    let fi = archive.files_info().unwrap();
    let idx = fi
        .empty_streams
        .iter()
        .position(|&e| !e)
        .unwrap_or(0);
    c.bench_function("Archive::extract_to_memory", |b| {
        b.iter(|| archive.extract_to_memory(black_box(idx)).unwrap())
    });
}

fn bench_builder_single_file(c: &mut Criterion) {
    let data = b"Hello, benchmark world! This is a typical short file.";
    c.bench_function("ArchiveBuilder::build (single file)", |b| {
        b.iter(|| {
            r7z::ArchiveBuilder::new()
                .add_file("hello.txt", black_box(data))
                .build()
                .unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_signature_parse,
    bench_archive_open,
    bench_archive_from_bytes,
    bench_extract_to_memory,
    bench_builder_single_file,
);
criterion_main!(benches);
