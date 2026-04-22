#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{criterion_group, criterion_main, Criterion};
use std::fs::File;
use std::hint::black_box;
use std::io::Write;
use std::path::{Path, PathBuf};

fn fixture_bytes() -> Vec<u8> {
    std::fs::read("tests/fixtures/test_1.7z").expect("test fixture missing")
}

fn bench_signature_parse(c: &mut Criterion) {
    let data = fixture_bytes();
    c.bench_function("SignatureHeader::parse", |b| {
        b.iter(|| r7z::SignatureHeader::parse(black_box(&data)).unwrap())
    });
}

fn bench_archive_open_mmap(c: &mut Criterion) {
    let path = Path::new("tests/fixtures/test_1.7z");
    c.bench_function("Archive::open mmap fixture", |b| {
        b.iter(|| r7z::Archive::open(black_box(path)).unwrap())
    });
}

fn bench_archive_open_seek(c: &mut Criterion) {
    let path = Path::new("tests/fixtures/test_1.7z");
    c.bench_function("Archive::open seek fixture", |b| {
        b.iter(|| {
            r7z::Archive::open_with_options(
                black_box(path),
                r7z::ArchiveOpenOptions {
                    storage_mode: r7z::ArchiveStorageMode::Seek,
                    ..Default::default()
                },
            )
            .unwrap();
        })
    });
}

fn sparse_archive_path() -> PathBuf {
    let fixture_dir = PathBuf::from("target/bench-fixtures");
    std::fs::create_dir_all(&fixture_dir).expect("create bench fixture dir");
    let path = fixture_dir.join("sparse_256mb.7z");
    if !path.exists() {
        let bytes = r7z::ArchiveBuilder::new()
            .add_file("payload.txt", b"sparse")
            .build()
            .expect("build sparse archive fixture");
        let mut file = File::create(&path).expect("create sparse archive fixture");
        file.write_all(&bytes).expect("write sparse archive header");
        file.set_len(256 * 1024 * 1024)
            .expect("extend sparse archive fixture");
    }
    path
}

fn bench_archive_open_seek_sparse(c: &mut Criterion) {
    let path = sparse_archive_path();
    c.bench_function("Archive::open seek sparse_256mb", |b| {
        b.iter(|| {
            r7z::Archive::open_with_options(
                black_box(path.as_path()),
                r7z::ArchiveOpenOptions {
                    storage_mode: r7z::ArchiveStorageMode::Seek,
                    ..Default::default()
                },
            )
            .unwrap();
        })
    });
}

fn bench_archive_from_bytes(c: &mut Criterion) {
    let data: bytes::Bytes = fixture_bytes().into();
    c.bench_function("Archive::from_bytes fixture", |b| {
        b.iter(|| r7z::Archive::from_bytes(black_box(data.clone())).unwrap())
    });
}

fn bench_extract_to_memory(c: &mut Criterion) {
    let archive = r7z::Archive::open(Path::new("tests/fixtures/test_1.7z")).unwrap();
    // Find the first non-empty file index
    let fi = archive.files_info().unwrap();
    let num_files = usize::try_from(fi.num_files).expect("num_files fits in usize");
    let idx = (0..num_files)
        .find(|&i| !fi.is_empty_stream(i))
        .unwrap_or(0);
    c.bench_function("Archive::extract_to_memory", |b| {
        b.iter(|| archive.extract_to_memory(black_box(idx)).unwrap())
    });
}

fn bench_extract_to_writer_seek_backed(c: &mut Criterion) {
    let archive = r7z::Archive::open_with_options(
        Path::new("tests/fixtures/test_1.7z"),
        r7z::ArchiveOpenOptions {
            storage_mode: r7z::ArchiveStorageMode::Seek,
            ..Default::default()
        },
    )
    .unwrap();
    let fi = archive.files_info().unwrap();
    let num_files = usize::try_from(fi.num_files).expect("num_files fits in usize");
    let idx = (0..num_files)
        .find(|&i| !fi.is_empty_stream(i))
        .unwrap_or(0);
    c.bench_function("Archive::extract_to_writer seek-backed non-aes", |b| {
        b.iter(|| {
            let mut sink = std::io::sink();
            archive
                .extract_to_writer(black_box(idx), &mut sink)
                .unwrap();
        })
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
    bench_archive_open_mmap,
    bench_archive_open_seek,
    bench_archive_open_seek_sparse,
    bench_archive_from_bytes,
    bench_extract_to_memory,
    bench_extract_to_writer_seek_backed,
    bench_builder_single_file,
);
criterion_main!(benches);
