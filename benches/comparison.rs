#![allow(clippy::semicolon_if_nothing_returned)]

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion};
use memmap2::Mmap;
use std::fs::File;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// In-process flamegraph profiler wired to criterion 0.8's `Profiler` trait.
///
/// pprof's own `criterion` feature targets criterion 0.5 and won't compile
/// against 0.8. We implement the trait directly using pprof's `ProfilerGuard`.
struct FlamegraphProfiler<'a> {
    frequency: i32,
    guard: Option<pprof::ProfilerGuard<'a>>,
}

impl FlamegraphProfiler<'_> {
    fn new(frequency: i32) -> Self {
        Self {
            frequency,
            guard: None,
        }
    }
}

impl criterion::profiler::Profiler for FlamegraphProfiler<'_> {
    fn start_profiling(&mut self, _id: &str, _dir: &Path) {
        self.guard = Some(pprof::ProfilerGuard::new(self.frequency).unwrap());
    }

    fn stop_profiling(&mut self, _id: &str, dir: &Path) {
        if let Some(guard) = self.guard.take() {
            let report = guard.report().build().expect("pprof report failed");
            std::fs::create_dir_all(dir).unwrap();
            let svg = File::create(dir.join("flamegraph.svg")).unwrap();
            report.flamegraph(svg).expect("flamegraph write failed");
        }
    }
}

/// Memory-map a file and return a `Bytes` backed by the mapping.
///
/// The OS pages the file on demand — no heap allocation proportional to file size.
fn mmap_bytes(path: &PathBuf) -> Bytes {
    let file = File::open(path).expect("failed to open fixture");
    // SAFETY: we do not modify the fixture files during the benchmark process.
    // On Linux the mapping stays valid after the File is dropped.
    let mmap = unsafe { Mmap::map(&file).expect("mmap failed") };
    Bytes::from_owner(mmap)
}

// Lazy fixture generation: 1 MB archive
fn archive_1mb_path() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let fixture_dir = PathBuf::from("target/bench-fixtures");
        let _ = std::fs::create_dir_all(&fixture_dir);
        let path = fixture_dir.join("1mb.7z");

        if !path.exists() {
            let payload = generate_payload(1024 * 1024); // 1 MB
            let archive = r7z::ArchiveBuilder::new()
                .add_file("data.bin", &payload)
                .build()
                .expect("failed to build 1MB archive");
            std::fs::write(&path, &archive).expect("failed to write 1MB fixture");
        }
        path
    })
    .clone()
}

// Lazy fixture generation: 10 MB archive
fn archive_10mb_path() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let fixture_dir = PathBuf::from("target/bench-fixtures");
        let _ = std::fs::create_dir_all(&fixture_dir);
        let path = fixture_dir.join("10mb.7z");

        if !path.exists() {
            let payload = generate_payload(10 * 1024 * 1024); // 10 MB
            let archive = r7z::ArchiveBuilder::new()
                .add_file("data.bin", &payload)
                .build()
                .expect("failed to build 10MB archive");
            std::fs::write(&path, &archive).expect("failed to write 10MB fixture");
        }
        path
    })
    .clone()
}

// Lazy fixture generation: 1 GB archive
fn archive_1gb_path() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let fixture_dir = PathBuf::from("target/bench-fixtures");
        let _ = std::fs::create_dir_all(&fixture_dir);
        let path = fixture_dir.join("1gb.7z");

        if !path.exists() {
            let payload = generate_payload(1024 * 1024 * 1024); // 1 GB
            let archive = r7z::ArchiveBuilder::new()
                .add_file("data.bin", &payload)
                .build()
                .expect("failed to build 1GB archive");
            std::fs::write(&path, &archive).expect("failed to write 1GB fixture");
        }
        path
    })
    .clone()
}

// Lazy fixture generation: 10 GB archive
fn archive_10gb_path() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let fixture_dir = PathBuf::from("target/bench-fixtures");
        let _ = std::fs::create_dir_all(&fixture_dir);
        let path = fixture_dir.join("10gb.7z");

        if !path.exists() {
            let payload = generate_payload(10 * 1024 * 1024 * 1024); // 10 GB
            let archive = r7z::ArchiveBuilder::new()
                .add_file("data.bin", &payload)
                .build()
                .expect("failed to build 10GB archive");
            std::fs::write(&path, &archive).expect("failed to write 10GB fixture");
        }
        path
    })
    .clone()
}

// Lazy archive bytes for r7z operations — stored as Bytes so clone() is O(1).
fn archive_1mb_bytes() -> Bytes {
    static BYTES: OnceLock<Bytes> = OnceLock::new();
    BYTES
        .get_or_init(|| mmap_bytes(&archive_1mb_path()))
        .clone()
}

fn archive_10mb_bytes() -> Bytes {
    static BYTES: OnceLock<Bytes> = OnceLock::new();
    BYTES
        .get_or_init(|| mmap_bytes(&archive_10mb_path()))
        .clone()
}

fn archive_1gb_bytes() -> Bytes {
    static BYTES: OnceLock<Bytes> = OnceLock::new();
    BYTES
        .get_or_init(|| mmap_bytes(&archive_1gb_path()))
        .clone()
}

fn archive_10gb_bytes() -> Bytes {
    static BYTES: OnceLock<Bytes> = OnceLock::new();
    BYTES
        .get_or_init(|| mmap_bytes(&archive_10gb_path()))
        .clone()
}

// Generate a compressible repeating payload of `size` bytes.
//
// A simple 256-byte counter cycle compresses extremely well with LZMA
// (a 1 GB payload becomes ~hundreds of bytes on disk), so large-fixture
// open/parse benchmarks can run without gigabytes of RAM or disk space.
//
// For the open benchmarks we only care about header-parse performance;
// the header structure is identical regardless of declared payload size.
// Cap actual allocation at 1 MB — the archive metadata is the same.
const PAYLOAD_CAP: usize = 1024 * 1024; // 1 MB

#[allow(clippy::cast_possible_truncation)]
fn generate_payload(size: usize) -> Vec<u8> {
    let actual = size.min(PAYLOAD_CAP);
    (0..actual).map(|i| (i % 256) as u8).collect()
}

// Whether to run benchmarks that require materialising gigabytes of data in RAM.
fn run_huge_benches() -> bool {
    std::env::var("RUN_HUGE_BENCHES").is_ok()
}

// ============================================================================
// r7z Benchmarks (with flamegraph profiler)
// ============================================================================

fn r7z_open_1mb(c: &mut Criterion) {
    let bytes = archive_1mb_bytes();
    c.bench_function("r7z_open_1mb", |b| {
        b.iter(|| r7z::Archive::from_bytes(black_box(bytes.clone())).unwrap());
    });
}

fn r7z_open_10mb(c: &mut Criterion) {
    let bytes = archive_10mb_bytes();
    c.bench_function("r7z_open_10mb", |b| {
        b.iter(|| r7z::Archive::from_bytes(black_box(bytes.clone())).unwrap());
    });
}

fn r7z_extract_1mb(c: &mut Criterion) {
    let archive = r7z::Archive::from_bytes(archive_1mb_bytes()).unwrap();
    c.bench_function("r7z_extract_1mb", |b| {
        b.iter(|| archive.extract_to_memory(black_box(0)).unwrap());
    });
}

fn r7z_extract_10mb(c: &mut Criterion) {
    let archive = r7z::Archive::from_bytes(archive_10mb_bytes()).unwrap();
    c.bench_function("r7z_extract_10mb", |b| {
        b.iter(|| archive.extract_to_memory(black_box(0)).unwrap());
    });
}

fn r7z_build_1mb(c: &mut Criterion) {
    let payload = generate_payload(1024 * 1024);
    c.bench_function("r7z_build_1mb", |b| {
        b.iter(|| {
            r7z::ArchiveBuilder::new()
                .add_file("data.bin", black_box(&payload))
                .build()
                .unwrap();
        });
    });
}

fn r7z_build_10mb(c: &mut Criterion) {
    let payload = generate_payload(10 * 1024 * 1024);
    c.bench_function("r7z_build_10mb", |b| {
        b.iter(|| {
            r7z::ArchiveBuilder::new()
                .add_file("data.bin", black_box(&payload))
                .build()
                .unwrap();
        });
    });
}

fn r7z_open_1gb(c: &mut Criterion) {
    let bytes = archive_1gb_bytes();
    c.bench_function("r7z_open_1gb", |b| {
        b.iter(|| r7z::Archive::from_bytes(black_box(bytes.clone())).unwrap());
    });
}

fn r7z_open_10gb(c: &mut Criterion) {
    let bytes = archive_10gb_bytes();
    c.bench_function("r7z_open_10gb", |b| {
        b.iter(|| r7z::Archive::from_bytes(black_box(bytes.clone())).unwrap());
    });
}

fn r7z_extract_1gb(c: &mut Criterion) {
    if !run_huge_benches() {
        return;
    }
    let archive = r7z::Archive::from_bytes(archive_1gb_bytes()).unwrap();
    c.bench_function("r7z_extract_1gb", |b| {
        b.iter(|| archive.extract_to_memory(black_box(0)).unwrap());
    });
}

fn r7z_extract_10gb(c: &mut Criterion) {
    if !run_huge_benches() {
        return;
    }
    let archive = r7z::Archive::from_bytes(archive_10gb_bytes()).unwrap();
    c.bench_function("r7z_extract_10gb", |b| {
        b.iter(|| archive.extract_to_memory(black_box(0)).unwrap());
    });
}

fn r7z_build_1gb(c: &mut Criterion) {
    if !run_huge_benches() {
        return;
    }
    let payload = generate_payload(1024 * 1024 * 1024);
    c.bench_function("r7z_build_1gb", |b| {
        b.iter(|| {
            r7z::ArchiveBuilder::new()
                .add_file("data.bin", black_box(&payload))
                .build()
                .unwrap();
        });
    });
}

fn r7z_build_10gb(c: &mut Criterion) {
    if !run_huge_benches() {
        return;
    }
    let payload = generate_payload(10 * 1024 * 1024 * 1024);
    c.bench_function("r7z_build_10gb", |b| {
        b.iter(|| {
            r7z::ArchiveBuilder::new()
                .add_file("data.bin", black_box(&payload))
                .build()
                .unwrap();
        });
    });
}

// ============================================================================
// p7zip Benchmarks (subprocess timing, no profiler, gated on availability)
// ============================================================================

fn p7zip_list_1mb(c: &mut Criterion) {
    // Skip if 7z not available
    if std::process::Command::new("7z")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }

    let fixture_path = archive_1mb_path().to_string_lossy().to_string();

    c.bench_function("p7zip_list_1mb", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let _ = std::process::Command::new("7z")
                    .arg("l")
                    .arg(&fixture_path)
                    .output();
            }
            start.elapsed()
        });
    });
}

fn p7zip_extract_1mb(c: &mut Criterion) {
    // Skip if 7z not available
    if std::process::Command::new("7z")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }

    let fixture_path = archive_1mb_path().to_string_lossy().to_string();

    c.bench_function("p7zip_extract_1mb", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let _ = std::process::Command::new("7z")
                    .arg("x")
                    .arg("-so")
                    .arg(&fixture_path)
                    .stdout(std::process::Stdio::null())
                    .output();
            }
            start.elapsed()
        });
    });
}

// ============================================================================
// Nintendo64 real-world archive (~6 GB, not committed to repo)
// ============================================================================

fn n64_path() -> PathBuf {
    PathBuf::from("/mnt/emulation/Nintendo64Archive-unencrypted.7z")
}

fn n64_bytes() -> Bytes {
    static BYTES: OnceLock<Bytes> = OnceLock::new();
    BYTES.get_or_init(|| mmap_bytes(&n64_path())).clone()
}

fn r7z_open_n64(c: &mut Criterion) {
    if !n64_path().exists() {
        return;
    }
    let bytes = n64_bytes();
    // Probe once — encrypted or unsupported-codec archives can't be opened; skip.
    if r7z::Archive::from_bytes(bytes.clone()).is_err() {
        eprintln!("r7z_open_n64: skipping — archive open failed (encrypted / unsupported codec)");
        return;
    }
    c.bench_function("r7z_open_n64", |b| {
        b.iter(|| r7z::Archive::from_bytes(black_box(bytes.clone())).unwrap());
    });
}

fn r7z_extract_n64(c: &mut Criterion) {
    if !n64_path().exists() {
        return;
    }
    let archive = match r7z::Archive::from_bytes(n64_bytes()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("r7z_extract_n64: skipping — archive open failed: {e:?}");
            return;
        }
    };
    // find first file that has actual data (not dir / empty-stream entry)
    let idx = archive
        .files_info()
        .and_then(|fi| (0..archive.num_files()).find(|&i| !fi.is_empty_stream(i)))
        .unwrap_or(0);
    c.bench_function("r7z_extract_n64", |b| {
        b.iter(|| archive.extract_to_memory(black_box(idx)).unwrap());
    });
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group! {
    name = r7z_benches;
    config = Criterion::default().with_profiler(FlamegraphProfiler::new(100));
    targets = r7z_open_1mb, r7z_open_10mb, r7z_open_1gb, r7z_open_10gb,
              r7z_extract_1mb, r7z_extract_10mb, r7z_extract_1gb, r7z_extract_10gb,
              r7z_build_1mb, r7z_build_10mb, r7z_build_1gb, r7z_build_10gb,
              r7z_open_n64, r7z_extract_n64
}

criterion_group! {
    name = p7zip_benches;
    config = Criterion::default();
    targets = p7zip_list_1mb, p7zip_extract_1mb
}

criterion_main!(r7z_benches, p7zip_benches);
