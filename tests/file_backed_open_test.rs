use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct CountingAlloc;

static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() && new_size > layout.size() {
            ALLOCATED_BYTES.fetch_add(new_size - layout.size(), Ordering::Relaxed);
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

fn reset_allocated_bytes() {
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
}

fn allocated_bytes() -> usize {
    ALLOCATED_BYTES.load(Ordering::Relaxed)
}

#[test]
fn from_reader_accepts_cursor() {
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("payload.txt", b"cursor-backed")
        .build()
        .unwrap();

    let archive = r7z::Archive::from_reader(Cursor::new(bytes)).unwrap();

    assert_eq!(archive.extract_to_memory(0).unwrap(), b"cursor-backed");
}

#[test]
fn open_mmap_parses_fixture() {
    let archive = r7z::Archive::open_with_options(
        Path::new("tests/fixtures/test_1.7z"),
        r7z::ArchiveOpenOptions {
            storage_mode: r7z::ArchiveStorageMode::Mmap,
            ..Default::default()
        },
    )
    .unwrap();

    assert!(archive.num_files() > 0);
}

#[test]
fn open_seek_mode_parses_fixture() {
    let archive = r7z::Archive::open_with_options(
        Path::new("tests/fixtures/test_1.7z"),
        r7z::ArchiveOpenOptions {
            storage_mode: r7z::ArchiveStorageMode::Seek,
            ..Default::default()
        },
    )
    .unwrap();

    assert!(archive.num_files() > 0);
}

#[test]
fn open_split_archive_first_volume_reads_siblings() {
    let tmp = tempfile::tempdir().unwrap();
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("alpha.txt", b"alpha")
        .add_file("nested/beta.txt", &vec![0x5Au8; 4096])
        .build()
        .unwrap();
    let first = tmp.path().join("split.7z.001");
    let chunk = bytes.len() / 3;
    std::fs::write(&first, &bytes[..chunk]).unwrap();
    std::fs::write(tmp.path().join("split.7z.002"), &bytes[chunk..chunk * 2]).unwrap();
    std::fs::write(tmp.path().join("split.7z.003"), &bytes[chunk * 2..]).unwrap();

    let archive = r7z::Archive::open(&first).unwrap();
    let names = archive.files_info().unwrap().names().collect::<Vec<_>>();
    let alpha_idx = names.iter().position(|name| name == "alpha.txt").unwrap();
    let beta_idx = names
        .iter()
        .position(|name| name == "nested/beta.txt")
        .unwrap();

    assert_eq!(archive.extract_to_memory(alpha_idx).unwrap(), b"alpha");
    assert_eq!(
        archive.extract_to_memory(beta_idx).unwrap(),
        vec![0x5Au8; 4096]
    );
}

#[test]
fn open_prepended_archive_finds_embedded_signature() {
    let tmp = tempfile::tempdir().unwrap();
    let mut bytes = b"MZ fake sfx stub\nnot a real executable\n".to_vec();
    bytes.extend_from_slice(
        &r7z::ArchiveBuilder::new()
            .add_file("payload.txt", b"embedded")
            .build()
            .unwrap(),
    );
    let archive_path = tmp.path().join("payload.exe");
    std::fs::write(&archive_path, bytes).unwrap();

    let archive = r7z::Archive::open(&archive_path).unwrap();

    assert_eq!(archive.num_files(), 1);
    assert_eq!(archive.extract_to_memory(0).unwrap(), b"embedded");
}

#[test]
fn sparse_large_seek_open_does_not_read_whole_file() {
    let tmp = tempfile::tempdir().unwrap();
    let archive_path = tmp.path().join("sparse.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("payload.txt", b"sparse")
        .build()
        .unwrap();
    std::fs::write(&archive_path, bytes).unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&archive_path)
        .unwrap();
    file.set_len(256 * 1024 * 1024).unwrap();
    drop(file);

    reset_allocated_bytes();
    let archive = r7z::Archive::open_with_options(
        &archive_path,
        r7z::ArchiveOpenOptions {
            storage_mode: r7z::ArchiveStorageMode::Seek,
            ..Default::default()
        },
    )
    .unwrap();
    let allocated = allocated_bytes();

    assert_eq!(archive.num_files(), 1);
    assert!(
        allocated < 8 * 1024 * 1024,
        "seek-backed open allocated {allocated} bytes"
    );
}

#[test]
fn metadata_limit_rejects_large_next_header() {
    let tmp = tempfile::tempdir().unwrap();
    let archive_path = tmp.path().join("limited.7z");
    let bytes = r7z::ArchiveBuilder::new()
        .add_file("payload.txt", b"metadata")
        .build()
        .unwrap();
    std::fs::write(&archive_path, bytes).unwrap();

    let err = match r7z::Archive::open_with_options(
        &archive_path,
        r7z::ArchiveOpenOptions {
            max_metadata_bytes: 1,
            storage_mode: r7z::ArchiveStorageMode::Seek,
        },
    ) {
        Ok(_) => panic!("archive opened despite metadata limit"),
        Err(err) => err,
    };

    assert!(matches!(err, r7z::R7zError::LimitExceeded("metadata")));
}

#[test]
fn metadata_limit_rejects_large_decoded_header() {
    let tmp = tempfile::tempdir().unwrap();
    let archive_path = tmp.path().join("decoded-header-limited.7z");
    let mut builder = r7z::ArchiveBuilder::new();
    for i in 0..128 {
        builder = builder.add_file(&format!("entry-{i:03}.txt"), b"x");
    }
    let bytes = builder.build().unwrap();
    let next_header_size = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
    std::fs::write(&archive_path, bytes).unwrap();

    let err = match r7z::Archive::open_with_options(
        &archive_path,
        r7z::ArchiveOpenOptions {
            max_metadata_bytes: next_header_size + 16,
            storage_mode: r7z::ArchiveStorageMode::Seek,
        },
    ) {
        Ok(_) => panic!("archive opened despite decoded metadata limit"),
        Err(err) => err,
    };

    assert!(matches!(err, r7z::R7zError::LimitExceeded("metadata")));
}

#[test]
fn extract_to_writer_from_seek_source_matches_from_bytes() {
    let bytes = r7z::ArchiveBuilder::new()
        .compression(r7z::Codec::Lzma2)
        .add_file("payload.txt", b"seek-backed extract")
        .build()
        .unwrap();
    let from_bytes = r7z::Archive::from_bytes(bytes.clone().into()).unwrap();
    let from_reader = r7z::Archive::from_reader(Cursor::new(bytes)).unwrap();

    let mut expected = Vec::new();
    let mut actual = Vec::new();
    from_bytes.extract_to_writer(0, &mut expected).unwrap();
    from_reader.extract_to_writer(0, &mut actual).unwrap();

    assert_eq!(actual, expected);
}

#[test]
fn extract_to_writer_non_aes_does_not_read_packed_stream_in_one_request() {
    let payload = vec![0xA5; 2 * 1024 * 1024];
    let bytes = r7z::ArchiveBuilder::new()
        .compression(r7z::Codec::Copy)
        .add_file("payload.bin", &payload)
        .build()
        .unwrap();
    let max_read_request = Arc::new(AtomicUsize::new(0));
    let reader = TrackingReader {
        inner: Cursor::new(bytes),
        max_read_request: Arc::clone(&max_read_request),
    };
    let archive = r7z::Archive::from_reader(reader).unwrap();

    max_read_request.store(0, Ordering::Relaxed);
    let mut out = Vec::new();
    archive.extract_to_writer(0, &mut out).unwrap();

    assert_eq!(out, payload);
    assert!(
        max_read_request.load(Ordering::Relaxed) <= 64 * 1024,
        "extract read the packed stream in a large request"
    );
}

struct TrackingReader {
    inner: Cursor<Vec<u8>>,
    max_read_request: Arc<AtomicUsize>,
}

impl Read for TrackingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.max_read_request
            .fetch_max(buf.len(), Ordering::Relaxed);
        self.inner.read(buf)
    }
}

impl Seek for TrackingReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}
