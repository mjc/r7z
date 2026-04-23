# r7z

A pure-Rust library for reading and writing `.7z` archives.

[![Crates.io](https://img.shields.io/crates/v/r7z)](https://crates.io/crates/r7z)
[![docs.rs](https://docs.rs/r7z/badge.svg)](https://docs.rs/r7z)
[![License: LGPL-2.1-or-later](https://img.shields.io/badge/license-LGPL--2.1--or--later-blue)](LICENSE)

r7z implements the 7z binary format spec in pure Rust using `nom` parser combinators. It reads archives created by p7zip / 7-Zip and can build new archives that those tools can open. No C FFI, no unsafe liblzma — compression is handled by the `lzma-rust2` crate.

## Features

- **Read** Copy, LZMA, LZMA2, BCJ+x86, and AES-256-SHA-256 encrypted `.7z` archives
- **Write** solid and multi-folder `.7z` archives with LZMA, LZMA2, or BCJ+x86+LZMA2 compression
- **CRC32 validation** on both the signature start-header and header/data blocks
- **p7zip / 7-Zip interoperability** — read p7zip archives, write archives p7zip can open
- Supports **EncodedHeader** format (compressed metadata; most p7zip archives) and **uncompressed Header** format
- Supports **encrypted headers** when opened with a password
- Safe extraction rejects absolute paths, parent-directory traversal, and Windows-prefixed paths
- Custom **7z varint** encoding/decoding (`sevenzip_varuint64_encode/decode`) — not LEB128
- Pure Rust — no `unsafe`, no C dependencies

## Installation

```toml
[dependencies]
r7z = "0.1"
```

**MSRV**: Rust 2024 edition (1.85+).

## Quick Start

### Reading — list and extract files

```rust
use r7z::Archive;
use std::path::Path;

let archive = Archive::open(Path::new("example.7z"))?;
println!("Files: {}", archive.num_files());

if let Some(fi) = archive.files_info() {
    for name in &fi.names {
        println!("  {name}");
    }
}

// Extract first file to an in-memory buffer.
// Directories are reported as R7zError::Directory; zero-byte files return an empty Vec.
let data = archive.extract_to_memory(0)?;
println!("{} bytes", data.len());

// Stream a file directly to any writer.
let mut out = std::fs::File::create("/tmp/first-file.bin")?;
let written = archive.extract_to_writer(0, &mut out)?;
println!("{written} bytes written");
```

`Archive::open` is file-backed and uses `mmap` by default, so opening a large
archive does not allocate a heap buffer for the full file. Use
`ArchiveOpenOptions { storage_mode: ArchiveStorageMode::Seek, ..Default::default() }`
when mmap is undesirable.

### Reading — extract all to disk safely

```rust
archive.extract_all(Path::new("/tmp/output"))?;
```

`extract_all` creates directories and zero-byte files correctly, rejects unsafe archive paths,
and streams decoded file data to disk instead of buffering full decoded folders in memory.

### Reading — encrypted archives

```rust
use r7z::Archive;
use std::path::Path;

let archive = Archive::open_with_password(Path::new("secret.7z"), Some("passphrase"))?;
let data = archive.extract_to_memory_with_password(0, Some("passphrase"))?;
```

### Building a single-file LZMA2 archive

```rust
use r7z::ArchiveBuilder;

let bytes = ArchiveBuilder::new()
    .add_file("hello.txt", b"Hello, world!")
    .build()?;
std::fs::write("out.7z", &bytes)?;
```

### Building a multi-file archive with explicit entries

```rust
use r7z::{ArchiveBuilder, EntryMeta};

let bytes = ArchiveBuilder::new()
    .add_file("alpha.txt", b"AAAA")
    .add_empty_file("empty.txt", EntryMeta::default())
    .add_directory("beta", EntryMeta::default())
    .add_file("beta/beta.txt", b"BBBBBBBB")
    .build()?;
```

### Writing metadata and encoded headers

```rust
use r7z::{ArchiveBuilder, ArchiveOptions, EntryMeta, HeaderMode};
use std::time::{Duration, UNIX_EPOCH};

let meta = EntryMeta {
    mtime: Some(UNIX_EPOCH + Duration::from_secs(1_710_504_000)),
    start_pos: Some(0),
    ..EntryMeta::from_unix_mode(0o100_644)
};

let bytes = ArchiveBuilder::new()
    .options(ArchiveOptions {
        header_mode: HeaderMode::Encoded,
        ..ArchiveOptions::default()
    })
    .add_file_entry("metadata.txt", b"with metadata", meta)
    .build()?;
```

`EntryMeta::attributes` stores raw 7z `WinAttrib` values. `EntryMeta::from_unix_mode(mode)` sets `(mode << 16) | 0x20`, `EntryMeta::directory_unix_mode(mode)` sets `(mode << 16) | 0x10`, and `EntryMeta::archive_file()` sets `0x20`.

### Building a BCJ+x86+LZMA2 archive

```rust
use r7z::{ArchiveBuilder, Codec};

let bytes = ArchiveBuilder::new()
    .add_file("program.bin", &program_bytes)
    .compression(Codec::Lzma2Bcj)
    .build()?;
```

### Building Copy or AES-encrypted archives

```rust
use r7z::{ArchiveBuilder, ArchiveOptions, Codec, EncryptionOptions};

let copy_bytes = ArchiveBuilder::new()
    .compression(Codec::Copy)
    .add_file("stored.bin", b"stored without compression")
    .build()?;

let mut options = ArchiveOptions::default();
options.encryption = Some(EncryptionOptions::default_for_password("secret"));

let encrypted_bytes = ArchiveBuilder::new()
    .options(options)
    .add_file("secret.txt", b"encrypted content")
    .build()?;
```

Set `EncryptionOptions::encrypt_header = true` to hide filenames and metadata until the password is supplied.
`EncryptionOptions::default_for_password(password)` uses p7zip-compatible writer defaults: cycle power 19, no salt, and a random 16-byte IV. Non-default salt and IV lengths up to 16 bytes are also supported.

### Writer API — file-backed archive creation

```rust
use r7z::build_streaming;
use std::fs::File;
use std::io::BufWriter;

let out_file = BufWriter::new(File::create("large.7z")?);  
let entries = vec![
    ("file1.bin".to_string(), File::open("file1.bin")?),
    ("file2.bin".to_string(), File::open("file2.bin")?),
].into_iter();

build_streaming(entries, out_file)?;
```

### Parsing from a seekable reader or in-memory buffer

7z archives require random access. `Archive::from_reader` accepts `Read + Seek`
sources such as `std::io::Cursor<Vec<u8>>` or `std::fs::File`; non-seekable
streams should be spooled by the caller before opening.

```rust
let file = std::fs::File::open("example.7z")?;
let archive = Archive::from_reader(file)?;
```

`ArchiveOpenOptions` controls file-backed storage mode and metadata limits:

```rust
use r7z::{Archive, ArchiveOpenOptions, ArchiveStorageMode};
use std::path::Path;

let archive = Archive::open_with_options(
    Path::new("example.7z"),
    ArchiveOpenOptions {
        storage_mode: ArchiveStorageMode::Seek,
        max_metadata_bytes: 64 * 1024 * 1024,
    },
)?;
```

For explicitly in-memory archives, use `Archive::from_bytes`:

```rust
let raw: Vec<u8> = std::fs::read("example.7z")?;
let archive = Archive::from_bytes(raw.into())?;
```

## API Reference

### `Archive` — Reading archives

| Method | Returns | Description |
|--------|---------|-------------|
| `Archive::open(path: &Path)` | `Result<Archive, R7zError>` | File-backed open using mmap by default |
| `Archive::open_with_password(path, password)` | `Result<Archive, R7zError>` | Open an archive with encrypted headers |
| `Archive::open_with_options(path, options)` | `Result<Archive, R7zError>` | Open with mmap/seek storage and metadata limits |
| `Archive::from_reader(reader)` | `Result<Archive, R7zError>` | Decode a seekable `Read + Seek` source |
| `Archive::from_reader_with_password(reader, password)` | `Result<Archive, R7zError>` | Decode a password-protected seekable source |
| `Archive::from_bytes(data: bytes::Bytes)` | `Result<Archive, R7zError>` | Decode a `.7z` from an in-memory buffer |
| `Archive::from_bytes_with_password(data, password)` | `Result<Archive, R7zError>` | Decode password-protected bytes |
| `archive.num_files()` | `usize` | Number of entries (files and directories) |
| `archive.files_info()` | `Option<&FilesInfo>` | File names, sizes, and attributes |
| `archive.streams_info()` | `Option<&StreamInfo>` | Raw stream/pack metadata |
| `archive.extract_to_memory(index: usize)` | `Result<Vec<u8>, R7zError>` | Decompress file at `index` (0-based) |
| `archive.extract_to_memory_with_password(index, password)` | `Result<Vec<u8>, R7zError>` | Decrypt/decompress file at `index` |
| `archive.extract_to_writer(index, writer)` | `Result<u64, R7zError>` | Stream file at `index` into a writer |
| `archive.extract_to_writer_with_password(index, writer, password)` | `Result<u64, R7zError>` | Stream encrypted file data into a writer |
| `archive.extract_all(dest: &Path)` | `Result<(), R7zError>` | Extract all files; creates subdirectories as needed |
| `archive.extract_all_with_password(dest, password)` | `Result<(), R7zError>` | Extract all files from an encrypted archive |

### `FilesInfo` — Entry metadata helpers

| Method | Description |
|--------|-------------|
| `fi.name(index)` | Decode a UTF-16LE entry name |
| `fi.names()` | Iterate decoded names |
| `fi.is_empty_stream(index)` | Entry has no data stream |
| `fi.is_empty_file(index)` | Entry is a zero-byte file |
| `fi.is_directory(index)` | Entry is a directory |
| `fi.is_anti(index)` | Entry is a 7z anti-item |

### `ArchiveBuilder` — Writing archives

Builder pattern — all methods consume `self` and return `Self` for chaining:

| Method | Description |
|--------|-------------|
| `ArchiveBuilder::new()` | Create an empty builder (LZMA2 compression default) |
| `.add_file(name: &str, data: &[u8])` | Queue a file with its content |
| `.add_symlink(name, target, meta)` | Queue a symlink-like entry; target bytes are stored as file data and Unix symlink mode bits are set |
| `.add_entry(entry, data)` | Queue an explicit `ArchiveEntry`; non-file entries must not provide stream data |
| `.add_empty_file(name, meta)` / `.add_directory(name, meta)` / `.add_anti_item(name, meta)` | Queue empty-stream entries |
| `.compression(codec: Codec)` | Set compression (`Codec::Copy`, `Codec::Lzma`, `Codec::Lzma2`, or `Codec::Lzma2Bcj`) |
| `.options(options: ArchiveOptions)` | Set codec, header mode, encryption, compression tuning, and streaming options |
| `.build()` | Produce the final `.7z` bytes as `Result<Vec<u8>, R7zError>` |

The builder defaults to **LZMA2**, matching p7zip / 7-Zip create behavior. It uses **solid compression** for non-empty files: file data is concatenated into one stream before compression, while directories, anti-items, and zero-byte files are represented with 7z empty-stream metadata.

`ArchiveOptions::compression` exposes p7zip-like tuning through `CompressionOptions`:
`CompressionLevel`, optional dictionary size, optional fast bytes, `SolidMode`
(`Solid`, `NonSolid`, or `Limit`), and optional LZMA2 chunk size. The existing
`Codec` still selects the algorithm.

### `ArchiveWriter` and `build_streaming` — file-backed builders

`ArchiveWriter<W: Write + Seek>` writes one or more compression folders and can store optional per-entry metadata. It also accepts explicit `ArchiveEntry` values through `.append_archive_entry(...)` and `.append_empty_entry(...)`:

```rust
use r7z::{ArchiveOptions, ArchiveWriter, Codec, EntryMeta};
use std::fs::File;

let file = File::create("out.7z")?;
let mut writer = ArchiveWriter::new(file, ArchiveOptions::default())?.compression(Codec::Lzma2);
writer.append_file("a.txt", &mut b"hello".as_ref(), EntryMeta::default())?;
writer.append_empty_file("empty.txt", EntryMeta::default())?;
writer.new_folder()?;
writer.append_entry("b.txt", &mut b"world".as_ref(), EntryMeta::default())?;
writer.finish()?;
```

When configured with `Codec::Copy` and no encryption, `ArchiveWriter` writes non-empty file payloads directly to the output as they are appended. With `Codec::Lzma`, default `Codec::Lzma2`, or `Codec::Lzma2Bcj` and no encryption, it streams into the compressed folder and writes those bytes when the folder is sealed by `new_folder()` or `finish()`. Encrypted writer paths still collect input before final archive assembly.

For file-backed output, use the convenience builder:

```rust
pub fn build_streaming<W, I, R>(entries: I, out: W) -> Result<(), R7zError>
where
    W: Write + Seek,
    I: IntoIterator<Item = (String, R)>,
    R: Read,

pub fn build_streaming_with_options<W, I, R>(
    entries: I,
    out: W,
    options: ArchiveOptions
) -> Result<(), R7zError>
where
    W: Write + Seek,
    I: IntoIterator<Item = (String, R)>,
    R: Read,

pub fn build_streaming_to_writer<W, I, R>(
    entries: I,
    out: W,
    options: ArchiveOptions
) -> Result<(), R7zError>
where
    W: Write,
    I: IntoIterator<Item = (String, R)>,
    R: Read,

pub fn build_streaming_volumes<P, I, R>(
    entries: I,
    base_path: P,
    archive_options: ArchiveOptions,
    volume_options: VolumeOptions
) -> Result<Vec<PathBuf>, R7zError>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = (String, R)>,
    R: Read,
```

Each `entry` is provided as a filename and `impl Read`; the builder writes the final `.7z` archive to any `Write + Seek` output. Use `build_streaming_with_options` for Copy, explicit header mode, or encryption settings.
`build_streaming_to_writer` accepts plain `Write` sinks by assembling through an
internal spool first. `build_streaming_volumes` writes p7zip-style split output
such as `archive.7z.001`, `archive.7z.002`, and returns the created paths.

### Link metadata

`FilesInfo::entry_type(index)` classifies entries as `File`, `Directory`,
`EmptyFile`, `Anti`, or `Symlink`. `Archive::symlink_target(index)` returns the
stored symlink target for entries marked with Unix symlink mode bits. `extract_all`
does not create filesystem symlinks; symlink entries extract as regular files
containing the target path bytes. Hard-link preservation is not supported for
`.7z` because p7zip does not reliably emit a standard hard-link representation
for this format.

### `Codec` — Compression algorithms

```rust
pub enum Codec {
    Copy,      // No compression — codec ID [0x00]
    Lzma,      // Classic LZMA — codec ID [0x03, 0x01, 0x01]
    Lzma2,     // Default — codec ID [0x21]
    Lzma2Bcj,  // x86 BCJ filter followed by LZMA2
}
```

`Lzma2` is the default and generally gives slightly better compression ratios.

### `R7zError` — Error variants

| Variant | Meaning |
|---------|---------|
| `R7zError::Parse` | Malformed archive — not valid 7z binary |
| `R7zError::InvalidProperty(u8)` | Unknown property tag byte in header |
| `R7zError::UnsupportedCodec(Vec<u8>)` | Codec ID not implemented (e.g., ZSTD) |
| `R7zError::Crc` | CRC32 mismatch — data corruption detected |
| `R7zError::Io(std::io::Error)` | File I/O failure |
| `R7zError::Decompression` | LZMA/LZMA2 stream could not be decoded |
| `R7zError::PasswordRequired` | Archive content or headers require a password |
| `R7zError::WrongPassword` | Reserved for password-specific failures |
| `R7zError::UnsafePath(String)` | Extracted path would escape the destination |
| `R7zError::Directory` | Requested entry is a directory or anti-item |
| `R7zError::LimitExceeded(&'static str)` | Configured metadata or safety limit was exceeded |

**Error handling example:**

```rust
match Archive::open(Path::new("archive.7z")) {
    Err(R7zError::Crc)                   => eprintln!("archive is corrupted"),
    Err(R7zError::Parse)                 => eprintln!("not a valid .7z file"),
    Err(R7zError::UnsupportedCodec(id))  => eprintln!("unsupported codec: {id:?}"),
    Err(e)                               => eprintln!("error: {e}"),
    Ok(archive)                          => { /* … */ }
}
```

### Low-level / parser types

These are public but primarily used for building advanced tooling:

| Type / Function | Location | Description |
|----------------|----------|-------------|
| `SignatureHeader` | `src/headers.rs` | 32-byte archive start header |
| `EncodedHeader` | `src/headers.rs` | Compressed header descriptor |
| `Header` | `src/headers.rs` | Fully decoded archive header |
| `PackInfo` / `UnpackInfo` | `src/pack_info.rs` | Stream layout metadata |
| `Folder` | `src/folder.rs` | Coder chain for one solid block |
| `CoderInfo` | `src/coder_info.rs` | Single coder within a Folder |
| `FilesInfo` | `src/files_info.rs` | File names, sizes, attributes |
| `StreamInfo` / `SubstreamInfo` | `src/stream_info.rs` | Stream/substream sizes and CRCs |
| `Property` | `src/property.rs` | Enum of all 7z property tag bytes |
| `sevenzip_varuint64_decode` | `src/parsers.rs` | 7z custom varint decode |
| `sevenzip_varuint64_encode` | `src/parsers.rs` | 7z custom varint encode |
| `decompress_folder` | `src/codec.rs` | Decompress a full Folder block |

## Format Compatibility

| Feature | Status |
|---------|--------|
| LZMA compression | Read + Write |
| LZMA2 compression | Read + Write (default) |
| Copy codec | Read + Write |
| Deflate compression | Read |
| Deflate64 compression | Read |
| BZip2 compression | Read |
| Delta filter + compression | Read |
| Swap2 / Swap4 filters + compression | Read |
| ARM / ARMT / IA64 / PPC / SPARC filters + compression | Read |
| BCJ x86 filter + LZMA2 | Read + Write |
| BCJ2 x86 filter + LZMA2 | Read |
| EncodedHeader archives (p7zip default) | Read + Write |
| Uncompressed Header archives | Read + Write |
| Solid archives | Read + Write |
| Multi-file archives | Read + Write |
| Multi-folder / non-solid archives | Read + Write via `ArchiveWriter` |
| Directories / zero-byte files / anti-items | Read + Write |
| AES-256-SHA-256 encrypted content | Read + Write |
| AES encrypted headers (`-mhe=on`) | Read + Write with password |
| PPMd | Read |
| Update existing archives | Not supported |
| Read split volumes | Not supported |
| Hard-link preservation | Not supported |

**7z specification:** [7zFormat.txt](https://github.com/google/omaha/blob/master/third_party/lzma/files/7zFormat.txt)

Archives written by r7z use format version 0.4 (standard). Multi-entry archives use EncodedHeader by default, matching p7zip behavior, and are fully readable by 7-Zip ≥ 9.x and p7zip.

`extract_to_writer` streams decoded file data into the supplied writer and is
the preferred low-allocation extraction API. `extract_to_memory` intentionally
allocates the requested file contents. AES-encrypted extraction still buffers
the encrypted pack stream internally before AES-CBC decryption; streaming AES is
a planned hardening follow-up.

Interop tests cover behavioral parity for p7zip-created and r7z-created LZMA,
LZMA2, and BCJ+x86+LZMA2 archives. The parity target is matching archive
listing/extraction behavior: file names, file contents, nested paths,
directories, zero-byte files, and exposed metadata where r7z supports it.
r7z does not guarantee byte-identical archive output, matching compression ratios,
or matching compressed stream bytes.

LZHAM and Fast LZMA2 variants from p7zip-zstd are not supported.

## Development

### Setup (NixOS / Nix Flakes)

With `nix flake` support, `direnv`, and the flake:

```bash
direnv allow
```

This loads the dev shell with:
- **Rust toolchain** (stable + clippy + rustfmt)
- **Profiling**: `perf`, `cargo-flamegraph`, `valgrind`
- **Build**: `cargo-nextest`, `gnuplot`, `hyperfine`

Running `cargo flamegraph --bin build_n64 -- /mnt/emulation/n64 /tmp/n64_build.7z` will build a 7z archive from a directory tree and profile the codepath.

### Without Nix

```bash
# Run all tests (unit + integration + p7zip interop)
cargo test

# Linting — must pass before commit
cargo clippy --all-targets --all-features -- -D clippy::pedantic

# Benchmarks (Criterion — parse, open, extract, build)
cargo bench

# Rustdoc
cargo doc --no-deps --open
```

**Interop tests** require `7z` (p7zip) in `PATH`. On macOS: `brew install p7zip`; on Ubuntu: `apt install p7zip-full`.

**CI** runs on GitHub Actions: format check → clippy → p7zip interop tests → rustdoc.

## License

Licensed under the GNU Lesser General Public License, version 2.1 or (at your option) any later version. See [LICENSE](LICENSE) for details.
