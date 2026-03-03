# r7z

A pure-Rust library for reading and writing `.7z` archives.

[![Crates.io](https://img.shields.io/crates/v/r7z)](https://crates.io/crates/r7z)
[![docs.rs](https://docs.rs/r7z/badge.svg)](https://docs.rs/r7z)
[![License: LGPL-2.1-or-later](https://img.shields.io/badge/license-LGPL--2.1--or--later-blue)](LICENSE)

r7z implements the 7z binary format spec in pure Rust using `nom` parser combinators. It reads archives created by p7zip / 7-Zip and can build new archives that those tools can open. No C FFI, no unsafe liblzma — compression is handled by the `lzma-rust2` crate.

## Features

- **Read** LZMA and LZMA2 compressed `.7z` archives (solid and multi-file)
- **Write** solid `.7z` archives with LZMA or LZMA2 compression
- **CRC32 validation** on both the signature start-header and header/data blocks
- **p7zip / 7-Zip interoperability** — read p7zip archives, write archives p7zip can open
- Supports **EncodedHeader** format (compressed metadata; most p7zip archives) and **uncompressed Header** format
- Custom **7z varint** encoding/decoding (`sevenzip_varuint64_encode/decode`) — not LEB128
- Pure Rust — no `unsafe`, no C dependencies

## Installation

```toml
[dependencies]
r7z = "0.1"
```

**MSRV**: Rust 2021 edition (1.56+).

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

// Extract first file to an in-memory buffer
let data = archive.extract_to_memory(0)?;
println!("{} bytes", data.len());
```

### Reading — extract all to disk

```rust
archive.extract_all(Path::new("/tmp/output"))?;
```

### Building a single-file LZMA archive

```rust
use r7z::ArchiveBuilder;

let bytes = ArchiveBuilder::new()
    .add_file("hello.txt", b"Hello, world!")
    .build()?;
std::fs::write("out.7z", &bytes)?;
```

### Building a multi-file LZMA2 archive

```rust
use r7z::{ArchiveBuilder, Codec};

let bytes = ArchiveBuilder::new()
    .add_file("alpha.txt", b"AAAA")
    .add_file("beta/beta.txt", b"BBBBBBBB")
    .compression(Codec::Lzma2)
    .build()?;
```

### Streaming builder — process large archives without loading all data into memory

```rust
use r7z::build_streaming;
use std::fs::File;
use std::io::BufWriter;

let out_file = BufWriter::new(File::create("large.7z")?);  
let entries = vec![
    ("file1.bin".to_string(), File::open("file1.bin")?),
    ("file2.bin".to_string(), File::open("file2.bin")?),
].into_iter();

build_streaming(entries, out_file)?;  // Pipes files through compressor directly to disk
```

### Parsing from an in-memory buffer

```rust
let raw: Vec<u8> = std::fs::read("example.7z")?;
let archive = Archive::from_bytes(raw)?;
```

## API Reference

### `Archive` — Reading archives

| Method | Returns | Description |
|--------|---------|-------------|
| `Archive::open(path: &Path)` | `Result<Archive, R7zError>` | Read and fully decode a `.7z` file from disk |
| `Archive::from_bytes(data: Vec<u8>)` | `Result<Archive, R7zError>` | Decode a `.7z` from an in-memory buffer |
| `archive.num_files()` | `usize` | Number of files (excluding directories and empty entries) |
| `archive.files_info()` | `Option<&FilesInfo>` | File names, sizes, and attributes |
| `archive.streams_info()` | `Option<&StreamInfo>` | Raw stream/pack metadata |
| `archive.extract_to_memory(index: usize)` | `Result<Vec<u8>, R7zError>` | Decompress file at `index` (0-based) |
| `archive.extract_all(dest: &Path)` | `Result<(), R7zError>` | Extract all files; creates subdirectories as needed |

### `ArchiveBuilder` — Writing archives

Builder pattern — all methods consume `self` and return `Self` for chaining:

| Method | Description |
|--------|-------------|
| `ArchiveBuilder::new()` | Create an empty builder (LZMA compression default) |
| `.add_file(name: &str, data: &[u8])` | Queue a file with its content |
| `.compression(codec: Codec)` | Set compression (`Codec::Lzma` or `Codec::Lzma2`) |
| `.build()` | Produce the final `.7z` bytes as `Result<Vec<u8>, R7zError>` |

The builder uses **solid compression**: all files are concatenated into one stream before compressing, which gives better ratios for many small files.

### `build_streaming` — Streaming builder for large archives

For archives too large to fit in memory, use the streaming builder:

```rust
pub fn build_streaming<W, I, R>(entries: I, out: W) -> Result<(), R7zError>
where
    W: Write + Seek,
    I: IntoIterator<Item = (String, R)>,
    R: Read,
```

Each `entry` (filename, `impl Read`) is piped through the LZMA2 compressor directly to the output file. Neither all input data nor all compressed output is held in memory simultaneously — only one file at a time.

### `Codec` — Compression algorithms

```rust
pub enum Codec {
    Lzma,   // Classic LZMA  — codec ID [0x03, 0x01, 0x01]
    Lzma2,  // Modern LZMA2  — codec ID [0x21]
}
```

`Lzma2` is the p7zip default and generally gives slightly better compression ratios.

### `R7zError` — Error variants

| Variant | Meaning |
|---------|---------|
| `R7zError::Parse` | Malformed archive — not valid 7z binary |
| `R7zError::InvalidProperty(u8)` | Unknown property tag byte in header |
| `R7zError::UnsupportedCodec(Vec<u8>)` | Codec ID not implemented (e.g., Deflate, BZip2) |
| `R7zError::Crc` | CRC32 mismatch — data corruption detected |
| `R7zError::Io(std::io::Error)` | File I/O failure |
| `R7zError::Decompression` | LZMA/LZMA2 stream could not be decoded |

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
| LZMA2 compression | Read + Write |
| BCJ x86 filter (passthrough) | Read (filter not applied) |
| Uncompressed Copy codec | Read |
| EncodedHeader archives (p7zip default) | Read |
| Uncompressed Header archives | Read + Write |
| Solid archives | Read + Write |
| Multi-file archives | Read + Write |
| Deflate / BZip2 / PPMd | Not supported |
| Encrypted archives (AES-256) | Not supported |

**7z specification:** [7zFormat.txt](https://github.com/google/omaha/blob/master/third_party/lzma/files/7zFormat.txt)

Archives written by r7z use format version 0.4 (standard), are in uncompressed-Header format, and are fully readable by 7-Zip ≥ 9.x and p7zip.

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

Running `cargo flamegraph --bin build_n64 -- /mnt/emulation/n64 /tmp/n64_build.7z` will build a streaming 7z archive from a directory tree and profile the codepath.

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
