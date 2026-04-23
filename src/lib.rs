//! # r7z
//!
//! A pure-Rust library for reading and writing 7z (`.7z`) archives.
//!
//! ## Reading
//!
//! ```rust,no_run
//! let archive = r7z::Archive::open(std::path::Path::new("my.7z")).unwrap();
//! println!("{} files", archive.num_files());
//! let bytes = archive.extract_to_memory(0).unwrap();
//! ```
//!
//! Password-protected archives can be opened and extracted with the password-aware
//! APIs:
//!
//! ```rust,no_run
//! let archive =
//!     r7z::Archive::open_with_password(std::path::Path::new("secret.7z"), Some("pass")).unwrap();
//! let bytes = archive.extract_to_memory_with_password(0, Some("pass")).unwrap();
//! ```
//!
//! `Archive::open` is file-backed by default. Generic reader input must be
//! seekable because 7z stores stream data and authoritative metadata in
//! different file regions:
//!
//! ```compile_fail
//! struct NetworkStream;
//!
//! impl std::io::Read for NetworkStream {
//!     fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
//!         Ok(0)
//!     }
//! }
//!
//! let _archive = r7z::Archive::from_reader(NetworkStream).unwrap();
//! ```
//!
//! `Archive::extract_all` rejects unsafe paths such as absolute names, parent
//! directory traversal, and Windows-prefixed paths. Directory entries and zero-byte
//! files are handled distinctly.
//!
//! ## Writing
//!
//! ```rust,no_run
//! let bytes = r7z::ArchiveBuilder::new()
//!     .add_file("hello.txt", b"Hello, world!")
//!     .build()
//!     .unwrap();
//! std::fs::write("out.7z", bytes).unwrap();
//! ```
//!
//! For file-backed or multi-folder writes, use [`ArchiveWriter`]. [`EntryMeta`] can
//! store optional timestamps and attributes. [`Codec::Lzma2Bcj`] applies
//! the x86 BCJ filter before LZMA2 compression for executable-like payloads.

extern crate num;
#[macro_use]
extern crate num_derive;

mod aes;
mod archive;
pub mod bcj;
mod bcj2;
mod byte_swap;
mod codec;
mod coder_info;
mod delta;
mod error;
mod files_info;
mod folder;
mod headers;
mod method;
mod pack_info;
mod parsers;
mod property;
mod stream_info;
mod write;

pub use archive::{
    Archive, ArchiveListing, ArchiveListingEntry, ArchiveMetadata, ArchiveOpenOptions,
    ArchiveStorageMode, ListingEntryKind, RawFolderBlock,
};
pub use codec::{
    CODEC_AES_256_SHA_256, CODEC_BCJ_ARM, CODEC_BCJ_ARM_THUMB, CODEC_BCJ_IA64, CODEC_BCJ_PPC,
    CODEC_BCJ_SPARC, CODEC_BCJ_X86, CODEC_BCJ2, CODEC_BZIP2, CODEC_COPY, CODEC_DEFLATE,
    CODEC_DEFLATE64, CODEC_DELTA, CODEC_LZMA, CODEC_LZMA2, CODEC_PPMD, CODEC_SWAP2, CODEC_SWAP4,
    decompress_folder, decompress_folder_with_password,
};
pub use coder_info::CoderInfo;
pub use error::R7zError;
pub use files_info::{EntryType, FilesInfo};
pub use folder::Folder;
pub use headers::{EncodedHeader, Header, SignatureHeader};
pub use method::{
    ALL_METHODS, MethodKind, P7ZIP_ORACLE_SHA, SevenZMethod, method_from_id, method_from_name,
};
pub use pack_info::{PackInfo, UnpackInfo};
pub use parsers::*;
pub use property::{Property, find_next_property_id};
pub use stream_info::{StreamInfo, SubstreamInfo};
pub use write::{
    ArchiveBuilder, ArchiveEntry, ArchiveOptions, ArchiveWriter, Codec, CompressionLevel,
    CompressionOptions, EncryptionOptions, EntryKind, EntryMeta, HeaderMode, SolidMode, SpoolMode,
    StreamingOptions, VolumeOptions, build_streaming, build_streaming_to_writer,
    build_streaming_volumes, build_streaming_with_options,
};

// Re-export nom's IResult for convenience in integration tests
pub use nom::IResult;
