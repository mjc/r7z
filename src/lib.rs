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
mod codec;
mod coder_info;
mod error;
mod files_info;
mod folder;
mod headers;
mod pack_info;
mod parsers;
mod property;
mod stream_info;
mod write;

pub use archive::{Archive, ArchiveMetadata};
pub use codec::{
    decompress_folder, decompress_folder_with_password, CODEC_AES_256_SHA_256, CODEC_BCJ_X86,
    CODEC_COPY, CODEC_LZMA, CODEC_LZMA2,
};
pub use coder_info::CoderInfo;
pub use error::R7zError;
pub use files_info::FilesInfo;
pub use folder::Folder;
pub use headers::{EncodedHeader, Header, SignatureHeader};
pub use pack_info::{PackInfo, UnpackInfo};
pub use parsers::*;
pub use property::{find_next_property_id, Property};
pub use stream_info::{StreamInfo, SubstreamInfo};
pub use write::{
    build_streaming, ArchiveBuilder, ArchiveEntry, ArchiveOptions, ArchiveWriter, Codec,
    EncryptionOptions, EntryKind, EntryMeta, HeaderMode,
};

// Re-export nom's IResult for convenience in integration tests
pub use nom::IResult;
