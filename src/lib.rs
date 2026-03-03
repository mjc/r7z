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
//! ## Writing
//!
//! ```rust,no_run
//! let bytes = r7z::ArchiveBuilder::new()
//!     .add_file("hello.txt", b"Hello, world!")
//!     .build()
//!     .unwrap();
//! std::fs::write("out.7z", bytes).unwrap();
//! ```

extern crate num;
#[macro_use]
extern crate num_derive;

mod archive;
mod builder;
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

pub use archive::{Archive, ArchiveMetadata};
pub use builder::{build_streaming, ArchiveBuilder, Codec};
pub use codec::{decompress_folder, CODEC_BCJ_X86, CODEC_COPY, CODEC_LZMA, CODEC_LZMA2};
pub use coder_info::CoderInfo;
pub use error::R7zError;
pub use files_info::FilesInfo;
pub use folder::Folder;
pub use headers::{EncodedHeader, Header, SignatureHeader};
pub use pack_info::{PackInfo, UnpackInfo};
pub use parsers::*;
pub use property::{find_next_property_id, Property};
pub use stream_info::{StreamInfo, SubstreamInfo};

// Re-export nom's IResult for convenience in integration tests
pub use nom::IResult;
