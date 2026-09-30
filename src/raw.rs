//! Low-level 7z format structures and parsers.
//!
//! Most applications should use [`crate::Archive`], its entry metadata, and the
//! writer APIs. This module exposes format-level data for tools that need direct
//! access to parsed 7z structures.

pub use crate::archive::ArchiveMetadata;
pub use crate::codec::{
    decompress_folder, decompress_folder_with_password, decompress_folder_with_password_and_sizes,
};
pub use crate::coder_info::CoderInfo;
pub use crate::entries::RawEntryName;
pub use crate::files_info::FilesInfo;
pub use crate::folder::Folder;
pub use crate::headers::{EncodedHeader, Header, SignatureHeader};
pub use crate::pack_info::{PackInfo, UnpackInfo};
pub use crate::parsers::{sevenzip_varuint64_decode, sevenzip_varuint64_encode, usize_cap};
pub use crate::property::{Property, find_next_property_id};
pub use crate::stream_info::{StreamInfo, SubstreamInfo};
pub use nom::IResult;
