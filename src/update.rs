//! APIs for rewriting an archive while retaining compressed data.

/// Version 1 of the archive update API.
pub mod v1 {
    pub use crate::{
        ArchiveEntryIndex, FolderIndex, PreservedArchiveEntry, PreservedEntryStream,
        RawFolderBlock, RawFolderHandle, write_archive_update,
    };
}
