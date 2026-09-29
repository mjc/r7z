//! APIs for rewriting an archive while retaining compressed data.

/// Version 1 of the archive update API.
pub mod v1 {
    pub use crate::archive::{ArchiveEntryIndex, FolderIndex, RawFolderBlock, RawFolderHandle};
    pub use crate::write::{
        PreservedArchiveEntry, PreservedEntryStream, build_archive_with_preserved_folders,
        write_archive_update, write_archive_with_preserved_folders,
    };
}
