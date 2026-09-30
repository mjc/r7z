# 0.2 API changes

The 0.2 API puts archive operations at the crate root and format-level parser
types in `r7z::raw`. Methods that expose parsed 7z structures now say `raw_`.
Archive header fields are private; raw inspection uses borrowed accessors.

| 0.1 | 0.2 |
|---|---|
| `r7z::Folder`, `r7z::CoderInfo` | `r7z::raw::{Folder, CoderInfo}` |
| `r7z::FilesInfo`, `r7z::StreamInfo` | `r7z::raw::{FilesInfo, StreamInfo}` |
| `r7z::Header`, `r7z::SignatureHeader`, `r7z::EncodedHeader` | `r7z::raw::{Header, SignatureHeader, EncodedHeader}` |
| `r7z::PackInfo`, `r7z::UnpackInfo`, `r7z::Property` | `r7z::raw::{PackInfo, UnpackInfo, Property}` |
| `r7z::ArchiveMetadata` | `r7z::raw::ArchiveMetadata` |
| `r7z::RawEntryName` | `r7z::raw::RawEntryName` |
| `r7z::sevenzip_varuint64_encode` and `decode` | `r7z::raw::sevenzip_varuint64_encode` and `decode` |
| `r7z::usize_cap`, `r7z::IResult` | `r7z::raw::{usize_cap, IResult}` |
| `r7z::decompress_folder` and `decompress_folder_with_password` | `r7z::raw::{decompress_folder, decompress_folder_with_password}` |
| `archive.files_info()` / `archive.streams_info()` | `archive.entries()` for normal use; `archive.raw_files_info()` / `archive.raw_streams_info()` for format tools |
| `archive.header`, `archive.signature`, `archive.encoded_header` | `archive.raw_header()`, `archive.raw_signature()`, `archive.raw_encoded_header()` |
| `archive.raw_folder_block(index)` | `archive.raw_folder(r7z::update::v1::FolderIndex::new(index))` |
| `FolderIndex`, preserved-folder types and writer functions | `r7z::update::v1` |
| entry-index parameters and fields using `usize` | `r7z::ArchiveEntryIndex::new(index)` |
| `ArchiveEntryIndex` for raw updates | `r7z::update::v1::ArchiveEntryIndex` (same type as the root export) |

`ArchiveEntryInfo` carries the entry's display name, original UTF-16 name, type,
and safe normalized path. Its `index` and all high-level entry-index parameters
use `ArchiveEntryIndex`; listing folder references use `FolderIndex`. Construct
these explicitly from zero-based positions. Use `r7z::raw` only when code needs
the 7z format representation itself.

Raw update inputs are tied to the archive that produced them. Use handles from
`Archive::raw_folder` with the versioned update API; do not construct a handle
from a folder index or reuse one with another archive. Stream reads verify
checksums as the requested folder is drained. Call `ArchiveReadSession::finish`
when the final folder must be verified; dropping a session leaves unread data
unverified.
