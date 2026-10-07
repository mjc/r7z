use crate::files_info::scan_files_info_with_external;
use crate::folder_decode::{ExternalFolderData, FolderLayout, FolderLayouts};
use crate::stream_info::scan_stream_info_with_external;
use crate::{FilesInfo, PackInfo, Property, R7zError, StreamInfo, UnpackInfo};
use bytes::Bytes;
use nom::IResult;
use std::cell::OnceCell;

fn scan_archive_properties(input: &[u8]) -> IResult<&[u8], ()> {
    let mut input = input;
    loop {
        let (i, property_id) = crate::sevenzip_varuint64_decode(input)?;
        input = i;
        if property_id == Property::END as u64 {
            break;
        }

        let (i, size) = crate::sevenzip_varuint64_decode(input)?;
        let sz = usize::try_from(size).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            ))
        })?;
        let (i, _) = nom::bytes::complete::take(sz)(i)?;
        input = i;
    }

    Ok((input, ()))
}

/// The outer `EncodedHeader` block that describes where the compressed main header lives.
///
/// Most 7z archives compress their metadata (the `Header`) using LZMA; the
/// `EncodedHeader` provides the [`PackInfo`] and [`UnpackInfo`] needed to locate
/// and decompress it.
#[derive(Debug, PartialEq)]
pub struct EncodedHeader {
    /// Where the compressed header stream is stored.
    pub pack_info: PackInfo,
    /// How to decompress the header stream.
    pub unpack_info: UnpackInfo,
}

impl EncodedHeader {
    pub(crate) fn folder(&self, metadata_limit: u64) -> Result<FolderLayout<'_>, R7zError> {
        match (
            self.pack_info.num_pack_streams,
            self.pack_info.pack_size.len(),
            self.unpack_info.num_folders,
            self.unpack_info.num_folders_usize(),
        ) {
            (1, 1, 1, 1) => {
                FolderLayouts::preflight(&self.pack_info, &self.unpack_info, None, metadata_limit)?
                    .into_layouts()
                    .next()
                    .ok_or(R7zError::Parse)?
            }
            _ => Err(R7zError::Parse),
        }
    }

    /// Parse an `EncodedHeader` block (pack info + unpack info).
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated or malformed.
    pub fn parse<'a>(input: &'a [u8], backing: &Bytes) -> IResult<&'a [u8], EncodedHeader> {
        let (input, pack_info) = PackInfo::parse(input)?;
        let (input, unpack_info) = UnpackInfo::parse(input, backing)?;
        Ok((
            input,
            EncodedHeader {
                pack_info,
                unpack_info,
            },
        ))
    }
}

pub(crate) enum NextHeader {
    Plain,
    Encoded(Box<EncodedHeader>),
}

impl NextHeader {
    pub(crate) fn parse(backing: &Bytes) -> Result<Self, R7zError> {
        let (input, tag) = Property::parse(backing).map_err(|_| R7zError::Parse)?;
        match tag {
            Property::Header => Ok(Self::Plain),
            Property::EncodedHeader => {
                let (_, encoded) =
                    EncodedHeader::parse(input, backing).map_err(|_| R7zError::Parse)?;
                Ok(Self::Encoded(Box::new(encoded)))
            }
            _ => Err(R7zError::Parse),
        }
    }
}

pub(crate) enum HeaderResolution {
    Complete(Box<Header>),
    RequiresExternalFolders(Box<PendingHeader>),
}

/// A header scan suspended at the section that needs external folder definitions.
/// Its backing bytes and already scanned sections cannot be replaced on resumption.
pub(crate) struct PendingHeader {
    scan: HeaderScan,
    additional: StreamInfo,
}

impl PendingHeader {
    pub(crate) fn resolve_with(
        self,
        decode: impl FnOnce(&StreamInfo) -> Result<crate::folder_decode::VerifiedExternalData, R7zError>,
    ) -> Result<Header, R7zError> {
        let external = decode(&self.additional)?;
        self.scan
            .advance(Some(external.into_data()))?
            .complete_exact()
    }
}

struct HeaderScan {
    data: Bytes,
    position: usize,
    streams_info_range: Option<std::ops::Range<u32>>,
    files_info_range: Option<std::ops::Range<u32>>,
    additional_streams_range: Option<std::ops::Range<u32>>,
    num_files: u64,
}

enum HeaderProgress {
    Complete {
        header: Box<Header>,
        consumed: usize,
    },
    Pending(Box<PendingHeader>),
}

impl HeaderProgress {
    fn complete_exact(self) -> Result<Header, R7zError> {
        match self {
            Self::Complete { header, consumed } if consumed == header.data.len() => Ok(*header),
            _ => Err(R7zError::Parse),
        }
    }

    fn into_resolution(self) -> Result<HeaderResolution, R7zError> {
        match self {
            Self::Pending(pending) => Ok(HeaderResolution::RequiresExternalFolders(pending)),
            complete @ Self::Complete { .. } => complete
                .complete_exact()
                .map(Box::new)
                .map(HeaderResolution::Complete),
        }
    }
}

impl HeaderScan {
    fn new(data: &Bytes) -> Result<Self, R7zError> {
        let (remaining, tag) = Property::parse(data).map_err(|_| R7zError::Parse)?;
        match tag {
            Property::Header => Ok(Self {
                data: data.clone(),
                position: data.len() - remaining.len(),
                streams_info_range: None,
                files_info_range: None,
                additional_streams_range: None,
                num_files: 0,
            }),
            _ => Err(R7zError::Parse),
        }
    }

    fn advance(mut self, external: Option<ExternalFolderData>) -> Result<HeaderProgress, R7zError> {
        // Keep slices independent of the owned scan so it can be suspended without copying bytes.
        let backing = self.data.clone();
        let mut input = backing.get(self.position..).ok_or(R7zError::Parse)?;
        let definitions = external
            .as_ref()
            .map_or(&[][..], ExternalFolderData::as_slice);
        loop {
            let (after_tag, tag) = Property::parse(input).map_err(|_| R7zError::Parse)?;
            match tag {
                Property::END => {
                    let consumed = backing.len() - after_tag.len();
                    return Ok(HeaderProgress::Complete {
                        consumed,
                        header: Box::new(Header {
                            data: self.data,
                            streams_info_range: self.streams_info_range,
                            files_info_range: self.files_info_range,
                            additional_streams_range: self.additional_streams_range,
                            external_folder_data: external.unwrap_or_default(),
                            num_files: self.num_files,
                            streams_cache: OnceCell::new(),
                            files_cache: OnceCell::new(),
                            additional_streams_cache: OnceCell::new(),
                        }),
                    });
                }
                Property::MainStreamsInfo | Property::AdditionalStreamsInfo => {
                    if tag == Property::MainStreamsInfo
                        && external.is_none()
                        && StreamInfo::uses_external_folder_data(after_tag)
                            .map_err(|_| R7zError::Parse)?
                            .1
                    {
                        let range = self
                            .additional_streams_range
                            .as_ref()
                            .ok_or(R7zError::Parse)?;
                        let bytes = backing
                            .get(range.start as usize..range.end as usize)
                            .ok_or(R7zError::Parse)?;
                        let Ok(([], additional)) = StreamInfo::parse(bytes, &backing) else {
                            return Err(R7zError::Parse);
                        };
                        return Ok(HeaderProgress::Pending(Box::new(PendingHeader {
                            scan: self,
                            additional,
                        })));
                    }
                    let (remaining, ()) = scan_stream_info_with_external(after_tag, definitions)
                        .map_err(|_| R7zError::Parse)?;
                    let start = u32::try_from(backing.len() - after_tag.len())
                        .map_err(|_| R7zError::Parse)?;
                    let end = u32::try_from(backing.len() - remaining.len())
                        .map_err(|_| R7zError::Parse)?;
                    match tag {
                        Property::MainStreamsInfo => self.streams_info_range = Some(start..end),
                        _ => self.additional_streams_range = Some(start..end),
                    }
                    input = remaining;
                }
                Property::FilesInfo => {
                    let (remaining, (count, uses_external_data)) =
                        scan_files_info_with_external(input).map_err(|_| R7zError::Parse)?;
                    if external.is_none() && uses_external_data {
                        let range = self
                            .additional_streams_range
                            .as_ref()
                            .ok_or(R7zError::Parse)?;
                        let bytes = backing
                            .get(range.start as usize..range.end as usize)
                            .ok_or(R7zError::Parse)?;
                        let Ok(([], additional)) = StreamInfo::parse(bytes, &backing) else {
                            return Err(R7zError::Parse);
                        };
                        return Ok(HeaderProgress::Pending(Box::new(PendingHeader {
                            scan: self,
                            additional,
                        })));
                    }
                    let start =
                        u32::try_from(backing.len() - input.len()).map_err(|_| R7zError::Parse)?;
                    let end = u32::try_from(backing.len() - remaining.len())
                        .map_err(|_| R7zError::Parse)?;
                    self.files_info_range = Some(start..end);
                    self.num_files = count;
                    input = remaining;
                }
                Property::ArchiveProperties => {
                    input = scan_archive_properties(after_tag)
                        .map_err(|_| R7zError::Parse)?
                        .0;
                }
                _ => {
                    let (remaining, size) =
                        crate::sevenzip_varuint64_decode(after_tag).map_err(|_| R7zError::Parse)?;
                    let size = usize::try_from(size).map_err(|_| R7zError::Parse)?;
                    input = remaining.get(size..).ok_or(R7zError::Parse)?;
                }
            }
            self.position = backing.len() - input.len();
        }
    }
}

/// The fully decoded 7z archive header containing stream and file metadata.
///
/// Metadata byte layouts are checked during [`parse`](Header::parse) via
/// zero-allocation scanners. [`StreamInfo`] and [`FilesInfo`] are constructed
/// on first access, and folder graphs are validated when parsed.
pub struct Header {
    /// Decompressed header bytes (cheap `Arc`-backed clone of the decode buffer).
    data: Bytes,
    /// Byte offset within `data` where `StreamInfo::parse` should start
    /// (after the `MainStreamsInfo` tag).
    streams_info_range: Option<std::ops::Range<u32>>,
    /// Byte offset within `data` where `FilesInfo::parse` should start
    /// (including the `FilesInfo` tag).
    files_info_range: Option<std::ops::Range<u32>>,
    /// Byte range containing `AdditionalStreamsInfo` when present.
    additional_streams_range: Option<std::ops::Range<u32>>,
    /// Decoded additional data streams, indexed by external folder references.
    external_folder_data: ExternalFolderData,
    /// Number of file entries (extracted during scan; avoids a lazy parse just
    /// to read the count).
    num_files: u64,
    /// Lazily-parsed stream descriptor.
    streams_cache: OnceCell<Result<StreamInfo, ()>>,
    /// Lazily-parsed file listing.
    files_cache: OnceCell<Result<FilesInfo, ()>>,
    additional_streams_cache: OnceCell<Result<StreamInfo, ()>>,
}

impl std::fmt::Debug for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Header")
            .field("data_len", &self.data.len())
            .field("streams_info_range", &self.streams_info_range)
            .field("files_info_range", &self.files_info_range)
            .field("additional_streams_range", &self.additional_streams_range)
            .field("num_files", &self.num_files)
            .field("streams_cache", &self.streams_cache)
            .field("files_cache", &self.files_cache)
            .field("additional_streams_cache", &self.additional_streams_cache)
            .field(
                "external_folder_streams",
                &self.external_folder_data.as_slice().len(),
            )
            .finish_non_exhaustive()
    }
}

impl Header {
    pub(crate) fn resolve_archive(backing: &Bytes) -> Result<HeaderResolution, R7zError> {
        HeaderScan::new(backing)?.advance(None)?.into_resolution()
    }

    /// Returns the number of file entries in the archive.
    ///
    /// This is extracted during the initial scan and does not trigger
    /// lazy parsing of [`FilesInfo`].
    #[must_use]
    pub fn num_files(&self) -> u64 {
        self.num_files
    }

    /// Access the stream descriptor, parsing it on first call.
    ///
    /// Returns `None` if the block is absent or fails full parsing. Use
    /// [`try_streams_info`](Self::try_streams_info) to distinguish those cases.
    ///
    #[must_use]
    pub fn streams_info(&self) -> Option<&StreamInfo> {
        self.try_streams_info().ok().flatten()
    }

    /// Access the stream descriptor and return any full-parser validation error.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Parse`] if the metadata fails validation.
    pub fn try_streams_info(&self) -> Result<Option<&StreamInfo>, R7zError> {
        let Some(range) = &self.streams_info_range else {
            return Ok(None);
        };
        let parsed = self.streams_cache.get_or_init(|| {
            let start = range.start as usize;
            let end = range.end as usize;
            self.data.get(start..end).ok_or(()).and_then(|slice| {
                StreamInfo::parse_with_external(
                    slice,
                    &self.data,
                    self.external_folder_data.as_slice(),
                )
                .ok()
                .filter(|(rest, _)| rest.is_empty())
                .map(|(_, value)| value)
                .ok_or(())
            })
        });
        parsed.as_ref().map(Some).map_err(|()| R7zError::Parse)
    }

    /// Access the file listing, parsing it on first call.
    ///
    /// Returns `None` if the block is absent or fails full parsing. Use
    /// [`try_files_info`](Self::try_files_info) to distinguish those cases.
    ///
    #[must_use]
    pub fn files_info(&self) -> Option<&FilesInfo> {
        self.try_files_info().ok().flatten()
    }

    /// Access the file listing and return any full-parser validation error.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Parse`] if the metadata fails validation.
    pub fn try_files_info(&self) -> Result<Option<&FilesInfo>, R7zError> {
        let Some(range) = &self.files_info_range else {
            return Ok(None);
        };
        let parsed = self.files_cache.get_or_init(|| {
            let start = range.start as usize;
            let end = range.end as usize;
            self.data.get(start..end).ok_or(()).and_then(|slice| {
                FilesInfo::parse_with_external(
                    slice,
                    &self.data,
                    self.external_folder_data.as_slice(),
                )
                .ok()
                .filter(|(rest, info)| rest.is_empty() && info.num_files == self.num_files)
                .map(|(_, value)| value)
                .ok_or(())
            })
        });
        parsed.as_ref().map(Some).map_err(|()| R7zError::Parse)
    }

    /// Access the additional metadata streams, if present.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Parse`] if the metadata fails validation.
    pub fn try_additional_streams_info(&self) -> Result<Option<&StreamInfo>, R7zError> {
        let Some(range) = &self.additional_streams_range else {
            return Ok(None);
        };
        let parsed = self.additional_streams_cache.get_or_init(|| {
            let start = range.start as usize;
            let end = range.end as usize;
            self.data.get(start..end).ok_or(()).and_then(|slice| {
                StreamInfo::parse(slice, &self.data)
                    .ok()
                    .filter(|(rest, _)| rest.is_empty())
                    .map(|(_, value)| value)
                    .ok_or(())
            })
        });
        parsed.as_ref().map(Some).map_err(|()| R7zError::Parse)
    }

    pub(crate) fn additional_pack_info(&self) -> Result<Option<&PackInfo>, R7zError> {
        Ok(self
            .try_additional_streams_info()?
            .and_then(|streams| streams.pack_info.as_ref()))
    }

    /// Parse and validate a decompressed 7z header block.
    ///
    /// The full structure is scanned for correctness (tags, sizes, folder
    /// layout) without allocating any interior collections.  The raw bytes
    /// are stored and the expensive [`StreamInfo`] / [`FilesInfo`] structs
    /// are constructed lazily on first access.
    ///
    /// Expects the input to start with the `Property::Header` (0x01) tag.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated, malformed, or does not start with
    /// the `Header` property tag.
    pub fn parse(backing: &Bytes) -> IResult<&[u8], Header> {
        match HeaderScan::new(backing).and_then(|scan| scan.advance(None)) {
            Ok(HeaderProgress::Complete { header, consumed }) => {
                Ok((&backing[consumed..], *header))
            }
            _ => Err(nom::Err::Failure(nom::error::Error::new(
                backing.as_ref(),
                nom::error::ErrorKind::Verify,
            ))),
        }
    }

    /// Parse a header with decoded external folder definition bytes.
    /// Each buffer is one additional data stream, in data-stream index order.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the header or a referenced folder definition is malformed.
    pub fn parse_with_external(
        backing: &Bytes,
        external_folder_data: Vec<Bytes>,
    ) -> IResult<&[u8], Header> {
        Self::parse_with_external_data(
            backing,
            ExternalFolderData::from_supplied(external_folder_data),
        )
    }

    fn parse_with_external_data(
        backing: &Bytes,
        external_folder_data: ExternalFolderData,
    ) -> IResult<&[u8], Header> {
        let scanned =
            HeaderScan::new(backing).and_then(|scan| scan.advance(Some(external_folder_data)));
        match scanned {
            Ok(HeaderProgress::Complete { header, consumed }) => {
                Ok((&backing[consumed..], *header))
            }
            _ => Err(nom::Err::Failure(nom::error::Error::new(
                backing.as_ref(),
                nom::error::ErrorKind::Verify,
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, HeaderResolution, scan_archive_properties};
    use crate::R7zError;
    use bytes::Bytes;

    #[test]
    fn scan_archive_properties_with_long_ids() {
        let input = [
            0xFF, 0x01, 0x00, 0x9A, 0x78, 0x56, 0x34, 0x12, 0x3F, 0x03, 0x00, 0x01, 0x02, 0xFF,
            0x02, 0x00, 0x9A, 0x78, 0x56, 0x34, 0x12, 0x3F, 0x05, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x00, 0xEE,
        ];

        let (rem, ()) = scan_archive_properties(&input).unwrap();

        assert_eq!(rem, &[0xEE]);
    }

    #[test]
    fn parse_header_with_archive_properties() {
        let header = Bytes::from_static(&[
            0x01, 0x02, 0xFF, 0x01, 0x00, 0x9A, 0x78, 0x56, 0x34, 0x12, 0x3F, 0x03, 0x00, 0x01,
            0x02, 0x00, 0x00,
        ]);

        let (rem, parsed) = Header::parse(&header).unwrap();

        assert_eq!(rem, []);
        assert_eq!(parsed.num_files(), 0);
        assert!(matches!(
            Header::resolve_archive(&header),
            Ok(HeaderResolution::Complete(_))
        ));
    }

    #[test]
    fn malformed_lazy_files_info_returns_error_instead_of_panicking() {
        // The scanner skips the zero-length Name property; the full parser
        // rejects it because its external flag is missing.
        let bytes = Bytes::from_static(&[0x01, 0x05, 0x01, 0x11, 0x00, 0x00, 0x00]);
        let (rem, header) = Header::parse(&bytes).unwrap();
        assert_eq!(rem, []);
        assert!(matches!(header.try_files_info(), Err(R7zError::Parse)));
        assert!(header.files_info().is_none());
    }

    #[test]
    fn lazy_header_sections_are_bounded_to_scanned_ranges() {
        let bytes = Bytes::from_static(&[
            0x01, // Header
            0x05, 0x01, 0x11, 0x05, 0x00, b'a', 0x00, 0x00, 0x00, // one file name
            0x00, // END FilesInfo
            0x19, 0x01, 0xAA, // Dummy property with one byte payload
            0x00, // END Header
        ]);
        let (rem, header) = Header::parse(&bytes).unwrap();
        assert_eq!(rem, []);
        assert_eq!(header.try_files_info().unwrap().unwrap().num_files, 1);
    }

    #[test]
    fn files_info_names_resolve_from_external_streams() {
        let bytes = Bytes::from_static(&[
            0x01, // Header
            0x05, 0x01, // one file
            0x11, 0x02, 0x01, 0x00, // Name: external stream 0
            0x00, // END FilesInfo
            0x00, // END Header
        ]);

        let (_, header) =
            Header::parse_with_external(&bytes, vec![Bytes::from_static(&[b'A', 0, 0, 0])])
                .unwrap();

        assert_eq!(
            header.try_files_info().unwrap().unwrap().name(0).as_deref(),
            Some("A")
        );
    }

    #[test]
    fn external_files_metadata_suspends_header_until_additional_streams_decode() {
        let bytes = Bytes::from_static(&[
            0x01, // Header
            0x03, // AdditionalStreamsInfo
            0x06, 0x00, 0x01, 0x09, 0x04, 0x00, // one packed stream, four bytes
            0x07, 0x0b, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0c, 0x04, 0x00, // one Copy folder
            0x08, 0x00, 0x00, // SubStreamsInfo and end AdditionalStreamsInfo
            0x05, 0x01, 0x11, 0x02, 0x01, 0x00, 0x00, // external Name index 0
            0x00, // end Header
        ]);
        let HeaderResolution::RequiresExternalFolders(pending) =
            Header::resolve_archive(&bytes).unwrap()
        else {
            panic!("external file metadata must suspend the header scan");
        };

        let mut budget = crate::resources::OperationBudget::for_metadata_limit(1024);
        let header = pending
            .resolve_with(|additional| {
                crate::folder_decode::ExternalFolderPlan::new(additional, &mut budget)?.decode(
                    |_| {
                        Ok(crate::codec::PackedInput {
                            reader: std::io::Cursor::new([b'A', 0, 0, 0]),
                            size: 4,
                        })
                    },
                    None,
                    &mut budget,
                )
            })
            .unwrap();

        assert_eq!(
            header.try_files_info().unwrap().unwrap().name(0).as_deref(),
            Some("A")
        );
    }

    #[test]
    fn main_streams_info_reads_folder_definition_from_additional_streams() {
        let bytes = Bytes::from_static(&[
            0x01, // Header
            0x03, // AdditionalStreamsInfo
            0x06, 0x00, 0x01, 0x09, 0x03, 0x00, // one packed stream, size 3
            0x07, 0x0b, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0c, 0x03, 0x00, // copy folder
            0x08, 0x00, 0x00, // SubStreamsInfo and end of AdditionalStreamsInfo
            0x04, // MainStreamsInfo
            0x07, 0x0b, 0x01, 0x01, 0x00, 0x0c, 0x03, 0x00, // external folder index 0
            0x00, // end MainStreamsInfo
            0x05, 0x00, 0x00, // empty FilesInfo
            0x00, // end Header
        ]);
        let external_folder = vec![Bytes::from_static(&[0x01, 0x01, 0x00])];

        assert!(Header::parse(&bytes).is_err());
        assert!(Header::parse_with_external(&bytes, Vec::new()).is_err());
        assert!(matches!(
            Header::resolve_archive(&bytes),
            Ok(HeaderResolution::RequiresExternalFolders(_))
        ));
        let (rest, header) = Header::parse_with_external(&bytes, external_folder.clone()).unwrap();
        assert_eq!(rest, b"");
        let streams = header.try_streams_info().unwrap().unwrap();
        let folder = streams
            .unpack_info
            .as_ref()
            .unwrap()
            .parse_folder(0)
            .unwrap();
        assert_eq!(folder.coders.len(), 1);

        let mut invalid_reference = bytes.to_vec();
        let reference = invalid_reference
            .windows(5)
            .position(|window| window == [0x07, 0x0b, 0x01, 0x01, 0x00])
            .unwrap()
            + 4;
        invalid_reference[reference] = 1;
        assert!(
            Header::parse_with_external(&Bytes::from(invalid_reference), external_folder).is_err()
        );
    }

    #[test]
    fn external_resolution_resumes_scanned_sections_and_requires_exact_end() {
        let bytes = Bytes::from_static(&[
            0x01, // Header
            0x05, 0x01, 0x11, 0x05, 0x00, b'a', 0x00, 0x00, 0x00,
            0x00, // FilesInfo before dependency
            0x03, // AdditionalStreamsInfo
            0x06, 0x00, 0x01, 0x09, 0x03, 0x00, 0x07, 0x0b, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0c,
            0x03, 0x00, 0x08, 0x00, 0x00,
            0x04, // MainStreamsInfo using external folder index zero
            0x07, 0x0b, 0x01, 0x01, 0x00, 0x0c, 0x03, 0x00, 0x00, 0x00, // END Header
        ]);
        let resolve = |bytes: &Bytes| {
            let HeaderResolution::RequiresExternalFolders(pending) =
                Header::resolve_archive(bytes)?
            else {
                panic!("external definitions must suspend the scan");
            };
            let mut budget = crate::resources::OperationBudget::for_metadata_limit(1024);
            pending.resolve_with(|additional| {
                crate::folder_decode::ExternalFolderPlan::new(additional, &mut budget)?.decode(
                    |_| {
                        Ok(crate::codec::PackedInput {
                            reader: std::io::Cursor::new([1, 1, 0]),
                            size: 3,
                        })
                    },
                    None,
                    &mut budget,
                )
            })
        };
        let header = resolve(&bytes).unwrap();
        assert_eq!(header.try_files_info().unwrap().unwrap().num_files, 1);
        assert_eq!(
            header
                .try_streams_info()
                .unwrap()
                .unwrap()
                .unpack_info
                .as_ref()
                .unwrap()
                .parse_folder(0)
                .unwrap()
                .coders
                .len(),
            1
        );

        let mut trailing = bytes.to_vec();
        trailing.push(0xff);
        assert!(matches!(
            resolve(&Bytes::from(trailing)),
            Err(R7zError::Parse)
        ));
    }

    #[test]
    fn archive_resolution_rejects_trailing_bytes_and_missing_additional_streams() {
        let trailing = Bytes::from_static(&[0x01, 0x00, 0xff]);
        assert!(matches!(
            Header::resolve_archive(&trailing),
            Err(R7zError::Parse)
        ));

        let missing_additional = Bytes::from_static(&[
            0x01, 0x04, // Header, MainStreamsInfo
            0x07, 0x0b, 0x01, 0x01, 0x00, // one external folder, buffer index zero
            0x0c, 0x03, 0x00, 0x00, // unpack size, end of MainStreamsInfo
            0x00, // end of Header
        ]);
        assert!(matches!(
            Header::resolve_archive(&missing_additional),
            Err(R7zError::Parse)
        ));
    }

    #[test]
    fn archive_resolution_accepts_empty_file_listing() {
        let header = Bytes::from_static(&[0x01, 0x05, 0x00, 0x11, 0x01, 0x00, 0x00, 0x00]);
        assert!(matches!(
            Header::resolve_archive(&header),
            Ok(HeaderResolution::Complete(_))
        ));
    }
}

/// The 32-byte fixed-size header at the start of every 7z archive.
///
/// Contains the magic bytes, format version, and the location and CRC of the
/// next header (either an [`EncodedHeader`] or a plain `Header`).
#[derive(Debug, PartialEq, Eq)]
pub struct SignatureHeader {
    /// Magic bytes: `37 7a bc af 27 1c`.
    pub signature: [u8; 6],
    /// Format major version (always `0x00`).
    pub major_version: u8,
    /// Format minor version (typically `0x04`).
    pub minor_version: u8,
    /// CRC32 of the 20-byte start-header fields that follow.
    pub start_header_crc: u32,
    /// Byte offset from the end of this 32-byte header to the next header block.
    pub next_header_offset: u64,
    /// Byte length of the next header block.
    pub next_header_size: u64,
    /// CRC32 of the next header block.
    pub next_header_crc: u32,
}

impl SignatureHeader {
    /// Validate the CRC over the 20-byte `StartHeader` (offset+size+crc).
    ///
    /// The `start_header_crc` field covers:
    /// `[next_header_offset (8), next_header_size (8), next_header_crc (4)]`.
    ///
    /// # Errors
    ///
    /// Returns [`R7zError::Crc`] if the computed CRC does not match `start_header_crc`.
    pub fn validate_start_header_crc(&self) -> Result<(), R7zError> {
        let mut buf = [0u8; 20];
        buf[..8].copy_from_slice(&self.next_header_offset.to_le_bytes());
        buf[8..16].copy_from_slice(&self.next_header_size.to_le_bytes());
        buf[16..].copy_from_slice(&self.next_header_crc.to_le_bytes());
        let computed = crc32fast::hash(&buf);
        if computed == self.start_header_crc {
            Ok(())
        } else {
            Err(R7zError::Crc)
        }
    }

    /// Parse the 32-byte `SignatureHeader` from the start of a 7z archive.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is shorter than 32 bytes or malformed.
    ///
    /// # Panics
    ///
    /// Never panics; all slice-to-array conversions are guarded by the `len < 32` check above.
    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureHeader> {
        if input.len() < 32 {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Eof,
            )));
        }
        // 7z signature header layout (32 bytes):
        //  [0..6]   magic bytes
        //  [6]      major_version
        //  [7]      minor_version
        //  [8..12]  start_header_crc  (u32 le)
        //  [12..20] next_header_offset (u64 le)
        //  [20..28] next_header_size   (u64 le)
        //  [28..32] next_header_crc   (u32 le)
        let signature: [u8; 6] = input[0..6].try_into().expect("slice is 6 bytes");
        let major_version = input[6];
        let minor_version = input[7];
        let start_header_crc =
            u32::from_le_bytes(input[8..12].try_into().expect("slice is 4 bytes"));
        let next_header_offset =
            u64::from_le_bytes(input[12..20].try_into().expect("slice is 8 bytes"));
        let next_header_size =
            u64::from_le_bytes(input[20..28].try_into().expect("slice is 8 bytes"));
        let next_header_crc =
            u32::from_le_bytes(input[28..32].try_into().expect("slice is 4 bytes"));
        Ok((
            &input[32..],
            SignatureHeader {
                signature,
                major_version,
                minor_version,
                start_header_crc,
                next_header_offset,
                next_header_size,
                next_header_crc,
            },
        ))
    }
}
