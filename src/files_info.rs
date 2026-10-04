use crate::{
    Property,
    entries::EntryKind,
    parsers::{bitmap_is_set, bytes_subslice},
    sevenzip_varuint64_decode,
};
use bytes::Bytes;
use nom::{IResult, bytes::complete::take};

/// Decode UTF-16LE, replacing unpaired surrogates with U+FFFD.
pub(crate) fn decode_name(data: &[u8]) -> String {
    char::decode_utf16(
        data.chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])),
    )
    .map(|character| character.unwrap_or(char::REPLACEMENT_CHARACTER))
    .collect()
}

/// File listing metadata from the 7z `FilesInfo` block.
#[derive(Debug, PartialEq, Eq)]
pub struct FilesInfo {
    /// Total number of entries (files + directories).
    pub num_files: u64,
    /// Raw UTF-16LE null-terminated name block (empty = no Name property present).
    name_data: Bytes,
    /// Creation timestamps as Windows FILETIME values (100ns intervals since 1601-01-01).
    pub ctimes: Vec<Option<u64>>,
    /// Last-access timestamps as Windows FILETIME values (100ns intervals since 1601-01-01).
    pub atimes: Vec<Option<u64>>,
    /// Last-modified timestamps as Windows FILETIME values (100ns intervals since 1601-01-01).
    pub mtimes: Vec<Option<u64>>,
    /// Per-entry start positions.
    pub start_positions: Vec<Option<u64>>,
    /// Windows file attributes per entry.
    pub attributes: Vec<Option<u32>>,
    /// Raw bitmap of empty-stream flags (empty = all false). Bit `i` = entry `i` has no data stream.
    pub empty_streams: Bytes,
    /// Raw bitmap of empty-file flags (empty = all false). Bit `i` = entry `i` is a zero-byte file.
    pub empty_files: Bytes,
    /// Raw bitmap of anti-item flags (empty = all false). Bit `i` = entry `i` is an anti-item.
    pub anti_items: Bytes,
    /// Mapping from file index to ordinal within the empty-stream bitmap payloads.
    empty_stream_ordinals: Vec<Option<usize>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryType {
    File,
    Directory,
    EmptyFile,
    Anti,
    Symlink,
    /// A symlink entry with no data stream for its target.
    EmptySymlink,
}

pub(crate) struct FilesInfoNameSlices {
    data: Bytes,
    count: usize,
    position: usize,
    index: usize,
}

impl Iterator for FilesInfoNameSlices {
    type Item = Option<Bytes>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        self.index += 1;
        if self.data.is_empty() || self.position + 1 >= self.data.len() {
            return Some(None);
        }
        let start = self.position;
        while self.position + 1 < self.data.len() {
            let is_null = self.data[self.position] == 0 && self.data[self.position + 1] == 0;
            self.position += 2;
            if is_null {
                return Some(Some(self.data.slice(start..self.position - 2)));
            }
        }
        Some(None)
    }
}

impl FilesInfo {
    /// Decode the name of entry `i` on demand (UTF-16LE, null-terminated).
    pub fn name(&self, i: usize) -> Option<String> {
        self.name_slices().nth(i)?.as_deref().map(decode_name)
    }

    /// Iterator over all decoded names (in archive order).
    ///
    /// # Panics
    ///
    /// Panics if `num_files` exceeds `usize::MAX` (impossible in practice).
    pub fn names(&self) -> impl Iterator<Item = String> + '_ {
        self.name_slices()
            .filter_map(|name| name.as_deref().map(decode_name))
    }

    pub(crate) fn name_slices(&self) -> FilesInfoNameSlices {
        FilesInfoNameSlices {
            data: self.name_data.clone(),
            count: usize::try_from(self.num_files).expect("num_files fits in usize"),
            position: 0,
            index: 0,
        }
    }

    /// Returns `true` if entry `i` has no data stream (directory or zero-byte file).
    pub fn is_empty_stream(&self, i: usize) -> bool {
        bitmap_is_set(&self.empty_streams, i)
    }

    /// Returns `true` if entry `i` is a genuine zero-byte file.
    pub fn is_empty_file(&self, i: usize) -> bool {
        let Some(empty_idx) = self.empty_stream_ordinal(i) else {
            return false;
        };
        bitmap_is_set(&self.empty_files, empty_idx)
    }

    /// Returns `true` if entry `i` is a directory.
    pub fn is_directory(&self, i: usize) -> bool {
        matches!(self.entry_kind(i), EntryKind::Directory)
    }

    /// Returns `true` if entry `i` is an anti-item.
    pub fn is_anti(&self, i: usize) -> bool {
        let Some(empty_idx) = self.empty_stream_ordinal(i) else {
            return false;
        };
        bitmap_is_set(&self.anti_items, empty_idx)
    }

    pub fn is_symlink(&self, i: usize) -> bool {
        self.attributes
            .get(i)
            .copied()
            .flatten()
            .is_some_and(|attrs| ((attrs >> 16) & 0o170_000) == 0o120_000)
    }

    /// Classify an entry using anti-item flags, stream presence, and Unix mode.
    /// Symlink mode takes precedence over directory flags; anti-items take precedence
    /// over both. Symlinks without a stream return [`EntryType::EmptySymlink`].
    pub fn entry_type(&self, i: usize) -> EntryType {
        self.entry_kind(i).entry_type()
    }

    pub(crate) fn entry_kind(&self, i: usize) -> EntryKind<()> {
        match (
            self.is_anti(i),
            self.is_empty_stream(i),
            self.is_symlink(i),
            self.is_empty_file(i),
        ) {
            (true, _, _, _) => EntryKind::Anti,
            (false, false, false, _) => EntryKind::File(()),
            (false, false, true, _) => EntryKind::Symlink(()),
            (false, true, true, _) => EntryKind::EmptySymlink,
            (false, true, false, true) => EntryKind::EmptyFile,
            (false, true, false, false) => EntryKind::Directory,
        }
    }

    fn empty_stream_ordinal(&self, i: usize) -> Option<usize> {
        self.empty_stream_ordinals.get(i).copied().flatten()
    }

    /// Parse a `FilesInfo` block from the header stream.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated, malformed, or does not start
    /// with the `FilesInfo` property tag, or if retained property bytes are not
    /// contained in `backing`. Repeated supported properties, mismatched name
    /// counts, and external references with invalid indices or payload sizes fail.
    pub fn parse<'a>(input: &'a [u8], backing: &Bytes) -> IResult<&'a [u8], FilesInfo> {
        Self::parse_with_external(input, backing, &[])
    }

    pub(crate) fn parse_with_external<'a>(
        input: &'a [u8],
        backing: &Bytes,
        external_data: &[Bytes],
    ) -> IResult<&'a [u8], FilesInfo> {
        let orig_input = input;
        let (input, tag) = Property::parse(input)?;
        if tag != Property::FilesInfo {
            return Err(nom::Err::Failure(nom::error::Error::new(
                orig_input,
                nom::error::ErrorKind::Satisfy,
            )));
        }

        let (input, num_files) = sevenzip_varuint64_decode(input)?;
        let n = usize::try_from(num_files).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            ))
        })?;

        // Lazy init: no allocations until the relevant property is seen.
        let mut files = Self {
            num_files,
            name_data: Bytes::new(),
            ctimes: Vec::new(),
            atimes: Vec::new(),
            mtimes: Vec::new(),
            start_positions: Vec::new(),
            attributes: Vec::new(),
            empty_streams: Bytes::new(),
            empty_files: Bytes::new(),
            anti_items: Bytes::new(),
            empty_stream_ordinals: Vec::new(),
        };
        let mut seen_properties = SeenFileProperties::default();
        let mut input = input;

        loop {
            let (i, tag) = Property::parse(input)?;
            input = i;
            if tag == Property::END {
                break;
            }
            seen_properties.register(tag, input)?;
            let (remaining, size) = sevenzip_varuint64_decode(input)?;
            let size = usize::try_from(size).map_err(|_| {
                nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::TooLarge,
                ))
            })?;
            let (remaining, block) = take(size)(remaining)?;
            match tag {
                Property::Name => {
                    files.name_data = property_data(input, block, backing, external_data)?;
                    validate_name_data(&files.name_data, n, input)?;
                }
                Property::CTime | Property::ATime | Property::MTime | Property::StartPos => {
                    let property = DefinedProperty::parse(input, block, n, backing, external_data)?;
                    let values = parse_defined_u64_values(
                        input,
                        property.all_defined,
                        property.bitmap,
                        &property.values,
                        n,
                    )?;
                    match tag {
                        Property::CTime => files.ctimes = values,
                        Property::ATime => files.atimes = values,
                        Property::MTime => files.mtimes = values,
                        Property::StartPos => files.start_positions = values,
                        _ => unreachable!(),
                    }
                }
                Property::Attributes => {
                    let property = DefinedProperty::parse(input, block, n, backing, external_data)?;
                    files.attributes = parse_defined_u32_values(
                        input,
                        property.all_defined,
                        property.bitmap,
                        &property.values,
                        n,
                    )?;
                }
                Property::EmptyStream => {
                    files.empty_streams = bytes_subslice(backing, block, input)?;
                }
                Property::EmptyFile => {
                    files.empty_files = bytes_subslice(backing, block, input)?;
                }
                Property::Anti => {
                    files.anti_items = bytes_subslice(backing, block, input)?;
                }
                _ => {}
            }
            input = remaining;
        }

        files.empty_stream_ordinals = empty_stream_ordinals(&files.empty_streams, n);
        Ok((input, files))
    }
}

fn empty_stream_ordinals(empty_streams: &[u8], num_files: usize) -> Vec<Option<usize>> {
    let mut next_empty = 0usize;
    (0..num_files)
        .map(|i| {
            if bitmap_is_set(empty_streams, i) {
                let ordinal = next_empty;
                next_empty += 1;
                Some(ordinal)
            } else {
                None
            }
        })
        .collect()
}

#[derive(Default)]
struct SeenFileProperties(u32);

impl SeenFileProperties {
    fn register<'a>(&mut self, tag: Property, input: &'a [u8]) -> Result<(), ParseError<'a>> {
        let property_mask = match tag {
            Property::Name
            | Property::CTime
            | Property::ATime
            | Property::MTime
            | Property::StartPos
            | Property::Attributes
            | Property::EmptyStream
            | Property::EmptyFile
            | Property::Anti => Some(1u32 << tag as u8),
            _ => None,
        };
        if let Some(property_mask) = property_mask {
            if self.0 & property_mask != 0 {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Verify,
                )));
            }
            self.0 |= property_mask;
        }
        Ok(())
    }
}

type ParseError<'a> = nom::Err<nom::error::Error<&'a [u8]>>;
struct DefinedProperty<'a> {
    all_defined: u8,
    bitmap: &'a [u8],
    values: Bytes,
}

impl<'b> DefinedProperty<'b> {
    fn parse<'a>(
        error_input: &'a [u8],
        block: &'b [u8],
        num_values: usize,
        backing: &Bytes,
        external_data: &[Bytes],
    ) -> Result<Self, ParseError<'a>> {
        let (&all_defined, payload) = block.split_first().ok_or_else(|| {
            nom::Err::Error(nom::error::Error::new(
                error_input,
                nom::error::ErrorKind::Eof,
            ))
        })?;
        let bitmap_len = if all_defined == 0 {
            num_values.div_ceil(8)
        } else {
            0
        };
        let (bitmap, payload) = payload.split_at_checked(bitmap_len).ok_or_else(|| {
            nom::Err::Error(nom::error::Error::new(
                error_input,
                nom::error::ErrorKind::Eof,
            ))
        })?;
        let values = property_data(error_input, payload, backing, external_data)?;
        Ok(Self {
            all_defined,
            bitmap,
            values,
        })
    }
}

fn property_data<'a>(
    error_input: &'a [u8],
    payload: &[u8],
    backing: &Bytes,
    external_data: &[Bytes],
) -> Result<Bytes, ParseError<'a>> {
    let (&external, data) = payload.split_first().ok_or_else(|| {
        nom::Err::Error(nom::error::Error::new(
            error_input,
            nom::error::ErrorKind::Eof,
        ))
    })?;
    match external {
        0 => bytes_subslice(backing, data, error_input),
        _ => external_property_data(error_input, data, external_data),
    }
}

fn external_property_data<'a>(
    error_input: &'a [u8],
    index_bytes: &[u8],
    external_data: &[Bytes],
) -> Result<Bytes, ParseError<'a>> {
    let (remaining, index) = sevenzip_varuint64_decode(index_bytes).map_err(|_| {
        nom::Err::Error(nom::error::Error::new(
            error_input,
            nom::error::ErrorKind::Verify,
        ))
    })?;
    if !remaining.is_empty() {
        return Err(nom::Err::Error(nom::error::Error::new(
            error_input,
            nom::error::ErrorKind::Verify,
        )));
    }
    let index = usize::try_from(index).map_err(|_| {
        nom::Err::Error(nom::error::Error::new(
            error_input,
            nom::error::ErrorKind::TooLarge,
        ))
    })?;
    external_data.get(index).cloned().ok_or_else(|| {
        nom::Err::Error(nom::error::Error::new(
            error_input,
            nom::error::ErrorKind::Eof,
        ))
    })
}

fn validate_name_data<'a>(
    data: &[u8],
    num_names: usize,
    error_input: &'a [u8],
) -> Result<(), ParseError<'a>> {
    let mut code_units = data.chunks_exact(2);
    let every_name_is_terminated = (0..num_names).all(|_| code_units.any(|unit| unit == [0, 0]));
    if !every_name_is_terminated
        || code_units.next().is_some()
        || !code_units.remainder().is_empty()
    {
        return Err(nom::Err::Error(nom::error::Error::new(
            error_input,
            nom::error::ErrorKind::Verify,
        )));
    }
    Ok(())
}

fn parse_defined_u64_values<'a>(
    error_input: &'a [u8],
    all_defined: u8,
    bitmap: &[u8],
    data: &[u8],
    num_values: usize,
) -> Result<Vec<Option<u64>>, ParseError<'a>> {
    let mut pos = 0;
    let mut values = Vec::with_capacity(num_values);
    for index in 0..num_values {
        let is_defined = all_defined != 0 || bitmap_is_set(bitmap, index);
        if is_defined {
            if pos + 8 > data.len() {
                return Err(nom::Err::Error(nom::error::Error::new(
                    error_input,
                    nom::error::ErrorKind::Eof,
                )));
            }
            values.push(Some(u64::from_le_bytes(
                data[pos..pos + 8].try_into().unwrap(),
            )));
            pos += 8;
        } else {
            values.push(None);
        }
    }
    if pos != data.len() {
        return Err(nom::Err::Error(nom::error::Error::new(
            error_input,
            nom::error::ErrorKind::Verify,
        )));
    }
    Ok(values)
}

fn parse_defined_u32_values<'a>(
    error_input: &'a [u8],
    all_defined: u8,
    bitmap: &[u8],
    data: &[u8],
    num_values: usize,
) -> Result<Vec<Option<u32>>, ParseError<'a>> {
    let mut pos = 0;
    let mut values = Vec::with_capacity(num_values);
    for index in 0..num_values {
        let is_defined = all_defined != 0 || bitmap_is_set(bitmap, index);
        if is_defined {
            if pos + 4 > data.len() {
                return Err(nom::Err::Error(nom::error::Error::new(
                    error_input,
                    nom::error::ErrorKind::Eof,
                )));
            }
            values.push(Some(u32::from_le_bytes(
                data[pos..pos + 4].try_into().unwrap(),
            )));
            pos += 4;
        } else {
            values.push(None);
        }
    }
    if pos != data.len() {
        return Err(nom::Err::Error(nom::error::Error::new(
            error_input,
            nom::error::ErrorKind::Verify,
        )));
    }
    Ok(values)
}

/// Walk a `FilesInfo` block without allocating.  Returns `num_files`.
///
/// Every sub-property is size-prefixed, so we simply verify the tag, read
/// `num_files`, then skip each sub-block by its declared size until `END`.
///
/// # Errors
///
/// Returns a nom error if the input is truncated or does not start with
/// the `FilesInfo` property tag.
pub(crate) fn scan_files_info_with_external(input: &[u8]) -> IResult<&[u8], (u64, bool)> {
    let orig = input;
    let (input, tag) = Property::parse(input)?;
    if tag != Property::FilesInfo {
        return Err(nom::Err::Failure(nom::error::Error::new(
            orig,
            nom::error::ErrorKind::Satisfy,
        )));
    }

    let (input, num_files) = sevenzip_varuint64_decode(input)?;
    let num_files_usize = usize::try_from(num_files).map_err(|_| {
        nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TooLarge,
        ))
    })?;
    let mut input = input;
    let mut uses_external_data = false;

    loop {
        let (i, tag) = Property::parse(input)?;
        input = i;
        if tag == Property::END {
            break;
        }
        // All FilesInfo sub-properties are size-prefixed
        let (i, size) = sevenzip_varuint64_decode(input)?;
        let sz = usize::try_from(size).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            ))
        })?;
        let (i, block) = take(sz)(i)?;
        let external_flag = match tag {
            Property::Name => block.first().copied(),
            Property::CTime
            | Property::ATime
            | Property::MTime
            | Property::StartPos
            | Property::Attributes => {
                let layout_start = match block.first().copied() {
                    Some(0) => 2 + num_files_usize.div_ceil(8),
                    Some(value) if value != 0 => 2,
                    _ => usize::MAX,
                };
                layout_start
                    .checked_sub(1)
                    .and_then(|index| block.get(index))
                    .copied()
            }
            _ => None,
        };
        uses_external_data |= external_flag.is_some_and(|flag| flag != 0);
        input = i;
    }

    Ok((input, (num_files, uses_external_data)))
}

#[cfg(test)]
mod tests {
    use super::{FilesInfo, scan_files_info_with_external};
    use bytes::Bytes;

    /// Minimal: 3 files, no sub-properties.
    #[test]
    fn scan_files_info_no_props() {
        // FilesInfo (0x05), num_files=3, END (0x00)
        let input = [0x05u8, 0x03, 0x00];
        let (rem, n) = scan_files_info_with_external(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(n, (3, false));
    }

    /// `num_files=0` is valid.
    #[test]
    fn scan_files_info_zero_files() {
        let input = [0x05u8, 0x00, 0x00];
        let (rem, n) = scan_files_info_with_external(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(n, (0, false));
    }

    /// One size-prefixed sub-property is skipped correctly.
    #[test]
    fn scan_files_info_with_sub_property() {
        // FilesInfo, num_files=2, MTime (0x14), size=5, 5 dummy bytes, END
        let input = [0x05u8, 0x02, 0x14, 0x05, 0x01, 0x00, 0x03, 0x04, 0x05, 0x00];
        let (rem, n) = scan_files_info_with_external(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(n, (2, false));
    }

    #[test]
    fn scan_files_info_detects_external_property_streams() {
        let name = [0x05, 0x01, 0x11, 0x02, 0x01, 0x00, 0x00];
        let time = [0x05, 0x01, 0x12, 0x03, 0x01, 0x01, 0x00, 0x00];

        assert_eq!(scan_files_info_with_external(&name).unwrap().1, (1, true));
        assert_eq!(scan_files_info_with_external(&time).unwrap().1, (1, true));
    }

    /// Trailing bytes after END are preserved in the remainder.
    #[test]
    fn scan_files_info_trailing_bytes() {
        let input = [0x05u8, 0x07, 0x00, 0xFF];
        let (rem, n) = scan_files_info_with_external(&input).unwrap();
        assert_eq!(rem, &[0xFF]);
        assert_eq!(n, (7, false));
    }

    /// Wrong opening tag returns a hard Failure.
    #[test]
    fn scan_files_info_wrong_tag() {
        assert!(scan_files_info_with_external(&[0x06u8]).is_err());
    }

    #[test]
    fn parse_files_info_rejects_name_data_outside_backing() {
        let input = [0x05u8, 0x01, 0x11, 0x05, 0x00, 0x41, 0x00, 0x00, 0x00, 0x00];
        let backing = Bytes::from_static(b"unrelated");

        assert!(FilesInfo::parse(&input, &backing).is_err());
    }

    #[test]
    fn external_files_metadata_resolves_names_times_and_attributes() {
        let input = [
            0x05, 0x01, // one file
            0x11, 0x02, 0x01, 0x00, // Name: external stream 0
            0x12, 0x03, 0x01, 0x01, 0x01, // CTime: external stream 1
            0x13, 0x03, 0x01, 0x01, 0x01, // ATime: external stream 1
            0x14, 0x03, 0x01, 0x01, 0x01, // MTime: external stream 1
            0x15, 0x03, 0x01, 0x01, 0x02, // Attributes: external stream 2
            0x00,
        ];
        let backing = Bytes::copy_from_slice(&input);
        let external = [
            Bytes::from_static(&[b'A', 0, 0, 0]),
            Bytes::from_static(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]),
            Bytes::from_static(&[0x81, 0x00, 0x00, 0x00]),
        ];

        let (remaining, files) =
            FilesInfo::parse_with_external(&input, &backing, &external).unwrap();

        assert!(remaining.is_empty());
        assert_eq!(files.name(0).as_deref(), Some("A"));
        assert_eq!(files.ctimes, [Some(0x0102_0304_0506_0708)]);
        assert_eq!(files.atimes, [Some(0x0102_0304_0506_0708)]);
        assert_eq!(files.mtimes, [Some(0x0102_0304_0506_0708)]);
        assert_eq!(files.attributes, [Some(0x81)]);
    }

    #[test]
    fn external_sparse_time_properties_keep_undefined_entries() {
        let input = [0x05, 0x02, 0x12, 0x04, 0x00, 0x80, 0x22, 0x00, 0x00];
        let backing = Bytes::copy_from_slice(&input);
        let external = [Bytes::from_static(&[
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        ])];

        let files = FilesInfo::parse_with_external(&backing, &backing, &external)
            .unwrap()
            .1;

        assert_eq!(files.ctimes, [Some(0x0102_0304_0506_0708), None]);
    }

    #[test]
    fn external_files_metadata_rejects_invalid_indices_and_trailing_values() {
        let invalid_index = [0x05, 0x01, 0x11, 0x02, 0x01, 0x01, 0x00];
        let invalid_index_backing = Bytes::copy_from_slice(&invalid_index);
        assert!(
            FilesInfo::parse_with_external(&invalid_index, &invalid_index_backing, &[]).is_err()
        );

        let trailing_values = [0x05, 0x01, 0x12, 0x03, 0x01, 0x01, 0x00, 0x00];
        let trailing_values_backing = Bytes::copy_from_slice(&trailing_values);
        let external = [Bytes::from_static(&[0; 9])];
        assert!(
            FilesInfo::parse_with_external(&trailing_values, &trailing_values_backing, &external)
                .is_err()
        );

        let truncated_values = [0x05, 0x01, 0x12, 0x03, 0x01, 0x01, 0x00, 0x00];
        let truncated_backing = Bytes::copy_from_slice(&truncated_values);
        let truncated_external = [Bytes::from_static(&[0; 7])];
        assert!(
            FilesInfo::parse_with_external(
                &truncated_values,
                &truncated_backing,
                &truncated_external
            )
            .is_err()
        );

        let trailing_index = [0x05, 0x01, 0x11, 0x03, 0x01, 0x00, 0x00, 0x00];
        let trailing_index_backing = Bytes::copy_from_slice(&trailing_index);
        assert!(
            FilesInfo::parse_with_external(
                &trailing_index,
                &trailing_index_backing,
                &truncated_external
            )
            .is_err()
        );
    }

    #[test]
    fn files_info_rejects_duplicate_properties_and_wrong_name_counts() {
        let duplicate_names = [
            0x05, 0x01, 0x11, 0x05, 0x00, b'A', 0x00, 0x00, 0x00, 0x11, 0x05, 0x00, b'B', 0x00,
            0x00, 0x00, 0x00,
        ];
        let duplicate_backing = Bytes::copy_from_slice(&duplicate_names);
        assert!(FilesInfo::parse(&duplicate_backing, &duplicate_backing).is_err());

        let missing_name = [0x05, 0x02, 0x11, 0x05, 0x00, b'A', 0x00, 0x00, 0x00, 0x00];
        let missing_backing = Bytes::copy_from_slice(&missing_name);
        assert!(FilesInfo::parse(&missing_backing, &missing_backing).is_err());

        let trailing_name_data = [
            0x05, 0x01, 0x11, 0x06, 0x00, b'A', 0x00, 0x00, 0x00, b'B', 0x00, 0x00,
        ];
        let trailing_backing = Bytes::copy_from_slice(&trailing_name_data);
        assert!(FilesInfo::parse(&trailing_backing, &trailing_backing).is_err());
    }

    #[test]
    fn files_info_preserves_invalid_utf16_and_replaces_it_for_display() {
        let input = [0x05, 0x01, 0x11, 0x05, 0x00, 0x00, 0xd8, 0x00, 0x00, 0x00];
        let backing = Bytes::copy_from_slice(&input);
        let files = FilesInfo::parse(&backing, &backing).unwrap().1;

        assert_eq!(files.name(0).as_deref(), Some("\u{fffd}"));
        assert_eq!(files.name_data.as_ref(), &[0x00, 0xd8, 0x00, 0x00]);
    }

    #[test]
    fn files_info_classifies_directory_zero_file_and_anti_items() {
        let fi = FilesInfo {
            num_files: 4,
            name_data: Bytes::new(),
            ctimes: Vec::new(),
            atimes: Vec::new(),
            mtimes: Vec::new(),
            start_positions: Vec::new(),
            attributes: Vec::new(),
            empty_streams: Bytes::from_static(&[0b1110_0000]),
            empty_files: Bytes::from_static(&[0b0100_0000]),
            anti_items: Bytes::from_static(&[0b0010_0000]),
            empty_stream_ordinals: vec![Some(0), Some(1), Some(2), None],
        };

        assert!(fi.is_directory(0));
        assert!(!fi.is_empty_file(0));
        assert!(!fi.is_directory(1));
        assert!(fi.is_empty_file(1));
        assert!(fi.is_anti(2));
        assert!(!fi.is_directory(2));
        assert!(!fi.is_empty_stream(9));
        assert!(!fi.is_empty_file(9));
        assert!(!fi.is_directory(9));
        assert!(!fi.is_anti(9));
    }
}
