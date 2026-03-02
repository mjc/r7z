use crate::{sevenzip_varuint64_decode, Property};
use bytes::Bytes;
use nom::{bytes::complete::take, IResult};

/// File listing metadata from the 7z `FilesInfo` block.
#[derive(Debug, PartialEq)]
pub struct FilesInfo {
    /// Total number of entries (files + directories).
    pub num_files: u64,
    /// Raw UTF-16LE null-terminated name block (empty = no Name property present).
    name_data: Bytes,
    /// Last-modified timestamps as Windows FILETIME values (100ns intervals since 1601-01-01).
    pub mtimes: Vec<Option<u64>>,
    /// Windows file attributes per entry.
    pub attributes: Vec<Option<u32>>,
    /// Raw bitmap of empty-stream flags (empty = all false). Bit `i` = entry `i` has no data stream.
    pub empty_streams: Bytes,
    /// Raw bitmap of empty-file flags (empty = all false). Bit `i` = entry `i` is a zero-byte file.
    pub empty_files: Bytes,
}

impl FilesInfo {
    /// Decode the name of entry `i` on demand (UTF-16LE, null-terminated).
    pub fn name(&self, i: usize) -> Option<String> {
        let data = &self.name_data;
        if data.is_empty() {
            return None;
        }
        let mut pos = 0usize;
        let mut idx = 0usize;
        while pos + 1 < data.len() {
            let start = pos;
            // Scan to null terminator
            loop {
                if pos + 1 >= data.len() {
                    break;
                }
                let is_null = data[pos] == 0 && data[pos + 1] == 0;
                pos += 2;
                if is_null {
                    break;
                }
            }
            if idx == i {
                let end = pos - 2; // exclude null terminator
                let s: String = char::decode_utf16(
                    data[start..end]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]])),
                )
                .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect();
                return Some(s);
            }
            idx += 1;
        }
        None
    }

    /// Iterator over all decoded names (in archive order).
    ///
    /// # Panics
    ///
    /// Panics if `num_files` exceeds `usize::MAX` (impossible in practice).
    pub fn names(&self) -> impl Iterator<Item = String> + '_ {
        let n = usize::try_from(self.num_files).expect("num_files fits in usize");
        (0..n).filter_map(move |i| self.name(i))
    }

    /// Returns `true` if entry `i` has no data stream (directory or zero-byte file).
    pub fn is_empty_stream(&self, i: usize) -> bool {
        self.empty_streams
            .get(i / 8)
            .is_some_and(|b| (b >> (i % 8)) & 1 == 1)
    }

    /// Returns `true` if entry `i` is a genuine zero-byte file.
    pub fn is_empty_file(&self, i: usize) -> bool {
        self.empty_files
            .get(i / 8)
            .is_some_and(|b| (b >> (i % 8)) & 1 == 1)
    }

    /// Parse a `FilesInfo` block from the header stream.
    ///
    /// # Errors
    ///
    /// Returns a nom error if the input is truncated, malformed, or does not start
    /// with the `FilesInfo` property tag.
    ///
    /// # Panics
    ///
    /// Panics if a block size encoded in the archive exceeds `usize::MAX`, which
    /// cannot happen in practice on any platform that can hold the archive in memory.
    #[allow(clippy::too_many_lines)]
    pub fn parse<'a>(input: &'a [u8], backing: &Bytes) -> IResult<&'a [u8], FilesInfo> {
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
        let mut name_data = Bytes::new();
        let mut mtimes: Vec<Option<u64>> = Vec::new();
        let mut attributes: Vec<Option<u32>> = Vec::new();
        let mut empty_streams = Bytes::new();
        let mut empty_files = Bytes::new();
        let mut input = input;

        loop {
            let (i, tag) = Property::parse(input)?;
            input = i;
            match tag {
                Property::END => break,
                Property::Name => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let sz = usize::try_from(size).map_err(|_| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    let (i, block) = take(sz)(i)?;
                    // block[0] is the external flag; block[1..] is the raw UTF-16LE name data.
                    name_data = backing.slice_ref(&block[1..]);
                    input = i;
                }
                Property::MTime => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let sz = usize::try_from(size).map_err(|_| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    let (i, block) = take(sz)(i)?;
                    let all_defined = block[0];
                    let (data_start, num_bytes) = if all_defined != 0 {
                        (1usize, 0usize)
                    } else {
                        let nb = n.div_ceil(8);
                        (1 + nb, nb)
                    };
                    let bitmap = if all_defined != 0 {
                        &[][..]
                    } else {
                        &block[1..=num_bytes]
                    };
                    mtimes = Vec::with_capacity(n.min(block.len() / 8));
                    let mut pos = data_start;
                    for j in 0..n {
                        let is_def = all_defined != 0 || (bitmap[j / 8] >> (j % 8)) & 1 == 1;
                        if is_def && pos + 8 <= block.len() {
                            let val = u64::from_le_bytes(block[pos..pos + 8].try_into().unwrap());
                            mtimes.push(Some(val));
                            pos += 8;
                        } else {
                            mtimes.push(None);
                        }
                    }
                    input = i;
                }
                Property::Attributes => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let sz = usize::try_from(size).map_err(|_| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    let (i, block) = take(sz)(i)?;
                    let all_defined = block[0];
                    let (data_start, num_bytes) = if all_defined != 0 {
                        (1usize, 0usize)
                    } else {
                        let nb = n.div_ceil(8);
                        (1 + nb, nb)
                    };
                    let bitmap = if all_defined != 0 {
                        &[][..]
                    } else {
                        &block[1..=num_bytes]
                    };
                    attributes = Vec::with_capacity(n.min(block.len() / 4));
                    let mut pos = data_start;
                    for j in 0..n {
                        let is_def = all_defined != 0 || (bitmap[j / 8] >> (j % 8)) & 1 == 1;
                        if is_def && pos + 4 <= block.len() {
                            let val = u32::from_le_bytes(block[pos..pos + 4].try_into().unwrap());
                            attributes.push(Some(val));
                            pos += 4;
                        } else {
                            attributes.push(None);
                        }
                    }
                    input = i;
                }
                Property::EmptyStream => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let sz = usize::try_from(size).map_err(|_| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    let (i, block) = take(sz)(i)?;
                    empty_streams = backing.slice_ref(block);
                    input = i;
                }
                Property::EmptyFile => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let sz = usize::try_from(size).map_err(|_| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    let (i, block) = take(sz)(i)?;
                    empty_files = backing.slice_ref(block);
                    input = i;
                }
                _ => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let sz = usize::try_from(size).map_err(|_| {
                        nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::TooLarge,
                        ))
                    })?;
                    let (i, _) = take(sz)(i)?;
                    input = i;
                }
            }
        }

        Ok((
            input,
            FilesInfo {
                num_files,
                name_data,
                mtimes,
                attributes,
                empty_streams,
                empty_files,
            },
        ))
    }
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
pub(crate) fn scan_files_info(input: &[u8]) -> IResult<&[u8], u64> {
    let orig = input;
    let (input, tag) = Property::parse(input)?;
    if tag != Property::FilesInfo {
        return Err(nom::Err::Failure(nom::error::Error::new(
            orig,
            nom::error::ErrorKind::Satisfy,
        )));
    }

    let (input, num_files) = sevenzip_varuint64_decode(input)?;
    let mut input = input;

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
        let (i, _) = take(sz)(i)?;
        input = i;
    }

    Ok((input, num_files))
}

#[cfg(test)]
mod tests {
    use super::scan_files_info;

    /// Minimal: 3 files, no sub-properties.
    #[test]
    fn scan_files_info_no_props() {
        // FilesInfo (0x05), num_files=3, END (0x00)
        let input = [0x05u8, 0x03, 0x00];
        let (rem, n) = scan_files_info(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(n, 3);
    }

    /// num_files=0 is valid.
    #[test]
    fn scan_files_info_zero_files() {
        let input = [0x05u8, 0x00, 0x00];
        let (rem, n) = scan_files_info(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(n, 0);
    }

    /// One size-prefixed sub-property is skipped correctly.
    #[test]
    fn scan_files_info_with_sub_property() {
        // FilesInfo, num_files=2, MTime (0x14), size=5, 5 dummy bytes, END
        let input = [0x05u8, 0x02, 0x14, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00];
        let (rem, n) = scan_files_info(&input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(n, 2);
    }

    /// Trailing bytes after END are preserved in the remainder.
    #[test]
    fn scan_files_info_trailing_bytes() {
        let input = [0x05u8, 0x07, 0x00, 0xFF];
        let (rem, n) = scan_files_info(&input).unwrap();
        assert_eq!(rem, &[0xFF]);
        assert_eq!(n, 7);
    }

    /// Wrong opening tag returns a hard Failure.
    #[test]
    fn scan_files_info_wrong_tag() {
        assert!(scan_files_info(&[0x06u8]).is_err());
    }
}
