use crate::{sevenzip_varuint64_decode, Property};
use bytes::Bytes;
use nom::{bytes::streaming::take, IResult};

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
    pub fn names(&self) -> impl Iterator<Item = String> + '_ {
        (0..self.num_files as usize).filter_map(move |i| self.name(i))
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

    pub fn parse(input: &[u8]) -> IResult<&[u8], FilesInfo> {
        let orig_input = input;
        let (input, tag) = Property::parse(input)?;
        if tag != Property::FilesInfo {
            return Err(nom::Err::Failure(nom::error::Error::new(
                orig_input,
                nom::error::ErrorKind::Satisfy,
            )));
        }

        let (input, num_files) = sevenzip_varuint64_decode(input)?;
        let n = num_files as usize;

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
                    let (i, block) = take(size as usize)(i)?;
                    // block[0] is the external flag; block[1..] is the raw UTF-16LE name data.
                    name_data = Bytes::copy_from_slice(&block[1..]);
                    input = i;
                }
                Property::MTime => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let (i, block) = take(size as usize)(i)?;
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
                        &block[1..1 + num_bytes]
                    };
                    mtimes = Vec::with_capacity(n);
                    let mut pos = data_start;
                    for j in 0..n {
                        let is_def =
                            all_defined != 0 || (bitmap[j / 8] >> (j % 8)) & 1 == 1;
                        if is_def && pos + 8 <= block.len() {
                            let val =
                                u64::from_le_bytes(block[pos..pos + 8].try_into().unwrap());
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
                    let (i, block) = take(size as usize)(i)?;
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
                        &block[1..1 + num_bytes]
                    };
                    attributes = Vec::with_capacity(n);
                    let mut pos = data_start;
                    for j in 0..n {
                        let is_def =
                            all_defined != 0 || (bitmap[j / 8] >> (j % 8)) & 1 == 1;
                        if is_def && pos + 4 <= block.len() {
                            let val =
                                u32::from_le_bytes(block[pos..pos + 4].try_into().unwrap());
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
                    let (i, block) = take(size as usize)(i)?;
                    empty_streams = Bytes::copy_from_slice(block);
                    input = i;
                }
                Property::EmptyFile => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let (i, block) = take(size as usize)(i)?;
                    empty_files = Bytes::copy_from_slice(block);
                    input = i;
                }
                _ => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let (i, _) = take(size as usize)(i)?;
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
