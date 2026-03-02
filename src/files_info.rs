use crate::{sevenzip_varuint64_decode, Property};
use nom::{bytes::streaming::take, number::streaming::le_u8, IResult};

#[derive(Debug, PartialEq)]
pub struct FilesInfo {
    pub num_files: u64,
    pub names: Vec<String>,
    pub mtimes: Vec<Option<u64>>,
    pub attributes: Vec<Option<u32>>,
    pub empty_streams: Vec<bool>,
    pub empty_files: Vec<bool>,
}

impl FilesInfo {
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

        let mut names: Vec<String> = Vec::new();
        let mut mtimes: Vec<Option<u64>> = vec![None; n];
        let mut attributes: Vec<Option<u32>> = vec![None; n];
        let mut empty_streams: Vec<bool> = vec![false; n];
        let mut empty_files: Vec<bool> = vec![false; n];
        let mut input = input;

        loop {
            let (i, tag) = Property::parse(input)?;
            input = i;
            match tag {
                Property::END => break,
                Property::Name => {
                    // Size-prefixed block: external byte + UTF-16LE names null-terminated
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let (i, block) = take(size as usize)(i)?;
                    let _external = block[0];
                    let name_data = &block[1..];
                    // Each name is null-terminated UTF-16LE
                    names = parse_utf16le_names(name_data, n);
                    input = i;
                }
                Property::MTime => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let (i, block) = take(size as usize)(i)?;
                    let all_defined = block[0];
                    let (data_start, defined_flags) = if all_defined != 0 {
                        (1usize, vec![true; n])
                    } else {
                        let num_bytes = n.div_ceil(8);
                        let bitmap = &block[1..1 + num_bytes];
                        let flags: Vec<bool> = (0..n)
                            .map(|i| (bitmap[i / 8] >> (i % 8)) & 1 == 1)
                            .collect();
                        (1 + num_bytes, flags)
                    };
                    let mut pos = data_start;
                    for (j, is_def) in defined_flags.iter().enumerate() {
                        if *is_def && pos + 8 <= block.len() {
                            let val = u64::from_le_bytes(block[pos..pos + 8].try_into().unwrap());
                            mtimes[j] = Some(val);
                            pos += 8;
                        }
                    }
                    input = i;
                }
                Property::Attributes => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let (i, block) = take(size as usize)(i)?;
                    let all_defined = block[0];
                    let (data_start, defined_flags) = if all_defined != 0 {
                        (1usize, vec![true; n])
                    } else {
                        let num_bytes = n.div_ceil(8);
                        let bitmap = &block[1..1 + num_bytes];
                        let flags: Vec<bool> = (0..n)
                            .map(|i| (bitmap[i / 8] >> (i % 8)) & 1 == 1)
                            .collect();
                        (1 + num_bytes, flags)
                    };
                    let mut pos = data_start;
                    for (j, is_def) in defined_flags.iter().enumerate() {
                        if *is_def && pos + 4 <= block.len() {
                            let val = u32::from_le_bytes(block[pos..pos + 4].try_into().unwrap());
                            attributes[j] = Some(val);
                            pos += 4;
                        }
                    }
                    input = i;
                }
                Property::EmptyStream => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let (i, block) = take(size as usize)(i)?;
                    empty_streams = (0..n)
                        .map(|i| (block[i / 8] >> (i % 8)) & 1 == 1)
                        .collect();
                    input = i;
                }
                Property::EmptyFile => {
                    let (i, size) = sevenzip_varuint64_decode(input)?;
                    let (i, block) = take(size as usize)(i)?;
                    empty_files = (0..n)
                        .map(|i| (block[i / 8] >> (i % 8)) & 1 == 1)
                        .collect();
                    input = i;
                }
                _ => {
                    // Skip unknown property: size-prefixed
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
                names,
                mtimes,
                attributes,
                empty_streams,
                empty_files,
            },
        ))
    }
}

fn parse_utf16le_names(data: &[u8], count: usize) -> Vec<String> {
    let mut names = Vec::with_capacity(count);
    let mut pos = 0;
    while names.len() < count && pos + 1 < data.len() {
        let start = pos;
        while pos + 1 < data.len() {
            let lo = data[pos];
            let hi = data[pos + 1];
            pos += 2;
            if lo == 0 && hi == 0 {
                break;
            }
        }
        let end = pos - 2; // exclude null terminator
        let u16_units: Vec<u16> = data[start..end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        names.push(String::from_utf16_lossy(&u16_units).to_string());
    }
    names
}

// Suppress warnings for unused le_u8 import until more of the parser is used
#[allow(dead_code)]
fn _use_le_u8(input: &[u8]) -> IResult<&[u8], u8> {
    le_u8(input)
}
