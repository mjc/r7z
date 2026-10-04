use crate::R7zError;
use std::io::Read;

const TOP_VALUE: u32 = 1 << 24;
const NUM_MODEL_BITS: u32 = 11;
const BIT_MODEL_TOTAL: u16 = 1 << NUM_MODEL_BITS;
const NUM_MOVE_BITS: u32 = 5;

pub(crate) fn decode<'a>(
    main: Box<dyn Read + 'a>,
    call: Box<dyn Read + 'a>,
    jump: Box<dyn Read + 'a>,
    rc: Box<dyn Read + 'a>,
    output_size: usize,
) -> Result<Vec<u8>, R7zError> {
    let mut main = StreamCursor::new(main);
    let mut call = StreamCursor::new(call);
    let mut jump = StreamCursor::new(jump);
    let mut control = RangeDecoder::new(rc)?;
    let mut output = Vec::with_capacity(output_size);
    let mut ip = 0u32;
    let mut prev = 0u8;

    while output.len() < output_size {
        control.normalize()?;

        let Some((opcode, prev_before_opcode)) =
            copy_until_branch_opcode(&mut main, &mut output, output_size, &mut ip, prev)?
        else {
            break;
        };
        prev = opcode;

        if !control.branch_is_encoded(opcode, prev_before_opcode)? {
            continue;
        }
        let absolute = match opcode {
            0xE8 => call.read_u32_be()?,
            _ => jump.read_u32_be()?,
        };
        ip = ip.wrapping_add(4);
        let relative = absolute.wrapping_sub(ip).to_le_bytes();
        if output.len().checked_add(4).ok_or(R7zError::Decompression)? > output_size {
            return Err(R7zError::Decompression);
        }
        output.extend_from_slice(&relative);
        prev = relative[3];

        control.normalize_if_available()?;
    }

    if output.len() != output_size || main.has_more()? || call.has_more()? || jump.has_more()? {
        return Err(R7zError::Decompression);
    }

    control.finish()?;
    Ok(output)
}

struct RangeDecoder<'a> {
    input: StreamCursor<'a>,
    code: u32,
    range: u32,
    probabilities: [u16; 2 + 256],
}

impl<'a> RangeDecoder<'a> {
    fn new(reader: Box<dyn Read + 'a>) -> Result<Self, R7zError> {
        let mut input = StreamCursor::new(reader);
        if input.read_byte()? != 0 {
            return Err(R7zError::Decompression);
        }
        let code = input.read_u32_be()?;
        if code == u32::MAX {
            return Err(R7zError::Decompression);
        }
        Ok(Self {
            input,
            code,
            range: u32::MAX,
            probabilities: [BIT_MODEL_TOTAL >> 1; 2 + 256],
        })
    }

    fn normalize(&mut self) -> Result<(), R7zError> {
        if self.range < TOP_VALUE {
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(self.input.read_byte()?);
        }
        Ok(())
    }

    fn normalize_if_available(&mut self) -> Result<(), R7zError> {
        if self.range < TOP_VALUE && self.input.has_more()? {
            self.normalize()?;
        }
        Ok(())
    }

    fn branch_is_encoded(&mut self, opcode: u8, previous: u8) -> Result<bool, R7zError> {
        let index = match opcode {
            0xE8 => 2 + usize::from(previous),
            0xE9 => 1,
            _ => 0,
        };
        let probability = self
            .probabilities
            .get_mut(index)
            .ok_or(R7zError::Decompression)?;
        let bound = (self.range >> NUM_MODEL_BITS) * u32::from(*probability);
        let encoded = self.code >= bound;
        if encoded {
            self.range -= bound;
            self.code -= bound;
            *probability -= *probability >> NUM_MOVE_BITS;
        } else {
            self.range = bound;
            *probability += (BIT_MODEL_TOTAL - *probability) >> NUM_MOVE_BITS;
        }
        Ok(encoded)
    }

    fn finish(mut self) -> Result<(), R7zError> {
        if self.code != 0 || self.input.has_more()? {
            return Err(R7zError::Decompression);
        }
        Ok(())
    }
}

fn copy_until_branch_opcode(
    main: &mut StreamCursor<'_>,
    output: &mut Vec<u8>,
    output_size: usize,
    ip: &mut u32,
    mut prev: u8,
) -> Result<Option<(u8, u8)>, R7zError> {
    while output.len() < output_size {
        let Some(opcode) = main.read_byte_optional()? else {
            return Ok(None);
        };
        output.push(opcode);
        *ip = ip.wrapping_add(1);

        if prev == 0x0F && (opcode & 0xF0) == 0x80 {
            return Ok(Some((opcode, prev)));
        }

        let prev_before_opcode = prev;
        prev = opcode;
        if (opcode & 0xFE) == 0xE8 {
            return Ok(Some((opcode, prev_before_opcode)));
        }
    }

    Ok(None)
}

struct StreamCursor<'a> {
    reader: Box<dyn Read + 'a>,
    buffer: [u8; 8192],
    pos: usize,
    len: usize,
}

impl<'a> StreamCursor<'a> {
    fn new(reader: Box<dyn Read + 'a>) -> Self {
        Self {
            reader,
            buffer: [0; 8192],
            pos: 0,
            len: 0,
        }
    }

    fn has_more(&mut self) -> Result<bool, R7zError> {
        if self.pos == self.len {
            self.len = loop {
                match self.reader.read(&mut self.buffer) {
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                    result => break result.map_err(R7zError::Io)?,
                }
            };
            self.pos = 0;
        }
        Ok(self.pos < self.len)
    }

    fn read_byte(&mut self) -> Result<u8, R7zError> {
        self.read_byte_optional()?.ok_or(R7zError::Decompression)
    }

    fn read_byte_optional(&mut self) -> Result<Option<u8>, R7zError> {
        if !self.has_more()? {
            return Ok(None);
        }
        let byte = *self.buffer.get(self.pos).ok_or(R7zError::Decompression)?;
        self.pos += 1;
        Ok(Some(byte))
    }

    fn read_u32_be(&mut self) -> Result<u32, R7zError> {
        Ok(u32::from_be_bytes([
            self.read_byte()?,
            self.read_byte()?,
            self.read_byte()?,
            self.read_byte()?,
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::decode;
    use crate::R7zError;
    use std::io::{self, Cursor, Read};

    struct Fragmented<R> {
        inner: R,
        chunk: usize,
        interrupt: bool,
    }

    impl<R: Read> Read for Fragmented<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let len = buf.len().min(self.chunk);
            self.inner.read(&mut buf[..len])
        }
    }

    fn reader(bytes: &[u8]) -> Box<dyn Read + '_> {
        Box::new(Cursor::new(bytes))
    }

    #[test]
    fn fragmented_and_interrupted_inputs_cross_cursor_boundaries() {
        let expected = vec![0x90; 20_000];
        for chunk in [3, 8192] {
            let main = Box::new(Fragmented {
                inner: Cursor::new(expected.as_slice()),
                chunk,
                interrupt: false,
            });
            let control = Box::new(Fragmented {
                inner: Cursor::new([0; 5]),
                chunk: 1,
                interrupt: false,
            });
            assert_eq!(
                decode(main, reader(&[]), reader(&[]), control, expected.len()).unwrap(),
                expected,
            );
        }
    }

    #[test]
    fn call_and_jump_addresses_use_their_own_streams() {
        // The initial bound selects a converted branch and leaves a zero code.
        let control = [0, 0x7f, 0xff, 0xfc, 0];
        let absolute = 9u32.to_be_bytes();
        for opcode in [0xe8, 0xe9] {
            let main = [opcode];
            let (call, jump) = match opcode {
                0xe8 => (absolute.as_slice(), &[][..]),
                _ => (&[][..], absolute.as_slice()),
            };
            assert_eq!(
                decode(
                    reader(&main),
                    reader(call),
                    reader(jump),
                    reader(&control),
                    5
                )
                .unwrap(),
                [opcode, 4, 0, 0, 0],
            );
        }
    }

    #[test]
    fn truncated_and_trailing_streams_are_rejected() {
        let main: &[u8] = &[0x90];
        let control: &[u8] = &[0; 5];
        for (main, call, jump, control, size) in [
            (main, &[][..], &[][..], control, 2),
            (main, &[][..], &[][..], control, 0),
            (main, &[0][..], &[][..], control, 1),
            (main, &[][..], &[0][..], control, 1),
            (main, &[][..], &[][..], &[0; 4][..], 1),
            (main, &[][..], &[][..], &[0; 6][..], 1),
        ] {
            assert!(matches!(
                decode(
                    reader(main),
                    reader(call),
                    reader(jump),
                    reader(control),
                    size
                ),
                Err(R7zError::Decompression),
            ));
        }
    }
}
