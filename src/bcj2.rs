use crate::R7zError;

const STREAM_CALL: usize = 1;
const STREAM_JUMP: usize = 2;
const TOP_VALUE: u32 = 1 << 24;
const NUM_MODEL_BITS: u32 = 11;
const BIT_MODEL_TOTAL: u16 = 1 << NUM_MODEL_BITS;
const NUM_MOVE_BITS: u32 = 5;

pub(crate) fn decode(
    main: &[u8],
    call: &[u8],
    jump: &[u8],
    rc: &[u8],
    output_size: usize,
) -> Result<Vec<u8>, R7zError> {
    if call.len() & 3 != 0 || jump.len() & 3 != 0 || rc.len() < 5 || rc[0] != 0 {
        return Err(R7zError::Decompression);
    }

    let mut streams = [
        StreamCursor::new(main),
        StreamCursor::new(call),
        StreamCursor::new(jump),
        StreamCursor::new(rc),
    ];
    streams[3].pos = 5;

    let mut code = u32::from_be_bytes([rc[1], rc[2], rc[3], rc[4]]);
    if code == 0xFFFF_FFFF {
        return Err(R7zError::Decompression);
    }
    let mut range = 0xFFFF_FFFFu32;
    let mut probs = [BIT_MODEL_TOTAL >> 1; 2 + 256];
    let mut output = Vec::with_capacity(output_size);
    let mut ip = 0u32;
    let mut prev = 0u8;

    while output.len() < output_size {
        if range < TOP_VALUE {
            normalize(&mut range, &mut code, &mut streams[3])?;
        }

        let Some((opcode, prev_before_opcode)) =
            copy_until_branch_opcode(&mut streams[0], &mut output, output_size, &mut ip, prev)?
        else {
            break;
        };
        prev = opcode;

        let prob_idx = if opcode == 0xE8 {
            2 + usize::from(prev_before_opcode)
        } else if opcode == 0xE9 {
            1
        } else {
            0
        };

        let prob = &mut probs[prob_idx];
        let bound = (range >> NUM_MODEL_BITS) * u32::from(*prob);
        if code < bound {
            range = bound;
            *prob += (BIT_MODEL_TOTAL - *prob) >> NUM_MOVE_BITS;
            continue;
        }

        range -= bound;
        code -= bound;
        *prob -= *prob >> NUM_MOVE_BITS;

        let stream_idx = if opcode == 0xE8 {
            STREAM_CALL
        } else {
            STREAM_JUMP
        };
        let absolute = streams[stream_idx].read_u32_be()?;
        ip = ip.wrapping_add(4);
        let relative = absolute.wrapping_sub(ip).to_le_bytes();
        if output.len().checked_add(4).ok_or(R7zError::Decompression)? > output_size {
            return Err(R7zError::Decompression);
        }
        output.extend_from_slice(&relative);
        prev = relative[3];

        if range < TOP_VALUE && !streams[3].is_empty() {
            normalize(&mut range, &mut code, &mut streams[3])?;
        }
    }

    if output.len() != output_size
        || !streams[0].is_empty()
        || !streams[1].is_empty()
        || !streams[2].is_empty()
        || !streams[3].is_empty()
        || code != 0
    {
        return Err(R7zError::Decompression);
    }

    Ok(output)
}

fn normalize(range: &mut u32, code: &mut u32, rc: &mut StreamCursor<'_>) -> Result<(), R7zError> {
    *range <<= 8;
    *code = (*code << 8) | u32::from(rc.read_byte()?);
    Ok(())
}

fn copy_until_branch_opcode(
    main: &mut StreamCursor<'_>,
    output: &mut Vec<u8>,
    output_size: usize,
    ip: &mut u32,
    mut prev: u8,
) -> Result<Option<(u8, u8)>, R7zError> {
    while output.len() < output_size {
        let Some(opcode) = main.read_byte_optional() else {
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
    data: &'a [u8],
    pos: usize,
}

impl<'a> StreamCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }

    fn read_byte(&mut self) -> Result<u8, R7zError> {
        self.read_byte_optional().ok_or(R7zError::Decompression)
    }

    fn read_byte_optional(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn read_u32_be(&mut self) -> Result<u32, R7zError> {
        let end = self.pos.checked_add(4).ok_or(R7zError::Decompression)?;
        let bytes = self
            .data
            .get(self.pos..end)
            .ok_or(R7zError::Decompression)?;
        self.pos = end;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}
