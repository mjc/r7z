use std::io::{self, Read};

const BUFFER_SIZE: usize = 8192;
const MAX_SWAP_WIDTH: usize = 4;

pub(crate) struct ByteSwapReader<R> {
    inner: R,
    width: usize,
    buffer: [u8; BUFFER_SIZE + MAX_SWAP_WIDTH],
    position: usize,
    length: usize,
    pending: [u8; MAX_SWAP_WIDTH],
    pending_len: usize,
    eof: bool,
}

impl<R> ByteSwapReader<R> {
    pub(crate) fn new(inner: R, width: usize) -> Self {
        debug_assert!(matches!(width, 2 | 4));
        Self {
            inner,
            width,
            buffer: [0; BUFFER_SIZE + MAX_SWAP_WIDTH],
            position: 0,
            length: 0,
            pending: [0; MAX_SWAP_WIDTH],
            pending_len: 0,
            eof: false,
        }
    }
}

impl<R: Read> ByteSwapReader<R> {
    fn fill_buffer(&mut self) -> io::Result<()> {
        self.position = 0;
        self.length = 0;
        while self.length == 0 && !self.eof {
            self.buffer[..self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
            let read = self
                .inner
                .read(&mut self.buffer[self.pending_len..self.pending_len + BUFFER_SIZE])?;
            if read == 0 {
                self.eof = true;
                self.length = self.pending_len;
                self.pending_len = 0;
                break;
            }

            let input_len = self.pending_len + read;
            self.length = input_len / self.width * self.width;
            swap_groups(&mut self.buffer[..self.length], self.width);
            self.pending_len = input_len - self.length;
            self.pending[..self.pending_len].copy_from_slice(&self.buffer[self.length..input_len]);
            self.position = 0;
        }
        Ok(())
    }
}

impl<R: Read> Read for ByteSwapReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.position == self.length {
            self.fill_buffer()?;
        }

        let available = self.length - self.position;
        let read = available.min(buf.len());
        buf[..read].copy_from_slice(&self.buffer[self.position..self.position + read]);
        self.position += read;
        Ok(read)
    }
}

fn swap_groups(bytes: &mut [u8], width: usize) {
    match width {
        2 => bytes.chunks_exact_mut(2).for_each(|chunk| {
            let word = u16::from_ne_bytes([chunk[0], chunk[1]]).swap_bytes();
            chunk.copy_from_slice(&word.to_ne_bytes());
        }),
        4 => bytes.chunks_exact_mut(4).for_each(|chunk| {
            let word = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]).swap_bytes();
            chunk.copy_from_slice(&word.to_ne_bytes());
        }),
        _ => unreachable!("supported byte-swap widths are 2 and 4"),
    }
}

#[cfg(test)]
mod tests {
    use super::ByteSwapReader;
    use std::io::Read;

    struct ShortReader<R>(R);

    impl<R: Read> Read for ShortReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let read = buf.len().min(1);
            self.0.read(&mut buf[..read])
        }
    }

    #[test]
    fn byte_swap_reader_handles_split_reads() {
        let mut reader = ByteSwapReader::new("badcfe".as_bytes(), 2);
        let mut out = Vec::new();
        let mut buf = [0u8; 1];

        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }

        assert_eq!(out, b"abcdef");
    }

    #[test]
    fn byte_swap_reader_leaves_trailing_partial_group_unchanged() {
        let mut reader = ByteSwapReader::new("dcbae".as_bytes(), 4);
        let mut out = Vec::new();

        reader.read_to_end(&mut out).unwrap();

        assert_eq!(out, b"abcde");
    }

    #[test]
    fn byte_swap_reader_handles_short_source_reads() {
        for (width, input, expected) in [
            (2, b"abcdefg".as_slice(), b"badcfeg".as_slice()),
            (4, b"abcdefghij".as_slice(), b"dcbahgfeij".as_slice()),
        ] {
            let mut reader = ByteSwapReader::new(ShortReader(input), width);
            let mut output = Vec::new();
            reader.read_to_end(&mut output).unwrap();
            assert_eq!(output, expected);
        }
    }
}
