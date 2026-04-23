use std::collections::VecDeque;
use std::io::{self, Read};

pub(crate) struct ByteSwapReader<R> {
    inner: R,
    width: usize,
    pending: Vec<u8>,
    output: VecDeque<u8>,
    eof: bool,
}

impl<R> ByteSwapReader<R> {
    pub(crate) fn new(inner: R, width: usize) -> Self {
        debug_assert!(matches!(width, 2 | 4));
        Self {
            inner,
            width,
            pending: Vec::with_capacity(width),
            output: VecDeque::with_capacity(width),
            eof: false,
        }
    }
}

impl<R: Read> ByteSwapReader<R> {
    fn fill_output(&mut self) -> io::Result<()> {
        while !self.eof && self.pending.len() < self.width {
            let mut buf = [0u8; 8192];
            let n = self.inner.read(&mut buf)?;
            if n == 0 {
                self.eof = true;
            } else {
                self.pending.extend_from_slice(&buf[..n]);
            }
        }

        if self.pending.len() >= self.width {
            let group = self.pending.drain(..self.width).rev();
            self.output.extend(group);
        } else if self.eof {
            self.output.extend(self.pending.drain(..));
        }

        Ok(())
    }
}

impl<R: Read> Read for ByteSwapReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut written = 0usize;
        while written < buf.len() {
            if self.output.is_empty() {
                self.fill_output()?;
                if self.output.is_empty() {
                    break;
                }
            }
            while written < buf.len() {
                let Some(byte) = self.output.pop_front() else {
                    break;
                };
                buf[written] = byte;
                written += 1;
            }
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::ByteSwapReader;
    use std::io::Read;

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
}
