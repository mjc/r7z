use std::io::{self, Read};

const MAX_SWAP_WIDTH: usize = 4;

pub(crate) struct ByteSwapReader<R> {
    inner: R,
    width: usize,
    pending: [u8; MAX_SWAP_WIDTH],
    pending_len: usize,
    pending_output_position: usize,
    pending_output_length: usize,
    eof: bool,
}

impl<R> ByteSwapReader<R> {
    pub(crate) fn new(inner: R, width: usize) -> Self {
        debug_assert!(matches!(width, 2 | 4));
        Self {
            inner,
            width,
            pending: [0; MAX_SWAP_WIDTH],
            pending_len: 0,
            pending_output_position: 0,
            pending_output_length: 0,
            eof: false,
        }
    }
}

impl<R: Read> ByteSwapReader<R> {
    fn drain_pending_output(&mut self, buf: &mut [u8]) -> usize {
        let remaining = self.pending_output_length - self.pending_output_position;
        let read = remaining.min(buf.len());
        let start = self.pending_output_position;
        buf[..read].copy_from_slice(&self.pending[start..start + read]);
        self.pending_output_position += read;
        if self.pending_output_position == self.pending_output_length {
            self.pending_output_position = 0;
            self.pending_output_length = 0;
        }
        read
    }

    fn read_small(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pending_output_length > 0 {
            return Ok(self.drain_pending_output(buf));
        }

        while self.pending_len < self.width && !self.eof {
            let read = self
                .inner
                .read(&mut self.pending[self.pending_len..self.width])?;
            if read == 0 {
                self.eof = true;
            } else {
                self.pending_len += read;
            }
        }

        if self.pending_len == 0 {
            return Ok(0);
        }

        if self.pending_len == self.width {
            swap_groups(&mut self.pending[..self.width], self.width);
        }
        self.pending_output_length = self.pending_len;
        self.pending_len = 0;
        Ok(self.drain_pending_output(buf))
    }
}

impl<R: Read> Read for ByteSwapReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.pending_output_length > 0 {
            return Ok(self.drain_pending_output(buf));
        }

        if buf.len() < self.width {
            return self.read_small(buf);
        }

        let mut filled = self.pending_len;
        buf[..filled].copy_from_slice(&self.pending[..filled]);
        self.pending_len = 0;

        loop {
            if self.eof {
                return Ok(filled);
            }

            match self.inner.read(&mut buf[filled..]) {
                Ok(0) => self.eof = true,
                Ok(read) => filled += read,
                Err(error) => {
                    self.pending[..filled].copy_from_slice(&buf[..filled]);
                    self.pending_len = filled;
                    return Err(error);
                }
            }

            let complete = filled / self.width * self.width;
            if complete > 0 {
                self.pending_len = filled - complete;
                self.pending[..self.pending_len].copy_from_slice(&buf[complete..filled]);
                swap_groups(&mut buf[..complete], self.width);
                return Ok(complete);
            }

            if self.eof {
                return Ok(filled);
            }
        }
    }
}

fn swap_groups(bytes: &mut [u8], width: usize) {
    #[cfg(target_arch = "x86_64")]
    if bytes.len() >= 64
        && std::is_x86_feature_detected!("avx512f")
        && std::is_x86_feature_detected!("avx512bw")
    {
        // SAFETY: Runtime feature detection confirms AVX-512F and AVX-512BW support.
        unsafe { swap_groups_avx512(bytes, width) };
        return;
    }

    swap_groups_scalar(bytes, width);
}

fn swap_groups_scalar(bytes: &mut [u8], width: usize) {
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

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw")]
unsafe fn swap_groups_avx512(bytes: &mut [u8], width: usize) {
    swap_groups_scalar(bytes, width);
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

    #[test]
    fn byte_swap_reader_handles_small_and_odd_output_buffers() {
        for (width, input, expected) in [
            (2, b"abcdefg".as_slice(), b"badcfeg".as_slice()),
            (4, b"abcdefghij".as_slice(), b"dcbahgfeij".as_slice()),
        ] {
            for buffer_size in [1, 2, 3, 5] {
                let mut reader = ByteSwapReader::new(ShortReader(input), width);
                let mut output = Vec::new();
                let mut buffer = [0; 5];

                loop {
                    let read = reader.read(&mut buffer[..buffer_size]).unwrap();
                    if read == 0 {
                        break;
                    }
                    output.extend_from_slice(&buffer[..read]);
                }

                assert_eq!(output, expected, "width {width}, buffer {buffer_size}");
            }
        }
    }

    #[test]
    fn swap_groups_reverses_groups_across_vector_boundaries() {
        for width in [2, 4] {
            let mut bytes: Vec<_> = (0..128 + width).map(|byte| byte as u8).collect();
            let expected: Vec<_> = bytes
                .chunks_exact(width)
                .flat_map(|group| group.iter().rev().copied())
                .collect();

            super::swap_groups(&mut bytes, width);

            assert_eq!(bytes, expected, "width {width}");
        }
    }
}
