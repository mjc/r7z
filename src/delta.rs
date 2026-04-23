use std::io::{self, Read};

const DELTA_STATE_SIZE: usize = 256;

pub(crate) struct DeltaReader<R> {
    inner: R,
    state: [u8; DELTA_STATE_SIZE],
    delta: usize,
    pos: usize,
}

impl<R> DeltaReader<R> {
    pub(crate) fn new(inner: R, props: &[u8]) -> Result<Self, crate::R7zError> {
        let &[prop] = props else {
            return Err(crate::R7zError::Decompression);
        };
        Ok(Self {
            inner,
            state: [0; DELTA_STATE_SIZE],
            delta: usize::from(prop) + 1,
            pos: 0,
        })
    }
}

impl<R: Read> Read for DeltaReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        for byte in &mut buf[..n] {
            let decoded = byte.wrapping_add(self.state[self.pos]);
            *byte = decoded;
            self.state[self.pos] = decoded;
            self.pos += 1;
            if self.pos == self.delta {
                self.pos = 0;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::DeltaReader;
    use std::io::Read;

    fn encode_delta(data: &[u8], delta: usize) -> Vec<u8> {
        let mut state = [0u8; 256];
        let mut pos = 0usize;
        data.iter()
            .map(|&byte| {
                let encoded = byte.wrapping_sub(state[pos]);
                state[pos] = byte;
                pos += 1;
                if pos == delta {
                    pos = 0;
                }
                encoded
            })
            .collect()
    }

    #[test]
    fn delta_reader_decodes_across_reads() {
        let original = b"abcdefabcdefabcdef";
        let encoded = encode_delta(original, 3);
        let mut reader = DeltaReader::new(encoded.as_slice(), &[2]).unwrap();
        let mut out = Vec::new();

        let mut buf = [0u8; 2];
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }

        assert_eq!(out, original);
    }

    #[test]
    fn delta_reader_rejects_invalid_properties() {
        assert!(DeltaReader::<&[u8]>::new([].as_slice(), &[]).is_err());
        assert!(DeltaReader::<&[u8]>::new([].as_slice(), &[0, 1]).is_err());
    }
}
