//! AES-256-SHA-256 decryption for 7z archives.
//!
//! The 7z format uses a custom key derivation (iterated SHA-256, not PBKDF2)
//! followed by AES-256-CBC decryption. The password is encoded as UTF-16LE.
//!
//! # Properties byte layout
//!
//! | Byte | Bits   | Meaning                                        |
//! |------|--------|------------------------------------------------|
//! | 0    | \[5:0\]  | `NumCyclesPower` (0–62, or 0x3F for raw key) |
//! | 0    | \[6\]    | IV present flag                              |
//! | 0    | \[7\]    | Salt present flag                            |
//! | 1*   | \[7:4\]  | Extra salt bytes (if salt flag set)          |
//! | 1*   | \[3:0\]  | Extra IV bytes (if IV flag set)              |
//! | 2+   |        | Salt bytes, then IV bytes                      |
//!
//! \* Byte 1 is only present if either the salt or IV flag is set.
//!
//! Salt size = ((byte0 >> 7) & 1) + (byte1 >> 4)
//! IV size   = ((byte0 >> 6) & 1) + (byte1 & 0x0F)

use crate::R7zError;
use aes::Aes256;
use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
use sha2::{Digest, Sha256};
use std::io;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
const CIPHERTEXT_BUFFER_SIZE: usize = 8192;

/// Bound p7zip's default AES KDF cost while rejecting maliciously huge values.
pub(crate) const MAX_AES_NUM_CYCLES_POWER: u8 = 24;

/// Parsed AES-256-SHA-256 properties from a 7z coder.
#[derive(Debug)]
pub(crate) struct AesProperties {
    /// Number of SHA-256 iterations = `2^num_cycles_power`.
    pub num_cycles_power: u8,
    /// Salt (0..16 bytes).
    pub salt: Vec<u8>,
    /// Initialization vector, zero-padded to 16 bytes.
    pub iv: [u8; 16],
}

impl AesProperties {
    /// Parse the AES properties from the coder's properties bytes.
    pub fn parse(props: &[u8]) -> Result<Self, R7zError> {
        if props.is_empty() {
            return Err(R7zError::Decompression);
        }

        let byte0 = props[0];
        let num_cycles_power = byte0 & 0x3F;
        let has_salt = (byte0 >> 7) & 1 != 0;
        let has_iv = (byte0 >> 6) & 1 != 0;

        let (salt_size, iv_size, rest) = if has_salt || has_iv {
            if props.len() < 2 {
                return Err(R7zError::Decompression);
            }
            let byte1 = props[1];
            let ss = (u8::from(has_salt)) + (byte1 >> 4);
            let is = (u8::from(has_iv)) + (byte1 & 0x0F);
            (ss as usize, is as usize, &props[2..])
        } else {
            (0, 0, &props[1..])
        };

        if rest.len() < salt_size + iv_size {
            return Err(R7zError::Decompression);
        }

        let salt = rest[..salt_size].to_vec();
        let mut iv = [0u8; 16];
        let iv_bytes = &rest[salt_size..salt_size + iv_size];
        iv[..iv_bytes.len()].copy_from_slice(iv_bytes);

        Ok(AesProperties {
            num_cycles_power,
            salt,
            iv,
        })
    }
}

/// Derive the 32-byte AES key from a password using the 7z custom SHA-256 KDF.
///
/// The password is first encoded as UTF-16LE. Then for `2^num_cycles_power`
/// iterations, we feed `salt || password_utf16le || counter_le_8bytes` into SHA-256.
#[cfg(test)]
pub(crate) fn derive_key(
    password: &str,
    salt: &[u8],
    num_cycles_power: u8,
) -> Result<[u8; 32], R7zError> {
    derive_key_with_control(password, salt, num_cycles_power, None)
}

pub(crate) fn derive_key_with_control(
    password: &str,
    salt: &[u8],
    num_cycles_power: u8,
    control: Option<&crate::OperationControl>,
) -> Result<[u8; 32], R7zError> {
    use zeroize::Zeroizing;
    if let Some(control) = control {
        control.check()?;
    }
    // Special case: 0x3F means raw key = salt || password, zero-padded
    if num_cycles_power == 0x3F {
        let pwd_utf16 = Zeroizing::new(
            password
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>(),
        );
        let mut key = [0u8; 32];
        let total = Zeroizing::new(
            salt.iter()
                .chain(pwd_utf16.iter())
                .copied()
                .collect::<Vec<u8>>(),
        );
        let len = total.len().min(32);
        key[..len].copy_from_slice(&total[..len]);
        return Ok(key);
    }

    if num_cycles_power > MAX_AES_NUM_CYCLES_POWER {
        return Err(R7zError::Decompression);
    }

    let pwd_utf16 = Zeroizing::new(
        password
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>(),
    );

    let num_rounds: u64 = 1u64 << num_cycles_power;

    // Pre-build the append buffer: salt || password_utf16le || counter[8]
    let prefix_len = salt.len() + pwd_utf16.len();
    let buf_len = prefix_len + 8;
    let mut buf = Zeroizing::new(vec![0u8; buf_len]);
    buf[..salt.len()].copy_from_slice(salt);
    buf[salt.len()..prefix_len].copy_from_slice(&pwd_utf16);

    let mut hasher = Sha256::new();
    for i in 0..num_rounds {
        if i % 1024 == 0
            && let Some(control) = control
        {
            control.check()?;
        }
        // Write counter as 8-byte LE into the last 8 bytes
        buf[prefix_len..].copy_from_slice(&i.to_le_bytes());
        hasher.update(buf.as_slice());
    }

    let result = hasher.finalize();
    if let Some(control) = control {
        control.check()?;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

pub(crate) struct Aes256CbcDecryptReader<R> {
    inner: R,
    cipher: Aes256,
    previous: [u8; 16],
    plaintext: [u8; 16],
    plaintext_position: usize,
    plaintext_length: usize,
    plaintext_size: Option<u64>,
    plaintext_read: u64,
    ciphertext_size: Option<u64>,
    ciphertext_read: u64,
    expected_ciphertext_size: Option<u64>,
    finished: bool,
}

impl<R: io::Read> Aes256CbcDecryptReader<R> {
    pub(crate) fn new(
        inner: R,
        key: &[u8; 32],
        iv: &[u8; 16],
        ciphertext_size: Option<u64>,
        plaintext_size: Option<u64>,
    ) -> Result<Self, R7zError> {
        if ciphertext_size.is_some_and(|size| size % 16 != 0) {
            return Err(R7zError::Decompression);
        }
        let padded_plaintext_size = plaintext_size
            .map(encrypted_size_for_plaintext)
            .transpose()?;
        if ciphertext_size
            .zip(padded_plaintext_size)
            .is_some_and(|(ciphertext, padded)| {
                ciphertext != padded && !(plaintext_size == Some(0) && ciphertext == 0)
            })
        {
            return Err(R7zError::Decompression);
        }

        Ok(Self {
            inner,
            cipher: Aes256::new(key.into()),
            previous: *iv,
            plaintext: [0; 16],
            plaintext_position: 0,
            plaintext_length: 0,
            plaintext_size,
            plaintext_read: 0,
            ciphertext_size,
            ciphertext_read: 0,
            expected_ciphertext_size: ciphertext_size.or(padded_plaintext_size),
            finished: false,
        })
    }

    fn read_block(&mut self) -> io::Result<bool> {
        if self.finished {
            return Ok(false);
        }
        if self
            .expected_ciphertext_size
            .is_some_and(|size| self.ciphertext_read == size)
        {
            let mut extra = [0; 1];
            if read_one(&mut self.inner, &mut extra)? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AES stream exceeds its declared plaintext size",
                ));
            }
            self.finished = true;
            return Ok(false);
        }

        let mut block = Block::<Aes256>::default();
        if read_one(&mut self.inner, &mut block[..1])? == 0 {
            if self
                .expected_ciphertext_size
                .is_some_and(|size| self.ciphertext_read != size)
                && !(self.ciphertext_size.is_none()
                    && self.plaintext_size == Some(0)
                    && self.ciphertext_read == 0)
            {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated AES stream",
                ));
            }
            self.finished = true;
            return Ok(false);
        }
        self.inner.read_exact(&mut block[1..])?;
        let ciphertext = block;
        self.cipher.decrypt_block(&mut block);
        for (byte, previous) in block.iter_mut().zip(self.previous) {
            *byte ^= previous;
        }
        self.previous.copy_from_slice(&ciphertext);
        self.ciphertext_read = self
            .ciphertext_read
            .checked_add(16)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "AES stream too large"))?;
        self.plaintext.copy_from_slice(&block);
        self.plaintext_position = 0;
        self.plaintext_length = self.plaintext_size.map_or(16, |size| {
            size.saturating_sub(self.plaintext_read).min(16) as usize
        });
        Ok(true)
    }
}

impl<R: io::Read> io::Read for Aes256CbcDecryptReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.plaintext_position == self.plaintext_length {
            if !self.read_block()? {
                return Ok(0);
            }
        }

        let length = output
            .len()
            .min(self.plaintext_length - self.plaintext_position);
        output[..length].copy_from_slice(
            &self.plaintext[self.plaintext_position..self.plaintext_position + length],
        );
        self.plaintext_position += length;
        self.plaintext_read = self
            .plaintext_read
            .checked_add(length as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "AES output too large"))?;
        Ok(length)
    }
}

fn encrypted_size_for_plaintext(size: u64) -> Result<u64, R7zError> {
    if size == 0 {
        return Ok(16);
    }
    size.checked_add(15)
        .map(|size| size / 16 * 16)
        .ok_or(R7zError::Decompression)
}

fn read_one(reader: &mut impl io::Read, output: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(output) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

pub(crate) fn encode_aes_properties(num_cycles_power: u8, salt: &[u8], iv: &[u8]) -> Vec<u8> {
    assert!(salt.len() <= 16, "7z AES salt must be at most 16 bytes");
    assert!(iv.len() <= 16, "7z AES IV must be at most 16 bytes");
    let mut props = Vec::with_capacity(2 + salt.len() + iv.len());
    let has_salt = !salt.is_empty();
    let has_iv = !iv.is_empty();
    props.push(
        (num_cycles_power & 0x3F) | if has_salt { 0x80 } else { 0 } | if has_iv { 0x40 } else { 0 },
    );
    if has_salt || has_iv {
        let salt_extra = salt.len().saturating_sub(usize::from(has_salt));
        let iv_extra = iv.len().saturating_sub(usize::from(has_iv));
        let salt_extra = u8::try_from(salt_extra).expect("salt length checked");
        let iv_extra = u8::try_from(iv_extra).expect("IV length checked");
        props.push((salt_extra << 4) | iv_extra);
        props.extend_from_slice(salt);
        props.extend_from_slice(iv);
    }
    props
}

pub(crate) fn encrypt_aes256_cbc_zero_pad(
    data: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<Vec<u8>, R7zError> {
    let padded_len = data.len().next_multiple_of(16);
    let padded_len = padded_len.max(16);
    let mut buf = vec![0u8; padded_len];
    buf[..data.len()].copy_from_slice(data);
    let encryptor = Aes256CbcEnc::new(key.into(), iv.into());
    let out = encryptor
        .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf, padded_len)
        .map_err(|_| R7zError::Decompression)?;
    Ok(out.to_vec())
}

pub(crate) struct Aes256CbcEncryptWriter<W> {
    inner: W,
    cipher: Aes256,
    previous: [u8; 16],
    pending: [u8; 16],
    pending_len: usize,
    ciphertext: [u8; CIPHERTEXT_BUFFER_SIZE],
    ciphertext_len: usize,
    plaintext_size: u64,
    encrypted_block: bool,
}

impl<W: io::Write> Aes256CbcEncryptWriter<W> {
    pub(crate) fn new(inner: W, key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self {
            inner,
            cipher: Aes256::new(key.into()),
            previous: *iv,
            pending: [0; 16],
            pending_len: 0,
            ciphertext: [0; CIPHERTEXT_BUFFER_SIZE],
            ciphertext_len: 0,
            plaintext_size: 0,
            encrypted_block: false,
        }
    }

    pub(crate) fn finish(mut self) -> io::Result<(W, u64)> {
        if self.pending_len != 0 || !self.encrypted_block {
            self.encrypt_pending()?;
        }
        self.flush_ciphertext()?;
        self.inner.flush()?;
        Ok((self.inner, self.plaintext_size))
    }

    fn encrypt_pending(&mut self) -> io::Result<()> {
        self.pending[self.pending_len..].fill(0);
        let mut block = Block::<Aes256>::default();
        block.copy_from_slice(&self.pending);
        for (byte, previous) in block.iter_mut().zip(self.previous) {
            *byte ^= previous;
        }
        self.cipher.encrypt_block(&mut block);
        let ciphertext_end = self.ciphertext_len + block.len();
        self.ciphertext[self.ciphertext_len..ciphertext_end].copy_from_slice(&block);
        self.ciphertext_len = ciphertext_end;
        self.previous.copy_from_slice(&block);
        self.pending = [0; 16];
        self.pending_len = 0;
        self.encrypted_block = true;
        if self.ciphertext_len == self.ciphertext.len() {
            self.flush_ciphertext()?;
        }
        Ok(())
    }

    fn flush_ciphertext(&mut self) -> io::Result<()> {
        if self.ciphertext_len == 0 {
            return Ok(());
        }
        self.inner
            .write_all(&self.ciphertext[..self.ciphertext_len])?;
        self.ciphertext_len = 0;
        Ok(())
    }
}

impl<W: io::Write> io::Write for Aes256CbcEncryptWriter<W> {
    fn write(&mut self, mut input: &[u8]) -> io::Result<usize> {
        let input_len = input.len();
        let plaintext_size = self
            .plaintext_size
            .checked_add(input_len as u64)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "encrypted stream too large")
            })?;
        while !input.is_empty() {
            let copied = (self.pending.len() - self.pending_len).min(input.len());
            self.pending[self.pending_len..self.pending_len + copied]
                .copy_from_slice(&input[..copied]);
            self.pending_len += copied;
            input = &input[copied..];
            if self.pending_len == self.pending.len() {
                self.encrypt_pending()?;
            }
        }
        self.plaintext_size = plaintext_size;
        Ok(input_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_ciphertext()?;
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[derive(Default)]
    struct CountWrites {
        bytes: Vec<u8>,
        writes: usize,
    }

    impl io::Write for CountWrites {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn parse_aes_properties_minimal() {
        // NumCyclesPower=19, no salt, no IV → just 1 byte
        let props = [19u8];
        let p = AesProperties::parse(&props).unwrap();
        assert_eq!(p.num_cycles_power, 19);
        assert_eq!(p.salt, [] as [u8; 0]);
        assert_eq!(p.iv, [0u8; 16]);
    }

    #[test]
    fn streaming_encrypt_matches_zero_padded_cbc_across_chunk_boundaries() {
        let key = [0x35; 32];
        let iv = [0xA7; 16];
        for data in [
            Vec::new(),
            (0..15).collect(),
            (0..16).collect(),
            (0..17).collect(),
            (0..65).collect(),
        ] {
            let expected = encrypt_aes256_cbc_zero_pad(&data, &key, &iv).unwrap();
            let mut writer = Aes256CbcEncryptWriter::new(Vec::new(), &key, &iv);
            for chunk in data.chunks(7) {
                writer.write_all(chunk).unwrap();
            }
            let (actual, plaintext_size) = writer.finish().unwrap();
            assert_eq!(plaintext_size, data.len() as u64);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn streaming_encrypt_batches_ciphertext_writes() {
        let data = vec![0x5A; 1024 * 1024];
        let mut writer = Aes256CbcEncryptWriter::new(CountWrites::default(), &[1; 32], &[2; 16]);
        writer.write_all(&data).unwrap();
        let (output, _) = writer.finish().unwrap();

        assert!(output.writes < data.len() / 1024);
        assert_eq!(output.bytes.len(), data.len());
    }

    #[test]
    fn streaming_encrypt_flushes_blocks_and_keeps_partial_plaintext() {
        let key = [7; 32];
        let iv = [9; 16];
        let mut data = vec![3; 16];
        data.extend_from_slice(&[4; 5]);
        let mut writer = Aes256CbcEncryptWriter::new(Vec::new(), &key, &iv);
        writer.write_all(&data[..16]).unwrap();
        writer.write_all(&data[16..]).unwrap();
        writer.flush().unwrap();

        let (ciphertext, plaintext_size) = writer.finish().unwrap();
        assert_eq!(plaintext_size, data.len() as u64);
        assert_eq!(
            ciphertext,
            encrypt_aes256_cbc_zero_pad(&data, &key, &iv).unwrap()
        );
    }

    #[test]
    fn streaming_decrypt_matches_zero_padded_cbc_across_chunk_boundaries() {
        let key = [0x35; 32];
        let iv = [0xA7; 16];
        for data in [
            Vec::new(),
            (0..15).collect(),
            (0..16).collect(),
            (0..17).collect(),
            (0..65).collect(),
        ] {
            let encrypted = encrypt_aes256_cbc_zero_pad(&data, &key, &iv).unwrap();
            let mut reader = Aes256CbcDecryptReader::new(
                io::Cursor::new(encrypted.as_slice()),
                &key,
                &iv,
                Some(encrypted.len() as u64),
                Some(data.len() as u64),
            )
            .unwrap();
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, data);
        }
    }

    #[test]
    fn streaming_decrypt_rejects_truncated_blocks_and_size_mismatches() {
        let key = [0x35; 32];
        let iv = [0xA7; 16];
        for ciphertext_size in [None, Some(0)] {
            let mut reader = Aes256CbcDecryptReader::new(
                io::Cursor::new(&[][..]),
                &key,
                &iv,
                ciphertext_size,
                Some(0),
            )
            .unwrap();
            assert_eq!(reader.read_to_end(&mut Vec::new()).unwrap(), 0);
        }

        let mut reader =
            Aes256CbcDecryptReader::new(io::Cursor::new([0; 15]), &key, &iv, None, None).unwrap();
        assert_eq!(
            reader.read_to_end(&mut Vec::new()).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        let mut reader =
            Aes256CbcDecryptReader::new(io::Cursor::new([0; 32]), &key, &iv, Some(16), Some(16))
                .unwrap();
        assert_eq!(
            reader.read_to_end(&mut Vec::new()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut reader =
            Aes256CbcDecryptReader::new(io::Cursor::new(&[][..]), &key, &iv, Some(16), Some(0))
                .unwrap();
        assert_eq!(
            reader.read_to_end(&mut Vec::new()).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        assert!(matches!(
            Aes256CbcDecryptReader::new(io::empty(), &key, &iv, Some(16), Some(17)),
            Err(R7zError::Decompression)
        ));
    }

    #[test]
    fn parse_aes_properties_with_salt_and_iv() {
        // byte0: num_cycles=19 | has_iv=1 | has_salt=1 → 0b1_1_010011 = 0xD3
        // byte1: salt_extra=0 (high nibble), iv_extra=0xF (low nibble)
        //   salt_size = 1 + 0 = 1
        //   iv_size   = 1 + 15 = 16
        // Then 1 byte salt + 16 bytes IV
        let mut props = vec![0xD3, 0x0F];
        props.push(0xAA); // salt
        props.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]); // IV

        let p = AesProperties::parse(&props).unwrap();
        assert_eq!(p.num_cycles_power, 19);
        assert_eq!(p.salt, &[0xAA]);
        assert_eq!(
            p.iv,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn derive_key_known_value() {
        // With 0 cycles (2^0 = 1 iteration), no salt, we can verify manually.
        // SHA256(password_utf16le || 0x0000000000000000)
        let key = derive_key("a", &[], 0).unwrap();
        // "a" in UTF-16LE = [0x61, 0x00]
        // One round: SHA256([0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        let mut hasher = Sha256::new();
        hasher.update([0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(key, expected);
    }

    #[test]
    fn derive_key_rejects_excessive_cycle_power() {
        assert!(matches!(
            derive_key("a", &[], MAX_AES_NUM_CYCLES_POWER + 1),
            Err(R7zError::Decompression)
        ));
    }

    #[test]
    fn aes_cbc_decrypt_roundtrip() {
        use aes::Aes256;
        use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;

        let key = [0x42u8; 32];
        let iv = [0x00u8; 16];
        let plaintext = b"Hello, 7z world!"; // exactly 16 bytes

        let mut buf = plaintext.to_vec();
        let encryptor = Aes256CbcEnc::new((&key).into(), (&iv).into());
        let ct = encryptor
            .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf, 16)
            .unwrap();
        let ciphertext = ct.to_vec();

        let mut decrypted = Aes256CbcDecryptReader::new(
            io::Cursor::new(ciphertext.as_slice()),
            &key,
            &iv,
            Some(ciphertext.len() as u64),
            Some(plaintext.len() as u64),
        )
        .unwrap();
        let mut output = Vec::new();
        decrypted.read_to_end(&mut output).unwrap();
        assert_eq!(output, plaintext);
    }

    #[test]
    fn encode_aes_properties_parse_roundtrip() {
        let salt = [0xAA, 0xBB, 0xCC, 0xDD];
        let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let props = encode_aes_properties(19, &salt, &iv);
        let parsed = AesProperties::parse(&props).unwrap();
        assert_eq!(parsed.num_cycles_power, 19);
        assert_eq!(parsed.salt, salt);
        assert_eq!(parsed.iv, iv);
    }

    #[test]
    fn encrypt_zero_pad_decrypt_truncates_to_original() {
        let key = [0x33u8; 32];
        let iv = [0x44u8; 16];
        let plaintext = b"not a block multiple";
        let encrypted = encrypt_aes256_cbc_zero_pad(plaintext, &key, &iv).unwrap();
        assert!(encrypted.len().is_multiple_of(16));

        let mut decrypted = Aes256CbcDecryptReader::new(
            io::Cursor::new(encrypted.as_slice()),
            &key,
            &iv,
            Some(encrypted.len() as u64),
            Some(plaintext.len() as u64),
        )
        .unwrap();
        let mut output = Vec::new();
        decrypted.read_to_end(&mut output).unwrap();
        assert_eq!(output, plaintext);
    }
}
