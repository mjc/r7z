//! AES-256-SHA-256 decryption for 7z archives.
//!
//! The 7z format uses a custom key derivation (iterated SHA-256, not PBKDF2)
//! followed by AES-256-CBC decryption. The password is encoded as UTF-16LE.
//!
//! # Properties byte layout
//!
//! | Byte | Bits   | Meaning                                        |
//! |------|--------|------------------------------------------------|
//! | 0    | \[5:0\]  | NumCyclesPower (0–62, or 0x3F for raw key)   |
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
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use sha2::{Digest, Sha256};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Parsed AES-256-SHA-256 properties from a 7z coder.
#[derive(Debug)]
pub(crate) struct AesProperties {
    /// Number of SHA-256 iterations = 2^num_cycles_power.
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
pub(crate) fn derive_key(password: &str, salt: &[u8], num_cycles_power: u8) -> [u8; 32] {
    // Special case: 0x3F means raw key = salt || password, zero-padded
    if num_cycles_power == 0x3F {
        let pwd_utf16: Vec<u8> = password
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut key = [0u8; 32];
        let total: Vec<u8> = salt.iter().chain(pwd_utf16.iter()).copied().collect();
        let len = total.len().min(32);
        key[..len].copy_from_slice(&total[..len]);
        return key;
    }

    let pwd_utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let num_rounds: u64 = 1u64 << num_cycles_power;

    // Pre-build the append buffer: salt || password_utf16le || counter[8]
    let prefix_len = salt.len() + pwd_utf16.len();
    let buf_len = prefix_len + 8;
    let mut buf = vec![0u8; buf_len];
    buf[..salt.len()].copy_from_slice(salt);
    buf[salt.len()..prefix_len].copy_from_slice(&pwd_utf16);

    let mut hasher = Sha256::new();
    for i in 0..num_rounds {
        // Write counter as 8-byte LE into the last 8 bytes
        buf[prefix_len..].copy_from_slice(&i.to_le_bytes());
        hasher.update(&buf);
    }

    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Decrypt `data` using AES-256-CBC with the given key and IV.
///
/// The input must be a multiple of 16 bytes (AES block size).
/// Returns the decrypted bytes (which may include padding beyond `unpack_size`;
/// the caller is responsible for truncating to the actual stream size).
pub(crate) fn decrypt_aes256_cbc(
    data: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<Vec<u8>, R7zError> {
    if !data.len().is_multiple_of(16) {
        return Err(R7zError::Decompression);
    }

    let mut buf = data.to_vec();
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    // Decrypt in-place, treating blocks as NoPadding (7z manages truncation itself)
    decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|_| R7zError::Decompression)?;

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aes_properties_minimal() {
        // NumCyclesPower=19, no salt, no IV → just 1 byte
        let props = [19u8];
        let p = AesProperties::parse(&props).unwrap();
        assert_eq!(p.num_cycles_power, 19);
        assert!(p.salt.is_empty());
        assert_eq!(p.iv, [0u8; 16]);
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
        let key = derive_key("a", &[], 0);
        // "a" in UTF-16LE = [0x61, 0x00]
        // One round: SHA256([0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        let mut hasher = Sha256::new();
        hasher.update([0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(key, expected);
    }

    #[test]
    fn aes_cbc_decrypt_roundtrip() {
        use aes::Aes256;
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;

        let key = [0x42u8; 32];
        let iv = [0x00u8; 16];
        let plaintext = b"Hello, 7z world!"; // exactly 16 bytes

        let mut buf = plaintext.to_vec();
        let encryptor = Aes256CbcEnc::new((&key).into(), (&iv).into());
        let ct = encryptor
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, 16)
            .unwrap();
        let ciphertext = ct.to_vec();

        let decrypted = decrypt_aes256_cbc(&ciphertext, &key, &iv).unwrap();
        assert_eq!(&decrypted, plaintext);
    }
}
