use thiserror::Error;

/// Errors returned by r7z operations.
#[derive(Debug, Error)]
pub enum R7zError {
    /// Binary structure could not be parsed (malformed archive).
    #[error("parse error")]
    Parse,

    /// A property tag byte was not recognised.
    #[error("invalid property: {0:#04x}")]
    InvalidProperty(u8),

    /// The codec identified by the given bytes is not supported.
    #[error("unsupported codec: {0:?}")]
    UnsupportedCodec(Vec<u8>),

    /// A CRC32 check failed (data is corrupted).
    #[error("CRC mismatch")]
    Crc,

    /// An underlying I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Decompression failed (corrupt or truncated stream).
    #[error("decompression error")]
    Decompression,

    /// The archive is encrypted and a password is required.
    #[error("password required")]
    PasswordRequired,

    /// The supplied password was incorrect (decryption produced garbage).
    #[error("wrong password")]
    WrongPassword,

    /// The archive entry name cannot be extracted safely under the destination directory.
    #[error("unsafe archive path: {0}")]
    UnsafePath(String),

    /// The requested entry is a directory or anti-item, not a regular file.
    #[error("entry is a directory")]
    Directory,
}
