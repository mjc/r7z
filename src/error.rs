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
}
