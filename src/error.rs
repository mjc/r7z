use thiserror::Error;

#[derive(Debug, Error)]
pub enum R7zError {
    #[error("parse error")]
    Parse,

    #[error("invalid property: {0:#04x}")]
    InvalidProperty(u8),

    #[error("unsupported codec: {0:?}")]
    UnsupportedCodec(Vec<u8>),

    #[error("CRC mismatch")]
    Crc,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("decompression error")]
    Decompression,
}
