//! 7z method identifiers used by p7zip / 7-Zip.
//!
//! The method ID bytes are the stable on-disk identifiers from
//! `DOC/Methods.txt` in p7zip.  Some CLI method names map to the same ID: for
//! example `FLZMA2` is p7zip's fast LZMA2 encoder and still writes the LZMA2
//! method ID.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodKind {
    Compression,
    Filter,
    Crypto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SevenZMethod {
    Copy,
    Lzma,
    Lzma2,
    BZip2,
    Ppmd,
    Deflate,
    Deflate64,
    Bcj,
    Bcj2,
    Arm,
    ArmThumb,
    Ia64,
    Ppc,
    Sparc,
    Delta,
    Swap2,
    Swap4,
    Zstd,
    Brotli,
    Lz4,
    Lz5,
    Lizard,
    FastLzma2,
    Lzham,
    SevenZAes,
    Aes256Cbc,
}

impl SevenZMethod {
    #[must_use]
    pub fn id(self) -> &'static [u8] {
        match self {
            Self::Copy => &[0x00],
            Self::Lzma => &[0x03, 0x01, 0x01],
            Self::Lzma2 | Self::FastLzma2 => &[0x21],
            Self::BZip2 => &[0x04, 0x02, 0x02],
            Self::Ppmd => &[0x03, 0x04, 0x01],
            Self::Deflate => &[0x04, 0x01, 0x08],
            Self::Deflate64 => &[0x04, 0x01, 0x09],
            Self::Bcj => &[0x03, 0x03, 0x01, 0x03],
            Self::Bcj2 => &[0x03, 0x03, 0x01, 0x1B],
            Self::Arm => &[0x03, 0x03, 0x05, 0x01],
            Self::ArmThumb => &[0x03, 0x03, 0x07, 0x01],
            Self::Ia64 => &[0x03, 0x03, 0x04, 0x01],
            Self::Ppc => &[0x03, 0x03, 0x02, 0x05],
            Self::Sparc => &[0x03, 0x03, 0x08, 0x05],
            Self::Delta => &[0x03],
            Self::Swap2 => &[0x02, 0x03, 0x02],
            Self::Swap4 => &[0x02, 0x03, 0x04],
            Self::Zstd => &[0x04, 0xF7, 0x11, 0x01],
            Self::Brotli => &[0x04, 0xF7, 0x11, 0x02],
            Self::Lz4 => &[0x04, 0xF7, 0x11, 0x04],
            Self::Lz5 => &[0x04, 0xF7, 0x11, 0x05],
            Self::Lizard => &[0x04, 0xF7, 0x11, 0x06],
            Self::Lzham => &[0x04, 0xF7, 0x10, 0x01],
            Self::SevenZAes => &[0x06, 0xF1, 0x07, 0x01],
            Self::Aes256Cbc => &[0x06, 0xF0, 0x01, 0x81],
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Copy => "Copy",
            Self::Lzma => "LZMA",
            Self::Lzma2 => "LZMA2",
            Self::BZip2 => "BZip2",
            Self::Ppmd => "PPMd",
            Self::Deflate => "Deflate",
            Self::Deflate64 => "Deflate64",
            Self::Bcj => "BCJ",
            Self::Bcj2 => "BCJ2",
            Self::Arm => "ARM",
            Self::ArmThumb => "ARMT",
            Self::Ia64 => "IA64",
            Self::Ppc => "PPC",
            Self::Sparc => "SPARC",
            Self::Delta => "Delta",
            Self::Swap2 => "Swap2",
            Self::Swap4 => "Swap4",
            Self::Zstd => "ZSTD",
            Self::Brotli => "BROTLI",
            Self::Lz4 => "LZ4",
            Self::Lz5 => "LZ5",
            Self::Lizard => "LIZARD",
            Self::FastLzma2 => "FLZMA2",
            Self::Lzham => "LZHAM",
            Self::SevenZAes => "7zAES",
            Self::Aes256Cbc => "AES256CBC",
        }
    }

    #[must_use]
    pub fn kind(self) -> MethodKind {
        match self {
            Self::Bcj
            | Self::Bcj2
            | Self::Arm
            | Self::ArmThumb
            | Self::Ia64
            | Self::Ppc
            | Self::Sparc
            | Self::Delta
            | Self::Swap2
            | Self::Swap4 => MethodKind::Filter,
            Self::SevenZAes | Self::Aes256Cbc => MethodKind::Crypto,
            _ => MethodKind::Compression,
        }
    }

    #[must_use]
    pub fn supported_by_r7z(self) -> bool {
        matches!(
            self,
            Self::Copy | Self::Lzma | Self::Lzma2 | Self::Bcj | Self::SevenZAes
        )
    }
}

#[must_use]
pub fn method_from_id(id: &[u8]) -> Option<SevenZMethod> {
    ALL_METHODS.iter().copied().find(|method| method.id() == id)
}

#[must_use]
pub fn method_from_name(name: &str) -> Option<SevenZMethod> {
    let normalized = name
        .bytes()
        .filter(|b| !matches!(b, b'-' | b'_' | b' '))
        .map(|b| b.to_ascii_lowercase())
        .collect::<Vec<_>>();
    ALL_METHODS.iter().copied().find(|method| {
        method
            .name()
            .bytes()
            .filter(|b| !matches!(b, b'-' | b'_' | b' '))
            .map(|b| b.to_ascii_lowercase())
            .eq(normalized.iter().copied())
    })
}

pub const P7ZIP_ORACLE_SHA: &str = "6819e2dc1917e1267babddc6391cea56ead7123d";

pub const ALL_METHODS: &[SevenZMethod] = &[
    SevenZMethod::Copy,
    SevenZMethod::Lzma,
    SevenZMethod::Lzma2,
    SevenZMethod::BZip2,
    SevenZMethod::Ppmd,
    SevenZMethod::Deflate,
    SevenZMethod::Deflate64,
    SevenZMethod::Bcj,
    SevenZMethod::Bcj2,
    SevenZMethod::Arm,
    SevenZMethod::ArmThumb,
    SevenZMethod::Ia64,
    SevenZMethod::Ppc,
    SevenZMethod::Sparc,
    SevenZMethod::Delta,
    SevenZMethod::Swap2,
    SevenZMethod::Swap4,
    SevenZMethod::Zstd,
    SevenZMethod::Brotli,
    SevenZMethod::Lz4,
    SevenZMethod::Lz5,
    SevenZMethod::Lizard,
    SevenZMethod::FastLzma2,
    SevenZMethod::Lzham,
    SevenZMethod::SevenZAes,
    SevenZMethod::Aes256Cbc,
];
