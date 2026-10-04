//! 7z method identifiers used by p7zip / 7-Zip.
//!
//! The method ID bytes are the stable on-disk identifiers from
//! `DOC/Methods.txt` in p7zip.  Some CLI method names map to the same ID: for
//! example `FLZMA2` is p7zip's fast LZMA2 encoder and still writes the LZMA2
//! method ID.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodKind {
    /// Data compression method.
    Compression,
    /// Transform applied before or after compression.
    Filter,
    /// Encryption method.
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
    Arm64,
    ArmThumb,
    Ia64,
    Ppc,
    Sparc,
    Riscv,
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

/// How a recognized 7z method can be handled by r7z.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodSupport {
    /// r7z can decode and encode this method.
    DecodeAndEncode,
    /// r7z can decode but cannot encode this method.
    DecodeOnly,
    /// r7z recognizes and lists this method, but can only preserve it by raw copy.
    RawCopyOnly,
}

impl MethodSupport {
    #[must_use]
    pub const fn can_decode(self) -> bool {
        matches!(self, Self::DecodeAndEncode | Self::DecodeOnly)
    }

    #[must_use]
    pub const fn can_encode(self) -> bool {
        matches!(self, Self::DecodeAndEncode)
    }
}

/// Registry metadata for one on-disk method ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodInfo {
    /// The method's typed identity.
    pub method: SevenZMethod,
    /// Stable ID stored in the 7z folder data.
    pub id: &'static [u8],
    /// Human-readable method name used by listings and CLI parsing.
    pub name: &'static str,
    /// Whether this method compresses, filters, or encrypts.
    pub kind: MethodKind,
    /// Decode and encode support provided by r7z.
    pub support: MethodSupport,
    stream_arity: (u64, u64),
}

/// Codec ID for classic LZMA.
pub const CODEC_LZMA: &[u8] = &[0x03, 0x01, 0x01];
/// Codec ID for LZMA2.
pub const CODEC_LZMA2: &[u8] = &[0x21];
/// Codec ID for the x86 BCJ filter.
pub const CODEC_BCJ_X86: &[u8] = &[0x03, 0x03, 0x01, 0x03];
/// Codec ID for the BCJ2 filter.
pub const CODEC_BCJ2: &[u8] = &[0x03, 0x03, 0x01, 0x1B];
/// Codec ID for the ARM filter.
pub const CODEC_BCJ_ARM: &[u8] = &[0x03, 0x03, 0x05, 0x01];
/// Codec ID for the ARM64 filter.
pub const CODEC_BCJ_ARM64: &[u8] = &[0x0A];
/// Codec ID for the ARM Thumb filter.
pub const CODEC_BCJ_ARM_THUMB: &[u8] = &[0x03, 0x03, 0x07, 0x01];
/// Codec ID for the IA-64 filter.
pub const CODEC_BCJ_IA64: &[u8] = &[0x03, 0x03, 0x04, 0x01];
/// Codec ID for the PowerPC filter.
pub const CODEC_BCJ_PPC: &[u8] = &[0x03, 0x03, 0x02, 0x05];
/// Codec ID for the SPARC filter.
pub const CODEC_BCJ_SPARC: &[u8] = &[0x03, 0x03, 0x08, 0x05];
/// Codec ID for the RISC-V filter.
pub const CODEC_BCJ_RISCV: &[u8] = &[0x0B];
/// Codec ID for uncompressed data.
pub const CODEC_COPY: &[u8] = &[0x00];
/// Codec ID for 7z AES.
pub const CODEC_AES_256_SHA_256: &[u8] = &[0x06, 0xF1, 0x07, 0x01];
/// Codec ID for Deflate.
pub const CODEC_DEFLATE: &[u8] = &[0x04, 0x01, 0x08];
/// Codec ID for `BZip2`.
pub const CODEC_BZIP2: &[u8] = &[0x04, 0x02, 0x02];
/// Codec ID for `PPMd`.
pub const CODEC_PPMD: &[u8] = &[0x03, 0x04, 0x01];
/// Codec ID for Deflate64.
pub const CODEC_DEFLATE64: &[u8] = &[0x04, 0x01, 0x09];
/// Codec ID for the Delta filter.
pub const CODEC_DELTA: &[u8] = &[0x03];
/// Codec ID for the 2-byte swap filter.
pub const CODEC_SWAP2: &[u8] = &[0x02, 0x03, 0x02];
/// Codec ID for the 4-byte swap filter.
pub const CODEC_SWAP4: &[u8] = &[0x02, 0x03, 0x04];

const ID_ZSTD: &[u8] = &[0x04, 0xF7, 0x11, 0x01];
const ID_BROTLI: &[u8] = &[0x04, 0xF7, 0x11, 0x02];
const ID_LZ4: &[u8] = &[0x04, 0xF7, 0x11, 0x04];
const ID_LZ5: &[u8] = &[0x04, 0xF7, 0x11, 0x05];
const ID_LIZARD: &[u8] = &[0x04, 0xF7, 0x11, 0x06];
const ID_FAST_LZMA2: &[u8] = CODEC_LZMA2;
const ID_LZHAM: &[u8] = &[0x04, 0xF7, 0x10, 0x01];
const ID_AES256CBC: &[u8] = &[0x06, 0xF0, 0x01, 0x81];

const METHOD_REGISTRY_DATA: [MethodInfo; 28] = [
    MethodInfo {
        method: SevenZMethod::Copy,
        id: CODEC_COPY,
        name: "Copy",
        kind: MethodKind::Compression,
        support: MethodSupport::DecodeAndEncode,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Lzma,
        id: CODEC_LZMA,
        name: "LZMA",
        kind: MethodKind::Compression,
        support: MethodSupport::DecodeAndEncode,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Lzma2,
        id: CODEC_LZMA2,
        name: "LZMA2",
        kind: MethodKind::Compression,
        support: MethodSupport::DecodeAndEncode,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::BZip2,
        id: CODEC_BZIP2,
        name: "BZip2",
        kind: MethodKind::Compression,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Ppmd,
        id: CODEC_PPMD,
        name: "PPMd",
        kind: MethodKind::Compression,
        support: MethodSupport::DecodeAndEncode,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Deflate,
        id: CODEC_DEFLATE,
        name: "Deflate",
        kind: MethodKind::Compression,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Deflate64,
        id: CODEC_DEFLATE64,
        name: "Deflate64",
        kind: MethodKind::Compression,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Bcj,
        id: CODEC_BCJ_X86,
        name: "BCJ",
        kind: MethodKind::Filter,
        support: MethodSupport::DecodeAndEncode,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Bcj2,
        id: CODEC_BCJ2,
        name: "BCJ2",
        kind: MethodKind::Filter,
        support: MethodSupport::DecodeOnly,
        stream_arity: (4, 1),
    },
    MethodInfo {
        method: SevenZMethod::Arm,
        id: CODEC_BCJ_ARM,
        name: "ARM",
        kind: MethodKind::Filter,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Arm64,
        id: CODEC_BCJ_ARM64,
        name: "ARM64",
        kind: MethodKind::Filter,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::ArmThumb,
        id: CODEC_BCJ_ARM_THUMB,
        name: "ARMT",
        kind: MethodKind::Filter,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Ia64,
        id: CODEC_BCJ_IA64,
        name: "IA64",
        kind: MethodKind::Filter,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Ppc,
        id: CODEC_BCJ_PPC,
        name: "PPC",
        kind: MethodKind::Filter,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Sparc,
        id: CODEC_BCJ_SPARC,
        name: "SPARC",
        kind: MethodKind::Filter,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Riscv,
        id: CODEC_BCJ_RISCV,
        name: "RISCV",
        kind: MethodKind::Filter,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Delta,
        id: CODEC_DELTA,
        name: "Delta",
        kind: MethodKind::Filter,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Swap2,
        id: CODEC_SWAP2,
        name: "Swap2",
        kind: MethodKind::Filter,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Swap4,
        id: CODEC_SWAP4,
        name: "Swap4",
        kind: MethodKind::Filter,
        support: MethodSupport::DecodeOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Zstd,
        id: ID_ZSTD,
        name: "ZSTD",
        kind: MethodKind::Compression,
        support: MethodSupport::RawCopyOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Brotli,
        id: ID_BROTLI,
        name: "BROTLI",
        kind: MethodKind::Compression,
        support: MethodSupport::RawCopyOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Lz4,
        id: ID_LZ4,
        name: "LZ4",
        kind: MethodKind::Compression,
        support: MethodSupport::RawCopyOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Lz5,
        id: ID_LZ5,
        name: "LZ5",
        kind: MethodKind::Compression,
        support: MethodSupport::RawCopyOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Lizard,
        id: ID_LIZARD,
        name: "LIZARD",
        kind: MethodKind::Compression,
        support: MethodSupport::RawCopyOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::FastLzma2,
        id: ID_FAST_LZMA2,
        name: "FLZMA2",
        kind: MethodKind::Compression,
        support: MethodSupport::DecodeAndEncode,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Lzham,
        id: ID_LZHAM,
        name: "LZHAM",
        kind: MethodKind::Compression,
        support: MethodSupport::RawCopyOnly,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::SevenZAes,
        id: CODEC_AES_256_SHA_256,
        name: "7zAES",
        kind: MethodKind::Crypto,
        support: MethodSupport::DecodeAndEncode,
        stream_arity: (1, 1),
    },
    MethodInfo {
        method: SevenZMethod::Aes256Cbc,
        id: ID_AES256CBC,
        name: "AES256CBC",
        kind: MethodKind::Crypto,
        support: MethodSupport::RawCopyOnly,
        stream_arity: (1, 1),
    },
];

/// Known 7z methods and their read, write, and raw-copy capabilities.
pub const METHOD_REGISTRY: &[MethodInfo] = &METHOD_REGISTRY_DATA;

const fn registry_methods<const N: usize>(registry: &[MethodInfo; N]) -> [SevenZMethod; N] {
    let mut methods = [SevenZMethod::Copy; N];
    let mut index = 0;
    while index < N {
        methods[index] = registry[index].method;
        index += 1;
    }
    methods
}

const ALL_METHODS_DATA: [SevenZMethod; 28] = registry_methods(&METHOD_REGISTRY_DATA);

#[must_use]
pub fn method_info(id: &[u8]) -> Option<&'static MethodInfo> {
    METHOD_REGISTRY.iter().find(|info| info.id == id)
}

impl SevenZMethod {
    fn info(self) -> &'static MethodInfo {
        METHOD_REGISTRY
            .iter()
            .find(|info| info.method == self)
            .expect("every method enum variant has registry metadata")
    }

    pub(crate) fn stream_arity(self) -> (u64, u64) {
        self.info().stream_arity
    }

    #[must_use]
    pub fn id(self) -> &'static [u8] {
        self.info().id
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        self.info().name
    }

    #[must_use]
    pub fn kind(self) -> MethodKind {
        self.info().kind
    }

    #[must_use]
    pub fn support(self) -> MethodSupport {
        self.info().support
    }

    #[must_use]
    pub fn supported_by_r7z(self) -> bool {
        self.info().can_decode()
    }
}

impl MethodInfo {
    #[must_use]
    pub const fn can_decode(self) -> bool {
        self.support.can_decode()
    }

    #[must_use]
    pub const fn can_encode(self) -> bool {
        self.support.can_encode()
    }
}

#[must_use]
pub fn method_from_id(id: &[u8]) -> Option<SevenZMethod> {
    method_info(id).map(|info| info.method)
}

#[must_use]
pub fn method_from_name(name: &str) -> Option<SevenZMethod> {
    let normalized = name
        .bytes()
        .filter(|b| !matches!(b, b'-' | b'_' | b' '))
        .map(|b| b.to_ascii_lowercase())
        .collect::<Vec<_>>();
    METHOD_REGISTRY
        .iter()
        .find(|info| {
            info.name
                .bytes()
                .filter(|b| !matches!(b, b'-' | b'_' | b' '))
                .map(|b| b.to_ascii_lowercase())
                .eq(normalized.iter().copied())
        })
        .map(|info| info.method)
}

pub const P7ZIP_ORACLE_SHA: &str = "6819e2dc1917e1267babddc6391cea56ead7123d";

pub const ALL_METHODS: &[SevenZMethod] = &ALL_METHODS_DATA;
