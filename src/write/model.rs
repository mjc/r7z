use std::{num::NonZeroU64, path::PathBuf, time::SystemTime};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Codec {
    Copy,
    Lzma,
    #[default]
    Lzma2,
    Ppmd,
    Lzma2Bcj,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HeaderMode {
    #[default]
    P7zipDefault,
    Plain,
    Encoded,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchiveOptions {
    pub codec: Codec,
    pub header_mode: HeaderMode,
    pub encryption: Option<EncryptionOptions>,
    pub compression: CompressionOptions,
    pub streaming: StreamingOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressionOptions {
    pub level: CompressionLevel,
    pub dictionary_size: Option<u32>,
    pub fast_bytes: Option<u32>,
    pub literal_context_bits: Option<u32>,
    pub literal_position_bits: Option<u32>,
    pub position_bits: Option<u32>,
    pub match_finder: Option<MatchFinder>,
    pub solid: SolidMode,
    pub lzma2_chunk_size: Option<NonZeroU64>,
}

impl Default for CompressionOptions {
    fn default() -> Self {
        Self {
            level: CompressionLevel::Normal,
            dictionary_size: None,
            fast_bytes: None,
            literal_context_bits: None,
            literal_position_bits: None,
            position_bits: None,
            match_finder: None,
            solid: SolidMode::Solid,
            lzma2_chunk_size: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchFinder {
    Hc4,
    Bt4,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CompressionLevel {
    Store,
    Fastest,
    Fast,
    #[default]
    Normal,
    Maximum,
    Ultra,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SolidMode {
    #[default]
    Solid,
    NonSolid,
    Limit {
        max_files: Option<NonZeroU64>,
        max_bytes: Option<NonZeroU64>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamingOptions {
    pub buffer_size: usize,
    pub spool: SpoolMode,
}

impl Default for StreamingOptions {
    fn default() -> Self {
        Self {
            buffer_size: 8192,
            spool: SpoolMode::Auto {
                memory_threshold: 16 * 1024 * 1024,
                dir: None,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpoolMode {
    Memory,
    TempFile {
        dir: Option<PathBuf>,
    },
    Auto {
        memory_threshold: u64,
        dir: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeOptions {
    pub sizes: Vec<NonZeroU64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptionOptions {
    pub password: String,
    pub encrypt_header: bool,
    pub num_cycles_power: u8,
    pub salt_len: u8,
    pub iv_len: u8,
}

impl EncryptionOptions {
    #[must_use]
    pub fn default_for_password(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            encrypt_header: false,
            num_cycles_power: 19,
            salt_len: 0,
            iv_len: 16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Anti,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryMeta {
    pub ctime: Option<SystemTime>,
    pub atime: Option<SystemTime>,
    pub mtime: Option<SystemTime>,
    pub attributes: Option<u32>,
    pub start_pos: Option<u64>,
}

impl EntryMeta {
    #[must_use]
    pub fn from_unix_mode(mode: u32) -> Self {
        Self {
            attributes: Some((mode << 16) | 0x20),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn directory_unix_mode(mode: u32) -> Self {
        Self {
            attributes: Some((mode << 16) | 0x10),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn archive_file() -> Self {
        Self {
            attributes: Some(0x20),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn symlink() -> Self {
        Self {
            attributes: Some((0o120_777 << 16) | 0x20),
            ..Self::default()
        }
    }

    pub(crate) fn with_symlink_default(mut self) -> Self {
        if self.attributes.is_none() {
            self.attributes = Some((0o120_777 << 16) | 0x20);
        }
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub name: String,
    pub kind: EntryKind,
    pub meta: EntryMeta,
}

impl ArchiveEntry {
    #[must_use]
    pub fn file(name: impl Into<String>, meta: EntryMeta) -> Self {
        Self {
            name: name.into(),
            kind: EntryKind::File,
            meta,
        }
    }

    #[must_use]
    pub fn directory(name: impl Into<String>, meta: EntryMeta) -> Self {
        Self {
            name: name.into(),
            kind: EntryKind::Directory,
            meta,
        }
    }

    #[must_use]
    pub fn anti(name: impl Into<String>, meta: EntryMeta) -> Self {
        Self {
            name: name.into(),
            kind: EntryKind::Anti,
            meta,
        }
    }
}

#[derive(Clone)]
pub(crate) struct WriteEntry {
    pub name: String,
    pub kind: EntryKind,
    pub meta: EntryMeta,
    pub has_stream: bool,
    pub data: Option<Vec<u8>>,
    pub folder_id: usize,
}

#[derive(Clone)]
pub(crate) struct CompletedFolder {
    pub file_indices: Vec<usize>,
    pub pack_sizes: Vec<u64>,
    pub coder_info: Vec<u8>,
    pub coder_unpack_sizes: Vec<u64>,
    pub folder_crc: Option<u32>,
    pub file_sizes: Vec<u64>,
    pub file_crcs: Vec<Option<u32>>,
}

#[derive(Clone)]
pub(crate) struct PreparedFolder {
    pub metadata: CompletedFolder,
    pub packed_streams: Vec<Vec<u8>>,
}
