use std::time::SystemTime;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Codec {
    Copy,
    Lzma,
    #[default]
    Lzma2,
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
    pub unix_mode: Option<u32>,
    pub start_pos: Option<u64>,
}

impl EntryMeta {
    #[must_use]
    pub fn from_unix_mode(mode: u32) -> Self {
        Self {
            attributes: Some((mode << 16) | 0x20),
            unix_mode: Some(mode),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn directory_unix_mode(mode: u32) -> Self {
        Self {
            attributes: Some((mode << 16) | 0x10),
            unix_mode: Some(mode),
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

pub(crate) struct CompletedFolder {
    pub file_indices: Vec<usize>,
    pub pack_size: u64,
    pub coder_info: Vec<u8>,
    pub coder_unpack_sizes: Vec<u64>,
    pub file_sizes: Vec<u64>,
    pub file_crcs: Vec<u32>,
}
