#![allow(clippy::missing_errors_doc)]

mod encode;
mod header;
mod model;

use crate::R7zError;
use header::encode_coder_info_copy;
use std::io::{Read, Seek, SeekFrom, Write};

pub use model::{
    ArchiveEntry, ArchiveOptions, Codec, EncryptionOptions, EntryKind, EntryMeta, HeaderMode,
};

use model::WriteEntry;

struct StreamingCopyFolder {
    file_indices: Vec<usize>,
    pack_size: u64,
    file_sizes: Vec<u64>,
    file_crcs: Vec<u32>,
}

impl StreamingCopyFolder {
    fn new() -> Self {
        Self {
            file_indices: Vec::new(),
            pack_size: 0,
            file_sizes: Vec::new(),
            file_crcs: Vec::new(),
        }
    }
}

pub struct ArchiveBuilder {
    entries: Vec<WriteEntry>,
    options: ArchiveOptions,
}

impl Default for ArchiveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            options: ArchiveOptions::default(),
        }
    }

    #[must_use]
    pub fn options(mut self, options: ArchiveOptions) -> Self {
        self.options = options;
        self
    }

    #[must_use]
    pub fn compression(mut self, codec: Codec) -> Self {
        self.options.codec = codec;
        self
    }

    #[must_use]
    pub fn add_file(mut self, name: &str, data: &[u8]) -> Self {
        if data.is_empty() {
            self.entries.push(WriteEntry {
                name: name.to_string(),
                kind: EntryKind::File,
                meta: EntryMeta::default(),
                has_stream: false,
                data: None,
                folder_id: 0,
            });
        } else {
            self.entries.push(WriteEntry {
                name: name.to_string(),
                kind: EntryKind::File,
                meta: EntryMeta::default(),
                has_stream: true,
                data: Some(data.to_vec()),
                folder_id: 0,
            });
        }
        self
    }

    #[must_use]
    pub fn add_file_entry(mut self, name: &str, data: &[u8], meta: EntryMeta) -> Self {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: !data.is_empty(),
            data: (!data.is_empty()).then(|| data.to_vec()),
            folder_id: 0,
        });
        self
    }

    #[must_use]
    pub fn add_empty_file(mut self, name: &str, meta: EntryMeta) -> Self {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: false,
            data: None,
            folder_id: 0,
        });
        self
    }

    #[must_use]
    pub fn add_directory(mut self, name: &str, meta: EntryMeta) -> Self {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::Directory,
            meta,
            has_stream: false,
            data: None,
            folder_id: 0,
        });
        self
    }

    #[must_use]
    pub fn add_anti_item(mut self, name: &str, meta: EntryMeta) -> Self {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::Anti,
            meta,
            has_stream: false,
            data: None,
            folder_id: 0,
        });
        self
    }

    pub fn build(self) -> Result<Vec<u8>, R7zError> {
        encode::build_archive(&self.entries, &self.options)
    }
}

pub struct ArchiveWriter<W: Write + Seek> {
    out: W,
    entries: Vec<WriteEntry>,
    options: ArchiveOptions,
    current_folder: usize,
    copy_started: bool,
    copy_current: StreamingCopyFolder,
    copy_completed: Vec<StreamingCopyFolder>,
}

impl<W: Write + Seek> ArchiveWriter<W> {
    pub fn new(out: W) -> Result<Self, R7zError> {
        Self::new_with_options(out, ArchiveOptions::default())
    }

    pub fn new_with_options(out: W, options: ArchiveOptions) -> Result<Self, R7zError> {
        Ok(Self {
            out,
            entries: Vec::new(),
            options,
            current_folder: 0,
            copy_started: false,
            copy_current: StreamingCopyFolder::new(),
            copy_completed: Vec::new(),
        })
    }

    #[must_use]
    pub fn compression(mut self, codec: Codec) -> Self {
        self.options.codec = codec;
        self
    }

    pub fn append(&mut self, name: &str, reader: impl Read) -> Result<(), R7zError> {
        self.append_file(name, reader, EntryMeta::default())
    }

    pub fn append_entry(
        &mut self,
        name: &str,
        reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        self.append_file(name, reader, meta)
    }

    pub fn append_file(
        &mut self,
        name: &str,
        mut reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        if self.should_stream_copy() {
            return self.append_copy_streaming(name, reader, meta);
        }

        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: !data.is_empty(),
            data: (!data.is_empty()).then_some(data),
            folder_id: self.current_folder,
        });
        Ok(())
    }

    pub fn append_empty_file(&mut self, name: &str, meta: EntryMeta) -> Result<(), R7zError> {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: false,
            data: None,
            folder_id: self.current_folder,
        });
        Ok(())
    }

    pub fn append_directory(&mut self, name: &str, meta: EntryMeta) -> Result<(), R7zError> {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::Directory,
            meta,
            has_stream: false,
            data: None,
            folder_id: self.current_folder,
        });
        Ok(())
    }

    pub fn append_anti_item(&mut self, name: &str, meta: EntryMeta) -> Result<(), R7zError> {
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::Anti,
            meta,
            has_stream: false,
            data: None,
            folder_id: self.current_folder,
        });
        Ok(())
    }

    pub fn new_folder(&mut self) -> Result<(), R7zError> {
        if self.should_stream_copy() {
            self.seal_copy_folder();
        } else if self
            .entries
            .iter()
            .any(|entry| entry.folder_id == self.current_folder && entry.has_stream)
        {
            self.current_folder += 1;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<W, R7zError> {
        if self.copy_started {
            self.seal_copy_folder();
            let folders: Vec<model::CompletedFolder> = self
                .copy_completed
                .into_iter()
                .map(model::CompletedFolder::from)
                .collect();
            return encode::finish_streamed_copy_archive(
                self.out,
                &self.entries,
                &folders,
                &self.options,
            );
        }

        let bytes = encode::build_archive(&self.entries, &self.options)?;
        self.out.seek(SeekFrom::Start(0))?;
        self.out.write_all(&bytes)?;
        self.out.flush()?;
        Ok(self.out)
    }

    fn should_stream_copy(&self) -> bool {
        self.options.codec == Codec::Copy && self.options.encryption.is_none()
    }

    fn append_copy_streaming(
        &mut self,
        name: &str,
        mut reader: impl Read,
        meta: EntryMeta,
    ) -> Result<(), R7zError> {
        if !self.copy_started {
            self.out.seek(SeekFrom::Start(0))?;
            self.out.write_all(&[0u8; 32])?;
            self.copy_started = true;
        }

        let mut hasher = crc32fast::Hasher::new();
        let mut size = 0u64;
        let mut buf = [0u8; 8192];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.out.write_all(&buf[..n])?;
            hasher.update(&buf[..n]);
            size = size.checked_add(n as u64).ok_or(R7zError::Parse)?;
        }

        let index = self.entries.len();
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
            has_stream: size > 0,
            data: None,
            folder_id: self.current_folder,
        });

        if size > 0 {
            self.copy_current.file_indices.push(index);
            self.copy_current.pack_size = self
                .copy_current
                .pack_size
                .checked_add(size)
                .ok_or(R7zError::Parse)?;
            self.copy_current.file_sizes.push(size);
            self.copy_current.file_crcs.push(hasher.finalize());
        }

        Ok(())
    }

    fn seal_copy_folder(&mut self) {
        if !self.copy_current.file_indices.is_empty() {
            self.copy_completed.push(std::mem::replace(
                &mut self.copy_current,
                StreamingCopyFolder::new(),
            ));
            self.current_folder += 1;
        }
    }
}

impl From<StreamingCopyFolder> for model::CompletedFolder {
    fn from(folder: StreamingCopyFolder) -> Self {
        Self {
            file_indices: folder.file_indices,
            pack_size: folder.pack_size,
            coder_info: encode_coder_info_copy(),
            coder_unpack_sizes: vec![folder.pack_size],
            file_sizes: folder.file_sizes,
            file_crcs: folder.file_crcs,
        }
    }
}

pub fn build_streaming<W, I, R>(entries: I, mut out: W) -> Result<(), R7zError>
where
    W: Write + Seek,
    I: IntoIterator<Item = (String, R)>,
    R: Read,
{
    let mut builder = ArchiveBuilder::new();
    for (name, mut reader) in entries {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        builder = builder.add_file(&name, &data);
    }
    let bytes = builder.build()?;
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&bytes)?;
    out.flush()?;
    Ok(())
}
