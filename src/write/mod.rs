#![allow(clippy::missing_errors_doc)]

mod encode;
mod header;
mod model;

use crate::R7zError;
use std::io::{Read, Seek, SeekFrom, Write};

pub use model::{
    ArchiveEntry, ArchiveOptions, Codec, EncryptionOptions, EntryKind, EntryMeta, HeaderMode,
};

use model::WriteEntry;

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
                data: None,
                folder_id: 0,
            });
        } else {
            self.entries.push(WriteEntry {
                name: name.to_string(),
                kind: EntryKind::File,
                meta: EntryMeta::default(),
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
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        self.entries.push(WriteEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            meta,
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
            data: None,
            folder_id: self.current_folder,
        });
        Ok(())
    }

    pub fn new_folder(&mut self) -> Result<(), R7zError> {
        if self
            .entries
            .iter()
            .any(|entry| entry.folder_id == self.current_folder && entry.data.is_some())
        {
            self.current_folder += 1;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<W, R7zError> {
        let bytes = encode::build_archive(&self.entries, &self.options)?;
        self.out.seek(SeekFrom::Start(0))?;
        self.out.write_all(&bytes)?;
        self.out.flush()?;
        Ok(self.out)
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
