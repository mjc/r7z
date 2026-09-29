use crate::entries::{Entries, Entry};
use crate::folder_decode::{FolderLayout, FolderLayouts, Substream, Substreams};
use crate::{FilesInfo, R7zError, StreamInfo};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FolderIndex(usize);

impl FolderIndex {
    pub(crate) fn get(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SubstreamIndex(usize);

impl SubstreamIndex {
    pub(crate) fn get(self) -> usize {
        self.0
    }

    pub(crate) fn is_first(self) -> bool {
        self.0 == 0
    }
}

pub(crate) type FileStream<'c, 'a> = Entry<'a, StreamLocation<'c, 'a>>;

pub(crate) struct StreamLocation<'c, 'a> {
    pub(crate) folder_index: FolderIndex,
    pub(crate) stream_index: SubstreamIndex,
    pub(crate) folder: &'c FolderLayout<'a>,
    pub(crate) stream: Substream,
}

struct FolderStreams<'a> {
    index: FolderIndex,
    folder: FolderLayout<'a>,
    streams: std::iter::Enumerate<Substreams<'a>>,
}

/// Maps file entries to substreams without allocating a table or opening decoders.
pub(crate) struct FileStreams<'a> {
    entries: Entries<'a>,
    folders: Option<std::iter::Enumerate<FolderLayouts<'a>>>,
    current: Option<FolderStreams<'a>>,
    pack_pos: u64,
}

impl<'a> FileStreams<'a> {
    pub(crate) fn new(
        files: Option<&'a FilesInfo>,
        num_files: usize,
        streams: Option<&'a StreamInfo>,
    ) -> Result<Self, R7zError> {
        let entries = Entries::new(files, num_files);
        let count = entries.stream_count();
        let folders = streams
            .filter(|streams| streams.unpack_info.is_some())
            .map(FolderLayouts::for_streams)
            .transpose()?;
        if folders.as_ref().map_or(0, FolderLayouts::stream_count) != count {
            return Err(R7zError::Parse);
        }
        let pack_pos = folders.as_ref().map_or(0, FolderLayouts::pack_pos);
        Ok(Self {
            entries,
            folders: folders.map(Iterator::enumerate),
            current: None,
            pack_pos,
        })
    }

    pub(crate) fn pack_pos(&self) -> u64 {
        self.pack_pos
    }

    /// The returned layout borrows the current folder until the next advance.
    pub(crate) fn next(&mut self) -> Result<Option<FileStream<'_, 'a>>, R7zError> {
        self.entries
            .next()
            .map(|entry| entry.bind(|()| self.next_stream()))
            .transpose()
    }

    fn next_stream(&mut self) -> Result<StreamLocation<'_, 'a>, R7zError> {
        while self
            .current
            .as_ref()
            .is_none_or(|folder| folder.streams.len() == 0)
        {
            let (index, folder) = self
                .folders
                .as_mut()
                .and_then(Iterator::next)
                .ok_or(R7zError::Parse)?;
            let folder = folder?;
            let streams = folder.substreams().enumerate();
            self.current = Some(FolderStreams {
                index: FolderIndex(index),
                folder,
                streams,
            });
        }
        let current = self.current.as_mut().ok_or(R7zError::Parse)?;
        let (index, stream) = current.streams.next().ok_or(R7zError::Parse)?;
        Ok(StreamLocation {
            folder_index: current.index,
            stream_index: SubstreamIndex(index),
            folder: &current.folder,
            stream,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn mixed_folders() -> StreamInfo {
        let bytes = Bytes::from_static(&[
            0x06, 0x00, 0x03, 0x09, 0x00, 0x02, 0x03, 0x00, // packed sizes
            0x07, 0x0b, 0x03, 0x00, // three inline folders
            0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, // Copy
            0x0c, 0x00, 0x02, 0x03, 0x00, // output sizes
            0x08, 0x0d, 0x00, 0x01, 0x02, // zero, one, two substreams
            0x09, 0x01, 0x00, 0x00, // explicit size and ends
        ]);
        StreamInfo::parse(&bytes, &bytes).unwrap().1
    }

    #[test]
    fn maps_zero_single_and_multiple_substream_folders_in_order() {
        let streams = mixed_folders();
        let mut files = FileStreams::new(None, 3, Some(&streams)).unwrap();
        let mut mapped = Vec::new();
        while let Some(file) = files.next().unwrap() {
            let crate::entries::EntryKind::File(location) = file.kind else {
                panic!("expected data stream")
            };
            mapped.push((
                file.metadata.index.get(),
                location.folder_index.get(),
                location.stream_index.get(),
                location.stream.range,
            ));
        }
        assert_eq!(mapped, [(0, 1, 0, 0..2), (1, 2, 0, 0..1), (2, 2, 1, 1..3)]);
        assert!(files.next().unwrap().is_none());
    }

    #[test]
    fn rejects_missing_and_surplus_substreams_before_traversal() {
        let streams = mixed_folders();
        for count in [0, 2, 4] {
            assert!(matches!(
                FileStreams::new(None, count, Some(&streams)),
                Err(R7zError::Parse)
            ));
        }
        assert!(matches!(
            FileStreams::new(None, 1, None),
            Err(R7zError::Parse)
        ));
        assert!(
            FileStreams::new(None, 0, None)
                .unwrap()
                .next()
                .unwrap()
                .is_none()
        );
    }
}
