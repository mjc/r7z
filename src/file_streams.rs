use crate::entries::{Entries, Entry, EntrySelection};
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
    streams: StreamLocations<'a>,
    pack_pos: u64,
}

/// Advances through folder and substream iterators independently of file metadata.
struct StreamLocations<'a> {
    folders: Option<std::iter::Enumerate<FolderLayouts<'a>>>,
    current: Option<FolderStreams<'a>>,
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
            streams: StreamLocations {
                folders: folders.map(Iterator::enumerate),
                current: None,
            },
            pack_pos,
        })
    }

    pub(crate) fn pack_pos(&self) -> u64 {
        self.pack_pos
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Map selected entries while each folder layout is borrowed by the callback.
    /// Returned values cannot retain that borrow; no layout clones or index table are needed.
    pub(crate) fn map_selected<T>(
        mut self,
        selection: EntrySelection<'_>,
        mut map: impl FnMut(FileStream<'_, 'a>) -> Result<T, R7zError>,
    ) -> impl Iterator<Item = Result<T, R7zError>> {
        selection.map(move |index| {
            let skip = index
                .get()
                .checked_sub(self.entries.next_index())
                .ok_or(R7zError::Parse)?;
            let file = self.nth(skip)?.ok_or(R7zError::Parse)?;
            map(file)
        })
    }

    /// Map every entry and validate the folder tables when traversal ends.
    pub(crate) fn map_all<T>(
        mut self,
        mut map: impl FnMut(FileStream<'_, 'a>) -> Result<T, R7zError>,
    ) -> impl Iterator<Item = Result<T, R7zError>> {
        let mut finished = false;
        std::iter::from_fn(move || {
            if finished {
                return None;
            }
            match self.next() {
                Ok(Some(file)) => Some(map(file)),
                Ok(None) => {
                    finished = true;
                    None
                }
                Err(error) => {
                    finished = true;
                    Some(Err(error))
                }
            }
        })
    }

    /// Skip file metadata and advance only the data streams those entries own.
    pub(crate) fn nth(&mut self, n: usize) -> Result<Option<FileStream<'_, 'a>>, R7zError> {
        let skipped_streams = self
            .entries
            .by_ref()
            .take(n)
            .filter(|entry| entry.kind.has_stream())
            .count();
        self.streams.advance_by(skipped_streams)?;
        self.next()
    }

    /// The returned layout borrows the current folder until the next advance.
    pub(crate) fn next(&mut self) -> Result<Option<FileStream<'_, 'a>>, R7zError> {
        match self.entries.next() {
            Some(entry) => entry.bind(|()| self.streams.nth(0)).map(Some),
            None => {
                self.streams.finish()?;
                Ok(None)
            }
        }
    }
}

impl<'a> StreamLocations<'a> {
    fn finish(&mut self) -> Result<(), R7zError> {
        if self
            .current
            .take()
            .is_some_and(|folder| folder.streams.len() != 0)
        {
            return Err(R7zError::Parse);
        }
        self.folders
            .iter_mut()
            .flatten()
            .try_for_each(|(_, folder)| {
                let folder = folder?;
                folder
                    .substreams()
                    .next()
                    .is_none()
                    .then_some(())
                    .ok_or(R7zError::Parse)
            })
    }

    fn advance_by(&mut self, count: usize) -> Result<(), R7zError> {
        match count {
            0 => Ok(()),
            count => self.nth(count - 1).map(|_| ()),
        }
    }

    /// Locate the containing folder before advancing within its substream iterator.
    fn nth(&mut self, mut n: usize) -> Result<StreamLocation<'_, 'a>, R7zError> {
        let remaining = self.folders.iter_mut().flatten().map(|(index, folder)| {
            folder.map(|folder| FolderStreams {
                index: FolderIndex(index),
                streams: folder.substreams().enumerate(),
                folder,
            })
        });
        self.current = self
            .current
            .take()
            .map(Ok)
            .into_iter()
            .chain(remaining)
            .find_map(|folder| match folder {
                Ok(folder) => match n.checked_sub(folder.streams.len()) {
                    Some(remaining) => {
                        n = remaining;
                        None
                    }
                    None => Some(Ok(folder)),
                },
                Err(error) => Some(Err(error)),
            })
            .transpose()?;
        let current = self.current.as_mut().ok_or(R7zError::Parse)?;
        let (index, stream) = current.streams.nth(n).ok_or(R7zError::Parse)?;
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
        let files = FileStreams::new(None, 3, Some(&streams)).unwrap();
        let mut mapped_files = files.map_selected(EntrySelection::All(0..3), |file| {
            let crate::entries::EntryKind::File(location) = file.kind else {
                panic!("expected data stream")
            };
            Ok((
                file.metadata.index.get(),
                location.folder_index.get(),
                location.stream_index.get(),
                location.stream.range.into_range(),
            ))
        });
        let mapped = mapped_files
            .by_ref()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(mapped, [(0, 1, 0, 0..2), (1, 2, 0, 0..1), (2, 2, 1, 1..3)]);
        assert!(mapped_files.next().is_none());
    }

    #[test]
    fn selected_mapping_skips_gaps_and_stops_consuming_on_callback_error() {
        let streams = mixed_folders();
        let files = FileStreams::new(None, 3, Some(&streams)).unwrap();
        let selected_indices = [
            crate::ArchiveEntryIndex::new(2),
            crate::ArchiveEntryIndex::new(0),
        ];
        let selected = EntrySelection::new(Some(&selected_indices), 3).unwrap();
        let mapped = files
            .map_selected(selected, |file| {
                let crate::entries::EntryKind::File(location) = file.kind else {
                    panic!("expected data stream")
                };
                Ok((
                    file.metadata.index.get(),
                    location.stream.range.into_range(),
                ))
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(mapped, [(0, 0..2), (2, 1..3)]);

        let mut visited = Vec::new();
        let files = FileStreams::new(None, 3, Some(&streams)).unwrap();
        let result = files
            .map_selected(EntrySelection::All(0..3), |file| {
                visited.push(file.metadata.index.get());
                match file.metadata.index.get() {
                    1 => Err(R7zError::InvalidOptions("callback failure")),
                    _ => Ok(()),
                }
            })
            .collect::<Result<(), _>>();
        assert!(matches!(
            result,
            Err(R7zError::InvalidOptions("callback failure"))
        ));
        assert_eq!(visited, [0, 1]);
    }

    #[test]
    fn nth_advances_across_folders_and_preserves_the_remaining_cursor() {
        let streams = mixed_folders();
        let mut files = FileStreams::new(None, 3, Some(&streams)).unwrap();
        assert_eq!(files.len(), 3);
        let file = files.nth(1).unwrap().unwrap();
        let crate::entries::EntryKind::File(location) = file.kind else {
            panic!("expected data stream")
        };
        assert_eq!(file.metadata.index.get(), 1);
        assert_eq!(location.folder_index.get(), 2);
        assert_eq!(location.stream_index.get(), 0);
        assert_eq!(files.len(), 1);
        assert_eq!(files.nth(0).unwrap().unwrap().metadata.index.get(), 2);
        assert_eq!(files.len(), 0);
        assert!(files.nth(usize::MAX).unwrap().is_none());

        let mut files = FileStreams::new(None, 3, Some(&streams)).unwrap();
        let file = files.nth(2).unwrap().unwrap();
        let crate::entries::EntryKind::File(location) = file.kind else {
            panic!("expected data stream")
        };
        assert_eq!(file.metadata.index.get(), 2);
        assert_eq!(location.folder_index.get(), 2);
        assert_eq!(location.stream_index.get(), 1);
        assert_eq!(location.stream.range.into_range(), 1..3);
        assert_eq!(files.len(), 0);

        let mut files = FileStreams::new(None, 3, Some(&streams)).unwrap();
        assert!(files.nth(usize::MAX).unwrap().is_none());
        assert_eq!(files.len(), 0);
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

    #[test]
    fn full_traversal_validates_the_final_folder_tables() {
        let mut streams = mixed_folders();
        streams
            .substream_info
            .as_mut()
            .unwrap()
            .unpack_sizes
            .push(0);
        let files = FileStreams::new(None, 3, Some(&streams)).unwrap();
        assert!(matches!(
            files.map_all(|_| Ok(())).collect::<Result<Vec<_>, _>>(),
            Err(R7zError::Parse)
        ));
    }
}
