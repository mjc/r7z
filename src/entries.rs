use crate::files_info::FilesInfoNameSlices;
use crate::{EntryType, FilesInfo, R7zError};
use std::borrow::Cow;

/// An index in the archive's file table, independent of folder/substream indexes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EntryIndex(usize);

impl EntryIndex {
    pub(crate) fn get(self) -> usize {
        self.0
    }
}

/// Entry classification before (`()`) and after binding its archive stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryKind<S> {
    File(S),
    Symlink(S),
    EmptyFile,
    EmptySymlink,
    Directory,
    Anti,
}

impl<S> EntryKind<S> {
    pub(crate) fn entry_type(&self) -> EntryType {
        match self {
            Self::File(_) => EntryType::File,
            Self::Symlink(_) => EntryType::Symlink,
            Self::EmptySymlink => EntryType::EmptySymlink,
            Self::EmptyFile => EntryType::EmptyFile,
            Self::Directory => EntryType::Directory,
            Self::Anti => EntryType::Anti,
        }
    }

    pub(crate) fn has_stream(&self) -> bool {
        matches!(self, Self::File(_) | Self::Symlink(_))
    }

    fn bind<T>(
        self,
        stream: impl FnOnce(S) -> Result<T, R7zError>,
    ) -> Result<EntryKind<T>, R7zError> {
        Ok(match self {
            Self::File(input) => EntryKind::File(stream(input)?),
            Self::Symlink(input) => EntryKind::Symlink(stream(input)?),
            Self::EmptyFile => EntryKind::EmptyFile,
            Self::EmptySymlink => EntryKind::EmptySymlink,
            Self::Directory => EntryKind::Directory,
            Self::Anti => EntryKind::Anti,
        })
    }
}

pub(crate) struct EntryMetadata<'a> {
    pub(crate) index: EntryIndex,
    pub(crate) name: Option<&'a [u8]>,
    pub(crate) modified: Option<u64>,
    pub(crate) attributes: Option<u32>,
}

impl EntryMetadata<'_> {
    pub(crate) fn name(&self) -> String {
        self.name.map_or_else(
            || format!("unknown-{}", self.index.get()),
            crate::files_info::decode_name,
        )
    }
}

pub(crate) struct Entry<'a, S> {
    pub(crate) metadata: EntryMetadata<'a>,
    pub(crate) kind: EntryKind<S>,
}

impl<'a, S> Entry<'a, S> {
    pub(crate) fn bind<T>(
        self,
        stream: impl FnOnce(S) -> Result<T, R7zError>,
    ) -> Result<Entry<'a, T>, R7zError> {
        Ok(Entry {
            metadata: self.metadata,
            kind: self.kind.bind(stream)?,
        })
    }
}

/// Names stay borrowed until a consumer needs a public entry or listing.
pub(crate) struct Entries<'a> {
    files: Option<&'a FilesInfo>,
    indices: std::ops::Range<usize>,
    names: Option<FilesInfoNameSlices<'a>>,
}

impl<'a> Entries<'a> {
    pub(crate) fn new(files: Option<&'a FilesInfo>, count: usize) -> Self {
        Self {
            files,
            indices: 0..count,
            names: files.map(FilesInfo::name_slices),
        }
    }
    pub(crate) fn next_index(&self) -> usize {
        self.indices.start
    }

    pub(crate) fn stream_count(&self) -> usize {
        self.indices
            .clone()
            .filter(|&index| self.kind(index).has_stream())
            .count()
    }

    fn kind(&self, index: usize) -> EntryKind<()> {
        self.files
            .map_or(EntryKind::File(()), |files| files.entry_kind(index))
    }
}

impl<'a> Iterator for Entries<'a> {
    type Item = Entry<'a, ()>;

    fn next(&mut self) -> Option<Self::Item> {
        self.nth(0)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.indices.size_hint()
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        let index = self.indices.nth(n)?;
        let name = self.names.as_mut().and_then(|names| names.nth(n)).flatten();
        let kind = self.kind(index);
        Some(Entry {
            metadata: EntryMetadata {
                index: EntryIndex(index),
                name,
                modified: self
                    .files
                    .and_then(|files| files.mtimes.get(index).copied().flatten()),
                attributes: self
                    .files
                    .and_then(|files| files.attributes.get(index).copied().flatten()),
            },
            kind,
        })
    }
}

impl ExactSizeIterator for Entries<'_> {}

/// Validated selection in archive order. Sorted callers keep their borrowed list.
pub(crate) enum EntrySelection<'a> {
    Empty,
    All(std::ops::Range<usize>),
    Selected {
        indices: Cow<'a, [usize]>,
        position: usize,
    },
}

impl<'a> EntrySelection<'a> {
    pub(crate) fn new(indices: Option<&'a [usize]>, count: usize) -> Result<Self, R7zError> {
        let indices = match indices {
            None => return Ok(Self::All(0..count)),
            Some([]) => return Ok(Self::Empty),
            Some(indices) => indices,
        };
        if indices.iter().any(|&index| index >= count) {
            return Err(R7zError::InvalidOptions(
                "selected entry index out of bounds",
            ));
        }
        let indices = if indices.is_sorted() {
            Cow::Borrowed(indices)
        } else {
            let mut sorted = indices.to_vec();
            sorted.sort_unstable();
            Cow::Owned(sorted)
        };
        if indices.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(R7zError::InvalidOptions("duplicate selected entry index"));
        }
        Ok(Self::Selected {
            indices,
            position: 0,
        })
    }
}

impl Iterator for EntrySelection<'_> {
    type Item = EntryIndex;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Empty => None,
            Self::All(indices) => indices.next().map(EntryIndex),
            Self::Selected { indices, position } => {
                let index = *indices.get(*position)?;
                *position += 1;
                Some(EntryIndex(index))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = match self {
            Self::Empty => 0,
            Self::All(indices) => indices.len(),
            Self::Selected { indices, position } => indices.len() - position,
        };
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for EntrySelection<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_borrows_sorted_inputs_and_owns_only_reordered_inputs() {
        for indices in [&[1][..], &[0, 2, 4][..]] {
            let selection = EntrySelection::new(Some(indices), 5).unwrap();
            assert!(matches!(
                selection,
                EntrySelection::Selected {
                    indices: Cow::Borrowed(_),
                    ..
                }
            ));
        }
        let indices = [4, 0, 2];
        let selection = EntrySelection::new(Some(&indices), 5).unwrap();
        assert!(matches!(
            selection,
            EntrySelection::Selected {
                indices: Cow::Owned(_),
                ..
            }
        ));
        let selected = selection.map(EntryIndex::get).collect::<Vec<_>>();
        assert_eq!(selected, [0, 2, 4]);
        assert_eq!(indices, [4, 0, 2]);
    }

    #[test]
    fn selection_iterator_tracks_remaining_indexes() {
        [None, Some(&[2, 0, 1][..])]
            .into_iter()
            .for_each(|indices| {
                let mut selection = EntrySelection::new(indices, 3).unwrap();
                assert_eq!(selection.size_hint(), (3, Some(3)));
                assert_eq!(selection.next().map(EntryIndex::get), Some(0));
                assert_eq!(selection.len(), 2);
                assert_eq!(selection.nth(1).map(EntryIndex::get), Some(2));
                assert_eq!(selection.size_hint(), (0, Some(0)));
                assert!(selection.next().is_none());
                assert!(selection.next().is_none());
            });
    }

    #[test]
    fn selection_rejects_duplicate_and_out_of_range_indices() {
        for indices in [&[1, 1][..], &[2, 0, 2][..]] {
            assert!(matches!(
                EntrySelection::new(Some(indices), 3),
                Err(R7zError::InvalidOptions("duplicate selected entry index"))
            ));
        }
        for indices in [&[3][..], &[usize::MAX][..]] {
            assert!(matches!(
                EntrySelection::new(Some(indices), 3),
                Err(R7zError::InvalidOptions(
                    "selected entry index out of bounds"
                ))
            ));
        }
        let all = EntrySelection::new(None, 3).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all.map(EntryIndex::get).collect::<Vec<_>>(), [0, 1, 2]);
        let mut none = EntrySelection::new(Some(&[]), 3).unwrap();
        assert!(matches!(none, EntrySelection::Empty));
        assert_eq!(none.len(), 0);
        assert!(none.next().is_none());
    }

    #[test]
    fn stream_binding_only_runs_for_file_and_symlink_streams() {
        for kind in [
            EntryKind::EmptyFile,
            EntryKind::EmptySymlink,
            EntryKind::Directory,
            EntryKind::Anti,
        ] {
            let bound: EntryKind<usize> =
                kind.bind(|(): ()| panic!("entry has no stream")).unwrap();
            assert_eq!(bound.entry_type(), kind.entry_type());
            assert!(!bound.has_stream());
        }
        assert_eq!(
            EntryKind::File(()).bind(|()| Ok(42)).unwrap(),
            EntryKind::File(42)
        );
        assert_eq!(
            EntryKind::Symlink(()).bind(|()| Ok(42)).unwrap(),
            EntryKind::Symlink(42)
        );
    }

    #[test]
    fn missing_names_use_the_file_index_without_allocating_a_name_table() {
        let mut entries = Entries::new(None, 3);
        assert_eq!(entries.stream_count(), 3);
        for (index, entry) in entries.by_ref().enumerate() {
            assert_eq!(entry.metadata.index.get(), index);
            assert!(entry.metadata.name.is_none());
            assert_eq!(entry.metadata.name(), format!("unknown-{index}"));
            assert_eq!(entry.kind, EntryKind::File(()));
        }
        assert!(entries.next().is_none());
    }
}
