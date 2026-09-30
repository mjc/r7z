use std::marker::PhantomData;
use std::ops::Range;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ByteRange<Space> {
    start: u64,
    end: u64,
    _space: PhantomData<Space>,
}

impl<Space> ByteRange<Space> {
    pub(crate) fn from_range(range: Range<u64>) -> Self {
        assert!(range.start <= range.end, "byte range start exceeds end");
        Self {
            start: range.start,
            end: range.end,
            _space: PhantomData,
        }
    }

    pub(crate) const fn start(self) -> u64 {
        self.start
    }

    pub(crate) const fn end(self) -> u64 {
        self.end
    }

    pub(crate) const fn len(self) -> u64 {
        self.end - self.start
    }

    #[cfg(test)]
    pub(crate) fn into_range(self) -> Range<u64> {
        self.start..self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArchiveSourceSpace {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PackedDataSpace {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecodedFolderSpace {}

pub(crate) type ArchiveSourceRange = ByteRange<ArchiveSourceSpace>;
pub(crate) type PackedRange = ByteRange<PackedDataSpace>;
pub(crate) type DecodedRange = ByteRange<DecodedFolderSpace>;
