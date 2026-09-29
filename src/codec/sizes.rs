use super::*;
use crate::folder::FolderGraph;

/// Unknown is an omitted size, never an empty output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputSize {
    Known(u64),
    Unknown,
}

impl OutputSize {
    pub(super) fn reconcile(self, other: Self) -> Result<Self, R7zError> {
        match (self, other) {
            (Self::Known(a), Self::Known(b)) if a != b => Err(R7zError::Parse),
            (Self::Unknown, size) | (size, Self::Unknown) => Ok(size),
            (size, _) => Ok(size),
        }
    }

    pub(super) fn require(self) -> Result<u64, R7zError> {
        match self {
            Self::Known(size) => Ok(size),
            Self::Unknown => Err(R7zError::InvalidOptions("coder requires an output size")),
        }
    }

    pub(super) fn buffered_bytes(self, cap: usize) -> usize {
        match self {
            Self::Known(size) => usize::try_from(size).unwrap_or(usize::MAX).min(cap),
            Self::Unknown => cap,
        }
    }
}

/// Borrows the caller's table and supplies the independently declared final size.
pub(super) struct CoderOutputSizes<'a> {
    declared: &'a [u64],
    final_index: usize,
    final_size: u64,
}

impl<'a> CoderOutputSizes<'a> {
    pub(super) fn complete(
        folder: &Folder,
        graph: &FolderGraph,
        final_size: u64,
        declared: &'a [u64],
    ) -> Result<Self, R7zError> {
        if declared.len() != folder.total_out_streams() {
            return Err(R7zError::InvalidFolderGraph);
        }
        Self::partial(folder, graph, final_size, declared)
    }

    pub(super) fn partial(
        folder: &Folder,
        graph: &FolderGraph,
        final_size: u64,
        declared: &'a [u64],
    ) -> Result<Self, R7zError> {
        if declared.len() > folder.total_out_streams() {
            return Err(R7zError::InvalidFolderGraph);
        }
        let final_index = graph.final_output().get();
        if declared
            .get(final_index)
            .is_some_and(|&size| size != final_size)
        {
            return Err(R7zError::Parse);
        }
        Ok(Self {
            declared,
            final_index,
            final_size,
        })
    }

    pub(super) fn get(&self, index: usize) -> OutputSize {
        if index == self.final_index {
            OutputSize::Known(self.final_size)
        } else {
            self.declared
                .get(index)
                .copied()
                .map_or(OutputSize::Unknown, OutputSize::Known)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_sizes_are_distinct_from_declared_empty_outputs() {
        let folder = Folder::parse(&[2, 1, 0, 1, 0, 1, 0]).unwrap().1;
        let graph = folder.graph().unwrap();
        let omitted = CoderOutputSizes::partial(&folder, &graph, 0, &[]).unwrap();
        let explicit = CoderOutputSizes::partial(&folder, &graph, 0, &[0]).unwrap();
        assert_eq!(omitted.get(0), OutputSize::Unknown);
        assert_eq!(explicit.get(0), OutputSize::Known(0));
        assert_eq!(omitted.get(1), OutputSize::Known(0));
    }

    #[test]
    fn complete_tables_require_every_output_and_partial_tables_reject_extras() {
        let folder = Folder::parse(&[2, 1, 0, 1, 0, 1, 0]).unwrap().1;
        let graph = folder.graph().unwrap();
        for declared in [&[][..], &[3][..], &[3, 3, 3][..]] {
            assert!(matches!(
                CoderOutputSizes::complete(&folder, &graph, 3, declared),
                Err(R7zError::InvalidFolderGraph)
            ));
        }
        assert!(CoderOutputSizes::complete(&folder, &graph, 3, &[3, 3]).is_ok());
        assert!(matches!(
            CoderOutputSizes::partial(&folder, &graph, 3, &[3, 3, 3]),
            Err(R7zError::InvalidFolderGraph)
        ));
    }

    #[test]
    fn independently_declared_final_sizes_must_agree() {
        let folder = Folder::parse(&[1, 1, 0]).unwrap().1;
        let graph = folder.graph().unwrap();
        assert!(matches!(
            CoderOutputSizes::partial(&folder, &graph, 3, &[0]),
            Err(R7zError::Parse)
        ));
        assert_eq!(
            OutputSize::Known(0).reconcile(OutputSize::Unknown).unwrap(),
            OutputSize::Known(0)
        );
        assert!(
            OutputSize::Known(0)
                .reconcile(OutputSize::Known(3))
                .is_err()
        );
    }
}
