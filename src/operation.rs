use crate::R7zError;
use std::{
    fmt,
    io::{self, Read},
    ops::ControlFlow,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Maximum bytes between cooperative cancellation checks and progress reports.
pub(crate) const CHECK_INTERVAL: usize = 64 * 1024;

/// Bytes processed by one archive operation, including skipped or drained data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationProgress {
    /// Which phase produced these bytes. Counts restart for each phase.
    pub phase: OperationPhase,
    /// Decoded bytes for reads; input bytes or copied packed bytes for writes.
    pub bytes_processed: u64,
}

/// Work whose byte count is reported by an operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OperationPhase {
    /// Decoding selected, skipped and drained folder data.
    #[default]
    Read,
    /// Reading encoder input or copying preserved compressed folders.
    Write,
    /// Copying a completed archive from its spool to a sink or volumes.
    CopyOutput,
}

/// Scope checked by a read session. This describes visited folders, not every
/// entry in the archive. Checks include lengths and available checksums.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadVerification {
    /// Every visited folder was drained and checked to its end.
    CompleteFolders,
    /// Selected entries were checked, but a folder tail was left unread.
    SelectedEntries,
    /// A previous read failed, leaving some requested data unchecked.
    Incomplete,
}

impl ReadVerification {
    pub(crate) fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Incomplete, _) | (_, Self::Incomplete) => Self::Incomplete,
            (Self::SelectedEntries, _) | (_, Self::SelectedEntries) => Self::SelectedEntries,
            (Self::CompleteFolders, Self::CompleteFolders) => Self::CompleteFolders,
        }
    }
}

struct Control {
    cancelled: Arc<AtomicBool>,
    progress: Option<Box<dyn Fn(OperationProgress) -> ControlFlow<()> + Send + Sync>>,
}

/// Shared cancellation and progress control. Clones refer to the same cancellation.
/// Cancellation is permanent; create a new control to start another operation.
#[derive(Clone)]
pub struct OperationControl(Arc<Control>);

impl Default for OperationControl {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationControl {
    /// Create a control without a progress callback.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(Control {
            cancelled: Arc::new(AtomicBool::new(false)),
            progress: None,
        }))
    }

    /// Report progress at most once per 64 KiB of processed data.
    /// Returning `Break(())` cancels all operations using this control.
    /// Callbacks run on the operation's thread and should return promptly.
    #[must_use]
    pub fn with_progress(
        callback: impl Fn(OperationProgress) -> ControlFlow<()> + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(Control {
            cancelled: Arc::new(AtomicBool::new(false)),
            progress: Some(Box::new(callback)),
        }))
    }

    /// Request cancellation from any thread.
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Relaxed);
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Relaxed)
    }

    pub(crate) fn check(&self) -> Result<(), R7zError> {
        if self.is_cancelled() {
            Err(R7zError::Cancelled)
        } else {
            Ok(())
        }
    }

    pub(crate) fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.0.cancelled)
    }
}

impl fmt::Debug for OperationControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperationControl")
            .field("cancelled", &self.is_cancelled())
            .field("reports_progress", &self.0.progress.is_some())
            .finish()
    }
}

impl PartialEq for OperationControl {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for OperationControl {}

#[derive(Default)]
pub(crate) struct OperationMonitor {
    phase: OperationPhase,
    control: Option<OperationControl>,
    processed: u64,
    reported: u64,
}

impl OperationMonitor {
    pub(crate) fn new(control: Option<OperationControl>) -> Self {
        Self {
            control,
            ..Self::default()
        }
    }

    pub(crate) fn check(&self) -> Result<(), R7zError> {
        self.control
            .as_ref()
            .map_or(Ok(()), OperationControl::check)
    }

    pub(crate) fn control(&self) -> Option<&OperationControl> {
        self.control.as_ref()
    }

    pub(crate) fn for_phase(mut self, phase: OperationPhase) -> Self {
        self.phase = phase;
        self
    }

    pub(crate) fn buffer_size(&self, requested: usize) -> usize {
        if self.control.is_some() {
            requested.min(CHECK_INTERVAL)
        } else {
            requested
        }
    }

    pub(crate) fn advance(&mut self, bytes: usize) -> Result<(), R7zError> {
        if let Some(control) = &self.control {
            self.processed = self.processed.saturating_add(bytes as u64);
            if self.processed - self.reported >= CHECK_INTERVAL as u64 {
                self.reported = self.processed;
                if control.0.progress.as_ref().is_some_and(|callback| {
                    callback(OperationProgress {
                        phase: self.phase,
                        bytes_processed: self.processed,
                    })
                    .is_break()
                }) {
                    control.cancel();
                }
            }
            control.check()?;
        }
        Ok(())
    }

    pub(crate) fn read(
        &mut self,
        reader: &mut (impl Read + ?Sized),
        buffer: &mut [u8],
    ) -> Result<usize, R7zError> {
        self.check()?;
        let size = self.buffer_size(buffer.len());
        let count = reader
            .read(&mut buffer[..size])
            .map_err(restore_read_error)?;
        self.advance(count)?;
        Ok(count)
    }

    pub(crate) fn copy_to(
        &mut self,
        reader: &mut impl Read,
        writer: &mut impl io::Write,
    ) -> Result<u64, R7zError> {
        if self.control.is_none() {
            return io::copy(reader, writer).map_err(R7zError::Io);
        }
        let mut buffer = [0; 8 * 1024];
        std::iter::from_fn(|| match self.read(reader, &mut buffer) {
            Ok(0) => None,
            Ok(count) => Some(
                writer
                    .write_all(&buffer[..count])
                    .map(|()| count as u64)
                    .map_err(R7zError::Io),
            ),
            Err(error) => Some(Err(error)),
        })
        .try_fold(0u64, |total, count| {
            total.checked_add(count?).ok_or(R7zError::Parse)
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("operation cancelled")]
pub(crate) struct CancelledRead;

pub(crate) fn read_io_error(error: R7zError) -> io::Error {
    match error {
        R7zError::Cancelled => io::Error::other(CancelledRead),
        error => io::Error::other(error),
    }
}

pub(crate) fn restore_callback_error(error: R7zError) -> R7zError {
    match error {
        R7zError::Io(error) => match error.downcast::<CancelledRead>() {
            Ok(_) => R7zError::Cancelled,
            Err(error) => R7zError::Io(error),
        },
        error => error,
    }
}

pub(crate) fn restore_read_error(error: io::Error) -> R7zError {
    match error.downcast::<CancelledRead>() {
        Ok(_) => R7zError::Cancelled,
        Err(error) => error.downcast::<R7zError>().unwrap_or_else(R7zError::Io),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn progress_cost_is_bounded_and_cancelled_reads_stop_before_io() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let control = OperationControl::with_progress(move |progress| {
            count.fetch_add(1, Ordering::Relaxed);
            assert_eq!(progress.bytes_processed, CHECK_INTERVAL as u64);
            ControlFlow::Break(())
        });
        let mut monitor = OperationMonitor::new(Some(control.clone()));
        let mut input = io::repeat(0);
        let mut bytes = [0; 1024];
        for _ in 0..63 {
            assert_eq!(monitor.read(&mut input, &mut bytes).unwrap(), 1024);
        }
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(matches!(
            monitor.read(&mut input, &mut bytes),
            Err(R7zError::Cancelled)
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(control.is_cancelled());
        assert!(matches!(
            monitor.read(&mut io::empty(), &mut bytes),
            Err(R7zError::Cancelled)
        ));
    }
}
