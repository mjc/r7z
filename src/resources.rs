use std::num::NonZeroUsize;

const DEFAULT_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_OPEN_VOLUMES: usize = 128;

/// Caller-configurable limits for opening, reading, and writing archives.
///
/// Each operation creates its own counters from this configuration. Cumulative
/// work, such as decoded output, is tracked separately from peak live memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Maximum prefix scanned while locating the archive signature.
    pub max_signature_scan_bytes: u64,
    /// Combined limit for header buffers, decoded external metadata, and stream slots.
    pub max_metadata_bytes: u64,
    /// Maximum estimated live decoder working set. `None` uses the built-in cap.
    pub max_decoder_working_set_bytes: Option<u64>,
    /// Maximum total decoded bytes for one read operation. `None` is unlimited.
    pub max_total_decoded_bytes: Option<u64>,
    /// Maximum bytes retained by an in-memory extraction. `None` is unlimited.
    pub max_retained_output_bytes: Option<u64>,
    /// Maximum bytes written to temporary archive spools. `None` is unlimited.
    pub max_temporary_storage_bytes: Option<u64>,
    /// Maximum number of split archive volumes held open at once.
    pub max_open_volumes: NonZeroUsize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_signature_scan_bytes: DEFAULT_METADATA_BYTES,
            max_metadata_bytes: DEFAULT_METADATA_BYTES,
            max_decoder_working_set_bytes: None,
            max_total_decoded_bytes: None,
            max_retained_output_bytes: None,
            max_temporary_storage_bytes: None,
            max_open_volumes: NonZeroUsize::new(DEFAULT_OPEN_VOLUMES).unwrap(),
        }
    }
}
