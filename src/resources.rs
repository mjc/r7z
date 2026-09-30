use crate::R7zError;
use std::num::NonZeroUsize;

const DEFAULT_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_OPEN_VOLUMES: usize = 128;

/// Caller-configurable limits for opening, reading, and writing archives.
///
/// One budget is created per archive operation and shared by nested work.
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

/// Bytes of output already produced by one archive read operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DecodedBytes(u64);

impl DecodedBytes {
    pub(crate) const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

/// Bytes retained or decoded while resolving archive headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MetadataBytes(u64);

impl MetadataBytes {
    pub(crate) const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

/// Mutable counters shared by every nested step in one archive operation.
pub(crate) struct OperationBudget {
    limits: ResourceLimits,
    metadata: MetadataBytes,
    decoded: DecodedBytes,
}

impl OperationBudget {
    pub(crate) fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            metadata: MetadataBytes::new(0),
            decoded: DecodedBytes::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_decoded_limit(limit: Option<u64>) -> Self {
        Self::new(ResourceLimits {
            max_total_decoded_bytes: limit,
            ..ResourceLimits::default()
        })
    }

    #[cfg(test)]
    pub(crate) fn for_metadata_limit(limit: u64) -> Self {
        Self::new(ResourceLimits {
            max_metadata_bytes: limit,
            ..ResourceLimits::default()
        })
    }

    pub(crate) fn decoded_remaining(&self) -> Option<DecodedBytes> {
        self.limits
            .max_total_decoded_bytes
            .map(|limit| DecodedBytes::new(limit - self.decoded.get()))
    }

    pub(crate) fn metadata_remaining(&self) -> MetadataBytes {
        MetadataBytes::new(self.limits.max_metadata_bytes - self.metadata.get())
    }

    pub(crate) fn charge_metadata(&mut self, bytes: MetadataBytes) -> Result<(), R7zError> {
        let Some(used) = self.metadata.get().checked_add(bytes.get()) else {
            return Err(self.metadata_limit_error());
        };
        if used > self.limits.max_metadata_bytes {
            return Err(self.metadata_limit_error());
        }
        self.metadata = MetadataBytes::new(used);
        Ok(())
    }

    pub(crate) fn metadata_limit_error(&self) -> R7zError {
        R7zError::ResourceLimitExceeded {
            resource: "metadata",
            limit: self.limits.max_metadata_bytes,
        }
    }

    pub(crate) fn map_metadata_error(&self, error: R7zError) -> R7zError {
        match error {
            R7zError::LimitExceeded("metadata") => self.metadata_limit_error(),
            error => error,
        }
    }

    pub(crate) fn decoded_limit_error(&self) -> R7zError {
        R7zError::ResourceLimitExceeded {
            resource: "total decoded output",
            limit: self.limits.max_total_decoded_bytes.unwrap_or(u64::MAX),
        }
    }

    fn next_decoded(&self, bytes: DecodedBytes) -> Result<DecodedBytes, R7zError> {
        let Some(decoded) = self.decoded.get().checked_add(bytes.get()) else {
            return self
                .limits
                .max_total_decoded_bytes
                .map_or(Ok(DecodedBytes::new(u64::MAX)), |_| {
                    Err(self.decoded_limit_error())
                });
        };
        if self
            .limits
            .max_total_decoded_bytes
            .is_some_and(|limit| decoded > limit)
        {
            return Err(self.decoded_limit_error());
        }
        Ok(DecodedBytes::new(decoded))
    }

    pub(crate) fn charge_decoded(&mut self, bytes: DecodedBytes) -> Result<(), R7zError> {
        self.decoded = self.next_decoded(bytes)?;
        Ok(())
    }

    pub(crate) fn with_eager_decoded_output<T>(
        &mut self,
        bytes: DecodedBytes,
        start: impl FnOnce() -> Result<T, R7zError>,
    ) -> Result<T, R7zError> {
        let next_total = self.next_decoded(bytes)?;
        match start() {
            Ok(output) => {
                self.decoded = next_total;
                Ok(output)
            }
            Err(error) => {
                if !matches!(error, R7zError::PasswordRequired) {
                    self.decoded = next_total;
                }
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DecodedBytes, MetadataBytes, OperationBudget, ResourceLimits};
    use crate::R7zError;

    fn nested_decode(budget: &mut OperationBudget, bytes: DecodedBytes) -> Result<(), R7zError> {
        budget.charge_decoded(bytes)
    }

    fn nested_metadata(budget: &mut OperationBudget, bytes: MetadataBytes) -> Result<(), R7zError> {
        budget.charge_metadata(bytes)
    }

    #[test]
    fn nested_work_shares_the_parent_decoded_byte_budget() {
        let mut budget = OperationBudget::new(ResourceLimits {
            max_total_decoded_bytes: Some(8),
            ..ResourceLimits::default()
        });

        budget.charge_decoded(DecodedBytes::new(5)).unwrap();
        assert!(matches!(
            nested_decode(&mut budget, DecodedBytes::new(4)),
            Err(R7zError::ResourceLimitExceeded {
                resource: "total decoded output",
                limit: 8,
            })
        ));
        nested_decode(&mut budget, DecodedBytes::new(3)).unwrap();
        assert!(matches!(
            nested_decode(&mut budget, DecodedBytes::new(1)),
            Err(R7zError::ResourceLimitExceeded {
                resource: "total decoded output",
                limit: 8,
            })
        ));
    }

    #[test]
    fn nested_work_shares_the_parent_metadata_budget() {
        let mut budget = OperationBudget::new(ResourceLimits {
            max_metadata_bytes: 8,
            ..ResourceLimits::default()
        });

        nested_metadata(&mut budget, MetadataBytes::new(5)).unwrap();
        assert!(matches!(
            nested_metadata(&mut budget, MetadataBytes::new(4)),
            Err(R7zError::ResourceLimitExceeded {
                resource: "metadata",
                limit: 8,
            })
        ));
        nested_metadata(&mut budget, MetadataBytes::new(3)).unwrap();
        assert!(matches!(
            nested_metadata(&mut budget, MetadataBytes::new(1)),
            Err(R7zError::ResourceLimitExceeded {
                resource: "metadata",
                limit: 8,
            })
        ));
    }
}
