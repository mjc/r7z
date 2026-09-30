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
    /// Maximum aggregate AES key-derivation work for one operation. `None` is unlimited.
    pub max_total_kdf_cycles: Option<u64>,
    /// Maximum bytes retained by an in-memory extraction. `None` is unlimited.
    pub max_retained_output_bytes: Option<u64>,
    /// Maximum cumulative bytes written to temporary archive spools. `None` is unlimited.
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
            max_total_kdf_cycles: None,
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

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct KdfCycles(u64);

#[allow(dead_code)]
impl KdfCycles {
    pub(crate) const fn new(cycles: u64) -> Self {
        Self(cycles)
    }

    const fn get(self) -> u64 {
        self.0
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TemporaryStorageBytes(u64);

#[allow(dead_code)]
impl TemporaryStorageBytes {
    pub(crate) const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    const fn get(self) -> u64 {
        self.0
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RetainedOutputBytes(u64);

#[allow(dead_code)]
impl RetainedOutputBytes {
    pub(crate) const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    const fn get(self) -> u64 {
        self.0
    }
}

/// Decoder memory simultaneously reserved by nested work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DecoderWorkingSetBytes(u64);

impl DecoderWorkingSetBytes {
    pub(crate) const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    const fn get(self) -> u64 {
        self.0
    }
}

/// Mutable counters shared by every nested step in one archive operation.
pub(crate) struct OperationBudget {
    limits: ResourceLimits,
    metadata: MetadataBytes,
    decoded: DecodedBytes,
    peak_decoder_working_set: DecoderWorkingSetBytes,
    kdf_cycles: KdfCycles,
    temporary_storage: TemporaryStorageBytes,
    retained_output: RetainedOutputBytes,
    peak_retained_output: RetainedOutputBytes,
    open_volumes: usize,
}

impl OperationBudget {
    pub(crate) fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            metadata: MetadataBytes::new(0),
            decoded: DecodedBytes::new(0),
            peak_decoder_working_set: DecoderWorkingSetBytes::new(0),
            kdf_cycles: KdfCycles::new(0),
            temporary_storage: TemporaryStorageBytes::new(0),
            retained_output: RetainedOutputBytes::new(0),
            peak_retained_output: RetainedOutputBytes::new(0),
            open_volumes: 0,
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
        start: impl FnOnce(&mut Self) -> Result<T, R7zError>,
    ) -> Result<T, R7zError> {
        let next_total = self.next_decoded(bytes)?;
        match start(self) {
            Ok(output) => {
                self.decoded = next_total;
                Ok(output)
            }
            Err(error) => {
                if !matches!(
                    error,
                    R7zError::PasswordRequired
                        | R7zError::ResourceLimitExceeded {
                            resource: "AES KDF cycles",
                            ..
                        }
                ) {
                    self.decoded = next_total;
                }
                Err(error)
            }
        }
    }

    pub(crate) fn admit_decoder_working_set(
        &mut self,
        bytes: DecoderWorkingSetBytes,
    ) -> Result<(), R7zError> {
        let hard_limit = crate::codec::MAX_DECODER_WORKING_SET_BYTES as u64;
        let limit = self
            .limits
            .max_decoder_working_set_bytes
            .map_or(hard_limit, |configured| configured.min(hard_limit));
        if bytes.get() > limit {
            return Err(self.decoder_working_set_error(limit));
        }
        self.peak_decoder_working_set = self.peak_decoder_working_set.max(bytes);
        Ok(())
    }

    fn decoder_working_set_error(&self, limit: u64) -> R7zError {
        R7zError::ResourceLimitExceeded {
            resource: "decoder working set",
            limit,
        }
    }

    pub(crate) fn charge_kdf_cycles(&mut self, cycles: KdfCycles) -> Result<(), R7zError> {
        let used = Self::next_total(
            self.kdf_cycles.get(),
            cycles.get(),
            self.limits.max_total_kdf_cycles,
            "AES KDF cycles",
        )?;
        self.kdf_cycles = KdfCycles::new(used);
        Ok(())
    }

    pub(crate) fn check_temporary_storage_write(
        &self,
        bytes: TemporaryStorageBytes,
    ) -> Result<(), R7zError> {
        Self::next_total(
            self.temporary_storage.get(),
            bytes.get(),
            self.limits.max_temporary_storage_bytes,
            "temporary storage",
        )
        .map(|_| ())
    }

    pub(crate) fn charge_temporary_storage_write(
        &mut self,
        bytes: TemporaryStorageBytes,
    ) -> Result<(), R7zError> {
        let written = Self::next_total(
            self.temporary_storage.get(),
            bytes.get(),
            self.limits.max_temporary_storage_bytes,
            "temporary storage",
        )?;
        self.temporary_storage = TemporaryStorageBytes::new(written);
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn with_retained_output_reservation<T>(
        &mut self,
        bytes: RetainedOutputBytes,
        operation: impl FnOnce(&mut Self) -> Result<T, R7zError>,
    ) -> Result<T, R7zError> {
        let limit = self.limits.max_retained_output_bytes.unwrap_or(u64::MAX);
        let Some(reserved) = self.retained_output.get().checked_add(bytes.get()) else {
            return Err(Self::resource_limit("retained output", limit));
        };
        if reserved > limit {
            return Err(Self::resource_limit("retained output", limit));
        }

        let previous = self.retained_output;
        self.retained_output = RetainedOutputBytes::new(reserved);
        self.peak_retained_output = self.peak_retained_output.max(self.retained_output);
        let result = operation(self);
        self.retained_output = previous;
        result
    }

    pub(crate) fn charge_open_volume(&mut self) -> Result<(), R7zError> {
        let limit = self.limits.max_open_volumes.get();
        let Some(open_volumes) = self.open_volumes.checked_add(1) else {
            return Err(Self::resource_limit("archive volume count", limit as u64));
        };
        if open_volumes > limit {
            return Err(Self::resource_limit("archive volume count", limit as u64));
        }
        self.open_volumes = open_volumes;
        Ok(())
    }

    pub(crate) fn release_open_volume(&mut self) {
        self.open_volumes = self.open_volumes.saturating_sub(1);
    }

    fn next_total(
        used: u64,
        amount: u64,
        limit: Option<u64>,
        resource: &'static str,
    ) -> Result<u64, R7zError> {
        let Some(total) = used.checked_add(amount) else {
            return limit.map_or(Ok(u64::MAX), |limit| {
                Err(Self::resource_limit(resource, limit))
            });
        };
        if limit.is_some_and(|limit| total > limit) {
            return Err(Self::resource_limit(resource, limit.unwrap_or(u64::MAX)));
        }
        Ok(total)
    }

    fn resource_limit(resource: &'static str, limit: u64) -> R7zError {
        R7zError::ResourceLimitExceeded { resource, limit }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DecodedBytes, DecoderWorkingSetBytes, KdfCycles, MetadataBytes, OperationBudget,
        ResourceLimits, RetainedOutputBytes, TemporaryStorageBytes,
    };
    use crate::R7zError;
    use std::num::NonZeroUsize;

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

    #[test]
    fn decoder_working_set_admission_tracks_the_peak_and_enforces_the_limit() {
        let mut budget = OperationBudget::new(ResourceLimits {
            max_decoder_working_set_bytes: Some(10),
            ..ResourceLimits::default()
        });

        assert!(matches!(
            budget.admit_decoder_working_set(DecoderWorkingSetBytes::new(11)),
            Err(R7zError::ResourceLimitExceeded {
                resource: "decoder working set",
                limit: 10,
            })
        ));
        budget
            .admit_decoder_working_set(DecoderWorkingSetBytes::new(6))
            .unwrap();
        budget
            .admit_decoder_working_set(DecoderWorkingSetBytes::new(10))
            .unwrap();
        assert_eq!(budget.peak_decoder_working_set.get(), 10);
    }

    #[test]
    fn kdf_work_and_temporary_storage_have_independent_limits() {
        let mut budget = OperationBudget::new(ResourceLimits {
            max_total_kdf_cycles: Some(8),
            max_temporary_storage_bytes: Some(8),
            ..ResourceLimits::default()
        });

        budget.charge_kdf_cycles(KdfCycles::new(6)).unwrap();
        assert!(matches!(
            budget.charge_kdf_cycles(KdfCycles::new(3)),
            Err(R7zError::ResourceLimitExceeded {
                resource: "AES KDF cycles",
                limit: 8,
            })
        ));
        budget
            .charge_temporary_storage_write(TemporaryStorageBytes::new(5))
            .unwrap();
        budget
            .charge_temporary_storage_write(TemporaryStorageBytes::new(3))
            .unwrap();
        assert!(matches!(
            budget.charge_temporary_storage_write(TemporaryStorageBytes::new(1)),
            Err(R7zError::ResourceLimitExceeded {
                resource: "temporary storage",
                limit: 8,
            })
        ));
    }

    #[test]
    fn retained_output_reservations_share_a_peak_limit_and_release_on_error() {
        let mut budget = OperationBudget::new(ResourceLimits {
            max_retained_output_bytes: Some(10),
            ..ResourceLimits::default()
        });
        let result =
            budget.with_retained_output_reservation(RetainedOutputBytes::new(6), |budget| {
                budget.with_retained_output_reservation(RetainedOutputBytes::new(5), |_| Ok(()))
            });
        assert!(matches!(
            result,
            Err(R7zError::ResourceLimitExceeded {
                resource: "retained output",
                limit: 10,
            })
        ));
        budget
            .with_retained_output_reservation(RetainedOutputBytes::new(10), |_| Ok(()))
            .unwrap();
    }

    #[test]
    fn opening_volumes_uses_a_count_limit() {
        let mut budget = OperationBudget::new(ResourceLimits {
            max_open_volumes: NonZeroUsize::new(2).unwrap(),
            ..ResourceLimits::default()
        });
        budget.charge_open_volume().unwrap();
        budget.charge_open_volume().unwrap();
        assert!(matches!(
            budget.charge_open_volume(),
            Err(R7zError::ResourceLimitExceeded {
                resource: "archive volume count",
                limit: 2,
            })
        ));
    }
}
