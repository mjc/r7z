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
    /// Maximum estimated working set for `LZMA`, `LZMA2`, and `PPMd` encoders.
    pub max_encoder_working_set_bytes: Option<u64>,
    /// Maximum total decoded bytes for one read operation. `None` is unlimited.
    pub max_total_decoded_bytes: Option<u64>,
    /// Maximum aggregate AES key-derivation work for one operation. `None` is unlimited.
    pub max_total_kdf_cycles: Option<u64>,
    /// Maximum bytes retained in memory by one archive operation. `None` is unlimited.
    pub max_retained_output_bytes: Option<u64>,
    /// Maximum cumulative bytes written to temporary archive spools. `None` is unlimited.
    pub max_temporary_storage_bytes: Option<u64>,
    /// Maximum number of volumes created for one archive. `None` is unlimited.
    pub max_volume_count: Option<NonZeroUsize>,
    /// Maximum number of split archive volumes held open at once.
    pub max_open_volumes: NonZeroUsize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_signature_scan_bytes: DEFAULT_METADATA_BYTES,
            max_metadata_bytes: DEFAULT_METADATA_BYTES,
            max_decoder_working_set_bytes: None,
            max_encoder_working_set_bytes: None,
            max_total_decoded_bytes: None,
            max_total_kdf_cycles: None,
            max_retained_output_bytes: None,
            max_temporary_storage_bytes: None,
            max_volume_count: None,
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

pub(crate) struct KdfBudget {
    used: KdfCycles,
    limit: Option<u64>,
}

impl KdfBudget {
    fn new(limit: Option<u64>) -> Self {
        Self {
            used: KdfCycles::new(0),
            limit,
        }
    }

    pub(crate) fn charge(&mut self, cycles: KdfCycles) -> Result<(), R7zError> {
        self.used = KdfCycles::new(OperationBudget::next_total(
            self.used.get(),
            cycles.get(),
            self.limit,
            "AES KDF cycles",
        )?);
        Ok(())
    }
}

pub(crate) struct TemporaryStorageBudget {
    written: TemporaryStorageBytes,
    limit: Option<u64>,
}

pub(crate) struct OpenVolumeBudget {
    open: usize,
    limit: NonZeroUsize,
}

pub(crate) struct VolumeCountBudget {
    created: usize,
    limit: Option<NonZeroUsize>,
}

impl VolumeCountBudget {
    fn new(limit: Option<NonZeroUsize>) -> Self {
        Self { created: 0, limit }
    }

    pub(crate) fn charge(&mut self, count: usize) -> Result<(), R7zError> {
        let Some(created) = self.created.checked_add(count) else {
            return Err(OperationBudget::resource_limit(
                "archive volume count",
                self.limit.map_or(u64::MAX, |limit| limit.get() as u64),
            ));
        };
        if self.limit.is_some_and(|limit| created > limit.get()) {
            return Err(OperationBudget::resource_limit(
                "archive volume count",
                self.limit.map_or(u64::MAX, |limit| limit.get() as u64),
            ));
        }
        self.created = created;
        Ok(())
    }
}

impl OpenVolumeBudget {
    fn new(limit: NonZeroUsize) -> Self {
        Self { open: 0, limit }
    }

    pub(crate) fn charge(&mut self) -> Result<(), R7zError> {
        let limit = self.limit.get();
        let Some(open) = self.open.checked_add(1) else {
            return Err(OperationBudget::resource_limit(
                "open archive volumes",
                limit as u64,
            ));
        };
        if open > limit {
            return Err(OperationBudget::resource_limit(
                "open archive volumes",
                limit as u64,
            ));
        }
        self.open = open;
        Ok(())
    }

    pub(crate) fn release(&mut self) {
        self.open = self.open.saturating_sub(1);
    }
}

impl TemporaryStorageBudget {
    fn new(limit: Option<u64>) -> Self {
        Self {
            written: TemporaryStorageBytes::new(0),
            limit,
        }
    }

    pub(crate) fn limit(&self) -> Option<u64> {
        self.limit
    }

    pub(crate) fn check_write(&self, bytes: TemporaryStorageBytes) -> Result<(), R7zError> {
        OperationBudget::next_total(
            self.written.get(),
            bytes.get(),
            self.limit,
            "temporary storage",
        )
        .map(|_| ())
    }

    pub(crate) fn charge_write(&mut self, bytes: TemporaryStorageBytes) -> Result<(), R7zError> {
        self.written = TemporaryStorageBytes::new(OperationBudget::next_total(
            self.written.get(),
            bytes.get(),
            self.limit,
            "temporary storage",
        )?);
        Ok(())
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

pub(crate) struct RetainedOutputBudget {
    retained: RetainedOutputBytes,
    limit: Option<u64>,
}

pub(crate) struct SpoolBudget {
    pub(crate) temporary_storage: TemporaryStorageBudget,
    pub(crate) retained_output: RetainedOutputBudget,
}

pub(crate) struct WriterOperation {
    pub(crate) kdf: KdfBudget,
    pub(crate) monitor: crate::operation::OperationMonitor,
}

pub(crate) struct WriterBudgets {
    pub(crate) operation: WriterOperation,
    pub(crate) spool: SpoolBudget,
    pub(crate) open_volumes: OpenVolumeBudget,
    pub(crate) volume_count: VolumeCountBudget,
}

impl RetainedOutputBudget {
    fn new(limit: Option<u64>) -> Self {
        Self {
            retained: RetainedOutputBytes::new(0),
            limit,
        }
    }

    pub(crate) fn check_resize(
        &self,
        current: RetainedOutputBytes,
        next: RetainedOutputBytes,
    ) -> Result<(), R7zError> {
        self.resized_total(current, next).map(|_| ())
    }

    fn resized_total(
        &self,
        current: RetainedOutputBytes,
        next: RetainedOutputBytes,
    ) -> Result<u64, R7zError> {
        let retained = self.retained.get().saturating_sub(current.get());
        OperationBudget::next_total(retained, next.get(), self.limit, "retained output")
    }

    pub(crate) fn resize(
        &mut self,
        current: RetainedOutputBytes,
        next: RetainedOutputBytes,
    ) -> Result<(), R7zError> {
        let retained = self.resized_total(current, next)?;
        self.retained = RetainedOutputBytes::new(retained);
        Ok(())
    }

    pub(crate) fn reserve(&mut self, bytes: RetainedOutputBytes) -> Result<(), R7zError> {
        self.resize(RetainedOutputBytes::new(0), bytes)
    }

    pub(crate) fn release(&mut self, bytes: RetainedOutputBytes) {
        self.retained = RetainedOutputBytes::new(self.retained.get().saturating_sub(bytes.get()));
    }

    pub(crate) fn limit(&self) -> Option<u64> {
        self.limit
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
    pub(crate) monitor: crate::operation::OperationMonitor,
    limits: ResourceLimits,
    metadata: MetadataBytes,
    decoded: DecodedBytes,
    peak_decoder_working_set: DecoderWorkingSetBytes,
    kdf: KdfBudget,
    temporary_storage: TemporaryStorageBudget,
    retained_output: RetainedOutputBudget,
    open_volumes: OpenVolumeBudget,
    volume_count: VolumeCountBudget,
}

impl OperationBudget {
    pub(crate) fn new(limits: ResourceLimits) -> Self {
        Self {
            monitor: crate::operation::OperationMonitor::default(),
            limits,
            metadata: MetadataBytes::new(0),
            decoded: DecodedBytes::new(0),
            peak_decoder_working_set: DecoderWorkingSetBytes::new(0),
            kdf: KdfBudget::new(limits.max_total_kdf_cycles),
            temporary_storage: TemporaryStorageBudget::new(limits.max_temporary_storage_bytes),
            retained_output: RetainedOutputBudget::new(limits.max_retained_output_bytes),
            open_volumes: OpenVolumeBudget::new(limits.max_open_volumes),
            volume_count: VolumeCountBudget::new(limits.max_volume_count),
        }
    }

    pub(crate) fn with_control(mut self, control: Option<crate::OperationControl>) -> Self {
        self.monitor = crate::operation::OperationMonitor::new(control);
        self
    }

    pub(crate) fn into_writer_budgets(self) -> WriterBudgets {
        WriterBudgets {
            operation: WriterOperation {
                kdf: self.kdf,
                monitor: self.monitor.for_phase(crate::OperationPhase::Write),
            },
            spool: SpoolBudget {
                temporary_storage: self.temporary_storage,
                retained_output: self.retained_output,
            },
            open_volumes: self.open_volumes,
            volume_count: self.volume_count,
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
            return Err(Self::decoder_working_set_error(limit));
        }
        self.peak_decoder_working_set = self.peak_decoder_working_set.max(bytes);
        Ok(())
    }

    fn decoder_working_set_error(limit: u64) -> R7zError {
        R7zError::ResourceLimitExceeded {
            resource: "decoder working set",
            limit,
        }
    }

    pub(crate) fn charge_kdf_cycles(&mut self, cycles: KdfCycles) -> Result<(), R7zError> {
        self.kdf.charge(cycles)
    }

    #[allow(dead_code)]
    pub(crate) fn with_retained_output_reservation<T>(
        &mut self,
        bytes: RetainedOutputBytes,
        operation: impl FnOnce(&mut Self) -> Result<T, R7zError>,
    ) -> Result<T, R7zError> {
        self.retained_output.reserve(bytes)?;
        let result = operation(self);
        self.retained_output.release(bytes);
        result
    }

    pub(crate) fn charge_open_volume(&mut self) -> Result<(), R7zError> {
        self.open_volumes.charge()
    }

    pub(crate) fn release_open_volume(&mut self) {
        self.open_volumes.release();
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

    #[test]
    fn defaults_match_documented_resource_limits() {
        let limits = ResourceLimits::default();

        assert_eq!(limits.max_signature_scan_bytes, 64 * 1024 * 1024);
        assert_eq!(limits.max_metadata_bytes, 64 * 1024 * 1024);
        assert_eq!(limits.max_decoder_working_set_bytes, None);
        assert_eq!(limits.max_encoder_working_set_bytes, None);
        assert_eq!(limits.max_total_decoded_bytes, None);
        assert_eq!(limits.max_total_kdf_cycles, None);
        assert_eq!(limits.max_retained_output_bytes, None);
        assert_eq!(limits.max_temporary_storage_bytes, None);
        assert_eq!(limits.max_volume_count, None);
        assert_eq!(limits.max_open_volumes, NonZeroUsize::new(128).unwrap());
    }

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
        let budget = OperationBudget::new(ResourceLimits {
            max_total_kdf_cycles: Some(8),
            max_temporary_storage_bytes: Some(8),
            ..ResourceLimits::default()
        });
        let mut budgets = budget.into_writer_budgets();

        budgets.operation.kdf.charge(KdfCycles::new(6)).unwrap();
        assert!(matches!(
            budgets.operation.kdf.charge(KdfCycles::new(3)),
            Err(R7zError::ResourceLimitExceeded {
                resource: "AES KDF cycles",
                limit: 8,
            })
        ));
        budgets
            .spool
            .temporary_storage
            .charge_write(TemporaryStorageBytes::new(5))
            .unwrap();
        budgets
            .spool
            .temporary_storage
            .charge_write(TemporaryStorageBytes::new(3))
            .unwrap();
        assert!(matches!(
            budgets
                .spool
                .temporary_storage
                .charge_write(TemporaryStorageBytes::new(1)),
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
                resource: "open archive volumes",
                limit: 2,
            })
        ));
    }
}
