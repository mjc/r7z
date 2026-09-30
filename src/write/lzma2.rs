use super::{encode, encode::ThreadRequest, model::CompressionOptions};
use crate::R7zError;
use lzma_rust2::{Lzma2Options, Lzma2Writer, Lzma2WriterMt};
use std::io::{self, Write};

const MIB: u64 = 1024 * 1024;
const DEFAULT_UNKNOWN_BUDGET: u64 = 512 * MIB;
const MAX_AUTO_BUDGET: u64 = 8 * 1024 * MIB;
const WORKER_OVERHEAD: u64 = 8 * MIB;
pub(super) const MAX_WORKERS: u32 = 256;

/// Includes encoder state, admitted input, output waiting for ordered emission,
/// the producer chunk, and a per-thread allowance. Caller-owned buffers are separate.
fn required_bytes(options: &Lzma2Options, workers: u32) -> Option<u64> {
    let chunk = options
        .chunk_size?
        .get()
        .max(u64::from(options.lzma_options.dict_size));
    let encoder = u64::from(options.lzma_options.get_memory_usage())
        .checked_mul(1024)?
        .checked_add(WORKER_OVERHEAD)?;
    if workers == 1 {
        return Some(encoder);
    }
    let pending = u64::from(workers).checked_add(1)?;
    // During activation the deferred first chunk can coexist briefly with
    // the producer buffer.
    let input = pending.checked_add(2)?.checked_mul(chunk)?;
    // An incompressible LZMA2 block is slightly larger than its input.
    // Twice the input size leaves ample room for framing and allocator growth.
    let output = pending.checked_mul(chunk.checked_mul(2)?)?;
    u64::from(workers)
        .checked_mul(encoder)?
        .checked_add(input)?
        .checked_add(output)
}

fn available_memory() -> Option<u64> {
    let host = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("MemAvailable:"))
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
                .and_then(|kib| kib.checked_mul(1024))
        });
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("0::"))
                .map(str::to_owned)
        })
        .and_then(|path| {
            let root = std::path::Path::new("/sys/fs/cgroup");
            let mut dir = root.join(path.trim_start_matches('/'));
            let mut available: Option<u64> = None;
            loop {
                let remaining = std::fs::read_to_string(dir.join("memory.max"))
                    .ok()
                    .and_then(|value| value.trim().parse::<u64>().ok())
                    .zip(
                        std::fs::read_to_string(dir.join("memory.current"))
                            .ok()
                            .and_then(|value| value.trim().parse::<u64>().ok()),
                    )
                    .map(|(limit, current)| limit.saturating_sub(current));
                if let Some(remaining) = remaining {
                    available = Some(available.map_or(remaining, |prior| prior.min(remaining)));
                }
                if dir == root || !dir.pop() {
                    break;
                }
            }
            available
        });
    match (host, cgroup) {
        (Some(host), Some(cgroup)) => Some(host.min(cgroup)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

pub(super) fn default_budget() -> u64 {
    available_memory().map_or(DEFAULT_UNKNOWN_BUDGET, |available| {
        (available / 2).min(MAX_AUTO_BUDGET)
    })
}

pub(super) fn set_default_budget(options: &mut super::model::ArchiveOptions) {
    if options.compression.encoder_memory_limit.is_none() {
        options.compression.encoder_memory_limit = Some(default_budget());
    }
}

fn select_workers(
    compression: &CompressionOptions,
    options: &Lzma2Options,
    known_size: Option<u64>,
    thread_request: ThreadRequest,
) -> Result<u32, R7zError> {
    let chunk = options
        .chunk_size
        .expect("r7z always sets the LZMA2 chunk size")
        .get()
        .max(u64::from(options.lzma_options.dict_size));
    let blocks = known_size.map_or(u64::from(MAX_WORKERS), |size| size.div_ceil(chunk).max(1));
    let requested = match thread_request {
        ThreadRequest::Single => 1,
        ThreadRequest::Fixed(count) => count.get(),
        ThreadRequest::Auto => std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .ok()
            .and_then(|count| u32::try_from(count).ok())
            .unwrap_or(MAX_WORKERS)
            .min(MAX_WORKERS),
    };
    let known_blocks = u32::try_from(blocks.min(u64::from(MAX_WORKERS))).unwrap_or(MAX_WORKERS);
    let requested = requested.min(known_blocks);
    let budget = compression
        .encoder_memory_limit
        .unwrap_or_else(default_budget);
    if required_bytes(options, 1).is_none_or(|required| required > budget) {
        return Err(R7zError::LimitExceeded("encoder memory"));
    }
    match thread_request {
        ThreadRequest::Auto => Ok((2..=requested)
            .rev()
            .find(|&workers| required_bytes(options, workers).is_some_and(|bytes| bytes <= budget))
            .unwrap_or(1)),
        _ => {
            if required_bytes(options, requested).is_none_or(|required| required > budget) {
                Err(R7zError::LimitExceeded("encoder memory"))
            } else {
                Ok(requested)
            }
        }
    }
}

enum State<W: Write> {
    Buffered {
        out: W,
        options: Lzma2Options,
        workers: u32,
        data: Vec<u8>,
    },
    Single(Box<Lzma2Writer<W>>),
    Parallel(Box<Lzma2WriterMt<W>>),
}

pub(super) struct Encoder<W: Write> {
    state: Option<State<W>>,
}

impl<W: Write> Encoder<W> {
    pub(super) fn new(
        out: W,
        compression: &CompressionOptions,
        known_size: Option<u64>,
        thread_request: ThreadRequest,
    ) -> Result<Self, R7zError> {
        let options = encode::lzma2_options(compression);
        let workers = select_workers(compression, &options, known_size, thread_request)?;
        let state = if workers == 1 {
            State::Single(Box::new(Lzma2Writer::new(out, options)))
        } else {
            State::Buffered {
                out,
                options,
                workers,
                data: Vec::new(),
            }
        };
        Ok(Self { state: Some(state) })
    }

    fn start(state: State<W>, parallel: bool) -> io::Result<State<W>> {
        let State::Buffered {
            out,
            options,
            workers,
            data,
        } = state
        else {
            return Ok(state);
        };
        if parallel {
            let mut writer = Lzma2WriterMt::new(out, options, workers)?;
            writer.write_all(&data)?;
            Ok(State::Parallel(Box::new(writer)))
        } else {
            let mut writer = Lzma2Writer::new(out, options);
            writer.write_all(&data)?;
            Ok(State::Single(Box::new(writer)))
        }
    }

    pub(super) fn finish(mut self) -> io::Result<W> {
        let state = self
            .state
            .take()
            .ok_or_else(|| io::Error::other("encoder is unavailable after an error"))?;
        match Self::start(state, false)? {
            State::Single(writer) => writer.finish(),
            State::Parallel(writer) => writer.finish(),
            State::Buffered { .. } => unreachable!(),
        }
    }
}

impl<W: Write> Write for Encoder<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(state) = self.state.as_mut() else {
            return Err(io::Error::other("encoder is unavailable after an error"));
        };
        if let State::Buffered { data, options, .. } = state {
            let threshold = options
                .chunk_size
                .expect("r7z always sets the LZMA2 chunk size")
                .get();
            let threshold = usize::try_from(threshold).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "LZMA2 chunk exceeds usize")
            })?;
            if data.len().saturating_add(buf.len()) <= threshold {
                data.extend_from_slice(buf);
                return Ok(buf.len());
            }
            let state = self.state.take().expect("encoder state exists");
            self.state = Some(Self::start(state, true)?);
        }
        match self.state.as_mut().expect("encoder state exists") {
            State::Single(writer) => writer.write(buf),
            State::Parallel(writer) => writer.write(buf),
            State::Buffered { .. } => unreachable!(),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.state.is_none() {
            return Err(io::Error::other("encoder is unavailable after an error"));
        }
        if matches!(self.state, Some(State::Buffered { .. })) {
            let state = self.state.take().expect("encoder state exists");
            self.state = Some(Self::start(state, false)?);
        }
        match self.state.as_mut().expect("encoder state exists") {
            State::Single(writer) => writer.flush(),
            State::Parallel(writer) => writer.flush(),
            State::Buffered { .. } => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::EncoderThreads;
    use super::*;

    fn prepared_threads(compression: &CompressionOptions) -> ThreadRequest {
        let options = super::super::model::ArchiveOptions {
            codec: super::super::model::Codec::Lzma2,
            compression: compression.clone(),
            ..Default::default()
        };
        match encode::validate_archive_options(&options).unwrap().codec {
            encode::PreparedCodec::Lzma2(threads) => threads,
            _ => unreachable!("the test selects the LZMA2 codec"),
        }
    }

    #[test]
    fn explicit_threads_respect_encoder_budget() {
        let mut compression = CompressionOptions {
            threads: EncoderThreads::Fixed(4),
            encoder_memory_limit: Some(2 * 1024 * MIB),
            ..CompressionOptions::default()
        };
        let options = encode::lzma2_options(&compression);
        let threads = prepared_threads(&compression);
        assert_eq!(
            select_workers(&compression, &options, Some(256 * MIB), threads).unwrap(),
            4
        );
        compression.encoder_memory_limit = Some(256 * MIB);
        assert!(matches!(
            select_workers(&compression, &options, Some(256 * MIB), threads),
            Err(R7zError::LimitExceeded("encoder memory"))
        ));
    }

    #[test]
    fn small_known_input_uses_single_writer() {
        let compression = CompressionOptions {
            threads: EncoderThreads::Fixed(4),
            encoder_memory_limit: Some(256 * MIB),
            ..CompressionOptions::default()
        };
        let options = encode::lzma2_options(&compression);
        let threads = prepared_threads(&compression);
        assert_eq!(
            select_workers(&compression, &options, Some(1024), threads).unwrap(),
            1
        );
    }

    #[test]
    fn auto_limits_workers_to_the_estimated_memory_allowance() {
        let mut compression = CompressionOptions::default();
        let options = encode::lzma2_options(&compression);
        let threads = prepared_threads(&compression);
        let single_worker = required_bytes(&options, 1).unwrap();
        let two_workers = required_bytes(&options, 2).unwrap();
        assert!(two_workers > single_worker);

        compression.encoder_memory_limit = Some(single_worker);
        assert_eq!(
            select_workers(&compression, &options, None, threads).unwrap(),
            1
        );

        compression.encoder_memory_limit = Some(single_worker - 1);
        assert!(matches!(
            select_workers(&compression, &options, None, threads),
            Err(R7zError::LimitExceeded("encoder memory"))
        ));
    }
}
