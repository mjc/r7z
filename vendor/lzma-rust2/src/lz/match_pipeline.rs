use super::lz_encoder::{LzEncoderData, MatchFind, MatchFinders, Matches};
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread::{self, JoinHandle},
};

pub(super) const INPUT_SIZE: usize = 64 * 1024;
pub(super) const POSITIONS: usize = 4096;
const RESULT_POSITIONS: usize = 8192;

enum Input {
    Bytes(Vec<u8>),
    Finish,
}

#[derive(Default)]
struct QueueState {
    inputs: VecDeque<Input>,
    input_bytes: usize,
    results: VecDeque<MatchBatch>,
    result_positions: usize,
    stopped: bool,
}

struct Queues {
    state: Mutex<QueueState>,
    input_ready: Condvar,
    results_ready: Condvar,
    result_space: Condvar,
    input_capacity: usize,
}

impl Queues {
    fn lock(&self) -> MutexGuard<'_, QueueState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn stop(&self) {
        self.lock().stopped = true;
        self.input_ready.notify_all();
        self.results_ready.notify_all();
        self.result_space.notify_all();
    }

    fn input(&self) -> Option<Input> {
        let state = self
            .input_ready
            .wait_while(self.lock(), |state| {
                state.inputs.is_empty() && !state.stopped
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut state = state;
        if state.stopped {
            return None;
        }
        let input = state.inputs.pop_front()?;
        if let Input::Bytes(bytes) = &input {
            state.input_bytes -= bytes.len();
        }
        Some(input)
    }

    fn publish(&self, batch: MatchBatch) -> bool {
        let mut state = self
            .result_space
            .wait_while(self.lock(), |state| {
                state.result_positions + batch.counts.len() > RESULT_POSITIONS && !state.stopped
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.stopped {
            return false;
        }
        state.result_positions += batch.counts.len();
        state.results.push_back(batch);
        self.results_ready.notify_one();
        true
    }
}

struct WorkerExit(Arc<Queues>);

impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.stop();
    }
}

#[derive(Default)]
struct MatchBatch {
    counts: Vec<u16>,
    pairs: Vec<(u32, i32)>,
    position: usize,
    pair: usize,
}

impl MatchBatch {
    fn new(nice_len: u32, positions: usize) -> Self {
        Self {
            counts: Vec::with_capacity(positions),
            pairs: Vec::with_capacity(positions * (nice_len as usize - 1)),
            ..Self::default()
        }
    }

    fn push(&mut self, matches: &Matches) {
        let count = matches.count as usize;
        self.counts.push(count as u16);
        self.pairs.extend(
            matches.len[..count]
                .iter()
                .copied()
                .zip(matches.dist[..count].iter().copied()),
        );
    }

    fn exhausted(&self) -> bool {
        self.position == self.counts.len()
    }

    fn next(&mut self, matches: Option<&mut Matches>) {
        let count = usize::from(self.counts[self.position]);
        if let Some(matches) = matches {
            matches.count = count as u32;
            for (index, &(length, distance)) in
                self.pairs[self.pair..self.pair + count].iter().enumerate()
            {
                matches.len[index] = length;
                matches.dist[index] = distance;
            }
        }
        self.position += 1;
        self.pair += count;
    }
}

pub(super) struct MatchPipeline {
    queues: Arc<Queues>,
    worker: Option<JoinHandle<()>>,
    batch: MatchBatch,
}

impl MatchPipeline {
    pub(super) fn new(mut data: LzEncoderData, mut finder: MatchFinders) -> io::Result<Self> {
        data.match_len_max = data.nice_len;
        let queues = Arc::new(Queues {
            state: Mutex::new(QueueState::default()),
            input_ready: Condvar::new(),
            results_ready: Condvar::new(),
            result_space: Condvar::new(),
            input_capacity: data.buf.len(),
        });
        let worker_queues = Arc::clone(&queues);
        let worker = thread::Builder::new()
            .name("lzma-match-finder".into())
            .spawn(move || {
                let _exit = WorkerExit(Arc::clone(&worker_queues));
                let mut matches = Matches::new(data.nice_len as usize - 1);
                for input in std::iter::from_fn(|| worker_queues.input()) {
                    match input {
                        Input::Bytes(bytes) => {
                            let used = data.fill_window(&bytes);
                            assert_eq!(
                                used,
                                bytes.len(),
                                "matcher window must admit encoder input"
                            );
                        }
                        Input::Finish => data.set_finishing(),
                    }
                    let required = if data.finishing {
                        4
                    } else {
                        data.nice_len as i32
                    };
                    let positions = (data.write_pos - data.read_pos - required).max(0) as usize;
                    for start in (0..positions).step_by(POSITIONS) {
                        let count = (positions - start).min(POSITIONS);
                        let mut batch = MatchBatch::new(data.nice_len, count);
                        for _ in 0..count {
                            finder.find_matches(&mut data, &mut matches);
                            batch.push(&matches);
                        }
                        if !worker_queues.publish(batch) {
                            return;
                        }
                    }
                    if data.finishing {
                        return;
                    }
                }
            })?;
        Ok(Self {
            queues,
            worker: Some(worker),
            batch: MatchBatch::default(),
        })
    }

    pub(super) fn overhead(window_size: usize, nice_len: usize) -> usize {
        // A mirrored window, geometrically allocated input packets, a producer
        // and consumer slab, and position-bounded queued results. Tiny writes
        // may produce one-position slabs, so include their metadata as well.
        3 * window_size
            + 2 * INPUT_SIZE
            + (RESULT_POSITIONS + 2 * POSITIONS)
                * (std::mem::size_of::<u16>()
                    + nice_len.saturating_sub(1) * std::mem::size_of::<(u32, i32)>())
            + RESULT_POSITIONS * std::mem::size_of::<MatchBatch>()
            + (window_size / INPUT_SIZE + 2) * std::mem::size_of::<Input>()
    }

    pub(super) fn input(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        let queues = Arc::clone(&self.queues);
        let mut state = queues.lock();
        if state.stopped {
            drop(state);
            return Err(self.disconnected());
        }
        if bytes.len() > queues.input_capacity - state.input_bytes {
            return Err(io::Error::other("match finder input window exceeded"));
        }
        state.input_bytes += bytes.len();
        if let Some(Input::Bytes(tail)) = state.inputs.back_mut() {
            let count = bytes.len().min(INPUT_SIZE - tail.len());
            tail.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
        }
        state.inputs.extend(
            bytes
                .chunks(INPUT_SIZE)
                .map(|bytes| Input::Bytes(bytes.to_vec())),
        );
        queues.input_ready.notify_one();
        Ok(())
    }

    pub(super) fn flush(&mut self) -> io::Result<()> {
        // Flush changes only the encoder read limit. The matcher already
        // publishes every position with enough lookahead; its short tail is
        // replayed when more input arrives, just as in the local finder.
        if self.queues.lock().stopped {
            return Err(self.disconnected());
        }
        Ok(())
    }

    pub(super) fn finish(&mut self) -> io::Result<()> {
        let queues = Arc::clone(&self.queues);
        let mut state = queues.lock();
        if state.stopped {
            drop(state);
            return Err(self.disconnected());
        }
        state.inputs.push_back(Input::Finish);
        queues.input_ready.notify_one();
        Ok(())
    }

    fn next(&mut self, matches: Option<&mut Matches>) -> io::Result<()> {
        if self.batch.exhausted() {
            let queues = Arc::clone(&self.queues);
            let mut state = queues
                .results_ready
                .wait_while(queues.lock(), |state| {
                    state.results.is_empty() && !state.stopped
                })
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let batch = state.results.pop_front();
            if let Some(batch) = batch {
                state.result_positions -= batch.counts.len();
                queues.result_space.notify_one();
                self.batch = batch;
            } else {
                drop(state);
                return Err(self.disconnected());
            }
        }
        self.batch.next(matches);
        Ok(())
    }

    pub(super) fn find_matches(
        &mut self,
        data: &mut LzEncoderData,
        matches: &mut Matches,
    ) -> io::Result<()> {
        matches.count = 0;
        if data.move_pos(data.nice_len as i32, 4) == 0 {
            return Ok(());
        }
        self.next(Some(matches))?;
        if let Some(index) = (matches.count as usize).checked_sub(1) {
            if matches.len[index] == data.nice_len {
                matches.len[index] = data.get_match_len(
                    matches.dist[index],
                    data.get_avail().min(data.match_len_max as i32),
                ) as u32;
            }
        }
        Ok(())
    }

    pub(super) fn skip(&mut self, data: &mut LzEncoderData, count: usize) -> io::Result<()> {
        (0..count).try_for_each(|_| match data.move_pos(data.nice_len as i32, 4) {
            0 => Ok(()),
            _ => self.next(None),
        })
    }

    fn disconnected(&mut self) -> io::Error {
        self.queues.stop();
        match self.worker.take().map(JoinHandle::join) {
            Some(Err(_)) => io::Error::other("match finder worker panicked"),
            _ => io::Error::other("match finder worker disconnected"),
        }
    }
}

impl Drop for MatchPipeline {
    fn drop(&mut self) {
        self.queues.stop();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::LzEncoder;
    use super::*;

    fn pipeline() -> MatchPipeline {
        let encoder = LzEncoder::new_bt4(64 * 1024, 4096, 4096, 32, 273, 32);
        MatchPipeline::new(
            encoder.data,
            MatchFinders::Bt4(super::super::bt4::Bt4::new(64 * 1024, 32, 32)),
        )
        .unwrap()
    }

    #[test]
    fn dropping_with_queued_results_joins_the_worker() {
        let mut pipeline = pipeline();
        pipeline.input(&vec![0; 64 * 1024]).unwrap();
        pipeline.next(None).unwrap();
        drop(pipeline);
    }

    #[test]
    fn oversized_input_is_rejected_before_queueing() {
        let mut pipeline = pipeline();
        let capacity = pipeline.queues.input_capacity;
        assert!(pipeline.input(&vec![0; capacity + 1]).is_err());
        assert_eq!(pipeline.queues.lock().input_bytes, 0);
    }

    #[test]
    fn worker_panic_wakes_the_reader_and_becomes_an_io_error() {
        let mut pipeline = pipeline();
        pipeline.queues.stop();
        pipeline.worker.take().unwrap().join().unwrap();
        pipeline.queues.lock().stopped = false;
        let queues = Arc::clone(&pipeline.queues);
        pipeline.worker = Some(thread::spawn(move || {
            let _exit = WorkerExit(queues);
            panic!("injected worker panic");
        }));
        let error = pipeline.next(None).unwrap_err();
        assert_eq!(error.to_string(), "match finder worker panicked");
        assert!(pipeline.worker.is_none());
    }
}
