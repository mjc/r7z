# Local lzma-rust2 patch

Based on the published `lzma-rust2` 0.21.0 crate, upstream revision
`7405a770f86e4cb28623d2b53be24324aada44dd`. The registry package checksum is
`fde178a3caf126c440fa15628147772d8ee590a39477d711353fbe2e58a73a5b`.
The original Apache-2.0 license, source, README, changelog, and manifest are
retained. The local manifest omits upstream examples, benchmarks, fixture-based
integration tests, and their development dependencies.

R7Z-1 / R7Z-PLAN-2 step 2:

- Bound dispatched but not yet returned work to the worker limit plus one.
  This includes queued input, running jobs, and results waiting for earlier
  jobs. Writers may also retain one producer chunk and the result being written.
- Apply backpressure to LZMA2, LZIP, and XZ writers and the shared LZIP reader.
- Report worker panics as I/O errors. On failure or drop, disconnect result
  receivers before joining workers so a blocked result send cannot deadlock.
- Join workers on completion and abort. Abort stops new work; already running
  block compression may finish before the join returns.
- Keep queue contents and closure under one mutex. This prevents a missed
  shutdown notification between an idle worker's predicate check and wait, and
  prevents submissions from racing past closure.

The bound is on pending jobs, not total process memory. Dictionary allocations,
caller-owned input/output, and format metadata remain separate; selecting a
worker count from a memory budget is the next implementation step.

Run the patch's unit regressions with
`cargo nextest run -p lzma-rust2 --lib -E 'test(work_pool::) | test(work_queue::)'`
and the public API regressions with `cargo nextest run --test lzma_mt_test`.
Upstream BCJ unit tests require external fixtures omitted from the published
crate, so the dependency command selects the affected pool and queue tests.

Rebased on 0.21.0, retaining its worker scheduling and decoder fixes. The
upstream blocking flush behavior uses the local `wait_for_result` method so
flush waits for all submitted output without closing the pool. Panic reporting
already overlaps upstream; local spawning additionally returns OS spawn errors.

The BT4 skip path uses the existing word-at-a-time `extend_match` helper, bounded
by the same nice-length limit, while retaining the original tree updates.
`tests/lzma_bt4_test.rs` compares compressed hashes with unmodified 0.21.0 over
word/match boundaries and dictionary wraps. Dependency `lz::` tests check tree
links at buffer ends and normalization at the 2 GiB position boundary; CI runs
them with and without the `optimization` feature.

The encoder memory estimate converts the LZ buffer from bytes to KiB and counts
all three hash tables. R7Z uses this corrected estimate for worker admission.

The LZMA2 writer accepts a shared cancellation flag. Result waits check it at the
existing 100 ms error-check interval. Workers check cancellation and shutdown
between 64 KiB input writes, so abort joins no longer require compressing the
remainder of an independent block. Cancellation has a distinct I/O error payload;
output errors retain their original cause.

Single-block match finding can run concurrently with the normal encoder. The
existing BT4 tree moves to one worker; a mirrored input window and queues are
bounded by bytes and positions. The encoder retains its original lookahead,
write cadence, and independent-block boundaries. Short matches transfer as
length/distance pairs; the main encoder extends nice-length matches using its
own window. Output errors stop and join the worker, and resets release the old
worker before creating its replacement. Differential tests require identical
compressed output through fragmented writes, flushes, window moves and resets.
R7Z selects this scheduling path only for sufficiently large single blocks,
when the thread and memory allowances permit it and the initial input prefix
contains more than 1024 distinct adjacent byte pairs. Repetitive or short
prefixes retain the local finder without changing compression settings.

Local matcher dispatch stays inlined; the pipeline implementations remain
separate so their size does not force local matching through extra calls.
Known multiblock inputs start the admitted MT writer directly, avoiding the
first-block staging copy. Dispatch replaces the producer buffer with one
reserved to the block size, avoiding repeated growth and copying on later
blocks. Unknown input lengths still defer MT activation until a second block.
