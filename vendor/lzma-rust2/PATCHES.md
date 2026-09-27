# Local lzma-rust2 patch

Based on the published `lzma-rust2` 0.16.2 crate, upstream revision
`4398f2a1fc016eb64a9f98a0f6b88da0db8f1c10`. The registry package checksum is
`47bb1e988e6fb779cf720ad431242d3f03167c1b3f2b1aae7f1a94b2495b36ae`.
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

The bound is on pending jobs, not total process memory. Dictionary allocations,
caller-owned input/output, and format metadata remain separate; selecting a
worker count from a memory budget is the next implementation step.

Run the patch's unit regressions with
`cargo nextest run -p lzma-rust2 --lib -E 'test(work_pool::) | test(work_queue::)'`
and the public API regressions with `cargo nextest run --test lzma_mt_test`.
Upstream BCJ unit tests require external fixtures omitted from the published
crate, so the dependency command selects the affected pool and queue tests.
