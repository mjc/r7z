# Benchmarks

## Current writer versus old whole-folder route — 2026-10-09

Current main with 64 KiB input reads took 2.84–4.09% less time for random
PPMd than the old whole-folder route. Random LZMA stayed within 0.40% and
changed direction between passes. Source LZMA took 0.59–1.15% less time.
Five of six Copy workloads were faster, but source Copy with 64 files in
one folder took 8.15–8.36% more time, about 10.6–10.9 microseconds.

### Scope and measurement

Old: `aa7c8619a12b764dadb7906391da5109688cf93f`, with the builder forced
to call its existing whole-folder buffered encoder. All 35 baseline source
files were checked against that commit. The only change removes the
builder's early streaming-route branch; the buffered encoder is unchanged.

Current: signed commit `5f5bf234ef907bfa9b04ebea13a13a31b4737fd9`, including
the 64 KiB input default and 64 KiB LZMA/PPMd output buffer. All 35 current
Rust source files in the benchmark snapshot were checked against main.
Both routes use lzma-rust2
`f9887afa12a4c7e5edba7e909f8ccc6dddabfde8` and shared dependencies in one
executable.

Tali: Ryzen 5 8600G, rustc 1.99.0, Linux x86-64, release with debug
information, default CPU target, Clang/LLD. Logical CPU 2, one encoder
thread, Normal compression, 1 MiB dictionary for compressed codecs,
plain headers, no encryption. The four corpora and their hashes match the
original comparison below.

Criterion 0.8 measured `ArchiveBuilder::build()` with setup and input
cloning outside the timed closure: 30 samples, 1-second warmup, at least
3 seconds per route and case. Pass 1 measured old first; pass 2 measured
current first. Route order was reversed at runtime without rebuilding.
CPU activity before the passes was 0.50–1.92%, with no I/O wait. The
reencodarr worker remained stopped.

All 29 workloads were extracted and checked byte-for-byte against their
inputs before timing in each pass. All 116 saved archives passed `7z t`.
Archive sizes matched except for the two source BCJ workloads, where the
current output was one byte larger in both passes.

The recorded commands were:

```sh
taskset -c 2 /home/mjc/projects/r7z/target/release/deps/encoding_paths-074b3d11333bd1c8 --bench --noplot
BENCH_REVERSE=1 taskset -c 2 /home/mjc/projects/r7z/target/release/deps/encoding_paths-074b3d11333bd1c8 --bench --noplot
```

### Results

Median milliseconds. Δ is `(current / old − 1) × 100`; negative means
current takes less time. Each comparison uses medians from the same pass.

| Workload | Old 1 | Current 1 | Δ 1 | Old 2 | Current 2 | Δ 2 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| empty-0 | 0.0554 | 0.0549 | -0.82% | 0.0562 | 0.0549 | -2.22% |
| empty-128 | 0.0612 | 0.0618 | +0.97% | 0.0598 | 0.0621 | +3.82% |
| executable-Bcj-1-solid | 188.0018 | 189.7012 | +0.90% | 187.9940 | 189.0080 | +0.54% |
| executable-Copy-1-solid | 0.1526 | 0.1231 | -19.29% | 0.1521 | 0.1332 | -12.45% |
| executable-Lzma-1-solid | 191.6519 | 189.3079 | -1.22% | 190.7241 | 186.9582 | -1.97% |
| executable-Lzma2-1-solid | 188.2647 | 187.6130 | -0.35% | 186.4998 | 188.2970 | +0.96% |
| executable-Ppmd-1-solid | 86.1355 | 84.3667 | -2.05% | 88.1378 | 84.2698 | -4.39% |
| random-Bcj-1-solid | 79.5848 | 80.4534 | +1.09% | 79.9656 | 80.2265 | +0.33% |
| random-Copy-1-solid | 0.1541 | 0.1137 | -26.18% | 0.1536 | 0.1130 | -26.42% |
| random-Lzma-1-solid | 76.9186 | 77.2156 | +0.39% | 77.5227 | 77.2142 | -0.40% |
| random-Lzma2-1-solid | 78.9662 | 79.0689 | +0.13% | 79.3327 | 79.6953 | +0.46% |
| random-Ppmd-1-solid | 156.1513 | 151.7144 | -2.84% | 157.9987 | 151.5442 | -4.09% |
| source-Bcj-1-solid | 110.4816 | 110.6050 | +0.11% | 109.4665 | 109.8191 | +0.32% |
| source-Bcj-64-solid | 109.4563 | 109.9358 | +0.44% | 109.4754 | 109.6665 | +0.17% |
| source-Copy-1-solid | 0.7039 | 0.0948 | -86.53% | 0.6903 | 0.0925 | -86.59% |
| source-Copy-64-solid | 0.1306 | 0.1412 | +8.15% | 0.1301 | 0.1410 | +8.36% |
| source-Copy-8-nonsolid | 0.1303 | 0.1092 | -16.21% | 0.1321 | 0.1039 | -21.33% |
| source-Lzma-1-solid | 111.4748 | 110.7198 | -0.68% | 110.2775 | 109.0132 | -1.15% |
| source-Lzma-64-solid | 109.7787 | 109.1362 | -0.59% | 110.0744 | 108.8168 | -1.14% |
| source-Lzma2-1-solid | 110.4583 | 110.3060 | -0.14% | 109.6190 | 109.6103 | -0.01% |
| source-Lzma2-64-solid | 109.0335 | 109.7242 | +0.63% | 108.8105 | 109.1097 | +0.28% |
| source-Lzma2-8-nonsolid | 94.4451 | 94.4541 | +0.01% | 94.4824 | 94.9971 | +0.54% |
| source-Ppmd-1-solid | 22.4879 | 22.4677 | -0.09% | 22.9145 | 22.3464 | -2.48% |
| source-Ppmd-64-solid | 22.3594 | 22.4708 | +0.50% | 22.9363 | 22.3472 | -2.57% |
| zero-Bcj-1-solid | 24.1754 | 24.1512 | -0.10% | 24.1614 | 24.1278 | -0.14% |
| zero-Copy-1-solid | 0.1429 | 0.1048 | -26.66% | 0.1427 | 0.1050 | -26.42% |
| zero-Lzma-1-solid | 23.7283 | 23.7168 | -0.05% | 23.7178 | 23.7247 | +0.03% |
| zero-Lzma2-1-solid | 23.7255 | 23.7086 | -0.07% | 23.6770 | 23.6869 | +0.04% |
| zero-Ppmd-1-solid | 4.1470 | 4.0582 | -2.14% | 4.1427 | 4.2407 | +2.37% |


Random PPMd's improvement and the 64-file Copy regression held in both
orders, with non-overlapping 95% bootstrap intervals for the route medians.
Random LZMA's intervals overlapped in both passes. These runs do not show
a consistent random LZMA penalty.

| Workload | Pass | Old median, 95% CI (ms) | Current median, 95% CI (ms) |
| --- | ---: | --- | --- |
| random-Lzma-1-solid | 1 | 76.9186 [76.7369, 77.1376] | 77.2156 [77.0990, 77.4934] |
| random-Lzma-1-solid | 2 | 77.5227 [77.4097, 77.7434] | 77.2142 [77.0724, 77.4426] |
| random-Ppmd-1-solid | 1 | 156.1513 [156.0376, 156.2781] | 151.7144 [151.6547, 151.7980] |
| random-Ppmd-1-solid | 2 | 157.9987 [157.9008, 158.1434] | 151.5442 [151.4616, 151.6742] |
| source-Copy-64-solid | 1 | 0.1306 [0.1305, 0.1307] | 0.1412 [0.1411, 0.1413] |
| source-Copy-64-solid | 2 | 0.1301 [0.1299, 0.1303] | 0.1410 [0.1407, 0.1410] |

LZMA2 and BCJ medians stayed within 1.10% of the old route. Source PPMd
with 64 files and zero PPMd changed direction between passes; neither
supports a general improvement claim. The 128-empty-file case took
0.97–3.82% more time, about 0.6–2.3 microseconds.

The previous comparison, using current `85e3d74` with 8 KiB input reads in
a different executable, found random PPMd 2.01–2.23% slower. The separate
same-executable input-size ablation below changed random PPMd by less
than 0.1%. This new old/current comparison establishes the current result;
it does not establish that input chunk size caused the reversal between
benchmark executables. Old PPMd time also moved between timing orders.

Harness, dependency lockfile, source hashes, idle samples, timings, and
archives are retained under
`target/benchmarks/encoding-paths/results/old-vs-64k-pass{1,2}/`, locally
and on Tali. The artifact root also contains `old-vs-64k-medians.json`,
the generated table, and `old-vs-64k-verification.json`. The earlier
8 KiB comparison remains in `results/old-vs-current-pass{1,2}/`.

## Input chunk size and codec sinks — 2026-10-09

Changing input reads from 8 KiB to 64 KiB reduced cached-file Copy time by
39.59–43.12% in two timing orders. Random LZMA took 0.50–0.93% less time.
Random PPMd changed by less than 0.1%. In-memory Copy took 4.98–8.99% more
time. The default input buffer is now 64 KiB; callers can still set
`StreamingOptions::buffer_size`. This adds 56 KiB to the per-entry input
allocation. The 64 KiB LZMA/PPMd output buffer is unchanged.

### Input comparison

Both sizes used the same writer source from `85e3d74`, dependencies,
corpora, host, CPU affinity, compression settings, and Criterion protocol
as the old/current comparison above. Each pass compared both sizes in one executable;
pass 1 measured 8 KiB first, pass 2 measured 64 KiB first. Input chunk size
was the only archive option changed. Compressed archive sizes matched for
all cases. All 48 saved archives were extracted and compared with their
inputs before timing; all 48 also passed `7z t`.

Median milliseconds. Δ is `(64 KiB / 8 KiB − 1) × 100`.

| Workload | 8 KiB 1 | 64 KiB 1 | Δ 1 | 8 KiB 2 | 64 KiB 2 | Δ 2 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| executable-Lzma-1-solid | 186.1968 | 186.3376 | +0.08% | 185.6463 | 185.6971 | +0.03% |
| executable-Ppmd-1-solid | 83.2663 | 83.2359 | -0.04% | 83.1277 | 83.1717 | +0.05% |
| random-Lzma-1-solid | 76.1078 | 75.7303 | -0.50% | 76.4894 | 75.7768 | -0.93% |
| random-Ppmd-1-solid | 146.7139 | 146.6361 | -0.05% | 146.3872 | 146.2665 | -0.08% |
| source-Copy-1-solid | 0.0951 | 0.1037 | +8.99% | 0.0974 | 0.1023 | +4.98% |
| source-Lzma-1-solid | 109.9433 | 109.9110 | -0.03% | 110.6831 | 110.3624 | -0.29% |
| source-Lzma-64-solid | 110.3242 | 109.8636 | -0.42% | 109.8611 | 110.1795 | +0.29% |
| source-Lzma2-1-solid | 110.2018 | 109.8629 | -0.31% | 110.2172 | 110.1230 | -0.09% |
| source-Ppmd-1-solid | 22.1055 | 22.1752 | +0.32% | 22.1220 | 22.1429 | +0.09% |
| source-Ppmd-64-solid | 22.1390 | 22.1242 | -0.07% | 22.0978 | 22.1243 | +0.12% |
| zero-Lzma-1-solid | 23.8392 | 23.8323 | -0.03% | 23.8477 | 23.8537 | +0.03% |
| zero-Ppmd-1-solid | 4.0475 | 4.0470 | -0.01% | 4.0456 | 4.0569 | +0.28% |

The file comparison measured `ArchiveWriter::append()` and `finish()` for
the same source corpus using Copy and a `File` reader. File opening and
writer construction were outside timing. Warmup kept the input in the
page cache; this measures the read path, not physical disk throughput.
Both sizes round-tripped through R7Z. The two passes used the same
executable, with the route order reversed at runtime.

| Pass | 8 KiB (ms) | 64 KiB (ms) | Δ |
| --- | ---: | ---: | ---: |
| 1 | 0.0864 | 0.0522 | -39.59% |
| 2 | 0.0911 | 0.0518 | -43.12% |

CPU activity before the completed runs was below 2%, with at most 0.08% I/O
wait. The reencodarr worker stayed stopped. These chunk-size comparisons
are independent of the earlier old-route timings; absolute times across
different benchmark executables are not interchangeable.

### Isolating output sinks

A direct-library benchmark removed archive metadata, checksums,
encryption dispatch, and input copying. It compared `Vec<u8>` with
`BufWriter<Cursor<Vec<u8>>>` using a 64 KiB output buffer, each with one
whole-input write and 64 KiB input writes. LZMA and PPMd settings and
corpora matched the archive comparison. All four combinations produced
identical compressed bytes before timing. Both timing orders used the
same executable.

Median milliseconds.

| Workload | Pass | Vec, whole | Vec, 64 KiB | Buffered cursor, whole | Buffered cursor, 64 KiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| source-Lzma | 1 | 108.6597 | 108.7750 | 108.2860 | 108.4282 |
| source-Lzma | 2 | 108.7260 | 108.8083 | 108.6432 | 108.4273 |
| source-Ppmd | 1 | 22.0760 | 22.0460 | 22.1218 | 22.1227 |
| source-Ppmd | 2 | 22.0172 | 22.0292 | 22.0623 | 22.0908 |
| random-Lzma | 1 | 80.5152 | 80.9730 | 75.3672 | 75.1543 |
| random-Lzma | 2 | 80.7639 | 81.2825 | 75.0555 | 74.7357 |
| random-Ppmd | 1 | 154.9592 | 154.9718 | 155.4495 | 155.1547 |
| random-Ppmd | 2 | 155.1781 | 155.1269 | 155.3300 | 155.3892 |

This did not reproduce the earlier 8 KiB archive executable's
2.01–2.23% random PPMd gap: the buffered cursor penalty was 0.10–0.32% with whole-input writes.
Buffering also made isolated random LZMA faster, so a generic claim that
`BufWriter` explains every remaining slowdown is unsupported. Different
writer types produce different codec monomorphizations; the isolated
sink uses a cursor, while R7Z uses its payload writer inside the buffer.

In the earlier archive benchmark executable, PPMd's `shift_low` compiled
to 227 bytes for a Vec sink and 256 bytes for the buffered payload sink.
The buffered fast path has an extra spare-capacity calculation and stack
store; it still appends directly to the buffer without an out-of-line
write call on every byte. This identifies a code difference, not its
share of the measured slowdown.

Focused CPU profiles encoded 64 random-data archives per route with the
same pinned writer sources, CPU affinity, and release settings. PPMd's
`encode_symbol`, `update_model`, and `create_successors` accounted for
95.01% of old-route samples and 91.46% of current-route samples. The
range coder's `shift_low` accounted for 1.62% and 1.74%, respectively.
The current builder itself accounted for 0.24%. These are sample shares
from a separate profiling executable, not before/after timing results.

An apparent memory-clearing increase in the first current-route profile
did not reproduce in a second capture with call stacks. It is not an
established cause. The direct sink and input comparisons narrow the
investigation, but do not fully attribute the earlier executable's PPMd
regression or the reversal in the current comparison above. Codec code
generation for R7Z's payload sink remains to be isolated.
Raw profiles and assembly are retained in the artifact root's
`results/diagnosis/` directory.

Harnesses, samples, logs, and archives are retained in
`target/benchmarks/encoding-paths/results/input-chunks-pass{1,2}/`,
`file-input-pass{1,2}/`, and `codec-sinks-pass{1,2}/`, locally and on Tali.
The input regression test checks actual read requests across two full
chunks and a short final chunk, then checks extracted contents.

## Buffered and streaming archive encoding — 2026-10-09

Streaming was faster for every Copy workload in both timing orders. It was
slower for random-data LZMA by 5.03–5.26%, source PPMd by 0.82–2.41%, and
128 empty files by 3.68–3.96%. The measurements do not establish that the
buffered route is always slower or equally fast.

### Scope

Baseline: `aa7c8619a12b764dadb7906391da5109688cf93f`, with the builder forced
to call its existing buffered encoder. Candidate Rust sources:
`8c22a2b9de6370be95adfa4abe6948a3489f69eb`. The baseline package was renamed
so both routes could run in the same executable with shared dependencies.
No baseline encoder code was changed. Both used lzma-rust2
`f9887afa12a4c7e5edba7e909f8ccc6dddabfde8`.

Public data-archive writes already used streaming at the baseline commit.
Deleting the dormant buffered encoder does not switch that public path.
Archives with no data streams now use the shared streaming finalizer; the
empty cases below measure that public behavior change.

### Measurement

Tali: AMD Ryzen 5 8600G, Linux x86-64, rustc 1.99.0. Release builds with debug
information, default CPU target, Clang/LLD for both passes. The project was
switched to Mold 3.0 separately after building the benchmark.

One encoder thread, Normal compression, 1 MiB dictionary for compressed
codecs, plain headers, no encryption. BCJ means x86 BCJ followed by LZMA2.
The source corpus was also split into 64 solid files and 8 non-solid files.

Criterion 0.8: 30 samples, 1-second warmup, at least 3 seconds of measurement
per case and route. Builder setup and input cloning were outside the timed
closure; `ArchiveBuilder::build()` was timed. The second pass reversed the
route order. Both passes ran on logical CPU 2. The reencodarr worker was
stopped; actual CPU activity before the second pass was 0.50–2.58% across
12 logical CPUs, with no I/O wait. It was left stopped.

Every workload was extracted and compared byte-for-byte before timing in
both passes. All 58 saved output archives also passed `7z t`. Output sizes
matched except that streaming BCJ on source data was one byte larger.

Measured command, run inside the benchmark workspace's devenv shell:

```sh
taskset -c 2 /home/mjc/projects/r7z/target/release/deps/encoding_paths-2185aaf514f1ecab --bench --noplot
```

Harness, forced-route patch, corpus, outputs, logs, and raw Criterion samples
are retained locally under `target/benchmarks/encoding-paths/` and on Tali
under `/tmp/r7z-encoding-paths/`.

### Results

Median times in milliseconds. Δ is `(streaming / buffered − 1) × 100`;
negative means streaming took less time. Pass 1 measured buffered first;
pass 2 measured streaming first. Each comparison uses that pass's medians.

| Workload | Buffered 1 | Streaming 1 | Δ 1 | Buffered 2 | Streaming 2 | Δ 2 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| empty-0 | 0.0560 | 0.0528 | -5.73% | 0.0550 | 0.0549 | -0.16% |
| empty-128 | 0.0576 | 0.0599 | +3.96% | 0.0599 | 0.0621 | +3.68% |
| executable-Bcj-1-solid | 188.2497 | 188.5475 | +0.16% | 188.9812 | 189.1020 | +0.06% |
| executable-Copy-1-solid | 0.1504 | 0.1274 | -15.28% | 0.1516 | 0.1185 | -21.87% |
| executable-Lzma-1-solid | 187.8606 | 191.0560 | +1.70% | 191.2460 | 191.8455 | +0.31% |
| executable-Lzma2-1-solid | 186.3956 | 187.1630 | +0.41% | 186.7524 | 187.4800 | +0.39% |
| executable-Ppmd-1-solid | 86.1236 | 87.4231 | +1.51% | 86.9920 | 87.1991 | +0.24% |
| random-Bcj-1-solid | 79.7553 | 80.3877 | +0.79% | 80.2817 | 80.1184 | -0.20% |
| random-Copy-1-solid | 0.1429 | 0.1074 | -24.81% | 0.1543 | 0.1083 | -29.84% |
| random-Lzma-1-solid | 77.0766 | 80.9540 | +5.03% | 77.6240 | 81.7103 | +5.26% |
| random-Lzma2-1-solid | 79.5686 | 79.5445 | -0.03% | 79.0417 | 80.0184 | +1.24% |
| random-Ppmd-1-solid | 156.5385 | 158.5450 | +1.28% | 157.9658 | 158.2222 | +0.16% |
| source-Bcj-1-solid | 109.7809 | 109.5039 | -0.25% | 109.6728 | 109.8596 | +0.17% |
| source-Bcj-64-solid | 109.5748 | 109.9405 | +0.33% | 109.7190 | 110.0235 | +0.28% |
| source-Copy-1-solid | 0.7036 | 0.0980 | -86.07% | 0.7339 | 0.0844 | -88.50% |
| source-Copy-64-solid | 0.1311 | 0.1158 | -11.68% | 0.1259 | 0.1077 | -14.42% |
| source-Copy-8-nonsolid | 0.1257 | 0.0976 | -22.31% | 0.1319 | 0.1016 | -22.96% |
| source-Lzma-1-solid | 110.2256 | 110.2194 | -0.01% | 109.6648 | 110.5542 | +0.81% |
| source-Lzma-64-solid | 110.1885 | 110.1706 | -0.02% | 110.1712 | 110.8070 | +0.58% |
| source-Lzma2-1-solid | 109.2193 | 111.0152 | +1.64% | 109.2534 | 109.1710 | -0.08% |
| source-Lzma2-64-solid | 108.9866 | 109.2789 | +0.27% | 109.3501 | 109.5189 | +0.15% |
| source-Lzma2-8-nonsolid | 94.6692 | 95.1900 | +0.55% | 94.8284 | 95.0266 | +0.21% |
| source-Ppmd-1-solid | 22.3990 | 22.9205 | +2.33% | 22.5691 | 22.7545 | +0.82% |
| source-Ppmd-64-solid | 22.3851 | 22.9250 | +2.41% | 22.5339 | 22.9153 | +1.69% |
| zero-Bcj-1-solid | 24.2666 | 24.2225 | -0.18% | 24.2589 | 24.2272 | -0.13% |
| zero-Copy-1-solid | 0.1377 | 0.1069 | -22.38% | 0.1384 | 0.0994 | -28.14% |
| zero-Lzma-1-solid | 23.8613 | 23.9913 | +0.54% | 23.8042 | 23.7854 | -0.08% |
| zero-Lzma2-1-solid | 23.7997 | 23.7900 | -0.04% | 23.7779 | 23.7836 | +0.02% |
| zero-Ppmd-1-solid | 4.1747 | 4.1664 | -0.20% | 4.1747 | 4.1291 | -1.09% |

Copy took 11.68–88.50% less time across these cases. The large one-file source
result is specific to that workload. Compression differences vary by input
and timing order; small differences should not be treated as universal
speedups or equivalence. Random-data LZMA, source PPMd, and the 128-empty-file
case had separated 95% median confidence intervals in both passes, with
streaming slower. The empty-file difference was about 2.2–2.3 microseconds
per archive. Confidence intervals describe sample variation within each
pass; they do not cover systematic timing-order effects or unmeasured inputs.

### Corpus

Source contains the tracked Rust sources from the baseline commit. Executable
is Tali's Bash binary. Random is deterministic xorshift64 data seeded with
`0x123456789abcdef0`; zero contains only zero bytes.

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| source | 800,635 | `9b706b5e53c8bab4851cf434e3737e75f366671a016405fc06ebe502650a5459` |
| executable | 1,213,640 | `58256e0bb8fe5c7661eea40900c1e8fc960316ff7bd401b05ef7fcdf28398c1f` |
| random | 1,048,576 | `4ef0e7f5a107fd0fdbf805d6f0d305b75bb8a77584878f3f324dc9ce69c3f88b` |
| zero | 1,048,576 | `30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58` |

## Output buffering diagnosis — 2026-10-09

LZMA and PPMd range encoders emit individual bytes. The streaming encoder
sends each byte through `PayloadWriter`'s encryption selection,
`CountingWriter`'s checked counter, and the archive cursor. The former
buffered encoder wrote those bytes directly to a `Vec<u8>`.

Two benchmark-only probes added a 64 KiB `std::io::BufWriter`. Putting it
inside the plain-payload variant left the encryption selection per byte
and barely affected the gap. Putting it directly after LZMA/PPMd, before
`PayloadWriter`, reduced LZMA time by 3.99–4.55% and source PPMd time by
1.80–2.49% in two opposite timing orders. Both probes preserved extracted
contents. These experiments did not change the production encoder.

An untimed run with a counted output cursor confirmed the write reduction:

| Workload | Streaming writes | Buffered output writes |
| --- | ---: | ---: |
| Random LZMA, one file | 1,062,886 | 20 |
| Source PPMd, one file | 128,919 | 5 |

These counts include headers; both routes produced identical archive sizes
and extracted contents. The input corpus and encoder settings were unchanged.

Median times in milliseconds. Δ compares the output-buffer probe with the
current streaming route in the same pass. Pass 1 measured the probe first;
pass 2 measured it last. The earlier machine, linker, and Criterion settings
were retained, and the worker was stopped again after being found active.

| Workload | Pass | Former buffered route | Current streaming | Output buffer | Δ |
| --- | ---: | ---: | ---: | ---: | ---: |
| empty-128 | 1 | 0.0595 | 0.0620 | 0.0626 | +1.11% |
| random-Lzma-1-solid | 1 | 76.5207 | 79.9660 | 76.7777 | -3.99% |
| source-Ppmd-1-solid | 1 | 22.2898 | 22.8853 | 22.4744 | -1.80% |
| source-Ppmd-64-solid | 1 | 22.4316 | 22.8192 | 22.2579 | -2.46% |
| empty-128 | 2 | 0.0592 | 0.0616 | 0.0615 | -0.14% |
| random-Lzma-1-solid | 2 | 76.9341 | 81.7607 | 78.0391 | -4.55% |
| source-Ppmd-1-solid | 2 | 22.3723 | 22.8244 | 22.2552 | -2.49% |
| source-Ppmd-64-solid | 2 | 22.3755 | 22.7995 | 22.3439 | -2.00% |

The result supports buffering compressed output before encryption dispatch
and byte accounting. It recovers a substantial part of the measured gap
without collecting a whole folder. The remaining LZMA difference against
the former route is not fully isolated. Empty archives have no payload
encoder; their overhead remains in per-entry metadata/writer processing.
The buffer probe does not address that path.

Probe sources, patches, write counts, logs, and Criterion samples are retained
with the earlier artifacts. `results/inner-buffer/` records the first placement;
`results/outer-buffer-pass1/` and `results/outer-buffer-pass2/` record the
placement before encryption dispatch.

## Production output buffer — 2026-10-09

R7Z now buffers LZMA and PPMd compressed output in a 64 KiB `BufWriter`
before payload encryption selection and byte accounting. The buffer drains
before AES finalization and folder metadata creation, and encoder memory
admission includes its capacity. Payload I/O errors make the sink terminal
so buffer cleanup cannot retry into a failed AES writer.

The pinned lzma-rust2 LZMA2 writer already buffers compressed chunks up to
64 KiB internally. Its LZMA writer writes range-coded bytes directly to its
sink. Copy, LZMA2, and BCJ-LZMA2 receive no additional output buffer.

Before uses Rust sources at `8c22a2b9de6370be95adfa4abe6948a3489f69eb`,
which are identical to `93fc0a0` under `src/`. After includes the production
buffer, memory admission, and terminal payload-error state in this commit.
The corpus, library revision, toolchain, linker, compression settings, CPU
pinning, and Criterion configuration match the earlier comparison.

Pass 1 measured before first; pass 2 measured after first. Actual CPU
activity before the passes was 0.42–1.66%, with no I/O wait. The worker
remained stopped. Each route was extracted and checked against every input
before timing in both passes. All 24 saved archives passed `7z t`; before
and after sizes matched for every workload.

```sh
taskset -c 2 /home/mjc/projects/r7z/target/release/deps/encoding_paths-f28f8d9dd975fe21 --bench --noplot
```

Median milliseconds; Δ is `(after / before − 1) × 100`.

| Workload | Before 1 | After 1 | Δ 1 | Before 2 | After 2 | Δ 2 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| executable-Lzma-1-solid | 189.0926 | 185.6678 | -1.81% | 189.6528 | 186.9597 | -1.42% |
| executable-Ppmd-1-solid | 86.1874 | 85.6168 | -0.66% | 86.2891 | 85.6768 | -0.71% |
| random-Lzma-1-solid | 80.8779 | 76.8785 | -4.94% | 80.6358 | 76.4214 | -5.23% |
| random-Ppmd-1-solid | 152.2010 | 155.6750 | +2.28% | 153.0478 | 156.0624 | +1.97% |
| source-Copy-1-solid | 0.0998 | 0.1009 | +1.16% | 0.1010 | 0.1002 | -0.79% |
| source-Lzma-1-solid | 110.5411 | 109.2029 | -1.21% | 111.2577 | 109.8049 | -1.31% |
| source-Lzma-64-solid | 110.7427 | 109.6118 | -1.02% | 110.8832 | 109.4679 | -1.28% |
| source-Lzma2-1-solid | 109.4853 | 109.2460 | -0.22% | 109.5267 | 109.7020 | +0.16% |
| source-Ppmd-1-solid | 22.7586 | 22.1139 | -2.83% | 22.9096 | 22.2007 | -3.09% |
| source-Ppmd-64-solid | 22.7916 | 22.1878 | -2.65% | 22.9378 | 22.1797 | -3.30% |
| zero-Lzma-1-solid | 23.7790 | 23.7888 | +0.04% | 23.7992 | 23.7689 | -0.13% |
| zero-Ppmd-1-solid | 4.1262 | 4.0670 | -1.44% | 4.1298 | 4.0849 | -1.09% |

Random LZMA took 4.94–5.23% less time, source LZMA 1.02–1.31% less,
and source PPMd 2.65–3.30% less. Random PPMd took 1.97–2.28% more time
in both orders. The optimization has that tradeoff; it is not a general
speedup for every input. Copy changed direction between passes, and the
LZMA2 control changed by less than 0.3%. Zero LZMA changed by less than 0.2%.

An 8 KiB probe did not consistently remove the random PPMd regression.
Its four-case run measured a faster buffered result, but the unbuffered
baseline also moved to about 158 ms. Restoring the full workload list
returned the unbuffered baseline to about 152 ms and the buffered route
still took about 156 ms. These probes ran after first and were not used
to claim an improvement over the paired 64 KiB measurements. The cause
of the random PPMd difference remains unisolated.

The new tests cover batched sink writes, plain and encrypted folder
boundaries with a final partial buffer, original sink-error propagation
at append and finalization, and the exact encoder-memory admission
boundary. The PPMd interoperability test uses incompressible input to
check that full buffers drain during append and that 7z extracts the result.

Raw samples and logs are retained in `results/production-pass1/` and
`results/production-pass2/` under the existing benchmark artifact directory.
The smaller-buffer probes are in `results/output-buffer-8k-focused/` and
`results/output-buffer-8k-full/`. The latter also retains its source and
harness snapshots. Production uses the 64 KiB implementation.
