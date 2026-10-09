# Benchmarks

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
contents. The production encoder has not been changed by these experiments.

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
