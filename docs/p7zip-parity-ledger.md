# p7zip-project `.7z` Parity Ledger

Primary oracle: `p7zip-project/p7zip` at `6819e2dc1917e1267babddc6391cea56ead7123d`.

Use `scripts/ensure_p7zip_oracle.sh` to clone/update `/tmp/r7z-p7zip-compare`,
check out the pinned commit, build `CPP/7zip/Bundles/Alone2`, and record
`7zz i` to `/tmp/r7z-p7zip-compare/7zz-i.txt`.

## Implemented

- Parser: core 7z headers, encoded headers, stream info, files info,
  SFX/prepended-byte signature scan.
- Decoder: Copy, LZMA, LZMA2, PPMd, x86/BCJ2/ARM/ARMT/IA64/PPC/SPARC BCJ filters, 7zAES in folder chains.
- Encoder: Copy, LZMA, LZMA2, PPMd, BCJ+LZMA2, 7zAES content/header encryption.
- CLI: `r7z l`, `x`, `e`, `t`, `a`, `d`, `u` with attached switches
  `-oDIR`, `-pPASS`, `-m0=...`, `-mx`, `-ms`, `-mf`, `-mhe`, `-v`,
  `-aoa`, `-aos`, `-y`, and no-op compatibility for `-bd` and `-bb`.
- CLI solid mode: `-ms=on`, `-ms=off`, file-count limits such as `-ms=1f`, and byte limits such as `-ms=8k`.
- CLI method grammar:
  `-m0=METHOD:d=SIZE:fb=N:lc=N:lp=N:pb=N:a=0|1:mc=N:c=SIZE:mt=N`,
  `-m0=METHOD:mf=bt4|hc4`, `-md=SIZE`, `-mfb=N`, `-mlc=N`, `-mlp=N`,
  `-mpb=N`, `-ma=0|1`, `-mmc=N`, `-mc=SIZE`, and `-mmf=bt4|hc4` for
  supported codecs. `-mmt=off|1` selects one LZMA2 encoder thread;
  `-mmt=on|N` and method-scoped `mt` select automatic or fixed threads.
- CLI normal LZMA2 level (`-mx=5`): 16 MiB dictionary, 32 fast bytes, and BT4,
  matching the pinned p7zip oracle's level-five settings.
- CLI selection: `*` and `?` wildcard matching for list/test/extract/delete
  archive operands and create/update disk path operands.
- CLI listing: `l` and `l -slt` report p7zip-like stable body fields and
  tables for archive metadata, paths, sizes, packed sizes, entry kinds, CRCs,
  encryption markers, methods, solid state, and block numbers. p7zip banner,
  version/copyright, and drive-scanning preamble text are intentionally not
  cloned.
- CLI overwrite policy: default extraction asks on interactive terminals and
  refuses/skips colliding outputs in non-interactive mode with warning status
  `1`; `-y` and `-aoa` overwrite without prompting; `-aos` skips existing
  outputs without warning status.
- CLI warnings: test/extract return warning status when explicit operands match
  no archive entries; create/update return warning status for missing literal
  disk inputs while unmatched disk wildcards are ignored.
- CLI update/delete preservation: `a`/`u`/`d` rewrite atomically and preserve
  unchanged retained folders as raw packed streams when possible. Unsupported
  visible-header folders such as ZSTD can be retained unchanged, dropped as a
  whole folder, or replaced as a whole folder without decoding. Partial rewrites
  of supported folders decode retained entries and re-encode them.
- Metadata: names, empty files, directories, anti-items, timestamps, attributes,
  symlink payloads.
- Volumes: write support from `r7z a -vSIZE`; read support opens first volumes
  such as `.7z.001` and reads sequential sibling volumes as one archive.
- Robustness: checked-in and generated 7z corpus manifest exercises supported,
  encrypted, split-volume, and known-unsupported archives; an optional Apache
  Commons Compress corpus fetcher records external open successes/failures.

## Gaps By Category

- Parser: no known p7zip parity gaps in the currently tracked subset.
- Decoder: no known classic p7zip decoder gaps in the currently tracked subset.
- Decoder extensions: ZSTD, Brotli, LZ4, LZ5, Lizard, LZHAM. `FLZMA2` is tracked
  as p7zip's fast LZMA2 encoder but has the same method ID as LZMA2 on disk.
- Encoder: extension codecs above, plus exact p7zip method-chain
  switch grammar beyond the currently supported dictionary/fast-bytes subset.
- CLI: full p7zip banner/version/copyright/scanning preamble impersonation is
  intentionally out of scope. PTY-level integration coverage for interactive
  overwrite prompts is still narrower than p7zip's own console matrix, though
  prompt parsing and policy are covered.
- Metadata: p7zip-like unsafe link materialization is intentionally not default;
  add explicit API/CLI knobs before enabling it.
- Update: exact original folder graph preservation is not guaranteed for folders
  that must be partially rewritten; supported partial folders are decoded and
  re-encoded. Partial rewrites of unsupported solid folders fail before rewriting
  the source archive. Updating split-volume inputs writes a normal unsplit
  replacement archive.
- Security: AES decryption still buffers encrypted streams; replace with a
  streaming CBC path before treating large encrypted archives as parity-complete.
- Robustness: fuzzing still needs extension from parsing into extraction and CLI
  argument parsing.

## Creation performance, 2026-09-27

Release CLI, `-mx=5`, five interleaved creation runs per case against the pinned
p7zip executable. Automatic mode is the default for both tools. Timings include
file reads, compression, archive writing, and CLI startup. Host-load spikes were
retried; all raw attempts and per-process CPU/RSS measurements are retained under
`target/benchmarks/2026-09-27-bounded-mt/`.

| Input | r7z auto wall median (range) | p7zip auto wall median (range) | r7z / p7zip | Archive bytes, r7z / p7zip |
| --- | ---: | ---: | ---: | ---: |
| 1 GiB zeros | 1.986 s (1.679–2.214) | 1.806 s (1.351–1.942) | 1.10x | 157,553 / 157,651 |
| 16 MiB repeated text | 0.244 s (0.239–0.295) | 0.103 s (0.077–0.110) | 2.37x | 2,781 / 2,772 |
| 16 MiB random | 4.369 s (3.980–7.144) | 0.936 s (0.909–1.347) | 4.67x | 16,778,145 / 16,778,396 |
| 30.7 MB r7z release binary | 5.359 s (5.261–12.063) | 2.607 s (2.539–3.205) | 2.06x | 5,121,733 / 5,147,177 |

For 1 GiB zeros, median CPU times were 19.586 s / 19.648 s and median peak
RSS was 3,428 MiB / 2,601 MiB for r7z / p7zip. Matched one-thread medians were
15.335 s / 19.342 s on zeros, 0.244 s / 0.344 s on text, 4.283 s / 3.776 s
on random input, and 5.355 s / 4.762 s on the binary. The wide ranges on
zeros and the binary reflect host CPU-speed variation; the raw log includes
rejected load spikes as well. A separate three-round run under 96% host idle
rechecked the random and binary inputs after two slower samples passed the
initial load filter: random 3.656 / 0.851 s and binary 5.120 / 2.427 s
(r7z / p7zip medians). The remaining gap is consistent. Every final archive
was cross-extracted by the other tool and matched the input SHA-256 exactly.

The input SHA-256 values are `49bc20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14`
(zeros), `30b5e90094f86bd54484e90f99d40c14a70f80fb44265bbebc85c6b1c8ca91dc`
(text), `d8c74c4cc1cc22b036a599384051485f6b002eafa39a9d2523c31f4b38272322`
(random), and `0b52385ab7f5475ee4d638741d1606411e7218c640d47a98c890cb9ae4c8b131`
(binary).

With the same 64 MiB LZMA2 blocks, increasing staged file reads from 8 KiB to
1 MiB reduced the 1 GiB r7z median from 2.406 s to 1.777 s in a separate
five-round interleaved comparison; 4 MiB reads measured 1.869 s and were not
kept. Archive bytes were unchanged. Parallel blocks still leave inputs shorter
than one block on the serial writer, so the default parity target remains open.

The branch tests check thread controls, memory admission and automatic fallback,
ordered multi-block output in buffered and incremental writers, BCJ continuity,
encryption, empty and separate folders, output-failure cleanup, and the corrected
dependency memory estimate. The bounded dependency tests cover pending work,
worker errors/panics, shared-reader behavior, and joining workers on drop.
