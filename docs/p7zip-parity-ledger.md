# p7zip-project `.7z` Parity Ledger

Primary oracle: `p7zip-project/p7zip` at `6819e2dc1917e1267babddc6391cea56ead7123d`.

Use `scripts/ensure_p7zip_oracle.sh` to clone/update `/tmp/r7z-p7zip-compare`,
check out the pinned commit, build `CPP/7zip/Bundles/Alone2`, and record
`7zz i` to `/tmp/r7z-p7zip-compare/7zz-i.txt`.

## Implemented

- Parser: core 7z headers, encoded headers, stream info, files info,
  SFX/prepended-byte signature scan.
- Decoder: Copy, LZMA, LZMA2, x86 BCJ filter, 7zAES in folder chains.
- Encoder: Copy, LZMA, LZMA2, BCJ+LZMA2, 7zAES content/header encryption.
- CLI: `r7z l`, `x`, `e`, `t`, `a`, `d`, `u` with attached switches
  `-oDIR`, `-pPASS`, `-m0=...`, `-mx`, `-ms`, `-mf`, `-mhe`, `-v`,
  `-aoa`, `-aos`, and no-op compatibility for `-y`, `-mmt`, `-bd`, and `-bb`.
- CLI solid mode: `-ms=on`, `-ms=off`, file-count limits such as `-ms=1f`, and byte limits such as `-ms=8k`.
- CLI method grammar: `-m0=METHOD:d=SIZE:fb=N:mt=N`, `-md=SIZE`, and
  `-mfb=N` for supported codecs; method-scoped `mt` is accepted as a no-op.
- CLI selection: `*` and `?` wildcard matching for list/test/extract/delete
  archive operands and create/update disk path operands.
- CLI listing: `l` and `l -slt` report p7zip-like stable fields for paths,
  sizes, entry kinds, and method names.
- CLI warnings: test/extract return warning status when explicit operands match
  no archive entries; create/update return warning status for missing literal
  disk inputs while unmatched disk wildcards are ignored.
- Metadata: names, empty files, directories, anti-items, timestamps, attributes,
  symlink payloads.
- Volumes: write support from `r7z a -vSIZE`; read support opens first volumes
  such as `.7z.001` and reads sequential sibling volumes as one archive.

## Gaps By Category

- Parser: no known p7zip parity gaps in the currently tracked subset.
- Decoder: BCJ2 multi-packed-stream graph, BZip2, PPMd, Deflate, Deflate64,
  Delta, ARM, ARMT, IA64, PPC, SPARC, Swap2, Swap4.
- Decoder extensions: ZSTD, Brotli, LZ4, LZ5, Lizard, LZHAM. `FLZMA2` is tracked
  as p7zip's fast LZMA2 encoder but has the same method ID as LZMA2 on disk.
- Encoder: all missing decoder methods above, plus exact p7zip method-chain
  switch grammar beyond the currently supported dictionary/fast-bytes subset.
- CLI: interactive overwrite prompts and byte-for-byte listing text are still
  incomplete.
- Metadata: p7zip-like unsafe link materialization is intentionally not default;
  add explicit API/CLI knobs before enabling it.
- Update: current `a`/`u`/`d` rewrite archives atomically for supported codecs,
  but does not preserve original folder graph or unsupported method streams.
- Security: AES decryption still buffers encrypted streams; replace with a
  streaming CBC path before treating large encrypted archives as parity-complete.
- Robustness: malformed corpus and fuzzing need extension from parsing into
  extraction and CLI argument parsing.
