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
  `-aoa`, `-aos`, `-y`, and no-op compatibility for `-mmt`, `-bd`, and `-bb`.
- CLI solid mode: `-ms=on`, `-ms=off`, file-count limits such as `-ms=1f`, and byte limits such as `-ms=8k`.
- CLI method grammar: `-m0=METHOD:d=SIZE:fb=N:mt=N`, `-md=SIZE`, and
  `-mfb=N` for supported codecs; method-scoped `mt` is accepted as a no-op.
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
