# 7z Corpus

This directory tracks the default no-network 7z corpus used by
`tests/corpus_test.rs`.

`manifest.tsv` is tab-separated:

```text
archive_path	password_or_-	expectation	expected_file_count
```

Expectations:

- `extract`: parse, open, and extract all non-directory/non-anti entries.
- `open`: parse and open only.
- `open_err`: record a known parser/open failure from an external corpus.
- `password_required`: record an encrypted-header archive that requires a
  password before it can be opened.

Keep third-party corpus archives out of this directory unless their provenance
and license are recorded. Use `target/corpus/7z/external` for downloaded
external corpora.

The classic `generated/` fixtures are reproducible from the pinned p7zip oracle:

```sh
scripts/generate_p7zip_corpus.sh
```

Optional third-party corpus archives are fetched into `target/` instead of
being vendored:

```sh
manifest="$(scripts/fetch_commons_compress_7z_corpus.sh)"
R7Z_EXTERNAL_7Z_CORPUS_MANIFEST="$manifest" cargo test --test corpus_test
```

The Apache Commons Compress corpus fetcher uses the project's GitHub test
resources as an external source.

## Official 7-Zip branch-filter fixtures

`arm64*.7z` and `riscv*.7z` were created with official 7-Zip 26.03
(`7z2603-linux-x64.tar.xz`, SHA-256
`dc99eff5008f1ab79bd7084c68513701547a808a89502bf4133683535ab3c695`)
from the [26.03 release](https://github.com/ip7z/7zip/releases/tag/26.03).
The input bytes match `branch_payload()` in `tests/codec_parity_test.rs`.
Run these commands in an empty directory with that `7zz` on `PATH`:

```sh
python3 - <<'PY'
from pathlib import Path
Path('arm64.bin').write_bytes(bytes.fromhex('01000094 00000090 00000014 1f2003d5') * 768)
Path('riscv.bin').write_bytes(bytes.fromhex('ef000000 97020000 e7800200 6f000000 0100') * 560)
PY
7zz a arm64.7z arm64.bin -m0=ARM64 -m1=LZMA2 -mmt=off -mtm=off -mta=off -mtc=off
7zz a arm64_offset4.7z arm64.bin -m0=ARM64:4 -m1=LZMA2 -mmt=off -mtm=off -mta=off -mtc=off
7zz a riscv.7z riscv.bin -m0=RISCV -m1=LZMA2 -mmt=off -mtm=off -mta=off -mtc=off
7zz a riscv_offset2.7z riscv.bin -m0=RISCV:2 -m1=LZMA2 -mmt=off -mtm=off -mta=off -mtc=off
```

The checked-in archives have SHA-256 values:

| Archive | SHA-256 |
| --- | --- |
| `arm64.7z` | `005050bf3c262bc873b0e7e3c9b90833137eb7409c93d5a8b86d792d324234e6` |
| `arm64_offset4.7z` | `cc30388a53c537d61ff4017c9be1eea4068436b69f66390182e6bb1dd112cf9a` |
| `riscv.7z` | `0bf1512b2f6756118987baf1c747cf4ca0137531b0a451db47073cce0ef3e66e` |
| `riscv_offset2.7z` | `9a7101b59363e384daf64ab0012ed0d831325d633d556cdb194b33b646a65118` |
