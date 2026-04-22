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

Keep third-party corpus archives out of this directory unless their provenance
and license are recorded. Use `target/corpus/7z/external` for downloaded
external corpora.

`generated/` is reproducible from the pinned p7zip oracle:

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
