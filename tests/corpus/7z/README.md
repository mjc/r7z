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

Keep third-party corpus archives out of this directory unless their provenance
and license are recorded. Use `target/corpus/7z/external` for downloaded
external corpora.
