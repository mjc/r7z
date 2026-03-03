# r7z — Claude Code Guidelines

## TDD Workflow

All new features follow red/green/refactor:
1. Write a failing test that captures the expected behavior
2. Write the minimum code to make it pass
3. Refactor while keeping tests green

## Before Every Commit

Both of these must pass with zero errors/warnings:

```
cargo test
cargo clippy
```

## Parsers

- Internal parsers use nom's `IResult<&[u8], T>` — never return bare tuples or panic
- Use `nom::Err::Failure` for hard errors (wrong property tag); `nom::Err::Error` for backtrackable errors
- Public API converts `IResult` → `Result<T, R7zError>` (see `src/error.rs`)
- Varint encoding: `sevenzip_varuint64_decode` in `src/parsers.rs` — NOT LEB128, NOT protobuf

## Format Spec Reference

Primary: <https://github.com/google/omaha/blob/master/third_party/lzma/files/7zFormat.txt>

Key layout:
```
[SignatureHeader 32 bytes]
[data blocks: packed streams of compressed file data]
[packed header stream: compressed header]
[EncodedHeader: PackInfo + UnpackInfo describing the packed header]
```

## Naming Conventions

- Parser structs match 7z spec names: `PackInfo`, `UnpackInfo`, `CoderInfo`, `Folder`, `FilesInfo`
- Property tags live in `Property` enum (`src/property.rs`)
- Codec IDs: `[0x03,0x01,0x01]` = LZMA, `[0x21]` = LZMA2, `[0x03,0x03,0x01,0x03]` = BCJ

## File Map

| File | Purpose |
|------|---------|
| `src/parsers.rs` | `sevenzip_varuint64_decode` |
| `src/property.rs` | Property tag enum |
| `src/coder_info.rs` | CoderInfo parser |
| `src/bcj.rs` | x86 BCJ (Branch/Call/Jump) filter encode/decode |
| `src/folder.rs` | Folder parser |
| `src/pack_info.rs` | PackInfo + UnpackInfo |
| `src/headers.rs` | SignatureHeader, EncodedHeader |
| `src/error.rs` | Public `R7zError` |
| `tests/fixtures/test_1.7z` | LZMA-compressed single-file 7z fixture |
| `tests/fixtures/bcj_lzma2.7z` | BCJ+LZMA2-compressed 7z fixture (p7zip-created) |
