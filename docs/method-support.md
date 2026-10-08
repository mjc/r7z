| Method | ID | Recognized | Decode | Encode |
| --- | --- | --- | --- | --- |
| Copy | `00` | yes | tested | tested |
| LZMA | `03 01 01` | yes | tested | tested |
| LZMA2 | `21` | yes | tested | tested |
| BZip2 | `04 02 02` | yes | tested | unsupported |
| PPMd | `03 04 01` | yes | tested | tested |
| Deflate | `04 01 08` | yes | tested | unsupported |
| Deflate64 | `04 01 09` | yes | tested | unsupported |
| BCJ | `03 03 01 03` | yes | tested | tested |
| BCJ2 | `03 03 01 1B` | yes | partial | unsupported |
| ARM | `03 03 05 01` | yes | tested | unsupported |
| ARM64 | `0A` | yes | tested | unsupported |
| ARMT | `03 03 07 01` | yes | tested | unsupported |
| IA64 | `03 03 04 01` | yes | tested | unsupported |
| PPC | `03 03 02 05` | yes | tested | unsupported |
| SPARC | `03 03 08 05` | yes | tested | unsupported |
| RISCV | `0B` | yes | tested | unsupported |
| Delta | `03` | yes | tested | unsupported |
| Swap2 | `02 03 02` | yes | tested | unsupported |
| Swap4 | `02 03 04` | yes | tested | unsupported |
| ZSTD | `04 F7 11 01` | yes | unsupported | unsupported |
| BROTLI | `04 F7 11 02` | yes | unsupported | unsupported |
| LZ4 | `04 F7 11 04` | yes | unsupported | unsupported |
| LZ5 | `04 F7 11 05` | yes | unsupported | unsupported |
| LIZARD | `04 F7 11 06` | yes | unsupported | unsupported |
| FLZMA2 | `21` | yes | tested | tested |
| LZHAM | `04 F7 10 01` | yes | unsupported | unsupported |
| 7zAES | `06 F1 07 01` | yes | tested | tested |
| AES256CBC | `06 F0 01 81` | yes | unsupported | unsupported |

This table is generated from `METHOD_REGISTRY`; the unit test in `src/method.rs` checks the checked-in copy. Recognition means the method ID has a registry entry. Raw copy is archive-update preservation of packed folder bytes and does not mean the codec can decode or encode; preservation is also possible for unrecognized method IDs.

## Properties and folder arrangements

- `FLZMA2` is a CLI name for the LZMA2 method ID `21`, not a separate on-disk codec; r7z handles it as LZMA2.
- Copy, BZip2, Deflate, Deflate64, BCJ x86, ARM, ARM Thumb, IA64, PPC, SPARC, Swap2, and Swap4 accept no coder properties. Delta requires its one-byte distance property; the stored value `n` means distance `n + 1`.
- LZMA uses its five-byte property block. LZMA2 uses its one-byte dictionary property. PPMd uses five bytes for order and memory; decoded size comes from folder metadata. 7zAES properties encode the cycle power, salt, and IV.
- ARM64 and RISC-V accept an optional four-byte little-endian start position. ARM64 requires four-byte alignment; RISC-V requires two-byte alignment.
- The linear decoders accept validated one-input/one-output coder chains. BCJ2 is partial: it reads the four-channel BCJ2 topology recognized by `FolderGraph`; no BCJ2 writer exists. Unknown methods can be retained as raw packed folders when the update preserves the complete folder.
- Encoded headers use the same decoder plan and property checks as file folders. The writer emits encoded headers with LZMA2 and optional 7zAES.

## Resource, integrity, features, and evidence

- Decoder working-set estimates are charged against the operation budget. LZMA/LZMA2 and PPMd charge their configured dictionary or memory; BCJ readers charge their filter buffers; BCJ2 charges four 256 KiB input buffers and its materialized output. Output size and dictionary caps apply before decoding.
- CRC verification is performed by the archive/folder layer when the corresponding packed, folder, or substream CRC is present. It is not a property of an individual codec. A consumer that stops before the stream is drained has not verified trailing checksums.
- r7z has no per-method Cargo feature switches. LZMA/LZMA2 and BCJ writing require the `encoder` feature enabled for the pinned lzma-rust2 dependency; the package also enables its `optimization` feature.
- Read/write evidence: [`interop_test.rs`](https://github.com/mjc/r7z/blob/main/tests/interop_test.rs) and [`interop_write_test.rs`](https://github.com/mjc/r7z/blob/main/tests/interop_write_test.rs) exercise Copy, LZMA, LZMA2, PPMd, AES, and x86 BCJ against p7zip. `interop_test.rs` includes p7zip fixtures for BZip2, Deflate, Deflate64, Delta, byte-swap, ARM-family filters, and BCJ2. [`codec_parity_test.rs`](https://github.com/mjc/r7z/blob/main/tests/codec_parity_test.rs) tests all BCJ decoders, Delta properties, ARM64/RISC-V properties, and the supported LZMA2 property cases. [`update_parity_audit_test.rs`](https://github.com/mjc/r7z/blob/main/tests/update_parity_audit_test.rs) confirms an unsupported method can be retained when its folder is unchanged. These are the evidence for `tested`; `partial` is limited to the arrangements listed above.
