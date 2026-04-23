# MemPalace Workflow for `r7z`

## Purpose

The `r7z` wing is the operational memory layer for the rewrite. It is not an archival dump. The palace should stay small, searchable, and authoritative for spec facts, design decisions, fixture provenance, coverage state, and performance history.

## Filing Rules

- Use normal verbatim drawers for technical and project memory.
- Use AAAK only for `mempalace_diary_write` session entries.
- Run `mempalace_check_duplicate` before every new drawer.
- Prefer updating an existing canonical drawer over filing a second drawer that says the same thing.
- Put the stable marker block at the top of every canonical drawer:

```text
R7Z_CANONICAL_ID: <stable-id>
R7Z_CANONICAL_KIND: <room_seed|registry|ledger|index|incident>
R7Z_SEARCH_KEYWORDS: <space-separated search terms>
```

- Keep the marker block within the first 200 characters so the validator can detect it from `list_drawers`.
- Include concrete source references in technical drawers: spec URL, local file paths, fixture filenames, benchmark commands, or test names.

## Room Ownership

- `spec_ledger`: official 7z format facts, property IDs, method IDs, binary layout rules, and invariants taken from `7zFormat.txt`, `Methods.txt`, or repo-local confirmations.
- `archive_model`: parser and writer structure, folder graph semantics, IR boundaries, and API invariants for `Archive`, `ArchiveBuilder`, and `ArchiveWriter`.
- `codec_backends`: supported method families, codec-property behavior, backend implementation notes, and encryption handling.
- `fixtures_and_interop`: fixture provenance, exact generation commands, passwords, external prerequisites, and interop quirks.
- `test_matrix`: feature-to-test coverage, CI expectations, malformed-corpus plans, and acceptance reports.
- `decisions_and_risks`: ADRs, incidents, compatibility tradeoffs, blockers, and unresolved gaps.
- `benchmarks`: baselines, profiling commands, regression thresholds, and ownership of hotspots.

## What Does Not Belong

- Do not put session history in project rooms. Diary entries are separate.
- Do not store large raw transcripts or scratch notes that do not change implementation choices.
- Do not file temporary debugging output unless it captures a durable incident or benchmark result.
- Do not duplicate the same fact across multiple rooms; link rooms with tunnels instead.

## Tunnel Policy

- Use explicit tunnels for cross-room ownership and traceability.
- Required labels for this project:
  - `spec->parser`
  - `spec->codec`
  - `fixture->test`
  - `adr->coverage`
  - `perf->owner`
- Prefer room-level tunnels that express stable relationships:
  - `spec_ledger` -> `archive_model` for structural feature groups
  - `spec_ledger` -> `codec_backends` for method families
  - `archive_model` -> `test_matrix` for parser and writer subsystems
  - `codec_backends` -> `test_matrix` for backend decisions
  - `fixtures_and_interop` -> `test_matrix` for fixture families
  - `benchmarks` -> `archive_model` and `codec_backends` for hotspot ownership

## Duplicate Control

- Always run `mempalace_check_duplicate` before `mempalace_add_drawer`.
- Canonical drawers must be idempotent: the same content should resolve to the same deterministic drawer ID.
- Re-seeding must update or no-op, never create a second canonical drawer.
- The validator treats more than one drawer with the same `R7Z_CANONICAL_ID` in a room as a failure.

## Session Cadence

- Before substantial work: search the `r7z` wing for existing facts and decisions.
- During work: file new durable facts into the owning room immediately.
- After each substantial session:
  - write a diary entry with `mempalace_diary_write`
  - reconnect if search freshness looks stale

## Current Acceptance Snapshot

- 2026-04-21: common 7z read parity was completed and committed in four implementation commits plus this memory-seed commit.
- Acceptance commands that passed: `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --doc`, and `git diff --check`.
- Durable scope: current-codec read robustness for Copy, Deflate, Deflate64, BZip2, PPMd, Delta, Swap2/Swap4, LZMA, LZMA2, BCJ+x86/BCJ2/ARM/ARMT/IA64/PPC/SPARC, AES-256-SHA-256 content, and AES encrypted headers; write parity for Copy, LZMA, LZMA2, PPMd, BCJ+x86+LZMA2, and 7zAES content/header encryption. Symmetric write parity for extension codecs remains intentionally out of scope.
