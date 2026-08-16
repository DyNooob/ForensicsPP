# Analysis foundation, firmware carving, and PCAP TLS

Date: 2026-08-16

This development snapshot keeps the public version at `1.0.0-beta.1` while introducing the first stage of the 1.0 architecture migration.

## Architecture

- Added random-access `EvidenceReader` for Blob/File and in-memory evidence.
- Added versioned `AnalysisEnvelope<T>` and an in-memory per-tool result store.
- Case Reporter now prefers structured analyzer output and keeps the legacy DOM fallback for tools not yet migrated.
- Moved lazy tool loading and service injection from `ToolHost` into `toolRuntimeRegistry`.
- Added architecture documentation in `docs/ARCHITECTURE.md`.

## Binary / firmware analysis

- Replaced one-hit-per-format embedded signature behavior with a multi-hit carver engine.
- Added explicit boundary confidence: exact, structural, heuristic, unknown.
- Added nested parent/depth relationships for structurally contained objects.
- Added extent-aware handling for common images/containers and multiple firmware/filesystem structures.
- Added recognition for SquashFS, U-Boot uImage, DTB, Android boot/sparse images, UBI, JFFS2, CPIO, ISO9660, FAT12/16/32, exFAT, EXT and NTFS alongside common executable/archive/database formats.
- Large carved payload bytes are not retained indefinitely in the workspace; metadata remains available when the memory guard is triggered.

## PCAP TLS metadata

- Added TLS record and handshake metadata parsing on reassembled TCP streams.
- Added ClientHello and ServerHello details, SNI, ALPN, versions, cipher suites and extension IDs.
- Added legacy-compatible JA3/JA3S string/hash generation with GREASE filtering.
- Added visible certificate SHA-256 fingerprints when Certificate handshake messages are present in plaintext capture data.
- Added TLS rows to the network UI, report text, structured findings, indicators and timeline output.

## Archive / Android safety

- Added a shared classic-ZIP central-directory parser that does not inflate entry data.
- Android APK/APKS/XAPK inspection now preflights outer and nested archives before `unzipSync`.
- Preflight limits entry count, single-entry expansion, total expansion and suspicious high compression ratios.
- Archive Tool reuses the same ZIP directory parser instead of maintaining a separate implementation.

## Tests and verification

Added focused regression tests for:

- EvidenceReader random ranges and invalid bounds
- structured result store/report text
- multi-hit and structural file carving
- FAT32/EXT extent calculation
- TLS ClientHello SNI/ALPN/version/cipher/JA3 extraction
- ZIP central-directory parsing and high-ratio expansion rejection

The repository copyright-header checker passes for all checked files. Core dependency-free modules pass strict TypeScript checking, and targeted executable smoke checks pass. A full `npm run verify` still requires a complete local `node_modules` installation.
