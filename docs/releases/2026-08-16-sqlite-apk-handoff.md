# 2026-08-16 forensic depth update

This development snapshot continues the `1.0.0-beta.1` stabilization work without changing the package version.

## Added

- SQLite record reconstruction from unallocated, freeblock and freelist regions.
- SQLite record serial-type decoding for NULL, integer, real, text and blob values.
- Conservative table-candidate ranking from the live schema rather than asserted table attribution.
- Historical SQLite WAL row recovery from superseded committed table-leaf pages and valid uncommitted frames.
- APK Signing Block v2/v3 parsing with signer algorithms, SDK ranges, public-key SHA-256 and X.509 certificate metadata.
- Recognition of the v3 proof-of-rotation additional-attribute ID when present.
- In-memory carved-artifact handoff from Binary/Firmware analysis to SQLite, Android, Archive, Image, Document and Binary workspaces.
- Parser-focused tests for SQLite recovery, APK v2/v3 signing structures and inter-tool handoff.

## Evidence limitations

- SQLite payload-only recovery cannot restore rowid when the deleted-cell prefix is missing.
- SQLite overflow payload reconstruction is not implemented in this pass.
- Schema matching is a ranked candidate only; it is not proof that a recovered record belonged to a specific table.
- APK Signing Block parsing is structural metadata extraction. APK content digests and signatures are not cryptographically verified in this snapshot.
- Artifact handoff is in-memory and short-lived; target analyzers keep their own browser size and format constraints.
