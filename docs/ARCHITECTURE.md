# Forensics++ analysis architecture

Forensics++ is moving from UI-coupled tools toward reusable browser-native DFIR primitives. The migration remains incremental: existing workspaces continue to run while large analyzers adopt shared readers, format registries, structured results and analyzer routing.

## Data flow

```text
File / Blob / carved bytes
        |
        v
EvidenceReader
        |
        +--> format registry / parser
        +--> container extractor
        +--> analyzer
        |
        v
AnalysisEnvelope<T>
        |
        +--> workspace renderer
        +--> Result Store
        +--> Case Reporter / .fppcase
        +--> Timeline / findings / IOC

Carved artifact
        |
        v
Analyzer Routing --> bounded in-memory Tool Handoff --> existing workspace
```

The important boundary is that React tools are consumers and controllers of analysis; format identification, extraction and result provenance should not live in UI condition chains.

## EvidenceReader

`src/core/evidence/reader.ts` defines the random-access evidence boundary:

```text
EvidenceReader
  size
  read(offset, length)
  slice(offset, length)
  stream(offset, length)
```

New large-file analyzers should use `EvidenceReader` instead of loading complete evidence with `File.arrayBuffer()`. Disk Image and Firmware Analyzer already use this model. Legacy full-buffer workers can migrate independently where their existing bounded input limits remain appropriate.

## Format registry and carving

`src/features/file/carver.ts` exposes the shared carver format registry. A format definition separates identification from boundary resolution and records:

- magic/pattern and optional validation
- format label, extension and MIME type
- confidence
- resolved size where the format provides enough structure
- boundary type: `exact`, `structural`, `heuristic`, or `unknown`

Multiple hits of the same format are retained. A magic match is never promoted to an exact carved object unless the format supplies an exact/structural extent rule.

Current registry coverage includes common archives/compression, images/documents, PE/ELF, SQLite, APK/ZIP, Android boot structures, U-Boot/DTB, SquashFS/JFFS2/UBI/UBIFS, common filesystem signatures and PEM material.

## Shared container extraction

`src/features/file/containerExtractors.ts` is the bounded container-expansion layer. It currently supports:

- ZIP/APK/JAR
- gzip
- zlib
- TAR
- CPIO newc

Expansion is guarded by entry count, per-entry bytes, total expanded bytes and compression-ratio limits. Unsupported complex formats can still be identified and carved without pretending they were successfully mounted or decompressed.

`src/features/file/recursiveCarver.ts` composes the format registry and container extractor under depth/object/expanded-byte limits. Whole-container self-hits are retained as evidence but are not recursively re-entered.

## Firmware Analyzer

`src/features/firmware/analyzer.ts` and `firmware.worker.ts` implement the dedicated Binwalk-like firmware workbench.

The source is scanned in bounded chunks through `EvidenceReader`; overlapping windows preserve magic matches that cross chunk boundaries. SHA-256 and entropy blocks are updated incrementally rather than requiring a whole-file buffer.

Firmware analysis currently provides:

- embedded-format discovery with absolute offset and resolved extent
- exact/structural/heuristic boundary confidence
- architecture hints for ELF, PE and U-Boot
- metadata for common firmware structures
- bounded recursive container expansion for supported containers
- interesting-path triage from extracted archive members
- clickable entropy map and high-entropy-region findings
- selective object extraction / analyzer handoff
- versioned `forensicspp.firmware-manifest/v1` JSON export

Automatic recursive expansion is limited to bounded source sizes. Large firmware remains top-level streaming analysis so the feature does not regress to an unbounded `arrayBuffer()` workflow.

## Analyzer routing and tool handoff

`src/core/analyzerRouting.ts` is the central carved-artifact routing policy. Binary and Firmware do not maintain independent `if SQLite -> ...` chains.

`src/core/toolHandoff.ts` carries a carved `File` to an existing workspace using an in-memory, per-target FIFO queue. Queues are bounded, entries expire after five minutes and bytes are neither uploaded nor persisted. Target workspaces keep their own size guards and parser/worker implementations.

Current routing includes SQLite, Android APK, archives, images, documents, disk/filesystem objects and binary analysis. A route is considered complete only when the target workspace consumes the handoff; Disk Image now does so as well.

## Structured analysis results

`src/features/analysis/result.ts` defines `AnalysisEnvelope<T>`:

```text
AnalysisEnvelope<T>
  schemaVersion
  analyzer
  source
  run
  summary
  findings
  indicators
  artifacts
  timeline
  limitations
  data: T
```

Analyzer-specific detail remains in `data`; common evidence/provenance is not flattened into UI text.

`src/features/analysis/resultStore.ts` provides:

- current result per tool
- bounded per-tool history
- result subscriptions
- case-safe snapshot serialization
- snapshot restore during case import

Case reporting consumes structured results first. Tools not yet migrated can still use the legacy DOM fallback until their analyzers publish envelopes.

## Versioned `.fppcase`

`src/features/reporter/casePackage.ts` writes schema **1.1** and continues to accept schema **1.0**.

A 1.1 package contains:

```text
manifest.json
case.json
notes.json
timeline.json
evidence.json
analysis.json
reports/report.md
```

`analysis.json` contains sanitized `AnalysisEnvelope` snapshots; binary buffers are represented as bounded metadata rather than silently embedding source bytes. `manifest.json` records each internal member size and SHA-256. Import rejects unsafe paths, expansion-limit violations, unsupported schemas and integrity mismatches.

Raw evidence remains reference-only by default so case packages stay predictable and do not silently duplicate multi-gigabyte evidence.

## SQLite forensic recovery

`src/features/sqlite/recovery.ts` reconstructs conservative SQLite record candidates from free/unallocated regions, historical WAL page versions and intact table-leaf cells. It understands SQLite varints, record headers, serial types, rowids, local-payload rules and overflow-page chains.

Recovery modes remain explicit:

- `cell`: intact table-leaf cell prefix and payload survive.
- `cell-overflow`: payload is rebuilt through one or more overflow pages.
- `record-payload`: only a plausible record payload survives; rowid is unknown.

Live schemas only rank candidate tables. Historical WAL provenance and overflow limitations remain visible instead of mixing uncertain page versions into a claimed recovered row.

## Android signature verification and re-signing

Android analysis separates parsing, verification and repair:

- v1/JAR: manifest entry digests, `.SF` digest and common RSA/ECDSA CMS signer signatures.
- v2/v3/v3.1: signer signatures, certificate/public-key consistency, APK chunk content digests and v3 SDK ranges.
- v4: optional companion `.idsig`, signed data, fs-verity Merkle material and correspondence with APK v2/v3 signer/digest material.

`src/features/android/signingRepair.ts` performs explicit **re-signing**, not recovery of an unknown developer identity. It can import a PKCS#8 private key plus X.509 certificate or create a temporary local repair identity, rebuild a v2 Signing Block and self-verify the result.

## PCAP TLS metadata

`src/features/pcap/tls.ts` analyzes reassembled TCP payloads for TLS handshake metadata without decrypting application traffic. It exposes ClientHello, ServerHello and visible Certificate messages, SNI, ALPN, versions, cipher suites, extension IDs, JA3/JA3S and certificate SHA-256 fingerprints.

Captures that start mid-session, contain missing TCP ranges or encrypt later handshake messages remain explicitly incomplete.

## Disk, Windows, bulk and memory triage

These features remain deliberately scoped as browser-side triage rather than claiming full TSK/Volatility parity:

- Disk Image Explorer uses random access for MBR/GPT and filesystem metadata probes (NTFS, FAT, exFAT, EXT, ISO9660); FAT root-directory browsing is bounded/read-only.
- Windows Artifact parses NTFS `$MFT` FILE records and `$UsnJrnl:$J` v2/v3 records into structured rows/timeline events.
- Bulk Artifact Scanner streams evidence in chunks and reports offset/encoding/context for common IOC/artifact families.
- Memory Triage parses Windows Minidump metadata and performs bounded PE-header discovery in raw dumps.

## Tool runtime registry

`src/components/toolRuntimeRegistry.tsx` owns lazy loading and runtime service injection for every `ToolId`. `ToolHost.tsx` stays a thin host. Tool metadata in `src/config/app.ts` carries `accepts` and `capabilities`, which are also searchable by the home workspace.

New tools should register once rather than extending a conditional chain in `ToolHost`.

## Migration rules

When migrating or adding an analyzer:

1. Keep parsing independent from React components.
2. Use `EvidenceReader` for large/random-access evidence.
3. Reuse the shared format/container registries instead of duplicating magic or archive logic.
4. Publish an `AnalysisEnvelope<T>` with explicit provenance and limitations.
5. Route carved artifacts through `analyzerRouting` + Tool Handoff; do not duplicate target parsers.
6. Add valid, malformed, boundary and differential/reference tests where practical.
7. Do not remove the reporter DOM fallback until all relevant legacy tools publish structured results.
