# Forensics++ workbench consolidation

Forensics++ should grow by forensic workflow depth, not by keeping every parser or operation as a top-level tool. `1.0.0-beta.4` starts consolidating workspaces where multiple entries operate on the same evidence, duplicate parsing, or maintain redundant file state.

## Merge rule

A capability should normally be merged into an existing workbench when all of the following are true:

1. It consumes the same primary evidence object.
2. Users commonly need the capability during the same examination session.
3. Keeping it separate causes duplicate parsing, duplicate file reads, or duplicated UI state.
4. The capability can be exposed as a page/tab without forcing unrelated heavy analysis to run eagerly.

A capability should remain an independent analyzer when its input model, execution model, evidence limits, or investigation workflow is materially different.

This distinction is important: fewer menu items alone are not an architectural improvement. Consolidation is useful only when the underlying evidence state and analysis pipeline are also shared.

## Consolidated in beta.4

### Image Workbench

The Image Workbench now owns:

- general image metadata and file structure
- PNG chunk/CRC/IHDR/IEND analysis
- hidden/trailing data and image steganography helpers
- QR decoding and payload classification
- image repair operations

Legacy `#png` and `#qr` routes remain compatible and open the corresponding Image Workbench page. PNG and QR no longer require separate top-level runtime workspaces or a second upload of the same image.

### Binary Workbench

The Binary Workbench now owns:

- file identification and signatures
- Hex/structure inspection
- PE/ELF/Mach-O analysis
- strings, timestamps and IOC extraction
- entropy analysis
- YARA scanning
- embedded-object discovery and analyzer handoff

Legacy `#fileid`, `#strings`, `#entropy` and `#yara` routes remain compatible and open the corresponding Binary Workbench page.

Heavy optional operations are lazy. Opening a binary does not automatically run a full strings scan, entropy pass and YARA scan. Those pages consume the same file state but execute their additional workers only when requested.

## Intentionally separate

The following analyzers should not be collapsed merely to reduce the navigation count:

- **Firmware Analyzer**: random-access/chunked scanning, recursive extraction and large-evidence limits differ from the bounded Binary Workbench.
- **Bulk Artifact Scanner**: streaming extraction from large arbitrary evidence differs from interactive strings analysis on a bounded binary.
- **Disk Image**: partition/filesystem random access is a distinct evidence model.
- **SQLite Forensics**: database/WAL/deleted-record reconstruction maintains database-specific provenance.
- **PCAP**: packet/stream/network timelines are a separate investigation model.
- **Android, Archive, Document, Memory**: each has format-specific extraction and safety limits.
- **Registry, EVTX and Windows Artifacts**: these may eventually share a Windows navigation hub, but should retain independent analyzers and result schemas.
- **Hash**: hashing text/files is a general evidence operation and should remain directly accessible.
- **Timestamp vs Timeline**: timestamp conversion and case/event timeline analysis solve different jobs.

A future hub may group related analyzers visually without coupling their parser state. A Windows hub is the clearest candidate for that treatment.

## Compatibility aliases

Merged tool IDs remain in `ToolId` for saved workspace/history compatibility, but are hidden from normal navigation and canonicalized to their owning workbench:

```text
png      -> image
qr       -> image
fileid   -> binary
strings  -> binary
entropy  -> binary
yara     -> binary
```

The old hash route is intentionally not rewritten. Canonicalization happens in the navigation/config layer so the runtime registry does not need separate lazy-loaded implementations for merged tools.

## Performance requirements for consolidated workbenches

Consolidation must not turn one click into every analysis running at once. Workbench pages follow these rules:

- parse the common source once when practical;
- keep the opened evidence object in one workbench state;
- run expensive secondary workers on demand;
- reuse structured analyzer results instead of scraping rendered DOM;
- preserve worker and size limits of the original specialized capability;
- record limitations when a large-file operation is intentionally sampled.

These rules also make later capability-aware routing possible without bringing back one top-level entry per parser.
