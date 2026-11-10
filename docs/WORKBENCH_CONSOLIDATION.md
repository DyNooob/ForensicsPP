# Workbench organization / 工作台组织

[Architecture](ARCHITECTURE.md) · [Tool reference](TOOLS.md)

## When capabilities belong together

Use a shared workspace when capabilities examine the same primary source, commonly occur in the same session and can reuse its file state or parsing. Add a page/tab only if secondary analysis remains lazy and independently bounded.

Keep a separate analyzer when its evidence model, access pattern, state or interpretation is materially different. Fewer navigation entries are not a substitute for better boundaries.

## Existing shared workspaces

| Workspace | Capabilities |
| --- | --- |
| Image | Preview, metadata, image-container analysis, PNG chunks/CRC, QR, channels/bit planes, hidden/trailing data and repair attempts |
| Binary | Identification, Hex/executable structure, strings/IOC, entropy, YARA, embedded-object discovery and analyzer handoff |
| Codec | Common encodings/charsets plus an explicit Chinese conversion page sharing the tool's navigation context |

Metadata must continue to come from original image bytes when a HEIC preview is decoded to PNG. Opening one Binary page must not eagerly run every expensive scan.

## Independent workspaces

Firmware, Disk, SQLite, PCAP and Bulk use different source access, result or resource models. Android, Archive, Document, Email, Registry, EVTX, Windows and Memory also retain domain-specific parsers and safety bounds. They may share navigation or report infrastructure without sharing one mutable parser state.

Hash remains a general evidence operation. Timestamp conversion and event Timeline are distinct tasks.

## Historical aliases

Aliases remain in the catalog for saved links and older workspace history. They are hidden in the normal navigation and canonicalized to their owner.

| Owner | Historical IDs |
| --- | --- |
| Image | `png`, `qr`, `gif`, `jpeg`, `webp`, `bmp`, `tiff`, `heif` |
| Binary | `fileid`, `strings`, `entropy`, `yara` |

The registry and route tests are the source of truth for the complete list. Do not create a second runtime implementation merely to preserve an old URL.

## Rules for a new page

- Reuse the existing source reference and derived-state ownership.
- Declare whether it needs original bytes, decoded pixels or another expensive derivative.
- Start secondary work explicitly and cancel it when its source becomes obsolete.
- Preserve the original parser's resource limits and provenance.
- Keep export/report behavior tied to the producing analysis run.
- Add direct-route/alias tests when navigation changes.
