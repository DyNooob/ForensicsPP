# Changelog

Forensics++ follows semantic versioning where practical. This file records user-visible changes and release engineering milestones.

## [Unreleased]

## [0.7.0] - 2026-07-12

### Added

- Registry Hive and Apple Plist browsers.
- Outlook MSG parsing in the email tool.
- SQLite WAL / SHM loading.
- Storage usage and quota display in Settings.
- Current-session tool management for releasing open files and results.

### Changed

- Tool pages remain mounted after they are opened, preserving state while navigating.
- SQLite columns can be resized and cells can be edited in place.
- Default accent color changed to `#4457A6`; four additional presets were added.
- Terms confirmation is a blocking modal again.
- README, Settings copy, and release notes were shortened.
- Persistent browser storage is now shown separately from current-tab memory.
- Tool loading and rendering were moved out of `App.tsx` into a dedicated host.

### Fixed

- PDF.js compatibility with Node.js 22 environments without `Promise.try`.
- Ant Design Switch styling inside tool panels.
- SQLite WAL recovery now verifies header and frame checksums and ignores corrupt tail frames.
- Generic OLE files are no longer accepted as Outlook MSG, and Registry Hive headers receive stricter validation.

## [0.6.0] - 2026-07-12

### Added

- Browser Artifact Studio for Chromium and Firefox history, downloads, cookies, logins, autofill and extension records.
- Windows EVTX Explorer with BinXML parsing, structured event filtering, raw XML and strict local Sigma matching.
- Office / PDF Forensics for PDF metadata and attachments, OOXML relationships and embedded parts, and OLE stream inspection.
- Static release ZIP generation with a SHA-256 checksum.
- Worker-based parsing for Android manifests, packet captures, IOC extraction and string extraction.

### Changed

- Reworked the desktop interface around a consistent Ant Design 5 tool layout.
- Rebuilt SQLite Browser with persistent table navigation and Browse, Structure, SQL and Changes views.
- Simplified password hash generation so bcrypt and Django PBKDF2 show only the requested result while common hashes remain available as a batch.
- Added isolated HTML email preview and reliable raw EML display.
- Changed archive browsing to read the directory first and extract entries only when requested.
- Changed image, JSON, IOC and string tools to use explicit actions instead of automatic heavy processing.
- Redesigned Settings, including Appearance, About, Local Data and a simplified open-source project list.
- Standardized upload areas, expandable sections, typography and desktop spacing across tools.

### Fixed

- Prevented raw evidence input from being stored in localStorage by affected tools.
- Moved large parsing tasks away from the main UI thread to reduce browser freezes.
- Fixed transparent select popups, collapsed-sidebar focus behavior, hidden file input accessibility and several table overflow issues.
- Corrected overly strong or ambiguous email authentication wording.

### Verification

- 31 automated tests across six test files.
- Layout audit covers 34 tool pages, 17 populated states and 12 file-loaded states.
- Production output is checked for required files, source leakage, copyright banners and size limits.

## [0.5.0] - 2026-07-12

### Changed

- The repository now publishes the complete React and TypeScript source instead of only compiled HTML, CSS and JavaScript.
- Rebuilt the interface around React 19 and Ant Design 5 with a shared workbench layout.
- GitHub Pages now installs locked dependencies, verifies the source and builds `dist/` in Actions.
- Added project copyright headers to first-party source and generated assets.

### Added

- Expanded browser-local tools for file integrity, SQLite, EML, images, archives, timestamps, traffic captures and system artifacts.
- Full build, development and deployment instructions.

### Notes

- `dist/` is generated output and is no longer committed to `main`.
- Existing GitHub Pages deployments must use **GitHub Actions** as their Pages source.

## [0.2.0]

- Historical compiled-site release.

[Unreleased]: https://github.com/DyNooob/ForensicsPP/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/DyNooob/ForensicsPP/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/DyNooob/ForensicsPP/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/DyNooob/ForensicsPP/releases/tag/v0.5.0
