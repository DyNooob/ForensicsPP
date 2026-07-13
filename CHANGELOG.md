# Changelog

Forensics++ follows semantic versioning where practical. This file records user-visible changes and release engineering milestones.

## [Unreleased]

## [0.8.1] - 2026-07-13

### Changed

- Kept evidence inputs and analysis results in the current browser tab instead of persistent local storage, while preserving tool state during navigation.
- Reworked file and text tool empty states around one clear primary action and added practical file-size checks before expensive parsing.
- Expanded the legal notice with authorization, evidence preservation, data handling, security, result, third-party and liability boundaries.
- Refined About and Local Data settings, including a compact current-session list and clearer project links.
- Changed production asset, legal-page and CyberChef paths to support static hosting from a subdirectory.

### Fixed

- Added incremental large-file hashing, byte-level progress, cancellation and a clear SM3 size limit instead of reading every selected file into memory at once.
- Warned before closing or replacing a modified SQLite database and stopped persisting SQL query history.
- Removed legacy evidence values left in localStorage by older versions without repeatedly clearing current settings.
- Corrected stale SEO version metadata, service-worker cache naming and the cached social-image path.
- Updated the layout audit to exercise current-session inputs instead of relying on removed persistent evidence state.

### Verification

- 48 automated tests across eight test files.
- Layout audit covers 36 routes, 17 populated states and 12 file-loaded states at 1366 × 900.
- Production build, copyright headers, static-package checks and a real subdirectory deployment were verified.

## [0.8.0] - 2026-07-13

### Changed

- Refined the main evidence tools around explicit actions, compact controls, predictable result areas, and less duplicated output.
- Reworked SQLite browsing with resizable columns, in-place editing, clearer edit-mode behavior, and simpler navigation.
- Simplified image analysis to focus on preview, metadata, channel inspection, structure checks, and practical recovery output.
- Improved archive, document, packet capture, email, timestamp, Windows artifact, Registry, Plist, browser artifact, and EVTX workflows.
- Reduced large-file limits and deferred expensive filtering in tools that could otherwise stall the browser.
- Shortened legal and consent text and updated the product contact address to `toolab@digiforensics.cn`.

### Fixed

- Removed empty or never-calculated SHA-256 fields from several analysis results.
- Fixed HTML email handling, MSG body decoding, invalid-file state retention, table overflow, and inconsistent result selection.
- Added packet-capture parser coverage and expanded parser regression tests.

### Verification

- 45 automated tests across eight test files.
- TypeScript checks, copyright-header checks, production build, and static release-package verification.

## [0.7.1] - 2026-07-13

### Changed

- Shortened the About page and made Local Data fit common desktop viewports without page scrolling.
- Added a compact two-column list for tools retained in the current browser tab.

### Fixed

- Rebuilt EXIF output as a bounded table with predictable field width and wrapped values.
- Added EXIF overflow coverage to the desktop layout audit.

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

[Unreleased]: https://github.com/DyNooob/ForensicsPP/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/DyNooob/ForensicsPP/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/DyNooob/ForensicsPP/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/DyNooob/ForensicsPP/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/DyNooob/ForensicsPP/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/DyNooob/ForensicsPP/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/DyNooob/ForensicsPP/releases/tag/v0.5.0
