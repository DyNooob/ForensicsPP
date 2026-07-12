# Changelog

Forensics++ follows semantic versioning where practical. This file records user-visible changes and release engineering milestones.

## [Unreleased]

### Added

- Automated tests for hashes, SM3, classical ciphers, timestamps, SQL/SQLite helpers, IOC extraction, Base32 and EML parsing.
- Pull request verification, release artifact validation and Dependabot configuration.
- Source repository contribution, security and release documentation.

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

[Unreleased]: https://github.com/DyNooob/ForensicsPP/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/DyNooob/ForensicsPP/releases/tag/v0.5.0
