# Forensics++ / ForensicsPP

Forensics++ is a static, local-first browser workbench for CTF/MISC, lightweight forensic triage, encoding and decoding, metadata inspection, hashes, archives, SQL dumps, and network evidence previews.

It is built as a public web toolbox: open the page, choose a tool, process the data in the browser, and review the result without needing a backend service or database.

## Highlights

- Static web application
- Browser-side file and text processing
- Local-first workflow
- Dark mode and customizable theme color
- Built-in legal notice and local cache controls
- CyberChef bundled as a local static workspace

## Tools

### Analysis

- Image metadata and channel analysis
- SQL dump parser and formatter
- AndroidManifest.xml parser
- IOC extractor
- URL analyzer
- HTTP message parser
- QR decoder
- File signature detector
- PNG chunk analyzer
- Archive index and preview for ZIP / APK / JAR / OOXML
- Binary header parser
- Strings extractor
- Entropy analyzer
- PCAP / PCAPNG header parser

### Transform

- Encoding and decoding helpers
- Classical cipher helpers
- Hash and HMAC calculator
- Timestamp converter
- Base converter
- UUID parser and generator
- JSON formatter
- Regex tester

### Security Helpers

- Backend password hash generation and verification
- JWT parser and HS256 helper
- Sensitive field and hash clue detection
- Local CyberChef workflow

## Local-first Behavior

Forensics++ is designed to keep common analysis work inside the browser.

- Files are processed locally by default.
- No backend service is required.
- No database is required.
- Text input and selected results may be stored in browser `localStorage`.
- Local cache can be cleared from the settings panel.

Tool output is intended for auxiliary analysis and should be reviewed with the original evidence.

## Use Responsibly

Forensics++ is intended for lawful and authorized use, including CTF/MISC, education, security research, personal data analysis, and lightweight forensic triage.

Do not use this project for unauthorized access, intrusion, privacy infringement, or unlawful activity.

## Open-source Projects

Forensics++ integrates or references:

- [CyberChef](https://github.com/gchq/CyberChef)
- [MDUI](https://github.com/zdhxiong/mdui)
- [React](https://github.com/facebook/react)
- [Vite](https://github.com/vitejs/vite)
- [TypeScript](https://github.com/microsoft/TypeScript)
- [CryptoJS](https://github.com/brix/crypto-js)
- [exifr](https://github.com/MikeKovarik/exifr)
- [jsQR](https://github.com/cozmo/jsQR)
- [bcrypt.js](https://github.com/dcodeIO/bcrypt.js)
- [fflate](https://github.com/101arrowz/fflate)
- [sql-formatter](https://github.com/sql-formatter-org/sql-formatter)

Third-party projects belong to their respective authors and are governed by their own licenses.

## Copyright

Copyright (c) 2026 DyNooob. All rights reserved.
