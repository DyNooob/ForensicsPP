# Troubleshooting / 排错指南

[Documentation](README.md) · [Offline guide](OFFLINE.md)

## Startup and resources

| Symptom | Check and action |
| --- | --- |
| HTML opens but analysis fails | Check whether the URL starts with `file://`. Use `start_server.py` or an existing local HTTP server for Worker/WASM analysis. |
| Blank page or missing module | Extract the whole ZIP. Check failed requests and MIME types in browser developer tools. A server must return the requested JS/WASM, not rewrite a missing asset to HTML. |
| Python command not found | Use an already installed Python 3 runtime, `py -3` on Windows where available, or an existing local static HTTP server. The package installs none automatically. |
| Port already in use | Run `python3 start_server.py --port 8766` and use the printed URL. |
| macOS launcher is not executable | Run `python3 start_server.py` directly, or restore execute permission for the trusted extracted `.command` file. |
| Website deep link becomes a server 404 | Configure SPA fallback for non-generated tool paths. Do not apply that fallback to missing JS/WASM paths. See [hosting](CDN.md). |
| Old version remains visible | Export important work first, reload, and inspect the displayed version. Clear application/site caches only after understanding that supported local workspace data may be lost. |

## Offline lookup data

The complete offline ZIP includes IP, mobile-prefix and administrative-division data. A first lookup should not require external access. If it fails, verify the ZIP checksum and extract again; missing/corrupt inputs must not be fixed by adding a remote fallback.

For a source build, import matching local inputs with `npm run prepare:offline -- --package <zip>`. A hash mismatch means the file does not match the source's pinned dataset. Do not bypass the integrity check. Website mode can legitimately download these datasets on demand and therefore has different failure modes.

Database attribution is historical/static. A different city or unmatched prefix is not necessarily a parser failure; record the dataset version and the exact input when investigating.

## Image and HEIC

- No EXIF can be normal for screenshots, stripped files or platform re-encodings. Check the original source before assuming extraction failed.
- HEIC/HEIF preview is best effort. Unsupported codec features, malformed containers, decode timeout or resource bounds may prevent display; original metadata/container analysis can still be available.
- The Image input guard is 64 MiB and the pixel guard is 50 MP. Large originals may not be automatically restored; Image persistence is separately limited to 8 MiB.
- A PNG preview export is a derivative. Preserve the original file and its own hash; do not treat converted-preview bytes as an original-evidence replacement.
- Capture time without a timezone remains ambiguous. GPS display does not use online reverse geocoding.

## Storage and clipboard

Browser private modes, enterprise policy, storage quotas and cleanup can prevent persistence. Session analysis may still work. Local restoration is convenience storage, not guaranteed retention. Export reports/case data before clearing site data or changing browser profiles.

Clipboard permissions vary by browser and context. Try normal `Ctrl/⌘+V`, drag-and-drop or file selection. Do not grant unrelated browser/extension permissions merely to make a paste button work.

## Long or cancelled work

A worker can time out or hit an explicit input/output budget. Split oversized lookup batches, select a smaller inspection region or use a specialist desktop tool for workflows outside the browser analyzer's scope. After Clear or input replacement, old results should not reappear; report a reproducible stale-result case if they do.

Changing a label language need not rewrite the language stored in an existing analysis result. Re-run when a new result in the selected language is needed.

## Reporting a reproducible issue

Include version, distribution (website/offline/source), tool ID, browser/OS, steps, expected result, observed result and a synthetic/public sample with provenance. Attach relevant console/error text after removing sensitive values. Do not attach credentials, private evidence or a full unreviewed case report. Use [the private security route](../SECURITY.md) for vulnerabilities.

### PNG opens incorrectly or reports an IHDR CRC error

Open **Image → Repair → Recover dimensions / check repair**. This searches dimensions using the stored IHDR CRC and complete IDAT scanline layout. CRC-only normalization does not recover a hidden width or height. A red CRC notice is an actual mismatch; orange scanline-only candidates remain unconfirmed. [Recovery behavior, limits and severity levels](ANALYSIS_RESULTS.md) explain how to review results.
