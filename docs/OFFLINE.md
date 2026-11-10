# Offline operation and builds / 离线使用与构建

[Documentation](README.md) · [Release engineering](RELEASE.md)

## Distribution contract

The `offline-static.zip` release is a complete browser application distribution. It includes app JS/CSS, workers, WASM, CyberChef, OpenCC dictionaries, IP/mobile-prefix/administrative-division datasets, license notices and HEIC codec corresponding sources. First use needs neither Internet access nor a populated browser cache.

The website build has a separate policy and may use configured CDNs or on-demand lookup data. A source ZIP is also a different artifact: it requires a prepared development toolchain to build.

## Download and verify / 下载与校验

Download the offline ZIP and `SHA256SUMS-v1.0.0.txt` from the [1.0.0 release](https://github.com/DyNooob/ForensicsPP/releases/tag/v1.0.0).

Run in the directory containing both files:

```sh
# macOS
shasum -a 256 ForensicsPP-v1.0.0-offline-static.zip
# Linux
sha256sum -c SHA256SUMS-v1.0.0.txt
```

Windows PowerShell:

```powershell
Get-FileHash .\ForensicsPP-v1.0.0-offline-static.zip -Algorithm SHA256
```

Compare the complete digest with the checksum file. A checksum detects changed bytes; its trust depends on obtaining the checksum from the intended release. There is no separate signed-checksum claim for this version.

## Launch / 启动

Extract the entire folder, then run inside it:

```sh
python3 start_server.py
```

Windows: `Start-ForensicsPP.bat` or `py -3 start_server.py`. macOS: `Start-ForensicsPP.command`. If execution permission is lost during extraction, run `python3 start_server.py` directly.

The launcher uses preinstalled Python 3 standard-library modules, installs nothing and binds only to `127.0.0.1`. The default URL is `http://127.0.0.1:8765/`. Keep the terminal open; press `Ctrl+C` to stop.

```sh
python3 start_server.py --port 8766
python3 start_server.py --no-browser
```

Any existing static HTTP server can instead serve the complete package from its root. Do not expose sensitive evidence through a shared server directory. Full Worker/WASM execution requires HTTP; `file://` is suitable only for the limited shell/basic-tool compatibility that browsers permit.

## Package layout

| Path | Purpose |
| --- | --- |
| `index.html`, `*.worker-*.js`, other emitted assets | Application and analysis runtime |
| `cyberchef/` | Bundled CyberChef engine, modules and upstream notices |
| `lookup/` | Fixed-version lookup data and provenance manifest |
| `licenses/`, `THIRD_PARTY_NOTICES.txt`, `LICENSE.txt` | Dependency/data and project licensing |
| `sources/heic-sources.tar.gz` | Codec corresponding sources and build instructions |
| `OFFLINE_MANIFEST.json` | Distribution identity and lookup/source integrity records |
| `start_server.py`, platform launchers | Local serving without package installation |
| `RELEASE_NOTES.md`, `TOOL_AUDIT.md` | Release behavior and validation scope |

## Network and storage boundaries

Every packaged HTML entry, including standalone CyberChef, restricts scripts, styles, workers and connections to permitted local/data/blob sources. CDN build variables do not select runtime resources in an offline build. Lookup failure does not trigger a remote fallback. Explicitly external CyberChef operations such as external HTTP requests cannot work under this policy.

This is an application resource policy, not a guarantee about operating-system traffic, browser extensions or other programs. Browser storage can still retain supported workspace data. Use the application's Local Data settings and the browser's own data controls according to your environment requirements.

## Rebuild on a prepared machine / 重建

Prerequisites: the source checkout, Node.js 22.13+, npm 10+ and the locked dependency tree already installed with `npm ci`. Dependency installation is a separate preparation step; it may require network access unless an appropriate local npm cache/mirror is available.

Import the fixed data and codec sources from an already downloaded, checksum-verified offline release:

```sh
npm run prepare:offline -- --package /absolute/path/ForensicsPP-v1.0.0-offline-static.zip
npm run build:offline
node scripts/verify-offline.mjs
npm run smoke:offline
npm run release:package -- --variant offline
```

`prepare:offline` reads the local ZIP, checks the three datasets against the source repository's pinned sizes/SHA-256, checks the codec archive against the package manifest and writes only the expected build-input paths. It performs no downloads. When a future release changes pinned data or codecs, prepare matching inputs rather than substituting an arbitrary old ZIP.

The build reads `release/lookup-data/<sha256>` and `release/offline-inputs/heic-sources.tar.gz`. Missing/corrupt inputs fail the build. `build:standalone` also creates a local offline distribution and therefore requires those inputs. `VENDOR_CDN_URL` and `ASSET_CDN_URL` are ignored by both the offline Vite stage and finalization.

A prepared build can be tested against misleading ambient CDN configuration:

```sh
VENDOR_CDN_URL=https://must-not-load.invalid \
ASSET_CDN_URL=https://must-not-load.invalid npm run build:offline
```

This verifies resource selection; it does not download from the example host. Browser validation uses a closed proxy for non-loopback traffic, a fresh browser context, local data queries and representative worker/WASM operations. See [validation](VALIDATION.md) for the limits of that check.

## Known boundaries

- Python is a launcher prerequisite, not included runtime software.
- Lookup data is static and dated; it is not live positioning or authoritative ownership information.
- HEIC support is best effort within decoder/resource limits; damaged or unusual encodings may not preview.
- Tool size limits and browser memory limits still apply when fully offline.
- Phone dataset upstream licensing is documented separately in [LICENSING.md](LICENSING.md).
