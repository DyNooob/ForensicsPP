# Licensing and data provenance / 许可与来源

[Documentation](README.md) · [Offline guide](OFFLINE.md)

## Project source

Forensics++ code is copyright © 2026 DyNooob and distributed under the repository's [MIT License](../LICENSE). Keep the copyright and permission notice with redistributed copies/substantial portions. This project license does not replace licenses attached to imported software, dictionaries, datasets or fixtures.

## Software inventory

[`src/config/openSource.ts`](../src/config/openSource.ts) drives the application's Open Source page. The lockfile records exact dependency versions. Offline finalization copies available license/notice files from installed non-development packages and writes `licenses/DEPENDENCIES.json` plus `THIRD_PARTY_NOTICES.txt`.

Important included components:

| Component | Attribution / terms | Distribution material |
| --- | --- | --- |
| React, Ant Design and many parser/UI libraries | Their respective MIT/other upstream terms | Dependency inventory and copied license files |
| OpenCC JS | MIT; incorporated dictionary data under Apache-2.0 | `licenses/opencc-js-LICENSE.txt`, `licenses/opencc-js-THIRD_PARTY_LICENSES.txt` |
| heic-to, libheif, libde265 | Upstream LGPL terms as included | License texts, separate decoder worker and `sources/heic-sources.tar.gz` |
| CyberChef | Apache-2.0; its bundled third-party notices also apply | `cyberchef/LICENSE.txt`, `UPSTREAM.txt`, `assets/main.js.LICENSE.txt` |
| YARA-X and other WASM components | Their upstream license terms | Dependency notices and bundled runtime files |

The separate HEIC worker is loaded for preview decoding and can be rebuilt/replaced. Its corresponding-source archive includes the recorded upstream codec sources and build instructions. Build tools remain build-time prerequisites. Offline packaging also records its HTML-policy modifications to CyberChef separately from unchanged upstream engine files.

## Lookup datasets

The exact upstream revisions, byte counts and SHA-256 values live in [`dataSources.json`](../src/features/lookup/dataSources.json) and the packaged `lookup/SOURCES.json`. Changing a URL is not a dataset update unless the pinned content/provenance is reviewed and checks pass.

| Dataset | Recorded source | Notice |
| --- | --- | --- |
| IPv4 regions | `lionsoul2014/ip2region` | Included upstream licensing notice; source attribution remains with upstream |
| Mobile prefixes | `pangongzi/phone` | **The pinned upstream `LICENSE` file is empty.** The package preserves that file and an explicit `phone-UPSTREAM.txt` notice. No MIT/Apache permission is inferred from an empty file. |
| Administrative areas | `xihan123/gb2260` | Included CC0 notice from the recorded revision |

The phone dataset is an existing project data source with an unresolved explicit license grant at that revision. Attribution is not a substitute for permission. Redistributors should resolve the terms with the upstream rights holder or replace the dataset under a documented appropriate license; do not describe the entire data bundle as MIT licensed.

These datasets are historical records, not live-location or authoritative ownership services.

## Fixtures and documentation

Generated fixtures should document construction and expected results. Public fixtures must retain origin, hash and applicable license. See [`tests/fixtures/README.md`](../tests/fixtures/README.md). A publicly downloadable file does not automatically grant unrestricted redistribution.

Current guides are separate from archived reports. Preserve factual release history and third-party attribution when reorganizing documentation. Do not retain deployment credentials as historical documentation.

## Adding a dependency or asset

Record name/version/source, the actual license, any notice obligations, browser/offline runtime files and corresponding sources where applicable. Update the lockfile, application inventory, packaged notices and relevant tests together. Do not hide unknown terms behind the project's root license.
