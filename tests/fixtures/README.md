# Test fixtures

[Validation guide](../../docs/VALIDATION.md)

Fixtures exercise the production parsers and import contracts. Never add real case evidence, live credentials or private user content. Keep provenance and independent expected values next to the fixture.

## Generated known-evidence cases

| File | Construction / expectation |
| --- | --- |
| `embedded-signatures.bin` | Generated signatures at known offsets; expected carving locations in `expected.json` |
| `sqlite-deleted-record.sqlite` | Controlled SQLite settings and deleted content; expected fragment/limitation behavior in `expected.json` |

`scripts/gen-validation-fixtures.mjs` regenerates these cases. Inspect its prerequisites and diffs before replacing committed bytes. `npm run validate` drives the actual analyzers; it does not generate fixtures automatically.

## Public EVTX

`Application.evtx` comes from the public test fixtures of [NickSmet/ts-evtx](https://github.com/NickSmet/ts-evtx/tree/main/test/fixtures), retrieved 2026-07-12. The upstream project is MIT licensed.

- Original path: `test/fixtures/Application.evtx`.
- SHA-256: `1b30b76425cc7d68c3e8aab718b2695bfcb60f2ba66eff3a73bcbfb923f6726c`.

## Case-package compatibility and rejection

The `.fppcase` files include historical 1.0/1.1 package shapes, a historical beta snapshot and deliberately tampered input. They verify backward compatibility, safe import and integrity failure behavior; do not replace them with only current-format exports.

## Optional local samples

The 1.0 HEIC browser check used exifr's public `test/fixtures/heic-iphone.heic`. It is a local test input under `tmp/`, not a committed fixture or release asset. The smoke's fixture-specific assertion requires that explicit input; no hidden download occurs during an offline build.
