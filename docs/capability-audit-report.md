# Forensics++ — Capability Truth Audit Report

**Date:** 2026-09-09
**Scope:** Round 2 of Web Delivery hardening — *Capability Truth Audit* (every user-visible capability must trace to real code + tests).
**Discipline:** `Never advertise a forensic capability the implementation cannot substantiate.` No README/roadmap/doc was used as evidence — only source (`src/`), registry (`src/config/app.ts`), SEO/static generator (`src/seo/`, `scripts/`), and real-Chrome smoke.

---

## 1. Baseline problems (confirmed before changes)

1. `sqlite-wal-recovery` was a **duplicate indexable tool page** (alias → same `sqlite` workbench) with its own canonical + sitemap entry → duplicate-content SEO risk.
2. Static tool pages + homepage repeated "runs in your browser / processed locally / not uploaded / enable JavaScript" 3–4×.
3. User-visible dual brand `Forensics++ ForensicsPP` appeared in static page header / homepage.
4. Several capability claims were over- or under-stated vs code (see §3/§4).
5. "Works offline once loaded" was unverified — service worker only pre-caches the app shell, not lazy tool chunks.
6. Language switch link labeled "中文介绍" instead of "中文".

---

## 2. Capability audit (per-tool, code-evidenced)

Verdicts: **VERIFIED** = code + (where relevant) tests confirm; **PARTIAL** = works with honest limitation; **UNVERIFIED** = no code proof; **FALSE/OVERCLAIM** = claim exceeds implementation (fixed this round).

| Tool | Claim → Code evidence | Verdict |
|------|----------------------|---------|
| EVTX Viewer | `features/evtx` parser: ElfChunk/event records, channel/level/eventID, timestamp normalize, filter/export. Limitation: no Windows message DLL → partial XML render. | VERIFIED (limitation honest) |
| SQLite Forensics | `features/sqlite`: schema + query; `envelope.ts` WAL frame parse (salt/checksum); freelist recovery. **`timeline` was empty (`envelope.ts:140`)** → removed. | VERIFIED (timeline dropped) |
| SQLite WAL Recovery | Not a separate workbench — alias → `sqlite` ToolHost. WAL handled inside SQLite tool. | Alias (see §4) |
| APK Signature | `AndroidManifestTool.tsx` + `signingVerify.ts` + `v4Verify.ts:236`: AXML parse; v1–v4 detect; **v4 actually verifies when companion `.idsig` present** (`AndroidManifestTool.tsx:304`). | VERIFIED (was under-claimed) |
| PCAP Analyzer | `features/pcap/analyzer.ts:685` `reassembleTcpDirection` uses `signedSequenceDistance` + `streamOffset` sort + `overlap` dedup + `retransmittedBytes` → **real seq-aware reassembly**. HTTP/DNS/TLS parsers present. IOC = extraction + local heuristics (no threat-intel feed). | VERIFIED (IOC wording fixed) |
| Registry Forensics | `features/registry`: regf/hbin parse, keys/values/types, last-write FILETIME→ISO, sequence/checksum integrity. **Only hive files** — `.reg` is a text export, not a hive. | VERIFIED (`.reg` removed) |
| Firmware Analyzer | `features/firmware/analyzer.ts`: magic scan (`matchAt`), `scanRecursiveCarvableObjects`, `carveObjectBytes:601` real byte extraction. FS detect = squashfs/ubi (**not cramfs**). | VERIFIED (cramfs dropped) |
| Binary File Analyzer | `BinaryTool.tsx:365` runs real `yara.worker.ts` → `matched` results; PE/ELF/Mach-O parse; magic/strings/entropy/hashes. | VERIFIED |
| Windows Artifacts | `features/windows`: LNK (target/time), Prefetch (exec), `$MFT`, `$UsnJrnl:$J`, `.reg` export. **No TrackerDataBlock parse** → "machine hints" dropped. | VERIFIED (hints dropped) |
| Image Forensics | `ImageTool.tsx:430` `runRepairAnalysis` real `action:"repair"` worker; EXIF/XMP, PNG chunk+CRC, QR decode, steg = YARA/strings clues. | VERIFIED |

---

## 3. Overclaims removed (Before → After → Reason → Evidence)

| # | Before | After | Reason | Evidence |
|---|--------|-------|--------|----------|
| 1 | SQLite extracts: "A timeline built from recovered timestamps" | removed | `envelope.ts:140` timeline is `[]` — never populated | `features/sqlite/envelope.ts` |
| 2 | Registry input: ".reg, .dat registry hive files" | "Windows Registry hive files (e.g. SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat)" | `.reg` is a text export, NOT a hive; parser only reads regf | `features/registry/*` |
| 3 | Windows: ".mft, .j files" + "machine hints" + "accessed files" | ".mft (NTFS $MFT)", ".j (NTFS $UsnJrnl:$J)"; dropped machine hints | No TrackerDataBlock/`droid`/`MachineId` parse (`features/windows` grep empty) | `features/windows/*` |
| 4 | APK: "Verify v1–v3.1 … v4 accepted but not verified" | "Verify v1–v4 signing schemes"; limitation: v4 needs companion `.idsig` | v4 IS verified when `.idsig` provided (`v4Verify.ts:236`, `AndroidManifestTool.tsx:304`) — prior copy was an under-claim | `features/android/v4Verify.ts` |
| 5 | PCAP desc: "flag IOCs locally" | "extract potential indicators locally" | IOC = regex/extraction + local heuristics, not threat-intel matching | `analyzer.ts` indicator code; extracts already said "Indicator extraction … with local risk heuristics" |
| 6 | Firmware: "filesystems (squashfs, ubi, **cramfs**, …)" | "filesystems (squashfs, ubi, and similar)" | No cramfs detector in source (grep `cramfs` → only文案) | `grep cramfs src` empty |
| 7 | Homepage/tool: "ForensicsPP · …" dual brand | "Forensics++" only | Brand unification rule §21 | `build-seo-pages.mjs`, `index.html` |
| 8 | "Works offline once loaded" | "Tools you have opened stay available offline." | SW pre-caches shell only (`public/sw.js` CORE_ASSETS), lazy chunks not cached → first-open-offline fails | `public/sw.js`, `scripts/finalize-dist.mjs` |
| 9 | Language link "中文介绍" | "中文" | Runtime i18n, not a separate intro page | `index.html` |

**NOT changed (verified real, not overclaim):** PCAP "TCP reassembly" (seq-aware code confirmed), Firmware "carve embedded objects" (real byte extraction confirmed), Binary "YARA" (real worker), Image "repair" (real worker).

---

## 4. Tool identity change — SQLite / WAL

**Decision: Case B (WAL is a sub-capability, not an independent tool).**
- `sqlite-wal-recovery` remains a reachable URL (alias) but canonicalizes to `/tools/sqlite-forensics/` and is `noindex`.
- Excluded from `sitemap.xml` (now **9 canonical routes**, was 10).
- Regression confirmed: `/tools/sqlite-wal-recovery/` still 200, opens the `sqlite` ToolHost, final URL stays, refresh keeps state (smoke:prod 126/126).
- No duplicate-content SEO exposure.

---

## 5. Registry changes — Capability Contract

- The Tool Registry (`src/config/app.ts`) already carries `capabilities`, `maturity`, `validation`, `accepts`, `help`. This round **extended** it (did not rebuild a second registry):
  - `sqlite`: dropped `"timeline"` capability (was false).
  - `registry`: `accepts` changed from `[".reg",".dat"]` → `[".dat"]` (hive-only).
  - `firmware`: `help` copy dropped `cramfs`.
- Source-of-truth flow: **implementation → tool capability metadata (`app.ts`) → SEO/static generator (`seoPages.mjs` + `build-seo-pages.mjs`) → page**. The `audit:capabilities` script and `capability-contract.test.ts` enforce consistency.
- Per-capability `status: verified|partial|experimental` enum is a recommended future refinement (round scope per §17: wire audit + metadata first, no mass refactor).

---

## 6. SEO / static-page changes

- `scripts/build-seo-pages.mjs`: alias canonical + noindex; root `index.html` canonical/og:url now env-aware (preview→`pre.forensicspp.com`); dual-brand tag removed from tool static header.
- `scripts/finalize-dist.mjs`: preview mode rewrites root canonical/og:url + injects noindex in one pass (no overwrite race).
- `src/seo/seoPages.mjs`: all §3 wording fixes (10 tools, EN+ZH).
- `index.html`: brand tag, "中文介绍"→"中文", offline wording.
- `lint:seo` (no marketing terms: powerful/comprehensive/etc.) passes on 10 pages.

---

## 7. Brand cleanup

- `Forensics++ ForensicsPP` user-visible string removed from tool static header + homepage.
- `Forensics++` retained as the product name; `ForensicsPP` remains only as repo/package/internal identifier (not user-facing).
- Preview badge already exists (`App.tsx` + `previewBadge` i18n), shown only in preview, removed in production — left as-is (already compliant with §27).

---

## 8. Offline verification

**Method:** read `public/sw.js` cache manifest + `scripts/finalize-dist.mjs`.
**Result:** SW uses network-first with cache fallback; `CORE_ASSETS` pre-caches only the app shell (index.html, core JS/CSS). Heavy-tool lazy chunks (pcap/firmware/evtx workers, yara.worker 15 MB) are **not** pre-cached.
**Conclusion:** "Works offline once loaded" is **false for first-open-offline**. Accurate statement: *"Tools you have opened stay available offline."* (already corrected in `index.html`). Standalone single-file build is the truly-offline path (separate `build:standalone`).

---

## 9. Tests / builds (real exit codes)

| Command | Result |
|---------|--------|
| `npm run typecheck` | 0 errors, exit 0 |
| `npm run test` | **451 passed** (81 files), exit 0 — includes 11 new `capability-contract` assertions |
| `npm run build` (prod) | exit 0; 197 files / 55.5 MiB; `verify:dist` + `lint:seo` green |
| `npm run build:standalone` | exit 0; 110 files / 65.7 MiB; `verify:dist` green |
| `npm run smoke:prod` | **126 passed, 0 failed** (real Chrome: pretty URLs, unknown→NotFound, back/forward, 4 viewports) |
| `npm run audit:capabilities` | **PASSED** (1 alias warning surfaced, not hidden) |
| Preview deploy (live curl) | `/` 200; noindex; canonical=`pre`; `robots.txt` `Disallow:/`; WAL→sqlite-forensics; PCAP/Windows/Registry fixes confirmed live |

---

## 10. Regression check (§47)

- Pretty URL / direct navigation: ✓ (smoke 126/126)
- Legacy hash routing: ✓ (`route-adapter.test.ts` + `useToolNavigation.ts` unchanged in logic)
- Standalone: ✓ (build green, verify:dist green)
- Sidebar / Command Palette / Case / Report / Tool Handoff / export / workspace: **unaffected** — changes this round were metadata/SEO/copy + alias canonical only; no workbench logic touched. WAL alias still opens correct ToolHost (smoke confirmed).

---

## 11. Remaining unverified / honest gaps

1. **Per-capability fixture tests** (§19): `audit:capabilities` + `capability-contract.test.ts` cover *consistency*, but dedicated fixture tests (sqlite sample.db-wal frame count, evtx event count, pcap DNS/HTTP/TLS) were **not added this round** — recommended next.
2. **Explicit `status` enum per capability** (§17): registry has `capabilities`+`maturity`+`validation`; a formal `verified|partial|experimental` per-capability status is a future refinement.
3. **Windows Artifacts** "accessed files" (Prefetch): kept but relies on Prefetch parse; not separately fixture-tested here.
4. **DNS response records**: PCAP parses query name/type only (not answer-section resolution) — documented as limitation, wording accurate.

---

## 12. Files changed this round (capability-audit scope)

- `src/config/app.ts` — sqlite/registry/firmware capability + accepts fixes
- `src/seo/seoPages.mjs` — all §3 wording (10 tools, EN+ZH)
- `scripts/build-seo-pages.mjs` — alias canonical/noindex, root canonical env-aware, brand
- `scripts/finalize-dist.mjs` — preview root canonical + noindex single-pass
- `index.html` — brand, 中文介绍→中文, offline wording
- `scripts/smoke-prod.mjs` — alias-aware canonical assertion (NEW)
- `scripts/audit-capabilities.mjs` — capability truth audit script (NEW)
- `tests/capability-contract.test.ts` — indexable/acceptedInput/description gate (NEW)

*(Working tree also carries unrelated prior-round changes: jwt/i18n/Web Delivery/App navigation — none committed per standing discipline.)*

---

## 13. Git state (§49)

- `git status --short`: 22 modified + 8 untracked (mixed rounds, uncommitted).
- `git diff --stat`: ~801 insertions / 935 deletions across 22 files.
- **No commit / no push / no production deploy** performed.
- Preview (`pre.forensicspp.com`) redeployed with these fixes (authorized earlier). Production site untouched.
