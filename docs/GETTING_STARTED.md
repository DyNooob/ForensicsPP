# Getting started / 入门指南

[Documentation](README.md) · [工具手册](TOOLS.md) · [离线指南](OFFLINE.md)

## 1. Choose how to run / 选择运行方式

| Distribution | Requirements | Network behavior |
| --- | --- | --- |
| Hosted website | Current browser | Loads the deployed application; configured CDN and lookup requests may occur |
| Complete offline ZIP | Current browser + existing local HTTP server, or Python 3 launcher | Runtime resources and lookup packs are local; no first-use Internet requirement |
| Source checkout | Node.js 22.13+, npm 10+, browser | Dependency installation is a preparation step; `npm run dev` runs the source |

隔离网、离线竞赛和本地检查请使用 Release 中名字带 `offline-static.zip` 的完整包，完整解压并使用本地 HTTP 启动。GitHub 自动提供的 “Source code” ZIP 是源码快照，不是可直接运行的发布包。

## 2. Open a workspace / 打开工具

Use the sidebar or Home search. Search accepts tool names, identifiers and selected capability keywords in English and Chinese. Home can suggest a destination for pasted text; the destination can be changed before executing.

The evidence inbox tracks loaded files for the current session. Tools accept their supported combinations of file selection, drag-and-drop, paste and analyzer handoff. Clipboard access depends on browser permission and context; normal text paste remains available.

## 3. Inspect a file / 检查文件

1. Keep an original copy outside the browser workspace.
2. Open the matching tool and select the file.
3. Start explicit analysis when the tool presents a run action. Secondary workbench pages may run additional analysis only when requested.
4. Review the summary, findings, source offsets, confidence and limitations together.
5. Export the relevant result, extracted object or report; record the application version and source hash when needed.

界面显示“成功”表示该步骤完成，不等于文件真实、完整或可信。解析出的 EXIF、邮件头、时间戳、证书字段和归属地数据库记录都可能需要独立核验。

## 4. Common workflows / 常见工作流

### Photograph → capture details

Open **Image Workbench / 图片工作台**. Populated capture fields appear at the top of Overview. The full metadata table remains available below, with search and JSON export. Empty fields are hidden by default and can be included. HEIC/HEIF uses a local preview decoder when the browser cannot decode it directly. Preview conversion does not replace the original bytes used for metadata and structure checks.

### Binary → extracted object → specialized analyzer

Open **Binary** or **Firmware**, inspect discovered objects and their boundary confidence, then hand a supported object to the suggested analyzer. Signature matches with unknown or heuristic extent need examiner review; an extraction is not necessarily a complete original file.

### Database → records → recovery candidates

Open **SQLite**, browse live tables and inspect the available forensic pages. Recovery candidates and historical WAL content have separate provenance and limitations. Preserve an original copy before enabling database edits or exporting a changed database.

### Chinese text → converted text

Open **Chinese conversion / 简繁转换** directly from the sidebar. Select the Traditional variant, paste text and choose a direction. `Ctrl/⌘ + Enter` converts to Simplified; adding `Shift` converts to Traditional. The Taiwan phrase option changes regional vocabulary in addition to glyphs. Names and ambiguous one-to-many characters still require review.

## 5. Export and resume / 导出与恢复

Supported tool state may be restored from browser storage, subject to tool-specific limits. This is convenience storage, not evidence custody. Clearing site data, browser policies or quota errors can remove or prevent restoration.

Case reporting uses structured analyzer results where available and a legacy fallback for remaining views. A `.fppcase` package records case data, notes, evidence references, timeline and analysis snapshots; it does not embed raw source evidence by default. See [analysis contracts](architecture/ANALYSIS_CONTRACTS.md).

## 6. Resolve a problem / 遇到问题

Check [troubleshooting](TROUBLESHOOTING.md) before filing a report. Include the version, distribution, tool, browser, reproduction steps and a synthetic/public sample. Report security issues privately through [SECURITY.md](../SECURITY.md).
