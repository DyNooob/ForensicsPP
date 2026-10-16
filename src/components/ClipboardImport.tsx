/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.forensicspp.com
 * Platform: DigiForensics.cn
 * Project: https://github.com/DyNooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import React from "react";
import { createPortal } from "react-dom";
import { AButton } from "./ui";
import { acceptsClipboardFile, filesFromClipboard, insertClipboardText, readClipboardPayload, requestClipboardImport } from "../utils/clipboardImport";
import { analyzerForArtifact } from "../core/analyzerRouting";
import { dispatchToolHandoff } from "../core/toolHandoff";
import { captureEvidence } from "../core/evidence/inbox";
import { rememberEvidenceFiles } from "../features/reporter/evidence";
import { launchTarget } from "../core/launchTarget";
import { saveHomeToolDraft } from "../app/useHomeToolDraft";
import type { ToolId } from "../config/app";

export function PasteButton({ english }: { english: boolean }) {
  return <AButton className="clipboard-paste-button" variant="outlined" aria-label={english ? "Paste image, file or text" : "粘贴图片、文件或文字"} onMouseDown={(event) => event.preventDefault()} onClick={requestClipboardImport} title={english ? "Paste image, file or text · Ctrl/Cmd+V" : "粘贴图片、文件或文字 · Ctrl/Cmd+V"}><span aria-hidden="true">⎘</span><span>{english ? "Paste" : "粘贴"}</span></AButton>;
}

export function ClipboardImport({ activeTool, english, enabled, onSelectTool, onOpenFiles }: {
  activeTool: ToolId; english: boolean; enabled: boolean; onSelectTool: (tool: ToolId) => void; onOpenFiles: () => void;
}) {
  const [notice, setNotice] = React.useState("");
  const [multiple, setMultiple] = React.useState(false);
  const [menu, setMenu] = React.useState<{ x: number; y: number } | null>(null);
  const menuButton = React.useRef<HTMLButtonElement>(null);
  const state = React.useRef({ activeTool, english, enabled, onSelectTool });
  state.current = { activeTool, english, enabled, onSelectTool };
  const operation = React.useRef(0);
  const root = () => document.querySelector<HTMLElement>(`[data-tool-id="${state.current.activeTool}"]:not([hidden])`);
  const importFiles = React.useCallback(async (files: File[]) => {
    if (!files.length || !state.current.enabled) return;
    const run = ++operation.current;
    const initialTool = state.current.activeTool;
    const file = files[0];
    const bytes = new Uint8Array(await file.slice(0, 65536).arrayBuffer());
    if (run !== operation.current || initialTool !== state.current.activeTool) return;
    const target = analyzerForArtifact({ label: file.name, mime: file.type, bytes });
    captureEvidence(files, "paste", "home");
    const input = root()?.querySelector<HTMLInputElement>('input[type="file"]:not([webkitdirectory]):not(:disabled)');
    const useCurrent = initialTool !== "home" && (initialTool === target || ["hash", "binary", "firmware", "bulk"].includes(initialTool) || Boolean(input && acceptsClipboardFile(input.accept, file)));
    if (input && useCurrent) {
      const transfer = new DataTransfer();
      (input.multiple ? files : [file]).forEach((file) => transfer.items.add(file));
      input.files = transfer.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    } else {
      dispatchToolHandoff({ sourceTool: initialTool, targetTool: target, file, label: file.name });
      state.current.onSelectTool(target);
      requestAnimationFrame(() => rememberEvidenceFiles(document.querySelector(`[data-tool-id="${target}"]`), [file]));
    }
    setMultiple(files.length > 1);
    setNotice(state.current.english ? (files.length > 1 ? `${files.length} files pasted. The first is open; all are available in Files.` : `Pasted ${file.name}`) : (files.length > 1 ? `已粘贴 ${files.length} 个文件。首个文件已打开，全部文件可在“文件”中继续分析。` : `已粘贴 ${file.name}`));
  }, []);
  const read = React.useCallback(async () => {
    setMenu(null);
    try {
      if (!state.current.enabled) return;
      const request = ++operation.current;
      const tool = state.current.activeTool;
      const { files, text } = await readClipboardPayload();
      if (request !== operation.current || tool !== state.current.activeTool) return;
      if (files.length) { await importFiles(files); return; }
      if (text) {
        const focused = document.activeElement;
        const editable = focused instanceof HTMLTextAreaElement || focused instanceof HTMLInputElement && ["text", "search", "url", "tel", "password"].includes(focused.type);
        const field = editable && !focused.readOnly && !focused.disabled ? focused : root()?.querySelector<HTMLTextAreaElement>('textarea:not([readonly]):not(:disabled)');
        if (field) insertClipboardText(field, text);
        else { const target = launchTarget(text); saveHomeToolDraft(target, text); state.current.onSelectTool(target); }
        return;
      }
      setMultiple(false);
      setNotice(state.current.english ? "No supported clipboard content. Copy an image or file, then try Ctrl/Cmd+V." : "剪贴板没有可读取的内容。请复制图片或文件，再按 Ctrl/Cmd+V。");
    } catch {
      setMultiple(false);
      setNotice(state.current.english ? "Clipboard access is unavailable. Click the page and press Ctrl/Cmd+V, or choose a file." : "浏览器暂未允许读取剪贴板。请点击页面后按 Ctrl/Cmd+V，或直接选择文件。");
    }
  }, [importFiles]);

  React.useEffect(() => {
    const paste = (event: ClipboardEvent) => {
      if (!state.current.enabled || (event.target instanceof Element && event.target.closest('.ant-modal, .ant-drawer, [role="dialog"]'))) return;
      const files = filesFromClipboard(event.clipboardData);
      if (!files.length) return; // Text paste retains the browser's editing behavior.
      event.preventDefault();
      void importFiles(files).catch(() => setNotice(state.current.english ? "Unable to read the pasted file. Try choosing it directly." : "无法读取粘贴的文件，请尝试直接选择文件。"));
    };
    const context = (event: MouseEvent) => {
      if (!state.current.enabled || !(event.target instanceof Element) || window.getSelection()?.toString()) return;
      if (event.target.closest('input, textarea, [contenteditable="true"], a, button, img, pre, code, table, [role="dialog"]')) return;
      if (!event.target.closest('.tool-panel, .home-file-drop, .desktop-drop-zone, .home-hero')) return;
      event.preventDefault();
      setMenu({ x: Math.max(8, Math.min(event.clientX, window.innerWidth - 220)), y: Math.max(8, Math.min(event.clientY, window.innerHeight - 60)) });
    };
    document.addEventListener("paste", paste);
    document.addEventListener("contextmenu", context);
    window.addEventListener("forensicspp:clipboard-import", read);
    return () => { document.removeEventListener("paste", paste); document.removeEventListener("contextmenu", context); window.removeEventListener("forensicspp:clipboard-import", read); operation.current += 1; };
  }, [importFiles, read]);
  React.useEffect(() => {
    if (!menu) return;
    const previous = document.activeElement as HTMLElement | null;
    menuButton.current?.focus();
    const close = (event: Event) => { if (event.target instanceof Element && event.target.closest('.clipboard-context-menu')) return; setMenu(null); };
    const escape = (event: KeyboardEvent) => { if (event.key === "Escape") { setMenu(null); previous?.focus(); } };
    document.addEventListener("pointerdown", close);
    window.addEventListener("keydown", escape);
    window.addEventListener("scroll", close, true);
    return () => { document.removeEventListener("pointerdown", close); window.removeEventListener("keydown", escape); window.removeEventListener("scroll", close, true); };
  }, [menu]);
  React.useEffect(() => { setMenu(null); }, [activeTool]);
  React.useEffect(() => {
    if (!notice || multiple) return;
    const timer = window.setTimeout(() => setNotice(""), 6000);
    return () => window.clearTimeout(timer);
  }, [notice, multiple]);
  return <>
    {notice && <div className="clipboard-notice" role="status"><span>{notice}</span>{multiple && <AButton size="small" onClick={onOpenFiles}>{english ? "View files" : "查看文件"}</AButton>}<AButton size="small" variant="text" onClick={() => setNotice("")} aria-label={english ? "Dismiss clipboard message" : "关闭粘贴提示"}>×</AButton></div>}
    {menu && createPortal(<div className="clipboard-context-menu" role="menu" style={{ left: menu.x, top: menu.y }}><button ref={menuButton} type="button" role="menuitem" onClick={() => void read()}>{english ? "Paste image / file" : "粘贴图片 / 文件"}<kbd>Ctrl/Cmd+V</kbd></button></div>, document.body)}
  </>;
}
