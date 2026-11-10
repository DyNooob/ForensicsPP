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
import { AButton, ASelect, ToolPanelHeader } from "./ui";
import { AutoTextarea } from "./AutoTextarea";
import { useStoredState } from "../utils/storage";
import { copyText } from "../utils/clipboard";
import { downloadTextFile } from "../utils/files";
import { runWorkerTask } from "../utils/workerTask";
import type { ChineseRegion, ChineseRequest } from "../features/codec/chinese";

export function ChineseConverter({ english, active }: { english: boolean; active: boolean }) {
  const [input, setInput] = useStoredState("chinese.input.v1", "");
  const [output, setOutput] = useStoredState("chinese.output.v1", "");
  const [region, setRegion] = useStoredState<ChineseRegion>("chinese.region.v1", "t");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [status, setStatus] = React.useState("");
  const fileInput = React.useRef<HTMLInputElement>(null);
  const controller = React.useRef<AbortController | null>(null);
  const request = React.useRef(0);
  const stop = () => { request.current++; controller.current?.abort(); controller.current = null; setBusy(false); setStatus(""); };
  React.useEffect(() => { if (!active) stop(); return () => { request.current++; controller.current?.abort(); }; }, [active]);
  const change = (text: string) => { stop(); setInput(text); setOutput(""); setError(""); };
  const run = async (direction: ChineseRequest["direction"]) => {
    if (!active || !input) return;
    stop();
    const id = request.current;
    const abort = new AbortController(); controller.current = abort;
    setBusy(true); setError(""); setOutput("");
    try {
      const result = await runWorkerTask<ChineseRequest, string>({
        createWorker: () => new Worker(new URL("../features/codec/chinese.worker.ts", import.meta.url), { type: "module" }),
        request: { input, direction, region }, signal: abort.signal, timeoutMs: 60_000
      });
      if (id !== request.current) return;
      setOutput(result);
      setStatus(english ? `${direction === "toSimplified" ? "Converted to Simplified" : "Converted to Traditional"} · ${result.length.toLocaleString()} UTF-16 units${result === input ? " · No changes needed" : ""}` : `${direction === "toSimplified" ? "已转为简体" : "已转为繁体"} · ${result.length.toLocaleString()} 字符${result === input ? " · 内容无需变化" : ""}`);
    } catch (error) {
      if (id === request.current && !abort.signal.aborted) setError(error instanceof Error ? error.message : String(error));
    } finally { if (id === request.current) { setBusy(false); controller.current = null; } }
  };
  const openFile = async (file?: File) => {
    if (!file || !active) return;
    stop(); const id = request.current;
    if (file.size > 2 * 1024 * 1024) { setError(english ? "Text files must be under 2 MiB." : "文本文件不能超过 2 MiB。"); return; }
    try { const text = await file.text(); if (id === request.current) change(text); }
    catch (error) { if (id === request.current) setError(String(error)); }
  };
  return <section className="tool-panel wide-panel chinese-converter" onKeyDown={(event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter" && !event.nativeEvent.isComposing) { event.preventDefault(); void run(event.shiftKey ? "toTraditional" : "toSimplified"); }
  }}>
    <ToolPanelHeader title={english ? "Simplified / Traditional Chinese" : "简繁转换"} actions={<>
      <AButton onClick={() => fileInput.current?.click()}>{english ? "Open text file" : "打开文本文件"}</AButton>
      <AButton disabled={!output} onClick={() => { const previous = input; change(output); setOutput(previous); }}>{english ? "Swap input / output" : "交换输入与结果"}</AButton>
      <AButton variant="text" disabled={!input && !output} onClick={() => change("")}>{english ? "Clear" : "清空"}</AButton>
    </>} />
    <p className="inline-note">{english ? "Offline OpenCC dictionaries · conversion runs locally. Phrase conversion distinguishes characters in context, such as 頭髮 / 發展." : "内置 OpenCC 离线词库 · 转换在本地完成。支持词组转换，例如区分「頭髮 / 發展」中的“发”。"}</p>
    <input ref={fileInput} type="file" className="hidden-file-input" accept=".txt,.md,.log,.csv,.json,text/*" aria-hidden="true" tabIndex={-1} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void openFile(file); }} />
    <div className="chinese-conversion-controls">
      <label className="stack-label">{english ? "Traditional variant" : "繁体字形与用词"}<ASelect aria-label={english ? "Traditional variant" : "繁体字形与用词"} value={region} onChange={(value) => { stop(); setRegion(value as ChineseRegion); setOutput(""); }} options={[
        { value: "t", label: english ? "Standard Traditional" : "标准繁体（字形转换）" },
        { value: "tw", label: english ? "Taiwan Traditional" : "台湾正体（字形转换）" },
        { value: "twp", label: english ? "Taiwan with regional phrases" : "台湾正体 + 地区用词" },
        { value: "hk", label: english ? "Hong Kong Traditional" : "香港繁体" }
      ]} /></label>
      <AButton variant="filled" disabled={!input || busy} onClick={() => void run("toSimplified")}>{english ? "Traditional → Simplified" : "繁体 → 简体"}</AButton>
      <AButton disabled={!input || busy} onClick={() => void run("toTraditional")}>{english ? "Simplified → Traditional" : "简体 → 繁体"}</AButton>
      {busy && <AButton onClick={stop}>{english ? "Cancel" : "取消"}</AButton>}
    </div>
    <p className="inline-note">{english ? "Keyboard: Ctrl / ⌘ + Enter → Simplified; add Shift → Traditional. Text import uses UTF-8 (up to 2 MiB)." : "键盘快捷转换：Ctrl / ⌘ + Enter 转简体，加 Shift 转繁体。文本文件按 UTF-8 读取，上限 2 MiB。"}</p>
    <div className="chinese-text-columns">
      <div className="text-panel"><div className="text-panel-title"><strong>{english ? "Original text" : "原文"}</strong><AButton variant="text" onClick={() => change("头发与发展，后台与皇后。软件、鼠标和计算机。\n頭髮與發展，後臺與皇后。軟體、滑鼠和電腦。")}>{english ? "Try example" : "载入示例"}</AButton></div>
        <AutoTextarea aria-label={english ? "Chinese input text" : "简繁转换原文"} value={input} onChange={(event) => change(event.currentTarget.value)} placeholder={english ? "Type or paste Chinese text…" : "输入或粘贴中文，选择上方方向开始转换…"} />
      </div>
      <div className="text-panel"><div className="text-panel-title"><strong>{english ? "Converted text" : "转换结果"}</strong><div className="mini-actions"><AButton variant="text" disabled={!output} onClick={() => void copyText(output)}>{english ? "Copy" : "复制结果"}</AButton><AButton variant="text" disabled={!output} onClick={() => downloadTextFile("chinese-converted.txt", output, "text/plain;charset=utf-8")}>{english ? "Download TXT" : "下载 TXT"}</AButton></div></div>
        <AutoTextarea aria-label={english ? "Chinese conversion output" : "简繁转换结果"} value={output} readOnly placeholder={english ? "The converted text appears here" : "转换后的文字会显示在这里"} />
      </div>
    </div>
    <div role="status" aria-live="polite" className="inline-note">{busy ? (english ? "Converting locally…" : "正在本地转换…") : status}</div>
    {error && <div role="alert" className="empty-state error-state">{error}</div>}
    <p className="inline-note">{english ? "Some Simplified characters have multiple Traditional forms. Review names and specialist terms against the original." : "简繁之间存在一对多与合并字形，姓名、专有名词请结合原文复核。"}</p>
  </section>;
}
