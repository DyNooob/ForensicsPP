/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import { copyText } from "../utils/clipboard";
import React from "react";
import { AButton, ASelect, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import { downloadTextFile } from "../utils/files";
import { useStoredState } from "../utils/storage";

type CodecFormat = {
  id: string;
  label: string;
  forward: string;
  reverse: string;
  group: "basic" | "text";
};

type DirectOperation = {
  id: string;
  label: string;
  group: "detect" | "charset" | "text";
};

const MAX_CODEC_FILE_BYTES = 16 * 1024 * 1024;

export type CodecToolServices = {
  transformText: (operation: string, input: string) => string;
};

export function CodecTool({ t, services, active = true }: { t: (typeof copy)["zh"]; services: CodecToolServices; active?: boolean }) {
  const [input, setInput] = useStoredState("codec.input.v2", "");
  const [output, setOutput] = useStoredState("codec.output.v2", "");
  const [operation, setOperation] = useStoredState("codec.operation", "urle");
  const [selectedFormat, setSelectedFormat] = useStoredState("codec.selectedFormat", "url");
  const [directOperation, setDirectOperation] = useStoredState("codec.directOperation", "autocodec");
  const [error, setError] = React.useState("");
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const requestRef = React.useRef(0);
  React.useEffect(() => {
    if (active) return;
    requestRef.current += 1;
  }, [active]);
  const english = t.waiting === "Waiting";

  const formats: CodecFormat[] = [
    { id: "url", label: "URL", forward: "urle", reverse: "urld", group: "basic" },
    { id: "base64", label: "Base64", forward: "b64e", reverse: "b64d", group: "basic" },
    { id: "base64url", label: "Base64URL", forward: "b64ue", reverse: "b64ud", group: "basic" },
    { id: "hex", label: "Hex", forward: "hex", reverse: "unhex", group: "basic" },
    { id: "binary", label: t.binaryBase, forward: "bin", reverse: "unbin", group: "basic" },
    { id: "base32", label: "Base32", forward: "base32e", reverse: "base32d", group: "basic" },
    { id: "base58", label: "Base58", forward: "base58e", reverse: "base58d", group: "basic" },
    { id: "unicode", label: "Unicode", forward: "unicode", reverse: "ununicode", group: "text" },
    { id: "quoted-printable", label: "Quoted-Printable", forward: "qpe", reverse: "qpd", group: "text" },
    { id: "escape", label: "Escape", forward: "escapee", reverse: "escaped", group: "text" },
    { id: "html", label: "HTML Entity", forward: "html", reverse: "unhtml", group: "text" },
    { id: "shellcode", label: "Shellcode", forward: "shell", reverse: "unshell", group: "text" }
  ];
  const directOperations: DirectOperation[] = [
    { id: "autocodec", label: t.autoDetectCodec, group: "detect" },
    { id: "detectjs", label: t.detectObfuscation, group: "detect" },
    { id: "gb18030d", label: "GB18030 Decode", group: "charset" },
    { id: "gbkd", label: "GBK Decode", group: "charset" },
    { id: "big5d", label: "Big5 Decode", group: "charset" },
    { id: "shiftjisd", label: "Shift_JIS Decode", group: "charset" },
    { id: "euckrd", label: "EUC-KR Decode", group: "charset" },
    { id: "utf16led", label: "UTF-16LE Decode", group: "charset" },
    { id: "utf16bed", label: "UTF-16BE Decode", group: "charset" },
    { id: "iso88591d", label: "ISO-8859-1 Decode", group: "charset" },
    { id: "windows1252d", label: "Windows-1252 Decode", group: "charset" },
    { id: "utf8hex", label: "UTF-8 → bytes", group: "charset" },
    { id: "utf16lehex", label: "UTF-16LE → bytes", group: "charset" },
    { id: "windows1252hex", label: "Windows-1252 → bytes", group: "charset" },
    { id: "rot13", label: "ROT13", group: "text" },
    { id: "reverse", label: t.reverse, group: "text" },
    { id: "upper", label: t.uppercase, group: "text" },
    { id: "lower", label: t.lowercase, group: "text" }
  ];
  const activeFormat = formats.find((item) => item.id === selectedFormat) ?? formats[0];
  const hasContent = Boolean(input || output);

  const run = (nextOperation: string) => {
    try {
      setOperation(nextOperation);
      setOutput(services.transformText(nextOperation, input));
      setError("");
    } catch (caught) {
      setOutput("");
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };
  const openFile = async (file?: File) => {
    if (!file || !active) return;
    const requestId = ++requestRef.current;
    setInput("");
    setOutput("");
    setError("");
    if (file.size > MAX_CODEC_FILE_BYTES) {
      setError(english ? "The file exceeds the 16 MiB limit." : "文件超过 16 MiB 限制。");
      return;
    }
    try {
      const value = await file.text();
      if (!active || requestId !== requestRef.current) return;
      setInput(value);
    } catch (caught) {
      if (active && requestId === requestRef.current) setError(caught instanceof Error ? caught.message : String(caught));
    }
  };
  const clear = () => {
    requestRef.current += 1;
    setInput("");
    setOutput("");
    setError("");
  };
  const swap = () => {
    setInput(output);
    setOutput(input);
    setError("");
  };
  const groupLabel = (group: CodecFormat["group"]) => group === "basic" ? t.codecBasic : t.codecText;
  const directGroupLabel = (group: DirectOperation["group"]) => {
    if (group === "detect") return t.codecFormat;
    if (group === "charset") return t.codecCharset;
    if (group === "text") return english ? "Text operations" : "文本操作";
    return english ? "Text operations" : "文本操作";
  };

  return (
    <div className={`tool-grid codec-workbench codec-simple-workbench ${hasContent ? "has-codec" : "empty-codec"}`}>
      <div className="tool-panel wide-panel codec-simple-panel">
        <ToolPanelHeader
          title={english ? "Encode / Decode" : "编码解码"}
          actions={<>
            <AButton variant="outlined" onClick={() => inputRef.current?.click()}>{t.codecOpenFile}</AButton>
            <AButton variant="outlined" disabled={!output} onClick={swap}>{t.swapText}</AButton>
            <AButton variant="text" disabled={!hasContent} onClick={clear}>{t.clear}</AButton>
          </>}
        />
        <input className="hidden-file-input" ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} accept=".txt,.log,.csv,.json,.xml,.html,.eml,text/*,message/rfc822,application/json" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void openFile(file); }} />

        <div className="codec-simple-controls">
          <section className="codec-simple-operation-row">
            <label className="stack-label">{english ? "Format" : "转换格式"}
              <ASelect
                aria-label={english ? "Format" : "转换格式"}
                value={activeFormat.id}
                onChange={(value) => setSelectedFormat(String(value))}
                options={(["basic", "text"] as CodecFormat["group"][]).map((group) => ({
                  label: groupLabel(group),
                  options: formats.filter((item) => item.group === group).map((item) => ({ value: item.id, label: item.label }))
                }))}
              />
            </label>
            <div className="codec-simple-primary-actions">
              <AButton variant={operation === activeFormat.forward ? "filled" : "outlined"} disabled={!input} onClick={() => run(activeFormat.forward)}>{t.encodeAction}</AButton>
              <AButton variant={operation === activeFormat.reverse ? "filled" : "outlined"} disabled={!input} onClick={() => run(activeFormat.reverse)}>{t.decodeAction}</AButton>
            </div>
          </section>

          <section className="codec-simple-operation-row secondary">
            <label className="stack-label">{english ? "Other operation" : "其他操作"}
              <ASelect
                aria-label={english ? "Other operation" : "其他操作"}
                value={directOperation}
                onChange={(value) => setDirectOperation(String(value))}
                options={(["detect", "charset", "text"] as DirectOperation["group"][]).map((group) => ({
                  label: directGroupLabel(group),
                  options: directOperations.filter((item) => item.group === group).map((item) => ({ value: item.id, label: item.label }))
                }))}
              />
            </label>
            <AButton variant="outlined" disabled={!input} onClick={() => run(directOperation)}>{english ? "Run" : "执行"}</AButton>
          </section>
        </div>

        <div className="text-panel codec-simple-text-panel">
          <div className="text-panel-title"><strong>{t.inputText}</strong><div className="mini-actions"><AButton variant="text" disabled={!input} onClick={() => void copyText(input)}>{t.copyInput}</AButton><AButton variant="text" disabled={!input} onClick={() => downloadTextFile(`codec-input-${Date.now()}.txt`, input, "text/plain;charset=utf-8")}>{t.download}</AButton></div></div>
          <textarea className="codec-simple-textarea" aria-label={english ? "Input text" : "输入文本"} value={input} onChange={(event) => { requestRef.current += 1; setInput(event.currentTarget.value); setOutput(""); setError(""); }} placeholder={t.textPlaceholder} />
        </div>
        {error && <div className="empty-state error-state">{error}</div>}
        <div className="text-panel codec-simple-text-panel">
          <div className="text-panel-title"><strong>{t.outputText}</strong><div className="mini-actions"><AButton variant="text" disabled={!output} onClick={() => void copyText(output)}>{t.copyOutput}</AButton><AButton variant="text" disabled={!output} onClick={() => downloadTextFile(`codec-output-${Date.now()}.txt`, output, "text/plain;charset=utf-8")}>{t.download}</AButton><AButton variant="text" disabled={!output} onClick={() => { setInput(output); setOutput(""); setError(""); }}>{t.codecApplyCandidate}</AButton></div></div>
          <textarea className="codec-simple-textarea" aria-label={english ? "Output text" : "输出文本"} value={output} readOnly />
        </div>
      </div>
    </div>
  );
}
