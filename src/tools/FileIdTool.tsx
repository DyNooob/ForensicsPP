/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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
import { AButton, ALinearProgress, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import type { FileSignatureDef } from "../models";
import { fileSignatures, hexPreview } from "../utils/binary";
import { formatBytes } from "../utils/files";

type FileIdResult = {
  name: string;
  size: number;
  mime: string;
  modified: string;
  extension: string;
  headerHex: string;
  matches: FileSignatureDef[];
  primary: FileSignatureDef | null;
  textLike: boolean;
};

function extensionOf(name: string) {
  const base = name.split(/[\\/]/).pop() ?? name;
  const index = base.lastIndexOf(".");
  return index > 0 ? base.slice(index + 1).toLowerCase() : "";
}

function signatureMatches(bytes: Uint8Array) {
  return fileSignatures.filter((signature) => {
    const offset = signature.offset ?? 0;
    const expected = signature.bytes.split(/\s+/).map((value) => Number.parseInt(value, 16));
    return expected.every((value, index) => bytes[offset + index] === value);
  });
}

function choosePrimary(matches: FileSignatureDef[]) {
  return [...matches].sort((left, right) => {
    const score = (item: FileSignatureDef) => item.bytes.split(/\s+/).length + (item.offset ? 10 : 0) - (/RIFF|ISO BMFF|ZIP \/ OOXML/i.test(item.label) ? 2 : 0);
    return score(right) - score(left);
  })[0] ?? null;
}

function isTextLike(bytes: Uint8Array) {
  if (!bytes.length) return false;
  const sample = bytes.subarray(0, Math.min(bytes.length, 8192));
  let printable = 0;
  let zero = 0;
  for (const byte of sample) {
    if (byte === 0) zero += 1;
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126) || byte >= 0x80) printable += 1;
  }
  return zero === 0 && printable / sample.length > 0.88;
}

export function FileIdTool({ t }: { t: (typeof copy)["zh"] }) {
  const english = t.waiting === "Waiting";
  const [result, setResult] = React.useState<FileIdResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [isDropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    setDropActive(false);
    setLoading(true);
    setError("");
    try {
      const bytes = new Uint8Array(await file.slice(0, 64 * 1024).arrayBuffer());
      const matches = signatureMatches(bytes);
      setResult({
        name: file.name,
        size: file.size,
        mime: file.type || "--",
        modified: file.lastModified ? new Date(file.lastModified).toLocaleString() : "--",
        extension: extensionOf(file.name),
        headerHex: hexPreview(bytes, 128),
        matches,
        primary: choosePrimary(matches),
        textLike: !matches.length && isTextLike(bytes)
      });
    } catch (caught) {
      setResult(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  };

  const clear = () => {
    setResult(null);
    setError("");
    setLoading(false);
    setDropActive(false);
    if (inputRef.current) inputRef.current.value = "";
  };

  const detectedType = result?.primary?.label ?? (result?.textLike ? (english ? "Plain text" : "文本文件") : (english ? "Unknown" : "未知"));
  const extensionMatch = result
    ? result.primary && result.extension
      ? result.primary.extensions.includes(result.extension) ? (english ? "Yes" : "是") : (english ? "No" : "否")
      : "--"
    : "--";

  const summaryRows: Array<[string, string]> = result ? [
    [english ? "Name" : "名称", result.name],
    [t.fileSize, formatBytes(result.size)],
    [english ? "Detected type" : "识别类型", detectedType],
    [english ? "Extension" : "扩展名", result.extension ? `.${result.extension}` : "--"],
    [english ? "Extension match" : "扩展名匹配", extensionMatch],
    ["MIME", result.mime],
    [english ? "Last modified" : "最后修改", result.modified]
  ] : [];

  return (
    <div className={`tool-grid fileid-workbench ${result ? "has-fileid" : "empty-fileid"}`}>
      <div className="tool-panel wide-panel fileid-source-panel">
        <PanelTitle title={english ? "Open file" : "选择文件"} />
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} onChange={(event) => void handleFile(event.target.files?.[0])} />
        <div
          className={`desktop-drop-zone ${isDropActive ? "active" : ""}`}
          role="button"
          tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              inputRef.current?.click();
            }
          }}
          onDragOver={(event) => {
            event.preventDefault();
            setDropActive(true);
          }}
          onDragLeave={() => setDropActive(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDropActive(false);
            void handleFile(event.dataTransfer.files?.[0]);
          }}
        >
          <strong>{result?.name || t.dropFileTitle}</strong>
          <span>{result ? `${detectedType} · ${formatBytes(result.size)}` : t.dropFileHint}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="text" disabled={!result && !error} onClick={clear}>{t.clear}</AButton>
        </div>
        {loading && <ALinearProgress />}
        {error && <pre className="result-box">{error}</pre>}
      </div>

      {result && (
        <>
          <div className="tool-panel wide-panel fileid-summary-panel">
            <PanelTitle title={t.fileProfile} />
            <InfoTable rows={summaryRows} />
          </div>

          <div className="tool-panel wide-panel fileid-signatures-panel">
            <PanelTitle title={t.matchedSignatures} />
            {result.matches.length ? (
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>{english ? "Signature" : "签名"}</th><th>{english ? "Offset" : "偏移"}</th><th>{english ? "Extensions" : "扩展名"}</th></tr></thead>
                  <tbody>
                    {result.matches.map((signature) => (
                      <tr key={`${signature.label}-${signature.offset ?? 0}`}>
                        <td>{signature.label}</td><td>{signature.offset ?? 0}</td><td>{signature.extensions.map((item) => `.${item}`).join(", ")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <div className="empty-state">{result.textLike ? (english ? "No binary signature; content appears to be text." : "未匹配二进制签名，内容看起来是文本。") : (english ? "No known signature matched." : "未匹配已知文件签名。")}</div>}
          </div>

          <div className="tool-panel wide-panel fileid-header-panel">
            <div className="panel-heading-row">
              <PanelTitle title={english ? "Header bytes" : "文件头字节"} />
              <AButton variant="text" onClick={() => void navigator.clipboard.writeText(result.headerHex)}>{t.copy}</AButton>
            </div>
            <textarea aria-label={english ? "File header bytes" : "文件头字节"} className="single-textarea compact-textarea" value={result.headerHex || "--"} readOnly />
          </div>
        </>
      )}
    </div>
  );
}
