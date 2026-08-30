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

import { copyText } from "../utils/clipboard";
import React from "react";
import { AButton, ALinearProgress, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import type { FileSignatureDef } from "../models";
import { fileSignatures, hexPreview } from "../utils/binary";
import { formatBytes } from "../utils/files";
import { useToolWorkspace } from "../utils/useToolWorkspace";

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

function isFileIdResult(value: unknown): value is FileIdResult {
  return Boolean(value && typeof value === "object" && "name" in value && "headerHex" in value && Array.isArray((value as FileIdResult).matches));
}

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

export function FileIdTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {  const [result, setResult] = React.useState<FileIdResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [isDropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const requestRef = React.useRef(0);
  const workspace = useToolWorkspace<FileIdResult>({
    id: "file-id",
    version: 1,
    isValid: isFileIdResult,
    onRestore: (restored) => {
      setResult(restored);
      setError("");
    }
  });
  React.useEffect(() => () => { requestRef.current += 1; }, []);
  React.useEffect(() => {
    if (active) return;
    requestRef.current += 1;
    setLoading(false);
    setDropActive(false);
  }, [active]);

  const handleFile = async (file: File | undefined) => {
    if (!file || !active) return;
    const requestId = ++requestRef.current;
    setDropActive(false);
    workspace.clear();
    setLoading(true);
    setError("");
    try {
      const bytes = new Uint8Array(await file.slice(0, 64 * 1024).arrayBuffer());
      if (!active || requestId !== requestRef.current) return;
      const matches = signatureMatches(bytes);
      const nextResult = {
        name: file.name,
        size: file.size,
        mime: file.type || "--",
        modified: file.lastModified ? new Date(file.lastModified).toLocaleString() : "--",
        extension: extensionOf(file.name),
        headerHex: hexPreview(bytes, 128),
        matches,
        primary: choosePrimary(matches),
        textLike: !matches.length && isTextLike(bytes)
      } satisfies FileIdResult;
      setResult(nextResult);
      workspace.save(nextResult);
    } catch (caught) {
      if (requestId === requestRef.current) {
        setResult(null);
        setError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      if (requestId === requestRef.current) setLoading(false);
    }
  };

  const clear = () => {
    requestRef.current += 1;
    workspace.clear();
    setResult(null);
    setError("");
    setLoading(false);
    setDropActive(false);
    if (inputRef.current) inputRef.current.value = "";
  };

  const detectedType = result?.primary?.label ?? (result?.textLike ? (t.plain_text) : (t.unknown));
  const extensionMatch = result
    ? result.primary && result.extension
      ? result.primary.extensions.includes(result.extension) ? (t.yes) : (t.no)
      : "--"
    : "--";

  const summaryRows: Array<[string, string]> = result ? [
    [t.name, result.name],
    [t.fileSize, formatBytes(result.size)],
    [t.detected_type, detectedType],
    [t.extension, result.extension ? `.${result.extension}` : "--"],
    [t.extension_match, extensionMatch],
    ["MIME", result.mime],
    [t.last_modified, result.modified]
  ] : [];

  return (
    <div className={`tool-grid fileid-workbench ${result ? "has-fileid" : "empty-fileid"}`}>
      <div className="tool-panel wide-panel fileid-source-panel">
        <PanelTitle title={t.open_file} />
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void handleFile(file); }} />
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
          <AButton variant="text" disabled={!result && !error && !loading} onClick={clear}>{t.clear}</AButton>
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
                  <thead><tr><th>{t.signature}</th><th>{t.stringOffset}</th><th>{t.extensions}</th></tr></thead>
                  <tbody>
                    {result.matches.map((signature) => (
                      <tr key={`${signature.label}-${signature.offset ?? 0}`}>
                        <td>{signature.label}</td><td>{signature.offset ?? 0}</td><td>{signature.extensions.map((item) => `.${item}`).join(", ")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <div className="empty-state">{result.textLike ? (t.no_binary_signature_content_appears_to_be_text) : (t.no_known_signature_matched)}</div>}
          </div>

          <div className="tool-panel wide-panel fileid-header-panel">
            <div className="panel-heading-row">
              <PanelTitle title={t.header_bytes} />
              <AButton variant="text" onClick={() => void copyText(result.headerHex)}>{t.copy}</AButton>
            </div>
            <textarea aria-label={t.file_header_bytes} className="single-textarea compact-textarea" value={result.headerHex || "--"} readOnly />
          </div>
        </>
      )}
    </div>
  );
}
