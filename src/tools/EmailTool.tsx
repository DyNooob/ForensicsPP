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
import { zipSync } from "fflate";
import { AButton, ALinearProgress, InfoTable, PanelTitle } from "../components/ui";
import {
  emailAttachmentPreferredExtension,
  emailSummaryValue,
} from "../features/email/workbench";
import { isMsgFile } from "../features/email/msg";
import { copy } from "../i18n";
import type { EmailAnalysis } from "../models";
import { downloadBlob, downloadTextFile, formatBytes, limitReportText } from "../utils/files";
import { hashBytesInWorker } from "../features/hash/task";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { runWorkerTask } from "../utils/workerTask";

const EMAIL_FILE_LIMIT = 64 * 1024 * 1024;
const MAX_PERSISTED_EMAIL_BYTES = 8 * 1024 * 1024;
const MAX_PERSISTED_EMAIL_BODY_CHARS = 512 * 1024;
export const MAX_EMAIL_HTML_PREVIEW_CHARS = 2 * 1024 * 1024;

export function limitEmailHtmlPreview(value: string) {
  return value.slice(0, MAX_EMAIL_HTML_PREVIEW_CHARS);
}
type EmailWorkerResult = { analysis: EmailAnalysis; source: string };
type EmailWorkerRequest = { format: "eml"; source: string } | { format: "msg"; bytes: ArrayBuffer };
type EmailWorkspace = {
  input: string;
  sourceFormat: "eml" | "msg";
  sourceBytes: Uint8Array | null;
  parsed: EmailAnalysis;
};

function persistableEmailWorkspace(value: EmailWorkspace): EmailWorkspace {
  let retained = 0;
  const inputBytes = new TextEncoder().encode(value.input).byteLength;
  const input = value.sourceFormat === "eml" && inputBytes > MAX_PERSISTED_EMAIL_BYTES ? "" : value.input;
  const sourceBytes = value.sourceBytes && value.sourceBytes.byteLength <= MAX_PERSISTED_EMAIL_BYTES ? value.sourceBytes.slice() : null;
  const attachments = value.parsed.attachments.map((attachment) => {
    if (attachment.content.byteLength > 0 && retained + attachment.content.byteLength <= MAX_PERSISTED_EMAIL_BYTES) {
      retained += attachment.content.byteLength;
      return { ...attachment, content: attachment.content.slice() };
    }
    return { ...attachment, content: new Uint8Array() };
  });
  const bodyText = value.parsed.bodyText.length > MAX_PERSISTED_EMAIL_BODY_CHARS
    ? `${value.parsed.bodyText.slice(0, MAX_PERSISTED_EMAIL_BODY_CHARS)}\n\n[preview truncated for local storage]`
    : value.parsed.bodyText;
  const bodyHtml = value.parsed.bodyHtml.length > MAX_PERSISTED_EMAIL_BODY_CHARS
    ? `${value.parsed.bodyHtml.slice(0, MAX_PERSISTED_EMAIL_BODY_CHARS)}<!-- preview truncated for local storage -->`
    : value.parsed.bodyHtml;
  return { ...value, input, sourceBytes, parsed: { ...value.parsed, bodyText, bodyHtml, attachments } };
}

function safeEmailFilename(value: string, fallback: string) {
  const cleaned = value
    .split(/[\\/]/)
    .pop()
    ?.replace(/[^\w.\-()[\] 一-龥]+/g, "_")
    .replace(/^_+|_+$/g, "") ?? "";
  return cleaned || fallback;
}

function sanitizeEmailHtml(value: string) {
  if (!value.trim()) return "";
  const truncated = value.length > MAX_EMAIL_HTML_PREVIEW_CHARS;
  const document = new DOMParser().parseFromString(limitEmailHtmlPreview(value), "text/html");
  document.querySelectorAll("script, iframe, object, embed, form, input, button, link, meta, style").forEach((node) => node.remove());
  document.querySelectorAll<HTMLElement>("*").forEach((node) => {
    for (const attribute of Array.from(node.attributes)) {
      if (/^on/i.test(attribute.name)) node.removeAttribute(attribute.name);
      if (/^(src|srcset|background|poster|action|formaction)$/i.test(attribute.name)) node.removeAttribute(attribute.name);
      if (attribute.name === "style" && /url\s*\(|expression\s*\(|behavior\s*:/i.test(attribute.value)) node.removeAttribute(attribute.name);
      if (attribute.name === "href" && !/^(?:#|mailto:|tel:)/i.test(attribute.value.trim())) node.setAttribute("href", "#");
    }
  });
  if (truncated) {
    const notice = document.createElement("p");
    notice.textContent = "[HTML preview truncated]";
    notice.setAttribute("data-preview-limit", "true");
    document.body.append(notice);
  }
  const baseStyle = "body{margin:0;padding:18px;color:#182230;background:#fff;font:14px/1.65 system-ui,sans-serif;overflow-wrap:anywhere}img{max-width:100%;height:auto}pre{white-space:pre-wrap}table{max-width:100%;border-collapse:collapse}td,th{padding:6px;border:1px solid #d9e0e8}";
  return `<!doctype html><html><head><meta charset="utf-8"><style>${baseStyle}</style></head><body>${document.body.innerHTML}</body></html>`;
}

export function EmailTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {
  const [input, setInput] = React.useState("");
  const [sourceFormat, setSourceFormat] = React.useState<"eml" | "msg">("eml");
  const [sourceBytes, setSourceBytes] = React.useState<Uint8Array | null>(null);
  const [parsed, setParsed] = React.useState<EmailAnalysis | null>(null);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [bodyMode, setBodyMode] = React.useState<"text" | "html">("text");
  const [attachmentHashes, setAttachmentHashes] = React.useState<Record<string, string>>({});
  const [attachmentHashingKey, setAttachmentHashingKey] = React.useState("");
  const [attachmentHashError, setAttachmentHashError] = React.useState("");
  const [isDropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);
  const attachmentHashAbortRef = React.useRef<AbortController | null>(null);
  const attachmentHashRequestRef = React.useRef(0);
  const english = t.waiting === "Waiting";
  const resetAttachmentHashes = React.useCallback(() => {
    attachmentHashAbortRef.current?.abort();
    attachmentHashAbortRef.current = null;
    attachmentHashRequestRef.current += 1;
    setAttachmentHashes({});
    setAttachmentHashingKey("");
    setAttachmentHashError("");
  }, []);
  const workspace = useToolWorkspace<EmailWorkspace>({
    id: "email",
    version: 2,
    isValid: (value): value is EmailWorkspace => Boolean(value && typeof value === "object" && typeof (value as EmailWorkspace).input === "string" && (value as EmailWorkspace).parsed),
    onRestore: (value) => {
      setInput(value.input);
      setSourceFormat(value.sourceFormat);
      setSourceBytes(value.sourceBytes);
      setParsed(value.parsed);
      resetAttachmentHashes();
      setError("");
    }
  });
  const storageState = workspace.state;

  const parseInWorker = (request: EmailWorkerRequest, signal: AbortSignal, transfer: Transferable[] = []) => runWorkerTask<EmailWorkerRequest, EmailWorkerResult>({
    createWorker: () => new Worker(new URL("../features/email/email.worker.ts", import.meta.url), { type: "module" }),
    request,
    transfer,
    signal,
    timeoutMs: 120_000
  });

  React.useEffect(() => {
    if (!parsed) return;
    setBodyMode(parsed.bodyText.trim() ? "text" : parsed.bodyHtml.trim() ? "html" : "text");
  }, [parsed]);

  const parseSource = async (source = input) => {
    if (!source.trim() || !active) return;
    workspace.clear();
    const controller = new AbortController();
    abortRef.current?.abort();
    abortRef.current = controller;
    setLoading(true);
    resetAttachmentHashes();
    try {
      const next = await parseInWorker({ format: "eml", source }, controller.signal);
      if (abortRef.current !== controller || controller.signal.aborted) return;
      setParsed(next.analysis);
      setError("");
      workspace.save(persistableEmailWorkspace({ input: source, sourceFormat: "eml", sourceBytes: null, parsed: next.analysis }));
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      if (abortRef.current === controller && active) {
        setParsed(null);
        setError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setLoading(false);
      }
    }
  };

  const handleFile = async (file: File | undefined) => {
    if (!file || !active) return;
    workspace.clear();
    const controller = new AbortController();
    abortRef.current?.abort();
    abortRef.current = controller;
    setDropActive(false);
    setLoading(true);
    setInput("");
    setSourceBytes(null);
    setSourceFormat("eml");
    setParsed(null);
    resetAttachmentHashes();
    setBodyMode("text");
    if (file.size > EMAIL_FILE_LIMIT) {
      setError(english ? "Email exceeds the 64 MiB browser parsing limit." : "邮件超过 64 MiB 浏览器解析上限。");
      setLoading(false);
      abortRef.current = null;
      return;
    }
    try {
      setError("");
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (abortRef.current !== controller || controller.signal.aborted) return;
      if (isMsgFile(file, bytes)) {
        const workerBytes = bytes.slice();
        const result = await parseInWorker({ format: "msg", bytes: workerBytes.buffer }, controller.signal, [workerBytes.buffer]);
        if (abortRef.current !== controller || controller.signal.aborted) return;
        setInput(result.source);
        setSourceBytes(bytes);
        setSourceFormat("msg");
        setParsed(result.analysis);
        setError("");
        workspace.save(persistableEmailWorkspace({ input: result.source, sourceFormat: "msg", sourceBytes: bytes, parsed: result.analysis }));
      } else {
        const source = new TextDecoder().decode(bytes);
        const result = await parseInWorker({ format: "eml", source }, controller.signal);
        if (abortRef.current !== controller || controller.signal.aborted) return;
        setInput(source);
        setSourceBytes(null);
        setSourceFormat("eml");
        setParsed(result.analysis);
        workspace.save(persistableEmailWorkspace({ input: source, sourceFormat: "eml", sourceBytes: null, parsed: result.analysis }));
      }
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      if (abortRef.current === controller && active) {
        setParsed(null);
        setSourceBytes(null);
        setError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setLoading(false);
      }
    }
  };

  const clearEmail = () => {
    workspace.clear();
    abortRef.current?.abort();
    abortRef.current = null;
    setLoading(false);
    setInput("");
    setSourceFormat("eml");
    setSourceBytes(null);
    setParsed(null);
    resetAttachmentHashes();
    setError("");
    setBodyMode("text");
    setDropActive(false);
    if (inputRef.current) inputRef.current.value = "";
  };

  React.useEffect(() => () => {
    abortRef.current?.abort();
    attachmentHashAbortRef.current?.abort();
  }, []);

  React.useEffect(() => {
    if (active) return;
    abortRef.current?.abort();
    abortRef.current = null;
    attachmentHashAbortRef.current?.abort();
    attachmentHashAbortRef.current = null;
    attachmentHashRequestRef.current += 1;
    setLoading(false);
    setAttachmentHashingKey("");
  }, [active]);

  const downloadRawEmail = () => {
    if (sourceFormat === "msg" && sourceBytes) {
      const bytes = sourceBytes.slice();
      downloadBlob(`email-source-${Date.now()}.msg`, new Blob([bytes.buffer], { type: "application/vnd.ms-outlook" }));
    } else if (input.trim()) downloadTextFile(`email-source-${Date.now()}.eml`, input, "message/rfc822;charset=utf-8");
  };

  const attachmentAvailable = (attachment: EmailAnalysis["attachments"][number]) => attachment.size === 0 || attachment.content.byteLength >= attachment.size;

  const downloadAttachment = (attachment: EmailAnalysis["attachments"][number]) => {
    if (!attachmentAvailable(attachment)) return;
    const bytes = attachment.content.slice();
    const extension = emailAttachmentPreferredExtension(attachment);
    const fallback = `attachment.${extension}`;
    const safeName = safeEmailFilename(attachment.filename, fallback);
    const fileName = /\.[A-Za-z0-9]{1,12}$/.test(safeName) ? safeName : `${safeName}.${extension}`;
    downloadBlob(fileName, new Blob([bytes.buffer], { type: attachment.contentType || "application/octet-stream" }));
  };

  const attachmentKey = (attachment: EmailAnalysis["attachments"][number], index: number) => `${index}:${attachment.filename}:${attachment.size}`;

  const hashAttachment = async (attachment: EmailAnalysis["attachments"][number], index: number) => {
    if (!active) return;
    const key = attachmentKey(attachment, index);
    if (attachmentHashes[key] || attachmentHashingKey) return;
    const requestId = ++attachmentHashRequestRef.current;
    setAttachmentHashingKey(key);
    setAttachmentHashError("");
    attachmentHashAbortRef.current?.abort();
    const controller = new AbortController();
    attachmentHashAbortRef.current = controller;
    try {
      const bytes = attachment.content.slice();
      const result = await hashBytesInWorker(bytes, ["sha256"], { signal: controller.signal });
      if (!result.sha256) throw new Error(english ? "SHA-256 calculation returned no result." : "SHA-256 计算没有返回结果。");
      if (attachmentHashAbortRef.current !== controller || controller.signal.aborted || requestId !== attachmentHashRequestRef.current) return;
      setAttachmentHashes((current) => ({ ...current, [key]: result.sha256 ?? "" }));
    } catch (caught) {
      if (attachmentHashAbortRef.current === controller && active && requestId === attachmentHashRequestRef.current && !(caught instanceof DOMException && caught.name === "AbortError")) setAttachmentHashError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (attachmentHashAbortRef.current === controller) attachmentHashAbortRef.current = null;
      if (requestId === attachmentHashRequestRef.current) setAttachmentHashingKey("");
    }
  };

  const downloadAttachmentsZip = () => {
    if (!parsed?.attachments.length || parsed.attachments.some((attachment) => !attachmentAvailable(attachment))) return;
    const files: Record<string, Uint8Array> = {};
    parsed.attachments.forEach((attachment, index) => {
      const fallback = `attachment-${index + 1}.${emailAttachmentPreferredExtension(attachment)}`;
      const name = safeEmailFilename(attachment.filename, fallback);
      files[`${String(index + 1).padStart(3, "0")}-${name}`] = attachment.content.slice();
    });
    downloadBlob(`email-attachments-${Date.now()}.zip`, new Blob([zipSync(files, { level: 6 })], { type: "application/zip" }));
  };

  const summaryRows = React.useMemo(() => {
    if (!parsed) return [];
    const labels = ["From", "To", "Cc", "Subject", "Date", "Message-ID", "Reply-To", "Return-Path"];
    const rows = labels
      .map((label) => [label, emailSummaryValue(parsed, label) || "--"] as [string, string])
      .filter(([, value], index) => value !== "--" || index < 6);
    return rows;
  }, [parsed]);

  const bodyText = parsed?.bodyText.trim() || "";
  const safeBodyHtml = React.useMemo(() => sanitizeEmailHtml(parsed?.bodyHtml || ""), [parsed?.bodyHtml]);
  const displayedBody = bodyMode === "html" ? parsed?.bodyHtml || "" : bodyText;
  const authSummary = parsed ? emailSummaryValue(parsed, "SPF / DKIM / DMARC") || "--" : "--";

  return (
    <div className={`tool-grid email-workbench ${parsed ? "has-email" : "empty-email"}`}>
      <div className="tool-panel wide-panel email-source-panel">
        <PanelTitle title={parsed ? (english ? "Email" : "邮件") : (english ? "Open email" : "打开邮件")} />
        <input
          className="hidden-file-input"
          ref={inputRef}
          type="file"
          aria-hidden="true"
          tabIndex={-1}
          accept=".eml,.msg,message/rfc822,application/vnd.ms-outlook,text/plain"
          onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void handleFile(file); }}
        />
        {parsed ? <div className="email-loaded-source"><div><strong>{emailSummaryValue(parsed, "Subject") || (english ? "Parsed email" : "已解析邮件")}</strong><span>{sourceFormat.toUpperCase()} · {formatBytes(parsed.rawSize)} · {parsed.attachments.length} {t.attachments} · {storageState === "saved" ? (english ? "saved locally" : "已保留") : storageState === "saving" ? (english ? "saving" : "正在保留") : storageState === "failed" ? (english ? "not saved" : "未保留") : ""}</span></div><div className="button-row compact-buttons"><AButton variant="outlined" onClick={() => inputRef.current?.click()}>{english ? "Replace" : "更换文件"}</AButton><AButton variant="text" disabled={!input.trim() || (sourceFormat === "msg" && !sourceBytes)} title={sourceFormat === "msg" && !sourceBytes ? (english ? "Re-analyze the MSG file to download the original." : "请重新分析 MSG 文件后下载原始文件。") : undefined} onClick={downloadRawEmail}>{sourceFormat.toUpperCase()}</AButton><AButton variant="text" onClick={clearEmail}>{t.clear}</AButton></div></div> : <><div
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
          <strong>{t.emailDropTitle}</strong>
          <span>{t.emailDropHint}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="outlined" disabled={!input.trim() || loading || sourceFormat === "msg"} onClick={() => void parseSource()}>{english ? "Parse" : "解析"}</AButton>
          <AButton variant="text" disabled={!input.trim() || (sourceFormat === "msg" && !sourceBytes)} onClick={downloadRawEmail}>{sourceFormat.toUpperCase()}</AButton>
          <AButton variant="text" disabled={!input.trim() && !parsed && !error && !loading} onClick={clearEmail}>{t.clear}</AButton>
        </div>
        <textarea
            className="single-textarea email-source-input"
            aria-label={english ? "Raw EML source" : "原始 EML 内容"}
            value={input}
            onChange={(event) => {
              setInput(event.currentTarget.value);
              setParsed(null);
              setError("");
              if (parsed || workspace.state !== "idle") workspace.clear();
            }}
            placeholder={t.textPlaceholder}
          /></>}
        {loading && <ALinearProgress />}
        {error && <pre className="result-box">{error}</pre>}
      </div>

      {parsed && (
        <>
          <div className="tool-panel wide-panel email-summary-panel">
            <PanelTitle title={t.summary} />
            <InfoTable rows={summaryRows} />
          </div>

          <div className="tool-panel wide-panel email-auth-panel">
            <div className="panel-heading-row">
              <PanelTitle title={english ? "Authentication-Results header" : "邮件头记录的认证结果"} />
              <span className="status-pill">{authSummary}</span>
            </div>
            {parsed.authAssessments.length ? (
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead>
                    <tr><th>{english ? "Mechanism" : "机制"}</th><th>{english ? "Reported result" : "头部记录"}</th><th>{english ? "Domain" : "域名"}</th><th>{english ? "Aligned" : "对齐"}</th></tr>
                  </thead>
                  <tbody>
                    {parsed.authAssessments.map((item) => (
                      <tr key={`${item.mechanism}-${item.source}`}>
                        <td>{item.mechanism}</td><td>{item.result}</td><td>{item.domain || "--"}</td><td>{item.aligned || "--"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <div className="empty-state">--</div>}
          </div>

          <div className="tool-panel wide-panel email-route-panel">
            <PanelTitle title={t.receivedChain} />
            {parsed.receivedHops.length ? (
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>#</th><th>From</th><th>By</th><th>IP</th><th>{english ? "Date" : "时间"}</th></tr></thead>
                  <tbody>
                    {parsed.receivedHops.map((hop) => (
                      <tr key={`${hop.index}-${hop.raw}`}>
                        <td>{hop.index}</td><td>{hop.from || "--"}</td><td>{hop.by || "--"}</td><td>{hop.ip || "--"}</td><td>{hop.date || "--"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <div className="empty-state">--</div>}
          </div>

          <div className="tool-panel wide-panel email-body-panel">
            <div className="panel-heading-row">
              <PanelTitle title={t.emailBody} />
              <div className="button-row compact-buttons">
                <AButton variant={bodyMode === "text" ? "filled" : "outlined"} onClick={() => setBodyMode("text")}>Text</AButton>
                <AButton variant={bodyMode === "html" ? "filled" : "outlined"} disabled={!parsed.bodyHtml} onClick={() => setBodyMode("html")}>HTML</AButton>
                <AButton variant="text" disabled={!displayedBody} onClick={() => void copyText(displayedBody)}>{t.copy}</AButton>
              </div>
            </div>
            {bodyMode === "html" && safeBodyHtml
              ? <iframe className="email-html-preview" title={english ? "Isolated email HTML preview" : "隔离的邮件 HTML 预览"} sandbox="" srcDoc={safeBodyHtml} />
              : <textarea aria-label={english ? "Email body preview" : "邮件正文预览"} className="single-textarea email-body-preview" value={limitReportText(bodyText || "--", 20000)} readOnly />}
          </div>

          <div className="tool-panel wide-panel email-attachments-panel">
            <div className="panel-heading-row">
              <PanelTitle title={t.attachments} />
              <AButton variant="text" disabled={!parsed.attachments.length || parsed.attachments.some((attachment) => !attachmentAvailable(attachment))} title={parsed.attachments.some((attachment) => !attachmentAvailable(attachment)) ? (english ? "Re-analyze the email to download all attachments." : "请重新分析邮件后下载全部附件。") : undefined} onClick={downloadAttachmentsZip}>ZIP</AButton>
            </div>
            {parsed.attachments.length ? (
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>{english ? "Name" : "名称"}</th><th>{english ? "Type" : "类型"}</th><th>{t.fileSize}</th><th>{t.emailSignature}</th><th>SHA-256</th><th>{t.emailDownloadAttachment}</th></tr></thead>
                  <tbody>
                    {parsed.attachments.map((attachment, index) => (
                      <tr key={`${attachment.filename}-${attachment.size}-${index}`}>
                        <td>{attachment.filename || `attachment-${index + 1}`}</td>
                        <td>{attachment.contentType || "--"}</td>
                        <td>{formatBytes(attachment.size)}</td>
                        <td>{attachment.signature || "--"}</td>
                        <td>
                          {attachmentHashes[attachmentKey(attachment, index)]
                            ? <button type="button" className="email-attachment-hash" title={t.copy} onClick={() => void copyText(attachmentHashes[attachmentKey(attachment, index)])}>{attachmentHashes[attachmentKey(attachment, index)]}</button>
                            : <AButton variant="text" disabled={!attachmentAvailable(attachment) || Boolean(attachmentHashingKey)} onClick={() => void hashAttachment(attachment, index)}>{!attachmentAvailable(attachment) ? (english ? "Re-analyze" : "需重新分析") : attachmentHashingKey === attachmentKey(attachment, index) ? (english ? "Calculating..." : "计算中...") : (english ? "Calculate" : "计算")}</AButton>}
                        </td>
                        <td><AButton variant="text" disabled={!attachmentAvailable(attachment)} title={!attachmentAvailable(attachment) ? (english ? "Re-analyze the email to download this attachment." : "请重新分析邮件后下载此附件。") : undefined} onClick={() => downloadAttachment(attachment)}>{attachmentAvailable(attachment) ? t.emailDownloadAttachment : (english ? "Re-analyze" : "需重新分析")}</AButton></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <div className="empty-state">--</div>}
            {attachmentHashError && <div className="empty-state error-state">{attachmentHashError}</div>}
          </div>

          <details className="image-advanced-shell email-advanced-shell wide-panel">
            <summary>{english ? "Raw headers and source" : "原始邮件头与源文"}</summary>
            <div className="email-raw-stack">
              <div className="tool-panel wide-panel">
                <PanelTitle title={t.emailHeaders} />
                {parsed.headers.length ? (
                  <div className="table-scroll compact-scroll">
                    <table className="data-table">
                      <thead><tr><th>{english ? "Header" : "字段"}</th><th>{english ? "Value" : "值"}</th></tr></thead>
                      <tbody>
                        {parsed.headers.map(([name, value], index) => (
                          <tr key={`${name}-${index}`}><td>{name}</td><td>{value}</td></tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : <div className="empty-state">--</div>}
              </div>
              <div className="tool-panel wide-panel">
                <PanelTitle title={sourceFormat === "msg" ? (english ? "MSG properties" : "MSG 属性") : (english ? "Raw EML" : "原始 EML")} />
                <pre className="result-box email-raw-source">{input || "--"}</pre>
              </div>
            </div>
          </details>
        </>
      )}
    </div>
  );
}
