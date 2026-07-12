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
import { zipSync } from "fflate";
import { AButton, ALinearProgress, InfoTable, PanelTitle } from "../components/ui";
import {
  emailAttachmentPreferredExtension,
  emailSummaryValue,
  parseEmail,
} from "../features/email/workbench";
import { copy } from "../i18n";
import type { EmailAnalysis } from "../models";
import { downloadBlob, downloadTextFile, formatBytes, limitReportText } from "../utils/files";

const EMAIL_FILE_LIMIT = 64 * 1024 * 1024;

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
  const document = new DOMParser().parseFromString(value, "text/html");
  document.querySelectorAll("script, iframe, object, embed, form, input, button, link, meta").forEach((node) => node.remove());
  document.querySelectorAll<HTMLElement>("*").forEach((node) => {
    for (const attribute of Array.from(node.attributes)) {
      if (/^on/i.test(attribute.name)) node.removeAttribute(attribute.name);
      if (/^(src|srcset|background|poster|action|formaction)$/i.test(attribute.name)) node.removeAttribute(attribute.name);
      if (attribute.name === "href" && !/^(?:#|mailto:|tel:)/i.test(attribute.value.trim())) node.setAttribute("href", "#");
    }
  });
  const baseStyle = "body{margin:0;padding:18px;color:#182230;background:#fff;font:14px/1.65 system-ui,sans-serif;overflow-wrap:anywhere}img{max-width:100%;height:auto}pre{white-space:pre-wrap}table{max-width:100%;border-collapse:collapse}td,th{padding:6px;border:1px solid #d9e0e8}";
  return `<!doctype html><html><head><meta charset="utf-8"><style>${baseStyle}</style></head><body>${document.body.innerHTML}</body></html>`;
}

export function EmailTool({ t }: { t: (typeof copy)["zh"] }) {
  const [input, setInput] = React.useState("");
  const [parsed, setParsed] = React.useState<EmailAnalysis | null>(null);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [bodyMode, setBodyMode] = React.useState<"text" | "html">("text");
  const [isDropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const english = t.waiting === "Waiting";

  const parseSource = async (source = input) => {
    if (!source.trim()) return;
    setLoading(true);
    try {
      setParsed(await parseEmail(source));
      setError("");
    } catch (caught) {
      setParsed(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  };

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    setDropActive(false);
    if (file.size > EMAIL_FILE_LIMIT) {
      setError(english ? "Email exceeds the 64 MiB browser parsing limit." : "邮件超过 64 MiB 浏览器解析上限。");
      return;
    }
    try {
      setError("");
      const source = await file.text();
      setInput(source);
      await parseSource(source);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const clearEmail = () => {
    setInput("");
    setParsed(null);
    setError("");
    setBodyMode("text");
    setDropActive(false);
    if (inputRef.current) inputRef.current.value = "";
  };

  const downloadRawEmail = () => {
    if (!input.trim()) return;
    downloadTextFile(`email-source-${Date.now()}.eml`, input, "message/rfc822;charset=utf-8");
  };

  const downloadAttachment = (attachment: EmailAnalysis["attachments"][number]) => {
    const bytes = attachment.content.slice();
    const extension = emailAttachmentPreferredExtension(attachment);
    const fallback = `attachment.${extension}`;
    const safeName = safeEmailFilename(attachment.filename, fallback);
    const fileName = /\.[A-Za-z0-9]{1,12}$/.test(safeName) ? safeName : `${safeName}.${extension}`;
    downloadBlob(fileName, new Blob([bytes.buffer], { type: attachment.contentType || "application/octet-stream" }));
  };

  const downloadAttachmentsZip = () => {
    if (!parsed?.attachments.length) return;
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
        <PanelTitle title={english ? "Open email" : "打开邮件"} />
        <input
          className="hidden-file-input"
          ref={inputRef}
          type="file"
          accept=".eml,message/rfc822,text/plain"
          onChange={(event) => void handleFile(event.target.files?.[0])}
        />
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
          <strong>{parsed ? emailSummaryValue(parsed, "Subject") || (english ? "Parsed email" : "已解析邮件") : t.emailDropTitle}</strong>
          <span>{parsed ? `${formatBytes(parsed.rawSize)} · ${parsed.receivedHops.length} Received · ${parsed.attachments.length} ${t.attachments}` : t.emailDropHint}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="outlined" disabled={!input.trim() || loading} onClick={() => void parseSource()}>{english ? "Parse" : "解析"}</AButton>
          <AButton variant="text" disabled={!input.trim()} onClick={downloadRawEmail}>EML</AButton>
          <AButton variant="text" disabled={!input.trim()} onClick={clearEmail}>{t.clear}</AButton>
        </div>
        {!parsed && (
          <textarea
            className="single-textarea email-source-input"
            aria-label={english ? "Raw EML source" : "原始 EML 内容"}
            value={input}
            onChange={(event) => {
              setInput(event.currentTarget.value);
              setParsed(null);
              setError("");
            }}
            placeholder={t.textPlaceholder}
          />
        )}
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
                <AButton variant="text" disabled={!displayedBody} onClick={() => void navigator.clipboard.writeText(displayedBody)}>{t.copy}</AButton>
              </div>
            </div>
            {bodyMode === "html" && safeBodyHtml
              ? <iframe className="email-html-preview" title={english ? "Isolated email HTML preview" : "隔离的邮件 HTML 预览"} sandbox="" srcDoc={safeBodyHtml} />
              : <textarea aria-label={english ? "Email body preview" : "邮件正文预览"} className="single-textarea email-body-preview" value={limitReportText(bodyText || "--", 20000)} readOnly />}
          </div>

          <div className="tool-panel wide-panel email-attachments-panel">
            <div className="panel-heading-row">
              <PanelTitle title={t.attachments} />
              <AButton variant="text" disabled={!parsed.attachments.length} onClick={downloadAttachmentsZip}>ZIP</AButton>
            </div>
            {parsed.attachments.length ? (
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>{english ? "Name" : "名称"}</th><th>{english ? "Type" : "类型"}</th><th>{t.fileSize}</th><th>{t.emailSignature}</th><th>{t.emailDownloadAttachment}</th></tr></thead>
                  <tbody>
                    {parsed.attachments.map((attachment, index) => (
                      <tr key={`${attachment.filename}-${attachment.size}-${index}`}>
                        <td>{attachment.filename || `attachment-${index + 1}`}</td>
                        <td>{attachment.contentType || "--"}</td>
                        <td>{formatBytes(attachment.size)}</td>
                        <td>{attachment.signature || "--"}</td>
                        <td><AButton variant="text" onClick={() => downloadAttachment(attachment)}>{t.emailDownloadAttachment}</AButton></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <div className="empty-state">--</div>}
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
                <PanelTitle title={english ? "Raw EML" : "原始 EML"} />
                <pre className="result-box email-raw-source">{input || "--"}</pre>
              </div>
            </div>
          </details>
        </>
      )}
    </div>
  );
}
