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
  stripEmailHtml
} from "../features/email/workbench";
import { copy } from "../i18n";
import type { EmailAnalysis } from "../models";
import { downloadBlob, downloadTextFile, formatBytes, limitReportText } from "../utils/files";
import { useStoredState } from "../utils/storage";

const EMAIL_FILE_LIMIT = 64 * 1024 * 1024;

function safeEmailFilename(value: string, fallback: string) {
  const cleaned = value
    .split(/[\\/]/)
    .pop()
    ?.replace(/[^\w.\-()[\] 一-龥]+/g, "_")
    .replace(/^_+|_+$/g, "") ?? "";
  return cleaned || fallback;
}

export function EmailTool({ t }: { t: (typeof copy)["zh"] }) {
  const [input, setInput] = useStoredState("email.input.v2", "");
  const [parsed, setParsed] = React.useState<EmailAnalysis | null>(null);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [bodyMode, setBodyMode] = React.useState<"text" | "html">("text");
  const [isDropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const english = t.waiting === "Waiting";

  React.useEffect(() => {
    if (!input.trim()) {
      setParsed(null);
      setError("");
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    parseEmail(input)
      .then((result) => {
        if (cancelled) return;
        setParsed(result);
        setError("");
      })
      .catch((caught) => {
        if (cancelled) return;
        setParsed(null);
        setError(caught instanceof Error ? caught.message : String(caught));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [input]);

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    setDropActive(false);
    if (file.size > EMAIL_FILE_LIMIT) {
      setError(english ? "Email exceeds the 64 MiB browser parsing limit." : "邮件超过 64 MiB 浏览器解析上限。");
      return;
    }
    try {
      setError("");
      setInput(await file.text());
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
  const bodyHtmlText = parsed?.bodyHtml ? stripEmailHtml(parsed.bodyHtml).trim() : "";
  const displayedBody = bodyMode === "html" ? bodyHtmlText : bodyText;
  const authSummary = parsed ? emailSummaryValue(parsed, "SPF / DKIM / DMARC") || "--" : "--";

  return (
    <div className={`tool-grid email-workbench ${parsed ? "has-email" : "empty-email"}`}>
      <div className="tool-panel wide-panel email-source-panel">
        <PanelTitle title={english ? "Email source" : "邮件来源"} />
        <input
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
          <AButton variant="text" disabled={!input.trim()} onClick={downloadRawEmail}>EML</AButton>
          <AButton variant="text" disabled={!input.trim()} onClick={clearEmail}>{t.clear}</AButton>
        </div>
        {!parsed && (
          <textarea
            className="single-textarea email-source-input"
            aria-label={english ? "Raw EML source" : "原始 EML 内容"}
            value={input}
            onChange={(event) => setInput(event.currentTarget.value)}
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
              <PanelTitle title={t.emailAuth} />
              <span className="status-pill">{authSummary}</span>
            </div>
            {parsed.authAssessments.length ? (
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead>
                    <tr><th>{english ? "Mechanism" : "机制"}</th><th>{english ? "Result" : "结果"}</th><th>{english ? "Domain" : "域名"}</th><th>{english ? "Aligned" : "对齐"}</th></tr>
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
            <textarea aria-label={english ? "Email body preview" : "邮件正文预览"} className="single-textarea email-body-preview" value={limitReportText(displayedBody || "--", 20000)} readOnly />
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
                      <tr key={`${attachment.sha256}-${index}`}>
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
                <textarea className="single-textarea email-raw-input" value={input} readOnly />
              </div>
            </div>
          </details>
        </>
      )}
    </div>
  );
}
