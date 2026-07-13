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
import { AButton, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import { formatBytes } from "../utils/files";

type HeaderRow = { name: string; value: string };
type ParamRow = { source: "Query" | "Form"; name: string; value: string };
type CookieRow = { source: "Cookie" | "Set-Cookie"; name: string; value: string; attributes: string };

type HttpMessage = {
  kind: "request" | "response" | "unknown";
  startLine: string;
  methodOrStatus: string;
  target: string;
  version: string;
  headers: HeaderRow[];
  params: ParamRow[];
  cookies: CookieRow[];
  body: string;
  host: string;
  contentType: string;
  contentLength: string;
  bodyBytes: number;
};

const MAX_HTTP_TEXT_BYTES = 16 * 1024 * 1024;

function unfoldHeaders(lines: string[]) {
  const result: string[] = [];
  lines.forEach((line) => {
    if (/^[\t ]/.test(line) && result.length) result[result.length - 1] += ` ${line.trim()}`;
    else result.push(line);
  });
  return result;
}

function decodeComponent(value: string) {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

function parseParams(value: string, source: ParamRow["source"]): ParamRow[] {
  if (!value) return [];
  return value.split("&").filter(Boolean).map((part) => {
    const index = part.indexOf("=");
    return {
      source,
      name: decodeComponent(index >= 0 ? part.slice(0, index) : part),
      value: decodeComponent(index >= 0 ? part.slice(index + 1) : "")
    };
  });
}

function parseCookies(headers: HeaderRow[]): CookieRow[] {
  const rows: CookieRow[] = [];
  headers.forEach((header) => {
    const lower = header.name.toLowerCase();
    if (lower === "cookie") {
      header.value.split(";").map((part) => part.trim()).filter(Boolean).forEach((part) => {
        const index = part.indexOf("=");
        rows.push({
          source: "Cookie",
          name: index >= 0 ? part.slice(0, index).trim() : part,
          value: index >= 0 ? part.slice(index + 1).trim() : "",
          attributes: ""
        });
      });
    }
    if (lower === "set-cookie") {
      const parts = header.value.split(";").map((part) => part.trim()).filter(Boolean);
      const first = parts.shift() ?? "";
      const index = first.indexOf("=");
      rows.push({
        source: "Set-Cookie",
        name: index >= 0 ? first.slice(0, index).trim() : first,
        value: index >= 0 ? first.slice(index + 1).trim() : "",
        attributes: parts.join("; ")
      });
    }
  });
  return rows;
}

function parseHttpMessage(input: string): HttpMessage {
  const normalized = input.replace(/\r\n?/g, "\n");
  const separator = normalized.indexOf("\n\n");
  const head = separator >= 0 ? normalized.slice(0, separator) : normalized;
  const body = separator >= 0 ? normalized.slice(separator + 2) : "";
  const lines = unfoldHeaders(head.split("\n"));
  const startLine = lines.shift()?.trim() ?? "";
  const headers: HeaderRow[] = lines.flatMap((line) => {
    const index = line.indexOf(":");
    return index > 0 ? [{ name: line.slice(0, index).trim(), value: line.slice(index + 1).trim() }] : [];
  });
  const headerValue = (name: string) => headers.find((header) => header.name.toLowerCase() === name)?.value ?? "";
  const request = startLine.match(/^([A-Z]+)\s+(\S+)\s+(HTTP\/\d(?:\.\d)?)$/);
  const response = startLine.match(/^(HTTP\/\d(?:\.\d)?)\s+(\d{3})\s*(.*)$/);
  const target = request?.[2] ?? "";
  const query = target.includes("?") ? target.slice(target.indexOf("?") + 1) : "";
  const contentType = headerValue("content-type");
  const params = [
    ...parseParams(query, "Query"),
    ...(/application\/x-www-form-urlencoded/i.test(contentType) ? parseParams(body, "Form") : [])
  ];

  return {
    kind: request ? "request" : response ? "response" : "unknown",
    startLine,
    methodOrStatus: request?.[1] ?? (response ? `${response[2]} ${response[3]}`.trim() : ""),
    target,
    version: request?.[3] ?? response?.[1] ?? "",
    headers,
    params,
    cookies: parseCookies(headers),
    body,
    host: headerValue("host"),
    contentType,
    contentLength: headerValue("content-length"),
    bodyBytes: new TextEncoder().encode(body).length
  };
}

function DataTable({ columns, rows }: { columns: string[]; rows: string[][] }) {
  if (!rows.length) return <div className="empty-state">--</div>;
  return (
    <div className="table-scroll compact-scroll">
      <table className="data-table">
        <thead><tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr></thead>
        <tbody>{rows.map((row, rowIndex) => (
          <tr key={rowIndex}>{row.map((value, columnIndex) => <td key={columnIndex}>{value || "--"}</td>)}</tr>
        ))}</tbody>
      </table>
    </div>
  );
}

export function HttpTool({ t }: { t: (typeof copy)["zh"] }) {
  const english = t.waiting === "Waiting";
  const [text, setText] = React.useState("");
  const [error, setError] = React.useState("");
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const requestRef = React.useRef(0);
  const parsed = React.useMemo(() => parseHttpMessage(text), [text]);
  const hasInput = Boolean(text.trim());

  const examples = {
    request: "GET /search?q=forensics&page=2 HTTP/1.1\nHost: example.test\nUser-Agent: ForensicsPP\nCookie: session=abc123; theme=light\nAccept: application/json\n\n",
    response: "HTTP/1.1 200 OK\nContent-Type: application/json; charset=utf-8\nContent-Length: 27\nSet-Cookie: session=abc123; HttpOnly; Secure\n\n{\"ok\":true,\"count\":2}"
  };

  const loadFile = async (file?: File) => {
    if (!file) return;
    const requestId = ++requestRef.current;
    setError("");
    setText("");
    if (file.size > MAX_HTTP_TEXT_BYTES) {
      setError(english ? "The file exceeds the 16 MiB limit." : "文件超过 16 MiB 限制。");
      return;
    }
    try {
      const value = await file.text();
      if (requestId === requestRef.current) setText(value);
    } catch (caught) {
      if (requestId === requestRef.current) setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const typeLabel = parsed.kind === "request"
    ? (english ? "Request" : "请求")
    : parsed.kind === "response" ? (english ? "Response" : "响应") : (english ? "Unknown" : "未知");
  const summaryRows: Array<[string, string]> = [
    [english ? "Message type" : "报文类型", hasInput ? typeLabel : "--"],
    [english ? "Start line" : "起始行", parsed.startLine || "--"],
    [english ? "Method / Status" : "方法 / 状态", parsed.methodOrStatus || "--"],
    [english ? "Target" : "目标", parsed.target || "--"],
    ["HTTP", parsed.version || "--"],
    ["Host", parsed.host || "--"],
    ["Content-Type", parsed.contentType || "--"],
    [english ? "Headers" : "请求头", String(parsed.headers.length)],
    [english ? "Body size" : "正文大小", formatBytes(parsed.bodyBytes)]
  ];

  return (
    <div className={`tool-grid http-workbench ${hasInput ? "has-http" : "empty-http"}`}>
      <div className="tool-panel wide-panel http-source-panel">
        <div className="panel-heading-row">
          <PanelTitle title={english ? "HTTP message" : "HTTP 报文"} />
          <div className="button-row compact-buttons">
            <AButton variant="text" onClick={() => setText(examples.request)}>{english ? "Request example" : "请求示例"}</AButton>
            <AButton variant="text" onClick={() => setText(examples.response)}>{english ? "Response example" : "响应示例"}</AButton>
          </div>
        </div>
        <textarea
          className="single-textarea http-source-textarea"
          aria-label={english ? "Raw HTTP message" : "原始 HTTP 报文"}
          value={text}
          spellCheck={false}
          placeholder={english ? "Paste a raw HTTP request or response" : "粘贴原始 HTTP 请求或响应"}
          onChange={(event) => setText(event.currentTarget.value)}
        />
        <input ref={inputRef} type="file" accept=".txt,.http,text/plain" hidden onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void loadFile(file); }} />
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{english ? "Open file" : "打开文件"}</AButton>
          <AButton variant="outlined" disabled={!text} onClick={() => void navigator.clipboard.writeText(text)}>{t.copy}</AButton>
          <AButton variant="text" disabled={!text && !error} onClick={() => { setText(""); setError(""); }}>{t.clear}</AButton>
        </div>
        {error && <div className="empty-state error-state">{error}</div>}
      </div>

      {hasInput && (
        <>
          <div className="tool-panel wide-panel http-summary-panel">
            <PanelTitle title={t.summary} />
            <InfoTable rows={summaryRows} />
          </div>

          <div className="tool-panel wide-panel http-headers-panel">
            <div className="panel-heading-row">
              <PanelTitle title={english ? "Headers" : "请求头"} />
              <AButton variant="text" disabled={!parsed.headers.length} onClick={() => void navigator.clipboard.writeText(parsed.headers.map((row) => `${row.name}: ${row.value}`).join("\n"))}>{t.copy}</AButton>
            </div>
            <DataTable columns={[english ? "Name" : "名称", english ? "Value" : "值"]} rows={parsed.headers.map((row) => [row.name, row.value])} />
          </div>

          {(parsed.params.length > 0 || parsed.cookies.length > 0) && (
            <div className="http-detail-grid wide-panel">
              {parsed.params.length > 0 && (
                <div className="tool-panel http-params-panel">
                  <PanelTitle title={english ? "Parameters" : "参数"} />
                  <DataTable columns={[english ? "Source" : "来源", english ? "Name" : "名称", english ? "Value" : "值"]} rows={parsed.params.map((row) => [row.source, row.name, row.value])} />
                </div>
              )}
              {parsed.cookies.length > 0 && (
                <div className="tool-panel http-cookies-panel">
                  <PanelTitle title="Cookies" />
                  <DataTable columns={[english ? "Source" : "来源", english ? "Name" : "名称", english ? "Value" : "值", english ? "Attributes" : "属性"]} rows={parsed.cookies.map((row) => [row.source, row.name, row.value, row.attributes])} />
                </div>
              )}
            </div>
          )}

          {parsed.body && (
            <div className="tool-panel wide-panel http-body-panel">
              <div className="panel-heading-row">
                <PanelTitle title={english ? "Body" : "正文"} />
                <AButton variant="text" onClick={() => void navigator.clipboard.writeText(parsed.body)}>{t.copy}</AButton>
              </div>
              <textarea aria-label={english ? "HTTP body" : "HTTP 正文"} className="single-textarea http-body-textarea" value={parsed.body} spellCheck={false} readOnly />
            </div>
          )}
        </>
      )}
    </div>
  );
}
