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
import { AButton, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import { formatBytes } from "../utils/files";
import { useStoredState } from "../utils/storage";

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

export function HttpTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {  const [text, setText] = useStoredState("http.text.v4", "");
  const [error, setError] = React.useState("");
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const requestRef = React.useRef(0);
  React.useEffect(() => {
    if (active) return;
    requestRef.current += 1;
  }, [active]);
  const parsed = React.useMemo(() => active ? parseHttpMessage(text) : parseHttpMessage(""), [active, text]);
  const hasInput = Boolean(text.trim());

  const examples = {
    request: "GET /search?q=forensics&page=2 HTTP/1.1\nHost: example.test\nUser-Agent: ForensicsPP\nCookie: session=abc123; theme=light\nAccept: application/json\n\n",
    response: "HTTP/1.1 200 OK\nContent-Type: application/json; charset=utf-8\nContent-Length: 27\nSet-Cookie: session=abc123; HttpOnly; Secure\n\n{\"ok\":true,\"count\":2}"
  };

  const loadFile = async (file?: File) => {
    if (!file || !active) return;
    const requestId = ++requestRef.current;
    setError("");
    setText("");
    if (file.size > MAX_HTTP_TEXT_BYTES) {
      setError(t.the_file_exceeds_the_16_mib_limit);
      return;
    }
    try {
      const value = await file.text();
      if (active && requestId === requestRef.current) setText(value);
    } catch (caught) {
      if (active && requestId === requestRef.current) setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const typeLabel = parsed.kind === "request"
    ? (t.httpRequest)
    : parsed.kind === "response" ? (t.httpResponse) : (t.unknown);
  const summaryRows: Array<[string, string]> = [
    [t.message_type, hasInput ? typeLabel : "--"],
    [t.start_line, parsed.startLine || "--"],
    [t.method_status, parsed.methodOrStatus || "--"],
    [t.target, parsed.target || "--"],
    ["HTTP", parsed.version || "--"],
    ["Host", parsed.host || "--"],
    ["Content-Type", parsed.contentType || "--"],
    [t.httpHeaders, String(parsed.headers.length)],
    [t.body_size, formatBytes(parsed.bodyBytes)]
  ];

  return (
    <div className={`tool-grid http-workbench ${hasInput ? "has-http" : "empty-http"}`}>
      <div className="tool-panel wide-panel http-source-panel">
        <div className="panel-heading-row">
          <PanelTitle title={t.http_message} />
          <div className="button-row compact-buttons">
            <AButton variant="text" onClick={() => setText(examples.request)}>{t.request_example}</AButton>
            <AButton variant="text" onClick={() => setText(examples.response)}>{t.response_example}</AButton>
          </div>
        </div>
        <textarea
          className="single-textarea http-source-textarea"
          aria-label={t.raw_http_message}
          value={text}
          spellCheck={false}
          placeholder={t.paste_a_raw_http_request_or_response}
          onChange={(event) => setText(event.currentTarget.value)}
        />
        <input ref={inputRef} type="file" accept=".txt,.http,text/plain" hidden aria-hidden="true" tabIndex={-1} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void loadFile(file); }} />
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.open_file}</AButton>
          <AButton variant="outlined" disabled={!text} onClick={() => void copyText(text)}>{t.copy}</AButton>
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
              <PanelTitle title={t.httpHeaders} />
              <AButton variant="text" disabled={!parsed.headers.length} onClick={() => void copyText(parsed.headers.map((row) => `${row.name}: ${row.value}`).join("\n"))}>{t.copy}</AButton>
            </div>
            <DataTable columns={[t.name, t.httpHeaderValue]} rows={parsed.headers.map((row) => [row.name, row.value])} />
          </div>

          {(parsed.params.length > 0 || parsed.cookies.length > 0) && (
            <div className="http-detail-grid wide-panel">
              {parsed.params.length > 0 && (
                <div className="tool-panel http-params-panel">
                  <PanelTitle title={t.httpParams} />
                  <DataTable columns={[t.iocSource, t.name, t.httpHeaderValue]} rows={parsed.params.map((row) => [row.source, row.name, row.value])} />
                </div>
              )}
              {parsed.cookies.length > 0 && (
                <div className="tool-panel http-cookies-panel">
                  <PanelTitle title="Cookies" />
                  <DataTable columns={[t.iocSource, t.name, t.httpHeaderValue, t.httpCookieAttrs]} rows={parsed.cookies.map((row) => [row.source, row.name, row.value, row.attributes])} />
                </div>
              )}
            </div>
          )}

          {parsed.body && (
            <div className="tool-panel wide-panel http-body-panel">
              <div className="panel-heading-row">
                <PanelTitle title={t.httpMessageBody} />
                <AButton variant="text" onClick={() => void copyText(parsed.body)}>{t.copy}</AButton>
              </div>
              <textarea aria-label={t.http_body} className="single-textarea http-body-textarea" value={parsed.body} spellCheck={false} readOnly />
            </div>
          )}
        </>
      )}
    </div>
  );
}
