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

function refang(value: string) {
  return value.trim()
    .replace(/^hxxps:/i, "https:")
    .replace(/^hxxp:/i, "http:")
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
    .replace(/\[:\]/g, ":");
}

function defang(value: string) {
  return value.replace(/^https:/i, "hxxps:").replace(/^http:/i, "hxxp:").replace(/\./g, "[.]");
}

function safeDecode(value: string) {
  try { return decodeURIComponent(value); } catch { return value; }
}

export function UrlTool({ t }: { t: (typeof copy)["zh"] }) {
  const english = t.waiting === "Waiting";
  const [input, setInput] = React.useState("");
  const parsed = React.useMemo(() => {
    const raw = refang(input);
    if (!raw) return { url: null as URL | null, normalized: "", error: "" };
    try {
      const withScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
      const url = new URL(withScheme);
      return { url, normalized: url.toString(), error: "" };
    } catch (caught) {
      return { url: null, normalized: "", error: caught instanceof Error ? caught.message : String(caught) };
    }
  }, [input]);

  const url = parsed.url;
  const params = url ? Array.from(url.searchParams.entries()) : [];
  const decoded = parsed.normalized ? safeDecode(parsed.normalized) : "";
  const sorted = React.useMemo(() => {
    if (!url) return "";
    const next = new URL(url.toString());
    next.search = "";
    [...params].sort(([left], [right]) => left.localeCompare(right)).forEach(([name, value]) => next.searchParams.append(name, value));
    return next.toString();
  }, [params, url]);

  const outputs: Array<[string, string]> = url ? [
    [english ? "Normalized" : "规范化", parsed.normalized],
    [english ? "Defanged" : "去活化", defang(parsed.normalized)],
    [english ? "Decoded" : "解码", decoded],
    [english ? "Sorted parameters" : "参数排序", sorted]
  ] : [];

  return (
    <div className={`tool-grid url-workbench ${url ? "has-url" : "empty-url"}`}>
      <div className="tool-panel wide-panel url-source-panel">
        <PanelTitle title="URL" />
        <textarea
          className="single-textarea url-source-textarea"
          aria-label={english ? "URL input" : "URL 输入"}
          value={input}
          spellCheck={false}
          placeholder="https://example.com/path?key=value"
          onChange={(event) => setInput(event.currentTarget.value)}
        />
        <div className="action-row">
          <AButton variant="outlined" onClick={() => setInput("https://example.com/download/report.pdf?source=email&lang=zh#page=2")}>{english ? "Example" : "示例"}</AButton>
          <AButton variant="text" disabled={!input} onClick={() => setInput("")}>{t.clear}</AButton>
        </div>
        {parsed.error && <div className="empty-state error-state">{parsed.error}</div>}
      </div>

      {url && (
        <>
          <div className="tool-panel wide-panel url-structure-panel">
            <PanelTitle title={english ? "Structure" : "结构"} />
            <InfoTable rows={[
              [english ? "Scheme" : "协议", url.protocol.replace(/:$/, "")],
              [english ? "Username" : "用户名", url.username || "--"],
              [english ? "Password" : "密码", url.password || "--"],
              [english ? "Host" : "主机", url.hostname],
              [english ? "Port" : "端口", url.port || "--"],
              [english ? "Path" : "路径", url.pathname || "/"],
              [english ? "Query" : "查询", url.search || "--"],
              [english ? "Fragment" : "片段", url.hash || "--"]
            ]} />
          </div>

          {params.length > 0 && (
            <div className="tool-panel wide-panel url-params-panel">
              <PanelTitle title={english ? "Query parameters" : "查询参数"} />
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>#</th><th>{english ? "Name" : "名称"}</th><th>{english ? "Value" : "值"}</th></tr></thead>
                  <tbody>{params.map(([name, value], index) => (
                    <tr key={`${name}-${index}`}><td>{index + 1}</td><td>{name}</td><td>{value || "--"}</td></tr>
                  ))}</tbody>
                </table>
              </div>
            </div>
          )}

          <div className="tool-panel wide-panel url-output-panel">
            <PanelTitle title={english ? "Representations" : "常用形式"} />
            <div className="url-output-list">
              {outputs.map(([label, value]) => (
                <div className="url-output-row" key={label}>
                  <div><strong>{label}</strong><code>{value}</code></div>
                  <AButton variant="text" onClick={() => void navigator.clipboard.writeText(value)}>{t.copy}</AButton>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
