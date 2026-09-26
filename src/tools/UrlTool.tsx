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
import { useHomeToolDraft } from "../app/useHomeToolDraft";
import { AButton, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import { useStoredState } from "../utils/storage";

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

export function UrlTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {  const [input, setInput] = useStoredState("url.input.v4", "");
  useHomeToolDraft("urltool", active, setInput);
  const parsed = React.useMemo(() => {
    if (!active) return { url: null as URL | null, normalized: "", error: "" };
    const raw = refang(input);
    if (!raw) return { url: null as URL | null, normalized: "", error: "" };
    try {
      const withScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
      const url = new URL(withScheme);
      return { url, normalized: url.toString(), error: "" };
    } catch (caught) {
      return { url: null, normalized: "", error: caught instanceof Error ? caught.message : String(caught) };
    }
  }, [active, input]);

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
    [t.normalizedUrl, parsed.normalized],
    [t.defangedUrl, defang(parsed.normalized)],
    [t.decodedUrl, decoded],
    [t.sorted_parameters, sorted]
  ] : [];

  return (
    <div className={`tool-grid url-workbench ${url ? "has-url" : "empty-url"}`}>
      <div className="tool-panel wide-panel url-source-panel">
        <PanelTitle title="URL" />
        <textarea
          className="single-textarea url-source-textarea"
          aria-label={t.url_input}
          value={input}
          spellCheck={false}
          placeholder="https://example.com/path?key=value"
          onChange={(event) => setInput(event.currentTarget.value)}
        />
        <div className="action-row">
          <AButton variant="outlined" onClick={() => setInput("https://example.com/download/report.pdf?source=email&lang=zh#page=2")}>{t.example}</AButton>
          <AButton variant="text" disabled={!input} onClick={() => setInput("")}>{t.clear}</AButton>
        </div>
        {parsed.error && <div className="empty-state error-state">{parsed.error}</div>}
      </div>

      {url && (
        <>
          <div className="tool-panel wide-panel url-structure-panel">
            <PanelTitle title={t.structure} />
            <InfoTable rows={[
              [t.scheme, url.protocol.replace(/:$/, "")],
              [t.username, url.username || "--"],
              [t.passwordValue, url.password || "--"],
              [t.host, url.hostname],
              [t.port, url.port || "--"],
              [t.jsonPath, url.pathname || "/"],
              [t.query, url.search || "--"],
              [t.fragment, url.hash || "--"]
            ]} />
          </div>

          {params.length > 0 && (
            <div className="tool-panel wide-panel url-params-panel">
              <PanelTitle title={t.query_parameters} />
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>#</th><th>{t.name}</th><th>{t.httpHeaderValue}</th></tr></thead>
                  <tbody>{params.map(([name, value], index) => (
                    <tr key={`${name}-${index}`}><td>{index + 1}</td><td>{name}</td><td>{value || "--"}</td></tr>
                  ))}</tbody>
                </table>
              </div>
            </div>
          )}

          <div className="tool-panel wide-panel url-output-panel">
            <PanelTitle title={t.representations} />
            <div className="url-output-list">
              {outputs.map(([label, value]) => (
                <div className="url-output-row" key={label}>
                  <div><strong>{label}</strong><code>{value}</code></div>
                  <AButton variant="text" onClick={() => void copyText(value)}>{t.copy}</AButton>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
