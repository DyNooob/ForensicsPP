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
import { AButton, ALinearProgress, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import type { AndroidApkEntry, AndroidComponent, AndroidManifestInfo } from "../models";
import { hexPreview } from "../utils/binary";
import { downloadTextFile, formatBytes } from "../utils/files";

type Finding = { level: string; title: string; detail: string };
type ArchiveInspection = {
  manifest: Uint8Array;
  rows: Array<[string, string]>;
  findings: Finding[];
  entries: AndroidApkEntry[];
};
type BinaryXmlInspection = { rows: Array<[string, string]>; findings: Finding[] };

export type AndroidManifestToolServices = {
  androidComponentKey: (component: AndroidComponent) => string;
  componentExportedEffective: (component: Pick<AndroidComponent, "exported" | "actions" | "categories">, targetSdk: string) => string;
  parseAndroidManifest: (xml: string, name: string, size: number, archiveInfo?: { rows: Array<[string, string]>; findings: Finding[]; entries?: AndroidApkEntry[]; axmlRows?: Array<[string, string]>; axmlFindings?: Finding[] }) => AndroidManifestInfo;
  inspectAndroidArchive: (bytes: Uint8Array) => ArchiveInspection;
  inspectAndroidBinaryXml: (bytes: Uint8Array) => BinaryXmlInspection;
  decodeAndroidManifestBytes: (bytes: Uint8Array) => string;
  androidComponentsToCsv: (components: AndroidComponent[]) => string;
  androidPermissionsToCsv: (rows: AndroidManifestInfo["permissionRows"]) => string;
  androidApkEntriesToCsv: (entries: AndroidApkEntry[]) => string;
};

type AndroidView = "overview" | "permissions" | "components" | "entries";
const MAX_ARCHIVE_SIZE = 256 * 1024 * 1024;

export function AndroidManifestTool({ t, services }: { t: (typeof copy)["zh"]; services: AndroidManifestToolServices }) {
  const english = t.waiting === "Waiting";
  const [info, setInfo] = React.useState<AndroidManifestInfo | null>(null);
  const [manifestText, setManifestText] = React.useState("");
  const [sourceName, setSourceName] = React.useState("pasted AndroidManifest.xml");
  const [view, setView] = React.useState<AndroidView>("overview");
  const [componentFilter, setComponentFilter] = React.useState("");
  const [entryFilter, setEntryFilter] = React.useState("");
  const [selectedComponentKey, setSelectedComponentKey] = React.useState("");
  const [selectedEntryName, setSelectedEntryName] = React.useState("");
  const [dropActive, setDropActive] = React.useState(false);
  const [parsing, setParsing] = React.useState(false);
  const [error, setError] = React.useState("");
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const workerRef = React.useRef<Worker | null>(null);
  const requestRef = React.useRef(0);
  const hasSource = Boolean(info || manifestText.trim() || error);
  const visibleComponents = React.useMemo(() => {
    const query = componentFilter.trim().toLowerCase();
    return (info?.components ?? []).filter((component) => !query || [
      component.type,
      component.name,
      component.exported,
      component.enabled,
      component.permission,
      component.actions.join(" "),
      component.categories.join(" "),
      component.data.join(" ")
    ].join(" ").toLowerCase().includes(query));
  }, [componentFilter, info?.components]);
  const visibleEntries = React.useMemo(() => {
    const query = entryFilter.trim().toLowerCase();
    return (info?.apkEntries ?? []).filter((entry) => !query || [entry.name, entry.directory, entry.extension, entry.role, entry.signature].join(" ").toLowerCase().includes(query));
  }, [entryFilter, info?.apkEntries]);
  const selectedComponent = selectedComponentKey && info
    ? info.components.find((component) => services.androidComponentKey(component) === selectedComponentKey) ?? null
    : null;
  const selectedEntry = selectedEntryName && info
    ? info.apkEntries.find((entry) => entry.name === selectedEntryName) ?? null
    : null;

  const resetReview = () => {
    setView("overview");
    setComponentFilter("");
    setEntryFilter("");
    setSelectedComponentKey("");
    setSelectedEntryName("");
  };

  const parseText = (text = manifestText, name = sourceName) => {
    setError("");
    try {
      setInfo(services.parseAndroidManifest(text, name, new Blob([text]).size));
      resetReview();
    } catch (caught) {
      setInfo(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const handleFile = async (file?: File) => {
    if (!file) return;
    setDropActive(false);
    setError("");
    if (file.size > MAX_ARCHIVE_SIZE) {
      setError(english ? "Files larger than 256 MiB are not opened in the browser." : "浏览器内不打开超过 256 MiB 的文件。");
      return;
    }
    setParsing(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      workerRef.current?.terminate();
      const requestId = ++requestRef.current;
      const worker = new Worker(new URL("../workers/android.worker.ts", import.meta.url), { type: "module" });
      workerRef.current = worker;
      worker.onmessage = (event: MessageEvent<{ id: number; xml?: string; archiveInfo?: { rows: Array<[string, string]>; findings: Finding[]; entries?: AndroidApkEntry[]; axmlRows?: Array<[string, string]>; axmlFindings?: Finding[] }; error?: string }>) => {
        if (event.data.id !== requestId) return;
        worker.terminate();
        workerRef.current = null;
        setParsing(false);
        if (event.data.error || !event.data.archiveInfo || event.data.xml == null) {
          setInfo(null);
          setError(event.data.error || (english ? "Android parsing failed." : "Android 解析失败。"));
          return;
        }
        try {
          setManifestText(event.data.xml);
          setSourceName(file.name);
          setInfo(services.parseAndroidManifest(event.data.xml, file.name, file.size, event.data.archiveInfo));
          resetReview();
        } catch (caught) {
          setInfo(null);
          setError(caught instanceof Error ? caught.message : String(caught));
        }
      };
      worker.onerror = (event) => {
        if (requestId !== requestRef.current) return;
        worker.terminate();
        workerRef.current = null;
        setParsing(false);
        setInfo(null);
        setError(event.message || (english ? "Android worker failed." : "Android 解析任务失败。"));
      };
      worker.postMessage({ id: requestId, bytes, name: file.name, size: file.size }, [bytes.buffer]);
    } catch (caught) {
      setInfo(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const clear = () => {
    requestRef.current += 1;
    workerRef.current?.terminate();
    workerRef.current = null;
    setManifestText("");
    setInfo(null);
    setError("");
    setSourceName("pasted AndroidManifest.xml");
    resetReview();
    if (inputRef.current) inputRef.current.value = "";
  };

  React.useEffect(() => () => workerRef.current?.terminate(), []);

  const exportInfoJson = () => {
    if (!info) return;
    downloadTextFile(`android-manifest-${Date.now()}.json`, JSON.stringify({ generatedAt: new Date().toISOString(), ...info }, null, 2), "application/json;charset=utf-8");
  };

  return (
    <div className={`tool-grid android-simple-workbench manifest-grid ${hasSource ? "has-android" : "empty-android"}`}>
      {parsing && <div className="wide-panel"><ALinearProgress /></div>}

      <section className="tool-panel wide-panel android-simple-source-panel manifest-input-panel">
        <ToolPanelHeader
          title={english ? "Open APK or manifest" : "选择 APK 或 Manifest"}
          actions={<AButton variant="text" disabled={!manifestText && !info} onClick={clear}>{t.clear}</AButton>}
        />
        <input
          className="hidden-file-input"
          ref={inputRef}
          type="file"
          accept=".apk,.apks,.xapk,.xml,.axml,text/xml,application/xml,application/vnd.android.package-archive"
          onChange={(event) => void handleFile(event.target.files?.[0])}
        />
        <div
          className={`desktop-drop-zone manifest-drop-zone ${dropActive ? "active" : ""}`}
          role="button"
          tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              inputRef.current?.click();
            }
          }}
          onDragOver={(event) => { event.preventDefault(); setDropActive(true); }}
          onDragLeave={() => setDropActive(false)}
          onDrop={(event) => { event.preventDefault(); void handleFile(event.dataTransfer.files?.[0]); }}
        >
          <strong>{info ? sourceName : t.uploadManifest}</strong>
          <span>{info ? `${info.sourceFormat} · ${formatBytes(info.size)}` : (english ? "APK, XML, or binary AXML" : "支持 APK、XML 和二进制 AXML")}</span>
        </div>
        {info ? <details className="android-xml-details"><summary>{english ? "View decoded XML" : "查看解码 XML"}</summary><textarea
          className="single-textarea android-simple-editor manifest-textarea"
          aria-label={english ? "Decoded AndroidManifest XML" : "解码后的 AndroidManifest XML"}
          value={manifestText}
          readOnly
        /></details> : <textarea
          className="single-textarea android-simple-editor manifest-textarea"
          aria-label={english ? "AndroidManifest XML input" : "AndroidManifest XML 输入"}
          value={manifestText}
          onChange={(event) => { setManifestText(event.target.value); setSourceName("pasted AndroidManifest.xml"); setInfo(null); resetReview(); }}
          placeholder="<manifest xmlns:android=&quot;http://schemas.android.com/apk/res/android&quot; ...>"
        />}
        <div className="android-simple-primary-action">
          <AButton variant="filled" disabled={parsing || !manifestText.trim()} onClick={() => parseText()}>{t.parseManifest}</AButton>
          <AButton variant="outlined" disabled={parsing} onClick={() => inputRef.current?.click()}>{t.uploadManifest}</AButton>
          <AButton variant="text" disabled={!manifestText} onClick={() => void navigator.clipboard.writeText(manifestText)}>{t.copy} XML</AButton>
          <AButton variant="text" disabled={!manifestText} onClick={() => downloadTextFile(`decoded-android-manifest-${Date.now()}.xml`, manifestText, "application/xml;charset=utf-8")}>{english ? "Download XML" : "下载 XML"}</AButton>
        </div>
        {error && <pre className="result-box android-simple-error">{error}</pre>}
      </section>

      {info && (
        <section className="tool-panel wide-panel android-simple-results-panel manifest-overview-panel">
          <ToolPanelHeader
            title={t.manifestSummary}
            subtitle={info.packageName || sourceName}
            actions={<AButton variant="outlined" onClick={exportInfoJson}>{t.exportJson}</AButton>}
          />
          <div className="android-simple-summary">
            <span><small>Package</small><strong>{info.packageName || "--"}</strong></span>
            <span><small>Version</small><strong>{info.versionName || info.versionCode || "--"}</strong></span>
            <span><small>SDK</small><strong>{info.minSdk || "--"} / {info.targetSdk || "--"}</strong></span>
            <span><small>{t.components}</small><strong>{info.components.length}</strong></span>
          </div>
          <ASegmentedGroup className="android-simple-tabs" value={view} selects="single">
            <ASegmentedButton value="overview" onClick={() => setView("overview")}>{english ? "Overview" : "概览"}</ASegmentedButton>
            <ASegmentedButton value="permissions" onClick={() => setView("permissions")}>{t.permissions} ({info.permissionRows.length})</ASegmentedButton>
            <ASegmentedButton value="components" onClick={() => setView("components")}>{t.components} ({info.components.length})</ASegmentedButton>
            <ASegmentedButton value="entries" disabled={!info.apkEntries.length} onClick={() => setView("entries")}>{english ? "APK entries" : "APK 条目"} ({info.apkEntries.length})</ASegmentedButton>
          </ASegmentedGroup>

          {view === "overview" && (
            <div className="android-simple-overview">
              <InfoTable rows={[
                [t.appLabel, info.appLabel || "--"],
                [t.launcherActivity, info.launcherActivity || "--"],
                [t.debuggable, info.debuggable || "--"],
                [t.allowBackup, info.allowBackup || "--"],
                [t.cleartextTraffic, info.cleartextTraffic || "--"],
                ["Network Security", info.networkSecurityConfig || "--"],
                ["Source", info.name],
                ["Format", info.sourceFormat],
                ["AXML", info.axmlRows.length ? `${info.axmlRows.length} rows` : "plain XML"]
              ]} />
              {(info.features.length || info.libraries.length || info.queries.length) > 0 && (
                <div className="android-simple-declarations">
                  {[...info.features.map((item) => `feature: ${item}`), ...info.libraries.map((item) => `library: ${item}`), ...info.queries.map((item) => `query: ${item}`)].map((item) => <code key={item}>{item}</code>)}
                </div>
              )}
              {info.axmlRows.length > 0 && <InfoTable rows={info.axmlRows} />}
            </div>
          )}

          {view === "permissions" && (
            <div className="android-simple-view">
              <div className="android-simple-view-actions">
                <AButton variant="outlined" disabled={!info.permissionRows.length} onClick={() => downloadTextFile(`android-permissions-${Date.now()}.csv`, services.androidPermissionsToCsv(info.permissionRows), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton>
              </div>
              {info.permissionRows.length ? (
                <div className="table-scroll android-simple-table-scroll">
                  <table className="data-table android-simple-permissions-table"><thead><tr><th>{t.permissions}</th><th>{t.category}</th></tr></thead><tbody>{info.permissionRows.map((row) => <tr key={row.permission}><td className="mono-cell">{row.permission}</td><td>{row.category}</td></tr>)}</tbody></table>
                </div>
              ) : <div className="empty-state">--</div>}
            </div>
          )}

          {view === "components" && (
            <div className="android-simple-view">
              <div className="android-simple-view-actions android-simple-filter-actions">
                <input className="text-input" value={componentFilter} onChange={(event) => setComponentFilter(event.target.value)} placeholder={english ? "Filter component, action, or permission" : "筛选组件、Action 或权限"} />
                <AButton variant="outlined" disabled={!visibleComponents.length} onClick={() => downloadTextFile(`android-components-${Date.now()}.csv`, services.androidComponentsToCsv(visibleComponents), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton>
              </div>
              {visibleComponents.length ? (
                <div className="table-scroll android-simple-table-scroll">
                  <table className="data-table android-simple-components-table">
                    <thead><tr><th>{t.componentType}</th><th>{t.componentName}</th><th>{t.exported}</th><th>Effective</th><th>{t.enabled}</th><th>{t.permissions}</th></tr></thead>
                    <tbody>{visibleComponents.map((component) => <tr className={selectedComponentKey === services.androidComponentKey(component) ? "selected-row" : ""} key={services.androidComponentKey(component)} onClick={() => setSelectedComponentKey(services.androidComponentKey(component))}><td>{component.type}</td><td>{component.name}</td><td>{component.exported}</td><td>{services.componentExportedEffective(component, info.targetSdk)}</td><td>{component.enabled}</td><td>{component.permission || "--"}</td></tr>)}</tbody>
                  </table>
                </div>
              ) : <div className="empty-state">--</div>}
            </div>
          )}

          {view === "entries" && (
            <div className="android-simple-view">
              <div className="android-simple-view-actions android-simple-filter-actions">
                <input className="text-input" value={entryFilter} onChange={(event) => setEntryFilter(event.target.value)} placeholder={english ? "Filter path, extension, or role" : "筛选路径、扩展名或类型"} />
                <AButton variant="outlined" disabled={!visibleEntries.length} onClick={() => downloadTextFile(`android-apk-entries-${Date.now()}.csv`, services.androidApkEntriesToCsv(visibleEntries), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton>
              </div>
              <div className="table-scroll android-simple-table-scroll">
                <table className="data-table android-simple-entries-table"><thead><tr><th>{english ? "Name" : "名称"}</th><th>{english ? "Role" : "类型"}</th><th>{t.fileSize}</th><th>Signature</th></tr></thead><tbody>{visibleEntries.map((entry) => <tr className={selectedEntryName === entry.name ? "selected-row" : ""} key={entry.name} onClick={() => setSelectedEntryName(entry.name)}><td>{entry.name}</td><td>{entry.role}</td><td>{formatBytes(entry.size)}</td><td>{entry.signature}</td></tr>)}</tbody></table>
              </div>
            </div>
          )}
        </section>
      )}

      {info && view === "components" && selectedComponent && (
        <section className="tool-panel wide-panel android-simple-detail-panel">
          <ToolPanelHeader title={english ? "Selected component" : "当前组件"} />
          <InfoTable rows={[
            [t.componentType, selectedComponent.type],
            [t.componentName, selectedComponent.name],
            [t.exported, selectedComponent.exported],
            ["Effective exported", services.componentExportedEffective(selectedComponent, info.targetSdk)],
            [t.enabled, selectedComponent.enabled],
            [t.permissions, selectedComponent.permission || "--"],
            ["Actions", selectedComponent.actions.join(", ") || "--"],
            ["Categories", selectedComponent.categories.join(", ") || "--"],
            ["Data", selectedComponent.data.join(", ") || "--"]
          ]} />
        </section>
      )}

      {view === "entries" && selectedEntry && (
        <section className="tool-panel wide-panel android-simple-detail-panel">
          <ToolPanelHeader title={english ? "Selected APK entry" : "当前 APK 条目"} />
          <InfoTable rows={[
            [english ? "Name" : "名称", selectedEntry.name],
            [english ? "Directory" : "目录", selectedEntry.directory || "--"],
            [english ? "Role" : "类型", selectedEntry.role],
            [t.fileSize, formatBytes(selectedEntry.size)],
            ["Signature", selectedEntry.signature]
          ]} />
          {selectedEntry.preview && <pre className="result-box android-simple-entry-preview">{selectedEntry.preview}</pre>}
        </section>
      )}
    </div>
  );
}
