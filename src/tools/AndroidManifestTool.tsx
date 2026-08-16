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
import { subscribeToolHandoff, takeToolHandoff } from "../core/toolHandoff";
import { AButton, ALinearProgress, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import type { AndroidApkEntry, AndroidComponent, AndroidManifestInfo, AndroidSigningInfo } from "../models";
import { PERM_CATEGORY_META, PERM_SEVERITY_META, type PermCategory, type PermSeverity } from "../features/android/permissionCatalog";
import { hexPreview } from "../utils/binary";
import { downloadBlob, downloadTextFile, formatBytes } from "../utils/files";
import { createTemporaryRepairIdentity, importRepairIdentity, resignApkV2 } from "../features/android/signingRepair";
import { verifyAndroidV4Idsig, type AndroidV4Verification } from "../features/android/v4Verify";
import { runWorkerTask } from "../utils/workerTask";
import { useStoredState } from "../utils/storage";
import { useToolWorkspace } from "../utils/useToolWorkspace";

type Finding = { level: string; title: string; detail: string };
type AndroidWorkerResult = {
  xml: string;
  archiveInfo: { rows: Array<[string, string]>; findings: Finding[]; entries?: AndroidApkEntry[]; signing?: AndroidSigningInfo; axmlRows?: Array<[string, string]>; axmlFindings?: Finding[] };
};

type AndroidWorkspace = {
  info: AndroidManifestInfo;
};

export type AndroidManifestToolServices = {
  androidComponentKey: (component: AndroidComponent) => string;
  componentExportedEffective: (component: Pick<AndroidComponent, "exported" | "actions" | "categories">, targetSdk: string) => string;
  parseAndroidManifest: (xml: string, name: string, size: number, archiveInfo?: { rows: Array<[string, string]>; findings: Finding[]; entries?: AndroidApkEntry[]; signing?: AndroidSigningInfo; axmlRows?: Array<[string, string]>; axmlFindings?: Finding[] }) => AndroidManifestInfo;
  androidComponentsToCsv: (components: AndroidComponent[]) => string;
  androidPermissionsToCsv: (rows: AndroidManifestInfo["permissionRows"]) => string;
  androidApkEntriesToCsv: (entries: AndroidApkEntry[]) => string;
};

type AndroidView = "overview" | "signing" | "permissions" | "components" | "entries";
const MAX_ARCHIVE_SIZE = 256 * 1024 * 1024;

export function AndroidManifestTool({ t, services, active = true }: { t: (typeof copy)["zh"]; services: AndroidManifestToolServices; active?: boolean }) {
  const english = t.waiting === "Waiting";
  const [info, setInfo] = React.useState<AndroidManifestInfo | null>(null);
  const [manifestText, setManifestText] = useStoredState("android.manifestText.v2", "");
  const [sourceName, setSourceName] = useStoredState("android.sourceName.v2", "pasted AndroidManifest.xml");
  const [view, setView] = React.useState<AndroidView>("overview");
  const [componentFilter, setComponentFilter] = React.useState("");
  const [permissionFilter, setPermissionFilter] = React.useState("");
  const [severityFilter, setSeverityFilter] = React.useState<PermSeverity | "all">("all");
  const [entryFilter, setEntryFilter] = React.useState("");
  const [selectedComponentKey, setSelectedComponentKey] = React.useState("");
  const [selectedEntryName, setSelectedEntryName] = React.useState("");
  const [dropActive, setDropActive] = React.useState(false);
  const [parsing, setParsing] = React.useState(false);
  const [error, setError] = React.useState("");
  const [sourceFile, setSourceFile] = React.useState<File | null>(null);
  const [repairKeyFile, setRepairKeyFile] = React.useState<File | null>(null);
  const [repairCertFile, setRepairCertFile] = React.useState<File | null>(null);
  const [repairBusy, setRepairBusy] = React.useState(false);
  const [repairStatus, setRepairStatus] = React.useState("");
  const [stripV1OnRepair, setStripV1OnRepair] = React.useState(true);
  const [v4File, setV4File] = React.useState<File | null>(null);
  const [v4Busy, setV4Busy] = React.useState(false);
  const [v4Result, setV4Result] = React.useState<AndroidV4Verification | null>(null);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);
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

  const permissionRows = info?.permissionRows ?? [];
  const permissionSeverityCounts = React.useMemo(() => {
    const counts: Record<string, number> = {};
    for (const row of permissionRows) counts[row.severity] = (counts[row.severity] ?? 0) + 1;
    return counts;
  }, [permissionRows]);
  const visiblePermissionRows = React.useMemo(() => {
    const query = permissionFilter.trim().toLowerCase();
    return permissionRows.filter((row) => {
      if (severityFilter !== "all" && row.severity !== severityFilter) return false;
      if (!query) return true;
      return [row.permission, row.labelZh, row.labelEn, row.descZh, row.descEn, row.categoryZh, row.categoryEn].join(" ").toLowerCase().includes(query);
    });
  }, [permissionRows, permissionFilter, severityFilter]);
  const permissionGroups = React.useMemo(() => {
    const groups = new Map<string, AndroidManifestInfo["permissionRows"]>();
    for (const row of visiblePermissionRows) {
      const key = row.categoryKey || "other";
      const bucket = groups.get(key);
      if (bucket) bucket.push(row);
      else groups.set(key, [row]);
    }
    const severityRank = (s: string) => PERM_SEVERITY_META[s as PermSeverity]?.order ?? 99;
    return Array.from(groups.entries())
      .map(([key, rows]) => ({
        key,
        meta: PERM_CATEGORY_META[key as PermCategory] ?? PERM_CATEGORY_META.other,
        rows: [...rows].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.shortName.localeCompare(b.shortName))
      }))
      .sort((a, b) => a.meta.order - b.meta.order);
  }, [visiblePermissionRows]);
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

  const workspace = useToolWorkspace<AndroidWorkspace>({
    id: "android-manifest",
    version: 1,
    isValid: (value): value is AndroidWorkspace => Boolean(
      value && typeof value === "object" &&
      (value as AndroidWorkspace).info &&
      Array.isArray((value as AndroidWorkspace).info.components)
    ),
    onRestore: (value) => {
      setSourceFile(null);
      setRepairStatus("");
      setInfo(value.info);
      setError("");
      resetReview();
    }
  });

  const parseText = (text = manifestText, name = sourceName) => {
    setSourceFile(null);
    setRepairStatus("");
    setV4File(null);
    setV4Result(null);
    abortRef.current?.abort();
    abortRef.current = null;
    setParsing(false);
    setError("");
    try {
      const next = services.parseAndroidManifest(text, name, new Blob([text]).size);
      setInfo(next);
      workspace.save({ info: next });
      resetReview();
    } catch (caught) {
      setInfo(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const handleFile = async (file?: File) => {
    if (!file || !active) return;
    setSourceFile(file);
    setRepairStatus("");
    setV4File(null);
    setV4Result(null);
    workspace.clear();
    setDropActive(false);
    setError("");
    abortRef.current?.abort();
    abortRef.current = null;
    setParsing(false);
    setManifestText("");
    setSourceName(file.name);
    setInfo(null);
    resetReview();
    if (file.size > MAX_ARCHIVE_SIZE) {
      setError(english ? "Files larger than 256 MiB are not opened in the browser." : "浏览器内不打开超过 256 MiB 的文件。");
      return;
    }
    setParsing(true);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (!active || controller.signal.aborted) return;
      const result = await runWorkerTask<{ bytes: Uint8Array; name: string; size: number }, AndroidWorkerResult>({
        createWorker: () => new Worker(new URL("../workers/android.worker.ts", import.meta.url), { type: "module" }),
        request: { bytes, name: file.name, size: file.size },
        transfer: [bytes.buffer],
        signal: controller.signal,
        timeoutMs: 180_000
      });
      if (!active || controller.signal.aborted) return;
      const next = services.parseAndroidManifest(result.xml, file.name, file.size, result.archiveInfo);
      setManifestText(result.xml);
      setSourceName(file.name);
      setInfo(next);
      workspace.save({ info: next });
      resetReview();
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      setInfo(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setParsing(false);
      }
    }
  };

  const handleFileRef = React.useRef(handleFile);
  handleFileRef.current = handleFile;
  React.useEffect(() => {
    if (!active) return;
    const consume = () => {
      const handoff = takeToolHandoff("android");
      if (handoff) void handleFileRef.current(handoff.file);
    };
    consume();
    return subscribeToolHandoff("android", consume);
  }, [active]);

  const clear = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    workspace.clear();
    setParsing(false);
    setManifestText("");
    setInfo(null);
    setSourceFile(null);
    setRepairKeyFile(null);
    setRepairCertFile(null);
    setRepairStatus("");
    setV4File(null);
    setV4Result(null);
    setError("");
    setSourceName("pasted AndroidManifest.xml");
    resetReview();
    if (inputRef.current) inputRef.current.value = "";
  };

  React.useEffect(() => () => abortRef.current?.abort(), []);
  React.useEffect(() => {
    if (active) return;
    abortRef.current?.abort();
    abortRef.current = null;
    setParsing(false);
  }, [active]);

  const exportInfoJson = () => {
    if (!info) return;
    downloadTextFile(`android-manifest-${Date.now()}.json`, JSON.stringify({ generatedAt: new Date().toISOString(), ...info }, null, 2), "application/json;charset=utf-8");
  };

  const repairableApk = Boolean(sourceFile && /\.apk$/i.test(sourceFile.name));
  const runV4Verification = async (file: File | null) => {
    setV4File(file);
    setV4Result(null);
    if (!file || !sourceFile || !repairableApk) return;
    setV4Busy(true);
    try {
      if (file.size > 32 * 1024 * 1024) throw new Error(english ? ".idsig files larger than 32 MiB are not opened." : "不打开超过 32 MiB 的 .idsig 文件。");
      const [apkBuffer, idsigBuffer] = await Promise.all([sourceFile.arrayBuffer(), file.arrayBuffer()]);
      setV4Result(await verifyAndroidV4Idsig(new Uint8Array(apkBuffer), new Uint8Array(idsigBuffer)));
    } catch (caught) {
      setV4Result({
        present: true, verified: false, version: null, complete: false, signatureAlgorithmId: null, signatureAlgorithm: "--",
        signatureVerified: false, publicKeyMatchesCertificate: false, rootHashVerified: false, treeVerified: null,
        apkDigestMatchesV2V3: false, certificateMatchesV2V3: false, certificateSha256: "", expectedRootHash: "", actualRootHash: "",
        errors: [caught instanceof Error ? caught.message : String(caught)], warnings: []
      });
    } finally {
      setV4Busy(false);
    }
  };
  const runGeneratedRepair = async () => {
    if (!sourceFile || !repairableApk) return;
    setRepairBusy(true);
    setRepairStatus(english ? "Generating a local repair signer and rebuilding the v2 signature…" : "正在生成本地修复签名身份并重建 v2 签名…");
    try {
      const input = new Uint8Array(await sourceFile.arrayBuffer());
      const identity = await createTemporaryRepairIdentity();
      const result = await resignApkV2(input, identity, { stripJarSignatures: stripV1OnRepair });
      const base = sourceFile.name.replace(/\.apk$/i, "");
      const readme = new TextEncoder().encode([
        "Forensics++ APK local repair bundle",
        `Source: ${sourceFile.name}`,
        `Generated: ${new Date().toISOString()}`,
        "Scheme: APK Signature Scheme v2 / RSA PKCS#1 v1.5 SHA-256",
        "IMPORTANT: This is a NEW signing identity. It does not restore the original developer signature and cannot update an app installed under the original key.",
        ...result.warnings
      ].join("\n"));
      const files: Record<string, Uint8Array> = {
        [`${base}-resigned.apk`]: result.bytes,
        "repair-cert.x509.der": identity.certificate,
        "README.txt": readme
      };
      if (identity.privateKeyPkcs8) files["repair-key.pk8"] = identity.privateKeyPkcs8;
      const bundle = zipSync(files, { level: 0 });
      downloadBlob(`${base}-repair-bundle.zip`, new Blob([bundle], { type: "application/zip" }));
      setRepairStatus(english
        ? `Re-sign complete and self-verified. ${result.strippedJarSignatures.length} JAR/v1 signature entries removed. A repair bundle containing the APK and new signer material was downloaded.`
        : `重签完成并通过自校验。移除了 ${result.strippedJarSignatures.length} 个 JAR/v1 签名条目；已下载包含 APK 与新签名材料的修复包。`);
    } catch (caught) {
      setRepairStatus(`${english ? "Repair failed" : "修复失败"}: ${caught instanceof Error ? caught.message : String(caught)}`);
    } finally {
      setRepairBusy(false);
    }
  };

  const runImportedRepair = async () => {
    if (!sourceFile || !repairableApk || !repairKeyFile || !repairCertFile) return;
    setRepairBusy(true);
    setRepairStatus(english ? "Importing signer and rebuilding the APK v2 signature…" : "正在导入签名身份并重建 APK v2 签名…");
    try {
      const [apkBuffer, keyBuffer, certBuffer] = await Promise.all([sourceFile.arrayBuffer(), repairKeyFile.arrayBuffer(), repairCertFile.arrayBuffer()]);
      const identity = await importRepairIdentity(new Uint8Array(keyBuffer), new Uint8Array(certBuffer), repairCertFile.name);
      const result = await resignApkV2(new Uint8Array(apkBuffer), identity, { stripJarSignatures: stripV1OnRepair });
      const base = sourceFile.name.replace(/\.apk$/i, "");
      downloadBlob(`${base}-resigned.apk`, new Blob([result.bytes], { type: "application/vnd.android.package-archive" }));
      setRepairStatus(english
        ? `Re-sign complete and self-verified with the imported identity. ${result.strippedJarSignatures.length} JAR/v1 signature entries removed.`
        : `已使用导入身份完成重签并通过自校验。移除了 ${result.strippedJarSignatures.length} 个 JAR/v1 签名条目。`);
    } catch (caught) {
      setRepairStatus(`${english ? "Repair failed" : "修复失败"}: ${caught instanceof Error ? caught.message : String(caught)}`);
    } finally {
      setRepairBusy(false);
    }
  };

  return (
    <div className={`tool-grid android-simple-workbench manifest-grid ${hasSource ? "has-android" : "empty-android"}`}>
      {parsing && <div className="wide-panel"><ALinearProgress /></div>}

      <section className="tool-panel wide-panel android-simple-source-panel manifest-input-panel">
        <ToolPanelHeader
          title={english ? "Open APK or manifest" : "选择 APK 或 Manifest"}
          actions={<AButton variant="text" disabled={!manifestText && !info && !error && !parsing} onClick={clear}>{t.clear}</AButton>}
        />
        <input
          className="hidden-file-input"
          ref={inputRef}
          type="file"
          aria-hidden="true"
          tabIndex={-1}
          accept=".apk,.apks,.xapk,.xml,.axml,text/xml,application/xml,application/vnd.android.package-archive"
          onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void handleFile(file); }}
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
          onDrop={(event) => { event.preventDefault(); setDropActive(false); void handleFile(event.dataTransfer.files?.[0]); }}
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
          <AButton variant="text" disabled={!manifestText} onClick={() => void copyText(manifestText)}>{t.copy} XML</AButton>
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
            <span><small>{t.permissions}</small><strong>{info.permissionRows.length}</strong></span>
            <span className={permissionSeverityCounts.dangerous ? "android-summary-danger" : ""}><small>{english ? "Dangerous" : "危险权限"}</small><strong>{permissionSeverityCounts.dangerous ?? 0}</strong></span>
            <span><small>{t.components}</small><strong>{info.components.length}</strong></span>
          </div>
          <ASegmentedGroup className="android-simple-tabs" value={view} selects="single">
            <ASegmentedButton value="overview" onClick={() => setView("overview")}>{english ? "Overview" : "概览"}</ASegmentedButton>
            <ASegmentedButton value="signing" disabled={!info.signing?.present} onClick={() => setView("signing")}>{english ? "Signing" : "签名"} ({info.signing?.signers.length ?? 0})</ASegmentedButton>
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

          {view === "signing" && info.signing && (
            <div className="android-simple-view android-signing-view">
              <InfoTable rows={[
                [english ? "Signing Block" : "签名块", info.signing.present ? (english ? "Present" : "存在") : "--"],
                [english ? "Signing Block schemes" : "签名块方案", info.signing.schemes.join(" + ") || "--"],
                [english ? "Cryptographically checked" : "密码学验证方案", info.signing.verification?.checkedSchemes.map((scheme) => scheme.toUpperCase()).join(" + ") || "--"],
                [english ? "Signers" : "Signer 数量", String(info.signing.signers.length)],
                [english ? "Block offset" : "签名块偏移", info.signing.blockOffset == null ? "--" : `0x${info.signing.blockOffset.toString(16).toUpperCase()}`],
                [english ? "Block size" : "签名块大小", info.signing.blockSize ? formatBytes(info.signing.blockSize) : "--"],
                [english ? "Central Directory" : "Central Directory", info.signing.centralDirectoryOffset == null ? "--" : `0x${info.signing.centralDirectoryOffset.toString(16).toUpperCase()}`],
                [english ? "Unknown pair IDs" : "未知 Pair ID", info.signing.unknownPairIds.join(", ") || "--"],
                [english ? "Integrity verification" : "完整性验证", info.signing.verification?.status === "verified" ? (english ? "Verified" : "验证通过") : info.signing.verification?.status === "failed" ? (english ? "Failed" : "验证失败") : (english ? "Not available" : "未执行")],
                [english ? "Verification time" : "验证耗时", info.signing.verification ? `${info.signing.verification.durationMs} ms` : "--"]
              ]} />
              {info.signing.warnings.length > 0 && <div className="forensic-inline-note">{info.signing.warnings.join(" · ")}</div>}
              {info.signing.verification?.errors.length ? <div className="forensic-inline-note error-state">{info.signing.verification.errors.join(" · ")}</div> : null}
              {info.signing.verification?.warnings.length ? <div className="forensic-inline-note">{info.signing.verification.warnings.join(" · ")}</div> : null}
              {info.signing.verification?.jarV1?.present ? <div className="tool-panel android-signing-signer">
                <ToolPanelHeader title="V1 / JAR signer" subtitle={info.signing.verification.jarV1.signerBase || undefined} />
                <InfoTable rows={[
                  [english ? "Manifest entries" : "Manifest 条目", `${info.signing.verification.jarV1.verifiedEntries} / ${info.signing.verification.jarV1.manifestEntries}`],
                  [english ? ".SF manifest digest" : ".SF Manifest 摘要", info.signing.verification.jarV1.sfManifestDigestVerified ? "✓" : "✗"],
                  [english ? "CMS signature" : "CMS 签名", info.signing.verification.jarV1.cmsSignatureVerified ? "✓" : "✗"],
                  [english ? "Signer certificate SHA-256" : "Signer 证书 SHA-256", info.signing.verification.jarV1.signerCertificateSha256 || "--"],
                  [english ? "Result" : "结果", info.signing.verification.jarV1.verified ? (english ? "Verified" : "通过") : (english ? "Failed" : "失败")]
                ]} />
              </div> : null}
              {info.signing.verification?.signerResults.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>Signer</th><th>{english ? "Algorithm" : "算法"}</th><th>{english ? "Signed data" : "签名数据"}</th><th>{english ? "APK digest" : "APK 摘要"}</th><th>{english ? "Cert key" : "证书公钥"}</th><th>{english ? "Result" : "结果"}</th></tr></thead><tbody>{info.signing.verification.signerResults.map((result) => <tr key={`verify-${result.scheme}-${result.signerIndex}`}><td>{result.scheme.toUpperCase()} #{result.signerIndex}</td><td>{result.selectedAlgorithm}</td><td>{result.signatureVerified ? "✓" : "✗"}</td><td>{result.contentDigestVerified ? "✓" : "✗"}</td><td>{result.publicKeyMatchesCertificate ? "✓" : "✗"}</td><td>{result.verified ? (english ? "Verified" : "通过") : (english ? "Failed" : "失败")}</td></tr>)}</tbody></table></div> : null}
              {info.signing.signers.map((signer) => <div className="tool-panel android-signing-signer" key={`${signer.scheme}-${signer.index}`}>
                <ToolPanelHeader title={`${signer.scheme.toUpperCase()} signer ${signer.index}`} subtitle={signer.minSdk == null ? undefined : `SDK ${signer.minSdk}–${signer.maxSdk ?? "?"}`} />
                <InfoTable rows={[
                  [english ? "Signature algorithms" : "签名算法", signer.signatures.map((item) => item.name).join(", ") || "--"],
                  [english ? "Digest algorithms" : "摘要算法", signer.digests.map((item) => item.name).join(", ") || "--"],
                  [english ? "Public key" : "公钥", `${formatBytes(signer.publicKeySize)} · SHA-256 ${signer.publicKeySha256}`],
                  [english ? "Additional attributes" : "附加属性", signer.attributes.join(", ") || "--"]
                ]} />
                {signer.certificates.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>#</th><th>SHA-256</th><th>{english ? "Subject" : "Subject"}</th><th>{english ? "Issuer" : "Issuer"}</th><th>{english ? "Serial" : "序列号"}</th><th>{english ? "Validity" : "有效期"}</th></tr></thead><tbody>{signer.certificates.map((certificate, certIndex) => <tr key={`${certificate.sha256}-${certIndex}`}><td>{certIndex + 1}</td><td><button type="button" className="sqlite-fragment-copy" title={certificate.sha256} onClick={() => void copyText(certificate.sha256)}>{certificate.sha256}</button></td><td>{certificate.subject}</td><td>{certificate.issuer}</td><td>{certificate.serial}</td><td>{certificate.validFrom} → {certificate.validTo}</td></tr>)}</tbody></table></div> : <div className="empty-state">{english ? "No signer certificate parsed." : "未解析到 Signer 证书。"}</div>}
                {signer.notes.length > 0 && <div className="forensic-inline-note">{signer.notes.join(" · ")}</div>}
              </div>)}
              <div className="tool-panel android-signing-signer">
                <ToolPanelHeader title={english ? "V4 companion verification" : "V4 伴随签名验证"} subtitle={english ? "APK Signature Scheme v4 is stored in a separate .idsig file and requires a complementary v2/v3 signer." : "APK Signature Scheme v4 保存在独立 .idsig 文件中，并要求 APK 同时具备 v2/v3 签名。"} />
                {!repairableApk ? <div className="forensic-inline-note">{english ? "Open a direct .apk file before selecting its .idsig companion." : "请先打开直接的 .apk 文件，再选择对应的 .idsig 伴随文件。"}</div> : null}
                <div className="android-simple-filter-actions">
                  <label>{english ? "Companion .idsig" : "伴随 .idsig"}<input type="file" accept=".idsig,application/octet-stream" disabled={!repairableApk || v4Busy} onChange={(event) => void runV4Verification(event.currentTarget.files?.[0] ?? null)} /></label>
                  {v4File ? <span className="muted">{v4File.name}</span> : null}
                </div>
                {v4Busy ? <ALinearProgress /> : null}
                {v4Result ? <>
                  <InfoTable rows={[
                    [english ? "V4 result" : "V4 结果", v4Result.verified ? (english ? "Verified" : "验证通过") : (english ? "Failed" : "验证失败")],
                    [english ? "Format" : "格式", `v${v4Result.version ?? "?"} · ${v4Result.complete ? (english ? "complete" : "完整") : (english ? "stripped" : "精简")}`],
                    [english ? "Signature" : "签名", `${v4Result.signatureAlgorithm} · ${v4Result.signatureVerified ? "✓" : "✗"}`],
                    [english ? "Certificate / public key" : "证书 / 公钥", v4Result.publicKeyMatchesCertificate ? "✓" : "✗"],
                    [english ? "Merkle root" : "Merkle 根", v4Result.rootHashVerified ? "✓" : "✗"],
                    [english ? "Merkle tree" : "Merkle 树", v4Result.treeVerified == null ? (english ? "Recalculated (stripped idsig)" : "已重算（精简 idsig）") : v4Result.treeVerified ? "✓" : "✗"],
                    [english ? "APK digest ↔ v2/v3" : "APK 摘要 ↔ v2/v3", v4Result.apkDigestMatchesV2V3 ? "✓" : "✗"],
                    [english ? "Signer cert ↔ v2/v3" : "Signer 证书 ↔ v2/v3", v4Result.certificateMatchesV2V3 ? "✓" : "✗"],
                    [english ? "Signer certificate SHA-256" : "Signer 证书 SHA-256", v4Result.certificateSha256 || "--"]
                  ]} />
                  {v4Result.errors.length ? <div className="forensic-inline-note error-state">{v4Result.errors.join(" · ")}</div> : null}
                  {v4Result.warnings.length ? <div className="forensic-inline-note">{v4Result.warnings.join(" · ")}</div> : null}
                </> : null}
              </div>
              <div className="tool-panel android-signing-signer">
                <ToolPanelHeader title={english ? "Re-sign / signature repair" : "重签 / 签名修复"} subtitle={english ? "Creates a new valid v2 signature; it never restores an unknown original private key." : "生成新的有效 v2 签名；无法恢复未知的原始私钥。"} />
                {!repairableApk && <div className="forensic-inline-note">{english ? "Re-open a direct .apk file to enable re-signing. APKS/XAPK containers are analyzed but are not rewritten here." : "请重新打开直接的 .apk 文件以启用重签；APKS/XAPK 可分析，但此处不会直接重写容器。"}</div>}
                <label className="checkbox-row"><input type="checkbox" checked={stripV1OnRepair} onChange={(event) => setStripV1OnRepair(event.currentTarget.checked)} /> <span>{english ? "Remove existing JAR/v1 signature entries before v2 re-signing (recommended when changing signer)" : "v2 重签前移除现有 JAR/v1 签名条目（更换签名者时推荐）"}</span></label>
                <div className="android-simple-primary-action">
                  <AButton variant="filled" disabled={!repairableApk || repairBusy} onClick={() => void runGeneratedRepair()}>{english ? "Generate local signer + repair" : "生成本地签名并修复"}</AButton>
                </div>
                <div className="android-simple-filter-actions">
                  <label>{english ? "PKCS#8 private key" : "PKCS#8 私钥"}<input type="file" accept=".pk8,.der,.pem" onChange={(event) => setRepairKeyFile(event.currentTarget.files?.[0] ?? null)} /></label>
                  <label>{english ? "X.509 certificate" : "X.509 证书"}<input type="file" accept=".cer,.crt,.der,.pem" onChange={(event) => setRepairCertFile(event.currentTarget.files?.[0] ?? null)} /></label>
                  <AButton variant="outlined" disabled={!repairableApk || !repairKeyFile || !repairCertFile || repairBusy} onClick={() => void runImportedRepair()}>{english ? "Re-sign with imported identity" : "使用导入身份重签"}</AButton>
                </div>
                {repairBusy && <ALinearProgress />}
                {repairStatus && <div className="forensic-inline-note">{repairStatus}</div>}
                <div className="forensic-inline-note">{english ? "Generated repair keys are returned inside the downloaded repair bundle. Keep them only if you intend to sign future builds with the same new identity. ZIP rebuilding used to remove v1 signatures can change entry alignment; production release APKs should still be checked with zipalign/apksigner." : "生成的修复私钥会包含在下载的修复包中；只有计划继续使用这一新身份签名后续版本时才应保存。移除 v1 签名需要重建 ZIP，可能改变条目对齐；生产发布 APK 仍建议使用 zipalign/apksigner 再检查。"}</div>
              </div>
            </div>
          )}

          {view === "permissions" && (
            <div className="android-simple-view android-perm-view">
              {permissionRows.length ? (
                <>
                  <div className="android-perm-summary">
                    <button
                      type="button"
                      className={`android-perm-chip sev-all ${severityFilter === "all" ? "is-active" : ""}`}
                      onClick={() => setSeverityFilter("all")}
                    >
                      <span className="android-perm-chip-count">{permissionRows.length}</span>
                      <span className="android-perm-chip-label">{english ? "All" : "全部"}</span>
                    </button>
                    {(Object.keys(PERM_SEVERITY_META) as PermSeverity[])
                      .filter((severity) => (permissionSeverityCounts[severity] ?? 0) > 0)
                      .map((severity) => (
                        <button
                          type="button"
                          key={severity}
                          className={`android-perm-chip sev-${severity} ${severityFilter === severity ? "is-active" : ""}`}
                          onClick={() => setSeverityFilter(severityFilter === severity ? "all" : severity)}
                        >
                          <span className="android-perm-chip-count">{permissionSeverityCounts[severity]}</span>
                          <span className="android-perm-chip-label">{english ? PERM_SEVERITY_META[severity].en : PERM_SEVERITY_META[severity].zh}</span>
                        </button>
                      ))}
                  </div>
                  <div className="android-simple-view-actions android-simple-filter-actions">
                    <input
                      className="text-input"
                      value={permissionFilter}
                      onChange={(event) => setPermissionFilter(event.target.value)}
                      placeholder={english ? "Filter by name, description, or category" : "按名称、说明或分类筛选"}
                    />
                    <AButton variant="outlined" disabled={!visiblePermissionRows.length} onClick={() => downloadTextFile(`android-permissions-${Date.now()}.csv`, services.androidPermissionsToCsv(visiblePermissionRows), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton>
                  </div>
                  {permissionGroups.length ? (
                    <div className="android-perm-groups">
                      {permissionGroups.map((group) => (
                        <div className="android-perm-group" key={group.key}>
                          <div className="android-perm-group-head">
                            <span className="android-perm-group-title">{english ? group.meta.en : group.meta.zh}</span>
                            <span className="android-perm-group-count">{group.rows.length}</span>
                          </div>
                          <div className="android-perm-list">
                            {group.rows.map((row) => (
                              <div className={`android-perm-card sev-${row.severity}`} key={row.permission}>
                                <div className="android-perm-card-head">
                                  <span className="android-perm-name">{english ? row.labelEn : row.labelZh}</span>
                                  <span className={`android-perm-badge sev-${row.severity}`}>{english ? PERM_SEVERITY_META[row.severity as PermSeverity]?.en ?? row.severity : PERM_SEVERITY_META[row.severity as PermSeverity]?.zh ?? row.severity}</span>
                                </div>
                                <code className="android-perm-const" title={row.permission}>{row.permission}</code>
                                <p className="android-perm-desc">{english ? row.descEn : row.descZh}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : <div className="empty-state">{english ? "No permissions match the filter." : "没有符合筛选条件的权限。"}</div>}
                </>
              ) : <div className="empty-state">{english ? "This app declares no permissions." : "该应用未声明任何权限。"}</div>}
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
