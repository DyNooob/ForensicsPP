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
import { useStaleRunGuard } from "../core/runtime";
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
import { clearAnalysisResult, publishAnalysisResult } from "../features/analysis/resultStore";
import { buildAndroidEnvelope } from "../features/android/envelope";

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
  const guard = useStaleRunGuard(active);
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
      publishAnalysisResult("android", buildAndroidEnvelope(value.info));
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
      publishAnalysisResult("android", buildAndroidEnvelope(next));
      workspace.save({ info: next });
      resetReview();
    } catch (caught) {
      setInfo(null);clearAnalysisResult("android");
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const handleFile = async (file?: File) => {
    if (!file || !active) return;
    const requestId = guard.next();
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
    setInfo(null);clearAnalysisResult("android");
    resetReview();
    if (file.size > MAX_ARCHIVE_SIZE) {
      setError(t.files_larger_than_256_mib_are_not_opened_in_the_browser);
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
      if (!guard.isCurrent(requestId) || controller.signal.aborted) return;
      const next = services.parseAndroidManifest(result.xml, file.name, file.size, result.archiveInfo);
      guard.commit(requestId, () => {
        setManifestText(result.xml);
        setSourceName(file.name);
        setInfo(next);
        publishAnalysisResult("android", buildAndroidEnvelope(next));
        workspace.save({ info: next });
        resetReview();
      });
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      setInfo(null);clearAnalysisResult("android");
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
    guard.next();
    workspace.clear();
    setParsing(false);
    setManifestText("");
    setInfo(null);clearAnalysisResult("android");
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
      if (file.size > 32 * 1024 * 1024) throw new Error(t.idsig_files_larger_than_32_mib_are_not_opened);
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
    setRepairStatus(t.generating_a_local_repair_signer_and_rebuilding_the_v2_signature);
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
      setRepairStatus(`${t.repair_failed}: ${caught instanceof Error ? caught.message : String(caught)}`);
    } finally {
      setRepairBusy(false);
    }
  };

  const runImportedRepair = async () => {
    if (!sourceFile || !repairableApk || !repairKeyFile || !repairCertFile) return;
    setRepairBusy(true);
    setRepairStatus(t.importing_signer_and_rebuilding_the_apk_v2_signature);
    try {
      const [apkBuffer, keyBuffer, certBuffer] = await Promise.all([sourceFile.arrayBuffer(), repairKeyFile.arrayBuffer(), repairCertFile.arrayBuffer()]);
      const identity = await importRepairIdentity(new Uint8Array(keyBuffer), new Uint8Array(certBuffer), repairCertFile.name);
      const result = await resignApkV2(new Uint8Array(apkBuffer), identity, { stripJarSignatures: stripV1OnRepair });
      const base = sourceFile.name.replace(/\.apk$/i, "");
      downloadBlob(`${base}-resigned.apk`, new Blob([result.bytes.slice()], { type: "application/vnd.android.package-archive" }));
      setRepairStatus(english
        ? `Re-sign complete and self-verified with the imported identity. ${result.strippedJarSignatures.length} JAR/v1 signature entries removed.`
        : `已使用导入身份完成重签并通过自校验。移除了 ${result.strippedJarSignatures.length} 个 JAR/v1 签名条目。`);
    } catch (caught) {
      setRepairStatus(`${t.repair_failed}: ${caught instanceof Error ? caught.message : String(caught)}`);
    } finally {
      setRepairBusy(false);
    }
  };

  return (
    <div className={`tool-grid android-simple-workbench manifest-grid ${hasSource ? "has-android" : "empty-android"}`}>
      {parsing && <div className="wide-panel"><ALinearProgress /></div>}

      <section className="tool-panel wide-panel android-simple-source-panel manifest-input-panel">
        <ToolPanelHeader
          title={t.open_apk_or_manifest}
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
          <span>{info ? `${info.sourceFormat} · ${formatBytes(info.size)}` : (t.apk_xml_or_binary_axml)}</span>
        </div>
        {info ? <details className="android-xml-details"><summary>{t.view_decoded_xml}</summary><textarea
          className="single-textarea android-simple-editor manifest-textarea"
          aria-label={t.decoded_androidmanifest_xml}
          value={manifestText}
          readOnly
        /></details> : <textarea
          className="single-textarea android-simple-editor manifest-textarea"
          aria-label={t.androidmanifest_xml_input}
          value={manifestText}
          onChange={(event) => { setManifestText(event.target.value); setSourceName("pasted AndroidManifest.xml"); setInfo(null);clearAnalysisResult("android"); resetReview(); }}
          placeholder="<manifest xmlns:android=&quot;http://schemas.android.com/apk/res/android&quot; ...>"
        />}
        <div className="android-simple-primary-action">
          <AButton variant="filled" disabled={parsing || !manifestText.trim()} onClick={() => parseText()}>{t.parseManifest}</AButton>
          <AButton variant="outlined" disabled={parsing} onClick={() => inputRef.current?.click()}>{t.uploadManifest}</AButton>
          <AButton variant="text" disabled={!manifestText} onClick={() => void copyText(manifestText)}>{t.copy} XML</AButton>
          <AButton variant="text" disabled={!manifestText} onClick={() => downloadTextFile(`decoded-android-manifest-${Date.now()}.xml`, manifestText, "application/xml;charset=utf-8")}>{t.download_xml}</AButton>
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
            <span className={permissionSeverityCounts.dangerous ? "android-summary-danger" : ""}><small>{t.dangerous}</small><strong>{permissionSeverityCounts.dangerous ?? 0}</strong></span>
            <span><small>{t.components}</small><strong>{info.components.length}</strong></span>
          </div>
          <ASegmentedGroup className="android-simple-tabs" value={view} selects="single">
            <ASegmentedButton value="overview" onClick={() => setView("overview")}>{t.overview}</ASegmentedButton>
            <ASegmentedButton value="signing" disabled={!info.signing?.present} onClick={() => setView("signing")}>{t.signing} ({info.signing?.signers.length ?? 0})</ASegmentedButton>
            <ASegmentedButton value="permissions" onClick={() => setView("permissions")}>{t.permissions} ({info.permissionRows.length})</ASegmentedButton>
            <ASegmentedButton value="components" onClick={() => setView("components")}>{t.components} ({info.components.length})</ASegmentedButton>
            <ASegmentedButton value="entries" disabled={!info.apkEntries.length} onClick={() => setView("entries")}>{t.apk_entries} ({info.apkEntries.length})</ASegmentedButton>
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
                [t.signing_block, info.signing.present ? (t.present) : "--"],
                [t.signing_block_schemes, info.signing.schemes.join(" + ") || "--"],
                [t.cryptographically_checked, info.signing.verification?.checkedSchemes.map((scheme) => scheme.toUpperCase()).join(" + ") || "--"],
                [t.signers, String(info.signing.signers.length)],
                [t.block_offset, info.signing.blockOffset == null ? "--" : `0x${info.signing.blockOffset.toString(16).toUpperCase()}`],
                [t.block_size, info.signing.blockSize ? formatBytes(info.signing.blockSize) : "--"],
                [english ? "Central Directory" : "Central Directory", info.signing.centralDirectoryOffset == null ? "--" : `0x${info.signing.centralDirectoryOffset.toString(16).toUpperCase()}`],
                [t.unknown_pair_ids, info.signing.unknownPairIds.join(", ") || "--"],
                [t.integrity_verification, info.signing.verification?.status === "verified" ? (t.verified) : info.signing.verification?.status === "failed" ? (t.failed) : (t.not_available)],
                [t.verification_time, info.signing.verification ? `${info.signing.verification.durationMs} ms` : "--"]
              ]} />
              {info.signing.warnings.length > 0 && <div className="forensic-inline-note">{info.signing.warnings.join(" · ")}</div>}
              {info.signing.verification?.errors.length ? <div className="forensic-inline-note error-state">{info.signing.verification.errors.join(" · ")}</div> : null}
              {info.signing.verification?.warnings.length ? <div className="forensic-inline-note">{info.signing.verification.warnings.join(" · ")}</div> : null}
              {info.signing.verification?.jarV1?.present ? <div className="tool-panel android-signing-signer">
                <ToolPanelHeader title="V1 / JAR signer" subtitle={info.signing.verification.jarV1.signerBase || undefined} />
                <InfoTable rows={[
                  [t.manifest_entries, `${info.signing.verification.jarV1.verifiedEntries} / ${info.signing.verification.jarV1.manifestEntries}`],
                  [t.sf_manifest_digest, info.signing.verification.jarV1.sfManifestDigestVerified ? "✓" : "✗"],
                  [t.cms_signature, info.signing.verification.jarV1.cmsSignatureVerified ? "✓" : "✗"],
                  [t.signer_certificate_sha_256, info.signing.verification.jarV1.signerCertificateSha256 || "--"],
                  [t.result, info.signing.verification.jarV1.verified ? (t.verified) : (t.failed)]
                ]} />
              </div> : null}
              {info.signing.verification?.signerResults.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>Signer</th><th>{t.algorithm}</th><th>{t.signed_data}</th><th>{t.apk_digest}</th><th>{t.cert_key}</th><th>{t.result}</th></tr></thead><tbody>{info.signing.verification.signerResults.map((result) => <tr key={`verify-${result.scheme}-${result.signerIndex}`}><td>{result.scheme.toUpperCase()} #{result.signerIndex}</td><td>{result.selectedAlgorithm}</td><td>{result.signatureVerified ? "✓" : "✗"}</td><td>{result.contentDigestVerified ? "✓" : "✗"}</td><td>{result.publicKeyMatchesCertificate ? "✓" : "✗"}</td><td>{result.verified ? (t.verified) : (t.failed)}</td></tr>)}</tbody></table></div> : null}
              {info.signing.signers.map((signer) => <div className="tool-panel android-signing-signer" key={`${signer.scheme}-${signer.index}`}>
                <ToolPanelHeader title={`${signer.scheme.toUpperCase()} signer ${signer.index}`} subtitle={signer.minSdk == null ? undefined : `SDK ${signer.minSdk}–${signer.maxSdk ?? "?"}`} />
                <InfoTable rows={[
                  [t.signature_algorithms, signer.signatures.map((item) => item.name).join(", ") || "--"],
                  [t.digest_algorithms, signer.digests.map((item) => item.name).join(", ") || "--"],
                  [t.public_key, `${formatBytes(signer.publicKeySize)} · SHA-256 ${signer.publicKeySha256}`],
                  [t.additional_attributes, signer.attributes.join(", ") || "--"]
                ]} />
                {signer.certificates.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>#</th><th>SHA-256</th><th>{english ? "Subject" : "Subject"}</th><th>{english ? "Issuer" : "Issuer"}</th><th>{t.serial}</th><th>{t.validity}</th></tr></thead><tbody>{signer.certificates.map((certificate, certIndex) => <tr key={`${certificate.sha256}-${certIndex}`}><td>{certIndex + 1}</td><td><button type="button" className="sqlite-fragment-copy" title={certificate.sha256} onClick={() => void copyText(certificate.sha256)}>{certificate.sha256}</button></td><td>{certificate.subject}</td><td>{certificate.issuer}</td><td>{certificate.serial}</td><td>{certificate.validFrom} → {certificate.validTo}</td></tr>)}</tbody></table></div> : <div className="empty-state">{t.no_signer_certificate_parsed}</div>}
                {signer.notes.length > 0 && <div className="forensic-inline-note">{signer.notes.join(" · ")}</div>}
              </div>)}
              <div className="tool-panel android-signing-signer">
                <ToolPanelHeader title={t.v4_companion_verification} subtitle={t.apk_signature_scheme_v4_is_stored_in_a_separate_idsig_file_and_requires_a_complementary_v2_v3_signer} />
                {!repairableApk ? <div className="forensic-inline-note">{t.open_a_direct_apk_file_before_selecting_its_idsig_companion}</div> : null}
                <div className="android-simple-filter-actions">
                  <label>{t.companion_idsig}<input type="file" accept=".idsig,application/octet-stream" disabled={!repairableApk || v4Busy} onChange={(event) => void runV4Verification(event.currentTarget.files?.[0] ?? null)} /></label>
                  {v4File ? <span className="muted">{v4File.name}</span> : null}
                </div>
                {v4Busy ? <ALinearProgress /> : null}
                {v4Result ? <>
                  <InfoTable rows={[
                    [t.v4_result, v4Result.verified ? (t.verified) : (t.failed)],
                    [t.format, `v${v4Result.version ?? "?"} · ${v4Result.complete ? (t.complete) : (t.stripped)}`],
                    [t.signature, `${v4Result.signatureAlgorithm} · ${v4Result.signatureVerified ? "✓" : "✗"}`],
                    [t.certificate_public_key, v4Result.publicKeyMatchesCertificate ? "✓" : "✗"],
                    [t.merkle_root, v4Result.rootHashVerified ? "✓" : "✗"],
                    [t.merkle_tree, v4Result.treeVerified == null ? (t.recalculated_stripped_idsig) : v4Result.treeVerified ? "✓" : "✗"],
                    [t.apk_digest_v2_v3, v4Result.apkDigestMatchesV2V3 ? "✓" : "✗"],
                    [t.signer_cert_v2_v3, v4Result.certificateMatchesV2V3 ? "✓" : "✗"],
                    [t.signer_certificate_sha_256, v4Result.certificateSha256 || "--"]
                  ]} />
                  {v4Result.errors.length ? <div className="forensic-inline-note error-state">{v4Result.errors.join(" · ")}</div> : null}
                  {v4Result.warnings.length ? <div className="forensic-inline-note">{v4Result.warnings.join(" · ")}</div> : null}
                </> : null}
              </div>
              <div className="tool-panel android-signing-signer">
                <ToolPanelHeader title={t.re_sign_signature_repair} subtitle={t.creates_a_new_valid_v2_signature_it_never_restores_an_unknown_original_private_key} />
                {!repairableApk && <div className="forensic-inline-note">{t.re_open_a_direct_apk_file_to_enable_re_signing_apks_xapk_containers_are_analyzed_but_are_not_rewritten_here}</div>}
                <label className="checkbox-row"><input type="checkbox" checked={stripV1OnRepair} onChange={(event) => setStripV1OnRepair(event.currentTarget.checked)} /> <span>{t.remove_existing_jar_v1_signature_entries_before_v2_re_signing_recommended_when_changing_signer}</span></label>
                <div className="android-simple-primary-action">
                  <AButton variant="filled" disabled={!repairableApk || repairBusy} onClick={() => void runGeneratedRepair()}>{t.generate_local_signer_repair}</AButton>
                </div>
                <div className="android-simple-filter-actions">
                  <label>{t.pkcs_8_private_key}<input type="file" accept=".pk8,.der,.pem" onChange={(event) => setRepairKeyFile(event.currentTarget.files?.[0] ?? null)} /></label>
                  <label>{t.x_509_certificate}<input type="file" accept=".cer,.crt,.der,.pem" onChange={(event) => setRepairCertFile(event.currentTarget.files?.[0] ?? null)} /></label>
                  <AButton variant="outlined" disabled={!repairableApk || !repairKeyFile || !repairCertFile || repairBusy} onClick={() => void runImportedRepair()}>{t.re_sign_with_imported_identity}</AButton>
                </div>
                {repairBusy && <ALinearProgress />}
                {repairStatus && <div className="forensic-inline-note">{repairStatus}</div>}
                <div className="forensic-inline-note">{t.generated_repair_keys_are_returned_inside_the_downloaded_repair_bundle_keep_them_only_if_you_intend_to_sign_future_builds_with_the_same_new_identity_zip_rebuilding_used_to_remove_v1_signatures_can_change_entry_alignment_production_release_apks_should_still_be_checked_with_zipalign_apksigner}</div>
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
                      <span className="android-perm-chip-label">{t.all}</span>
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
                      placeholder={t.filter_by_name_description_or_category}
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
                  ) : <div className="empty-state">{t.no_permissions_match_the_filter}</div>}
                </>
              ) : <div className="empty-state">{t.this_app_declares_no_permissions}</div>}
            </div>
          )}

          {view === "components" && (
            <div className="android-simple-view">
              <div className="android-simple-view-actions android-simple-filter-actions">
                <input className="text-input" value={componentFilter} onChange={(event) => setComponentFilter(event.target.value)} placeholder={t.filter_component_action_or_permission} />
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
                <input className="text-input" value={entryFilter} onChange={(event) => setEntryFilter(event.target.value)} placeholder={t.filter_path_extension_or_role} />
                <AButton variant="outlined" disabled={!visibleEntries.length} onClick={() => downloadTextFile(`android-apk-entries-${Date.now()}.csv`, services.androidApkEntriesToCsv(visibleEntries), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton>
              </div>
              <div className="table-scroll android-simple-table-scroll">
                <table className="data-table android-simple-entries-table"><thead><tr><th>{t.name}</th><th>{t.role}</th><th>{t.fileSize}</th><th>Signature</th></tr></thead><tbody>{visibleEntries.map((entry) => <tr className={selectedEntryName === entry.name ? "selected-row" : ""} key={entry.name} onClick={() => setSelectedEntryName(entry.name)}><td>{entry.name}</td><td>{entry.role}</td><td>{formatBytes(entry.size)}</td><td>{entry.signature}</td></tr>)}</tbody></table>
              </div>
            </div>
          )}
        </section>
      )}

      {info && view === "components" && selectedComponent && (
        <section className="tool-panel wide-panel android-simple-detail-panel">
          <ToolPanelHeader title={t.selected_component} />
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
          <ToolPanelHeader title={t.selected_apk_entry} />
          <InfoTable rows={[
            [t.name, selectedEntry.name],
            [t.directory, selectedEntry.directory || "--"],
            [t.role, selectedEntry.role],
            [t.fileSize, formatBytes(selectedEntry.size)],
            ["Signature", selectedEntry.signature]
          ]} />
          {selectedEntry.preview && <pre className="result-box android-simple-entry-preview">{selectedEntry.preview}</pre>}
        </section>
      )}
    </div>
  );
}
