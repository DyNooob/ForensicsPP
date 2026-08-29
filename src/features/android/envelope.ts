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
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import { appVersion } from "../../config/app";
import type { CaseEvidenceFile } from "../../models";
import type { AnalysisArtifact, AnalysisEnvelope, AnalysisFinding, AnalysisIndicator, AnalysisLimitation } from "../analysis/result";
import type { AndroidManifestInfo } from "../../models";

export type AndroidEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
};

const APK_ENTRY_CAP = 300;

function isAffirmative(value: string | undefined): boolean {
  return value === "true" || value === "yes" || value === "1";
}

/**
 * Map an Android APK/manifest analysis to a unified AnalysisEnvelope (beta.6 P0-2).
 *
 * Surfaces signing state, risky manifest flags (debuggable / allowBackup /
 * cleartextTraffic), dangerous permissions, and risky APK entries.
 */
export function buildAndroidEnvelope(info: AndroidManifestInfo, meta: AndroidEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const findings: AnalysisFinding[] = [];

  for (const finding of info.findings ?? []) {
    findings.push({ level: finding.level as AnalysisFinding["level"], title: finding.title, detail: finding.detail, category: "android-manifest", confidence: "high" });
  }

  const signing = info.signing;
  if (signing) {
    for (const warning of signing.warnings) {
      findings.push({ level: "warn", title: "Signing warning", detail: warning, category: "android-signing", confidence: "high" });
    }
    if (signing.present && !signing.verified) {
      findings.push({ level: "error", title: "Signature not verified", detail: "APK signature block present but verification failed or is incomplete.", category: "android-signing", confidence: "high" });
    } else if (!signing.present) {
      findings.push({ level: "warn", title: "No signature block", detail: "No APK signing block (v2/v3/v3.1) found; the package is unsigned or uses only v1/jar signing.", category: "android-signing", confidence: "high" });
    }
  }

  if (isAffirmative(info.debuggable)) {
    findings.push({ level: "warn", title: "Debuggable", detail: "android:debuggable=\"true\" — the app can be attached by a debugger; common in malware/sample builds.", category: "android-config", confidence: "high", review: true });
  }
  if (isAffirmative(info.allowBackup)) {
    findings.push({ level: "warn", title: "Allow backup", detail: "android:allowBackup=\"true\" — application data may be extracted via adb backup.", category: "android-config", confidence: "high", review: true });
  }
  if (isAffirmative(info.cleartextTraffic)) {
    findings.push({ level: "warn", title: "Cleartext traffic", detail: "android:usesCleartextTraffic=\"true\" — plaintext network traffic is permitted.", category: "android-config", confidence: "high", review: true });
  }

  const dangerousPermissions = (info.permissionRows ?? []).filter((row) => row.severity === "high" || row.severity === "critical");
  if (dangerousPermissions.length > 0) {
    findings.push({
      level: "warn",
      title: "Dangerous permissions",
      detail: `${dangerousPermissions.length} high/critical permission(s) requested: ${dangerousPermissions.slice(0, 12).map((row) => row.shortName).join(", ")}${dangerousPermissions.length > 12 ? "…" : ""}.`,
      category: "android-permission",
      confidence: "high"
    });
  }

  const indicators: AnalysisIndicator[] = info.packageName
    ? [{
        type: "package",
        value: info.packageName,
        normalized: info.packageName.toLowerCase(),
        source: "AndroidManifest",
        context: info.versionName || info.versionCode
      }]
    : [];

  const riskyEntries = (info.apkEntries ?? [])
    .filter((entry) => entry.risk.length > 0)
    .slice(0, APK_ENTRY_CAP);
  const artifacts: AnalysisArtifact[] = riskyEntries.map((entry, index) => ({
    id: `apk-entry-${index}`,
    label: `${entry.name}${entry.directory ? ` (${entry.directory})` : ""}`,
    kind: "apk-entry",
    size: entry.size,
    confidence: entry.risk.includes("high") || entry.risk.includes("critical") ? "high" : "medium"
  }));

  const limitations: AnalysisLimitation[] = [
    { code: "ANDROID_TRIAGE_SCOPE", detail: "Manifest analysis covers signing, permissions, components, and APK entries; it does not decompile code or perform behavioral analysis." }
  ];

  const source: CaseEvidenceFile = {
    name: info.name,
    size: info.size,
    type: "application/vnd.android.package-archive",
    lastModified: ""
  };

  const signingSchemes = signing?.schemes ?? [];

  return {
    schemaVersion: "1",
    id: `android-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "android", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { sourceFormat: info.sourceFormat } },
    summary: {
      title: "Android APK / manifest analysis",
      text: `${info.packageName || info.name} · ${info.versionName || info.versionCode}${signing?.present ? ` · signing ${signingSchemes.join("/") || "v1"}` : " · unsigned"}`,
      metrics: [
        { label: "Package", value: info.packageName || "--" },
        { label: "Version", value: info.versionName || info.versionCode || "--" },
        { label: "Target SDK", value: info.targetSdk || "--" },
        { label: "Min SDK", value: info.minSdk || "--" },
        { label: "Permissions", value: String((info.permissionRows ?? []).length) },
        { label: "Components", value: String((info.components ?? []).length) },
        { label: "Signing", value: signing?.present ? signingSchemes.join("/") || "v1" : "none" },
        { label: "Risky entries", value: String(riskyEntries.length) }
      ]
    },
    findings: findings.map((f) => ({ ...f, code: f.code ?? f.category ?? "android.finding" })),
    indicators,
    artifacts,
    timeline: [],
    limitations,
    data: {
      packageName: info.packageName,
      versionName: info.versionName,
      versionCode: info.versionCode,
      minSdk: info.minSdk,
      targetSdk: info.targetSdk,
      compileSdk: info.compileSdk,
      permissionCount: (info.permissionRows ?? []).length,
      componentCount: (info.components ?? []).length,
      signingSchemes,
      verified: signing?.verified ?? false,
      debuggable: info.debuggable,
      allowBackup: info.allowBackup,
      cleartextTraffic: info.cleartextTraffic
    }
  };
}
