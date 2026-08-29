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
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import { describe, expect, it } from "vitest";
import { buildAndroidEnvelope } from "../src/features/android/envelope";
import type { AndroidManifestInfo } from "../src/models";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

function makeInfo(overrides: Partial<AndroidManifestInfo> = {}): AndroidManifestInfo {
  return {
    name: "app.apk",
    size: 2048,
    sourceFormat: "apk",
    packageName: "com.example.app",
    versionCode: "1",
    versionName: "1.0",
    minSdk: "21",
    targetSdk: "33",
    compileSdk: "33",
    appLabel: "Example",
    appIcon: "",
    appTheme: "",
    debuggable: "false",
    allowBackup: "false",
    cleartextTraffic: "false",
    networkSecurityConfig: "",
    launcherActivity: ".Main",
    permissions: [],
    permissionRows: [],
    features: [],
    libraries: [],
    queries: [],
    componentRows: [],
    axmlRows: [],
    components: [],
    apkRows: [],
    apkEntries: [],
    findings: [],
    ...overrides
  };
}

describe("buildAndroidEnvelope", () => {
  it("summarizes a benign manifest", () => {
    const envelope = buildAndroidEnvelope(makeInfo());
    expect(envelope.schemaVersion).toBe("1");
    expect(envelope.analyzer.id).toBe("android");
    expect(envelope.source[0].name).toBe("app.apk");
    expect(envelope.indicators.some((indicator) => indicator.type === "package" && indicator.value === "com.example.app")).toBe(true);
    expect(envelope.findings.some((finding) => finding.category === "android-config")).toBe(false);
  });

  it("flags risky manifest settings", () => {
    const envelope = buildAndroidEnvelope(makeInfo({ debuggable: "true", allowBackup: "true", cleartextTraffic: "true" }));
    expect(envelope.findings.some((finding) => finding.title === "Debuggable")).toBe(true);
    expect(envelope.findings.some((finding) => finding.title === "Allow backup")).toBe(true);
    expect(envelope.findings.some((finding) => finding.title === "Cleartext traffic")).toBe(true);
  });

  it("assigns machine-readable finding codes and review flags (5.6)", () => {
    const envelope = buildAndroidEnvelope(makeInfo({ debuggable: "true", cleartextTraffic: "true" }));
    // Every finding must carry a stable code (not derived from the title text).
    expect(envelope.findings.every((finding) => typeof finding.code === "string" && finding.code.length > 0)).toBe(true);
    const debuggable = envelope.findings.find((finding) => finding.title === "Debuggable");
    expect(debuggable?.code).toBe("android-config");
    expect(debuggable?.review).toBe(true);
    const cleartext = envelope.findings.find((finding) => finding.title === "Cleartext traffic");
    expect(cleartext?.code).toBe("android-config");
    expect(cleartext?.review).toBe(true);
  });

  it("reports unverified signatures as an error", () => {
    const envelope = buildAndroidEnvelope(makeInfo({
      signing: { present: true, blockOffset: 0, blockSize: 100, centralDirectoryOffset: 50, schemes: ["v2"], signers: [], unknownPairIds: [], warnings: [], verified: false }
    }));
    expect(envelope.findings.some((finding) => finding.title === "Signature not verified" && finding.level === "error")).toBe(true);
  });

  it("maps risky APK entries to artifacts", () => {
    const envelope = buildAndroidEnvelope(makeInfo({
      apkEntries: [
        { name: "classes.dex", directory: "", extension: "dex", size: 1024, signature: "", role: "code", risk: ["high"], preview: "" },
        { name: "res/icon.png", directory: "res", extension: "png", size: 256, signature: "", role: "resource", risk: [], preview: "" }
      ]
    }));
    expect(envelope.artifacts.filter((artifact) => artifact.kind === "apk-entry")).toHaveLength(1);
  });
});

describe("android envelope result store integration", () => {
  it("publishes under the android tool key", () => {
    clearAnalysisResults();
    publishAnalysisResult("android", buildAndroidEnvelope(makeInfo({ name: "a.apk", size: 3 })));
    expect(currentAnalysisResult("android")).not.toBeNull();
    clearAnalysisResults();
  });
});
