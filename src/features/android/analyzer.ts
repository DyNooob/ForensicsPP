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

import { unzipSync } from "fflate";
import type { AndroidApkEntry, AndroidComponent, AndroidManifestInfo } from "../../models";
import { fileSignatureForBytes, fileSignatures, previewText, shannonEntropy } from "../../utils/binary";
import { archiveExtension, formatBytes } from "../../utils/files";
import { PERM_CATEGORY_META, resolveAndroidPermission } from "./permissionCatalog";

const androidNamespace = "http://schemas.android.com/apk/res/android";

const androidResourceNames: Record<number, string> = {
  0x01010000: "theme",
  0x01010001: "label",
  0x01010002: "icon",
  0x01010003: "name",
  0x01010006: "permission",
  0x01010007: "readPermission",
  0x01010008: "writePermission",
  0x01010009: "protectionLevel",
  0x0101000a: "permissionGroup",
  0x0101000b: "sharedUserId",
  0x0101000c: "hasCode",
  0x0101000d: "persistent",
  0x0101000e: "enabled",
  0x0101000f: "debuggable",
  0x01010010: "exported",
  0x01010011: "process",
  0x01010012: "taskAffinity",
  0x01010013: "multiprocess",
  0x01010014: "finishOnTaskLaunch",
  0x01010015: "clearTaskOnLaunch",
  0x01010016: "stateNotNeeded",
  0x01010017: "excludeFromRecents",
  0x01010018: "authorities",
  0x01010019: "syncable",
  0x0101001b: "grantUriPermissions",
  0x0101001c: "priority",
  0x0101001d: "launchMode",
  0x0101001e: "screenOrientation",
  0x0101001f: "configChanges",
  0x01010020: "description",
  0x01010021: "targetPackage",
  0x01010024: "value",
  0x01010025: "resource",
  0x01010026: "mimeType",
  0x01010027: "scheme",
  0x01010028: "host",
  0x01010029: "port",
  0x0101002a: "path",
  0x0101002b: "pathPrefix",
  0x0101002c: "pathPattern",
  0x0101002d: "action",
  0x0101002e: "data",
  0x0101002f: "targetClass",
  0x01010036: "id",
  0x01010039: "tag",
  0x0101003d: "manageSpaceActivity",
  0x0101003f: "allowClearUserData",
  0x01010066: "permissionGroup",
  0x0101006c: "required",
  0x0101021f: "hardwareAccelerated",
  0x0101020c: "minSdkVersion",
  0x0101021b: "versionCode",
  0x0101021c: "versionName",
  0x01010271: "maxSdkVersion",
  0x01010270: "targetSdkVersion",
  0x01010280: "allowBackup",
  0x010102be: "installLocation",
  0x010102c9: "largeHeap",
  0x01010327: "requiresSmallestWidthDp",
  0x01010328: "compatibleWidthLimitDp",
  0x01010329: "largestWidthLimitDp",
  0x010103a9: "supportsRtl",
  0x010104ec: "usesCleartextTraffic",
  0x010104f1: "networkSecurityConfig",
  0x01010572: "compileSdkVersion",
  0x01010573: "compileSdkVersionCodename",
  0x01010591: "requestLegacyExternalStorage",
  0x010105c3: "foregroundServiceType",
  0x010105c4: "directBootAware",
  0x0101063e: "usesPermissionFlags"
};

function xmlEscape(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function readLength8(bytes: Uint8Array, offset: number): [number, number] {
  const first = bytes[offset];
  if ((first & 0x80) === 0) return [first, offset + 1];
  return [((first & 0x7f) << 7) | bytes[offset + 1], offset + 2];
}

function readLength16(view: DataView, offset: number): [number, number] {
  const first = view.getUint16(offset, true);
  if ((first & 0x8000) === 0) return [first, offset + 2];
  return [((first & 0x7fff) << 16) | view.getUint16(offset + 2, true), offset + 4];
}

function parseAndroidStringPool(bytes: Uint8Array, offset: number) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const size = view.getUint32(offset + 4, true);
  const headerSize = view.getUint16(offset + 2, true);
  const stringCount = view.getUint32(offset + 8, true);
  const flags = view.getUint32(offset + 20, true);
  const stringsStart = offset + view.getUint32(offset + 24, true);
  const utf8 = Boolean(flags & 0x100);
  const decoder = new TextDecoder(utf8 ? "utf-8" : "utf-16le");
  const strings: string[] = [];
  for (let index = 0; index < stringCount; index += 1) {
    let stringOffset = stringsStart + view.getUint32(offset + headerSize + index * 4, true);
    if (utf8) {
      [, stringOffset] = readLength8(bytes, stringOffset);
      const [byteLength, dataOffset] = readLength8(bytes, stringOffset);
      strings.push(decoder.decode(bytes.slice(dataOffset, dataOffset + byteLength)));
    } else {
      const [charLength, dataOffset] = readLength16(view, stringOffset);
      strings.push(decoder.decode(bytes.slice(dataOffset, dataOffset + charLength * 2)));
    }
  }
  return { strings, size };
}

function androidString(strings: string[], index: number) {
  return index >= 0 && index < strings.length ? strings[index] : "";
}

function formatAndroidTypedValue(dataType: number, data: number, strings: string[]) {
  if (dataType === 0x03) return androidString(strings, data);
  if (dataType === 0x10) return String(data | 0);
  if (dataType === 0x11) return `0x${data.toString(16)}`;
  if (dataType === 0x12) return data ? "true" : "false";
  if (dataType === 0x01) return `@0x${data.toString(16).padStart(8, "0")}`;
  if (dataType === 0x02) return `?0x${data.toString(16).padStart(8, "0")}`;
  if (dataType === 0x04) {
    const buffer = new ArrayBuffer(4);
    new DataView(buffer).setUint32(0, data, true);
    return String(new DataView(buffer).getFloat32(0, true));
  }
  if (dataType >= 0x1c && dataType <= 0x1f) return `#${data.toString(16).padStart(8, "0")}`;
  return String(data);
}

function formatAndroidAttributeValue(name: string, dataType: number, data: number, strings: string[], raw: string) {
  if (raw) return raw;
  if (name === "protectionLevel" && (dataType === 0x10 || dataType === 0x11)) {
    const base = data & 0x0f;
    const baseName = ({ 0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem" } as Record<number, string>)[base] ?? `0x${base.toString(16)}`;
    const flags = [
      data & 0x10 ? "privileged" : "",
      data & 0x20 ? "development" : "",
      data & 0x40 ? "appop" : "",
      data & 0x80 ? "pre23" : "",
      data & 0x100 ? "installer" : "",
      data & 0x200 ? "verifier" : "",
      data & 0x400 ? "preinstalled" : "",
      data & 0x800 ? "setup" : "",
      data & 0x1000 ? "instant" : "",
      data & 0x2000 ? "runtime" : ""
    ].filter(Boolean);
    return [baseName, ...flags].join("|");
  }
  if (name === "launchMode" && (dataType === 0x10 || dataType === 0x11)) {
    return ({ 0: "standard", 1: "singleTop", 2: "singleTask", 3: "singleInstance", 4: "singleInstancePerTask" } as Record<number, string>)[data] ?? String(data);
  }
  if (name === "installLocation" && (dataType === 0x10 || dataType === 0x11)) {
    return ({ 0: "auto", 1: "internalOnly", 2: "preferExternal" } as Record<number, string>)[data] ?? String(data);
  }
  return formatAndroidTypedValue(dataType, data, strings);
}

function decodeAndroidBinaryXml(bytes: Uint8Array) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint16(0, true) !== 0x0003) throw new Error("Not an Android binary XML document");
  let offset = view.getUint16(2, true);
  const strings: string[] = [];
  const resourceIds: number[] = [];
  const namespaces: Record<string, string> = {};
  const output: string[] = [];
  const stack: string[] = [];
  let rootStarted = false;

  while (offset + 8 <= bytes.length) {
    const type = view.getUint16(offset, true);
    const size = view.getUint32(offset + 4, true);
    if (!size) break;

    if (type === 0x0001) {
      const pool = parseAndroidStringPool(bytes, offset);
      strings.splice(0, strings.length, ...pool.strings);
    } else if (type === 0x0180) {
      for (let cursor = offset + 8; cursor + 4 <= offset + size; cursor += 4) {
        resourceIds.push(view.getUint32(cursor, true));
      }
    } else if (type === 0x0100) {
      const prefix = androidString(strings, view.getInt32(offset + 16, true));
      const uri = androidString(strings, view.getInt32(offset + 20, true));
      if (prefix && uri) namespaces[prefix] = uri;
    } else if (type === 0x0102) {
      const nsIndex = view.getInt32(offset + 16, true);
      const nameIndex = view.getInt32(offset + 20, true);
      const tagName = androidString(strings, nameIndex);
      const attrStart = view.getUint16(offset + 24, true);
      const attrSize = view.getUint16(offset + 26, true) || 20;
      const attrCount = view.getUint16(offset + 28, true);
      const attrs: string[] = [];
      if (!rootStarted) {
        Object.entries(namespaces).forEach(([prefix, uri]) => attrs.push(prefix ? `xmlns:${prefix}="${xmlEscape(uri)}"` : `xmlns="${xmlEscape(uri)}"`));
        if (!Object.values(namespaces).includes(androidNamespace)) attrs.push(`xmlns:android="${androidNamespace}"`);
        rootStarted = true;
      }
      for (let index = 0; index < attrCount; index += 1) {
        const attrOffset = offset + attrStart + index * attrSize;
        const attrNs = view.getInt32(attrOffset, true);
        const attrNameIndex = view.getInt32(attrOffset + 4, true);
        const rawValueIndex = view.getInt32(attrOffset + 8, true);
        const dataType = bytes[attrOffset + 15];
        const data = view.getUint32(attrOffset + 16, true);
        const resourceName = androidResourceNames[resourceIds[attrNameIndex]];
        const localName = androidString(strings, attrNameIndex) || resourceName || `attr_${index}`;
        const attrNsUri = androidString(strings, attrNs);
        const prefix = attrNsUri === androidNamespace ? "android:" : "";
        const raw = androidString(strings, rawValueIndex);
        const value = formatAndroidAttributeValue(localName, dataType, data, strings, raw);
        attrs.push(`${prefix}${localName}="${xmlEscape(value)}"`);
      }
      const name = tagName;
      output.push(`${"  ".repeat(stack.length)}<${name}${attrs.length ? ` ${attrs.join(" ")}` : ""}>`);
      stack.push(name);
    } else if (type === 0x0103) {
      const name = stack.pop() || androidString(strings, view.getInt32(offset + 20, true));
      output.push(`${"  ".repeat(stack.length)}</${name}>`);
    }

    offset += size;
  }

  if (!output.length) throw new Error("Binary XML did not contain readable tags");
  return output.join("\n");
}

function inspectAndroidBinaryXml(bytes: Uint8Array) {
  const rows: Array<[string, string]> = [];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  try {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (bytes.length < 8 || view.getUint16(0, true) !== 0x0003) {
      rows.push(["AXML format", "plain XML / not binary AXML"]);
      return { rows, findings };
    }
    const declaredSize = view.getUint32(4, true);
    let offset = view.getUint16(2, true);
    let stringCount = 0;
    let resourceIds = 0;
    let startTags = 0;
    let endTags = 0;
    let namespaces = 0;
    let maxAttrs = 0;
    let totalAttrs = 0;
    let maxDepth = 0;
    let depth = 0;
    const chunkTypes: Record<string, number> = {};
    while (offset + 8 <= bytes.length) {
      const type = view.getUint16(offset, true);
      const size = view.getUint32(offset + 4, true);
      const key = `0x${type.toString(16).padStart(4, "0")}`;
      chunkTypes[key] = (chunkTypes[key] ?? 0) + 1;
      if (size < 8 || offset + size > bytes.length) {
        findings.push({ level: "danger", title: "AXML chunk boundary anomaly", detail: `${key}@${offset} declares ${size} bytes, file has ${bytes.length - offset} remaining.` });
        break;
      }
      if (type === 0x0001) stringCount = view.getUint32(offset + 8, true);
      if (type === 0x0180) resourceIds += Math.max(0, Math.floor((size - 8) / 4));
      if (type === 0x0100 || type === 0x0101) namespaces += 1;
      if (type === 0x0102) {
        startTags += 1;
        depth += 1;
        maxDepth = Math.max(maxDepth, depth);
        const attrCount = view.getUint16(offset + 28, true);
        totalAttrs += attrCount;
        maxAttrs = Math.max(maxAttrs, attrCount);
      }
      if (type === 0x0103) {
        endTags += 1;
        depth = Math.max(0, depth - 1);
      }
      offset += size;
    }
    rows.push(
      ["AXML declared size", formatBytes(declaredSize)],
      ["AXML actual size", formatBytes(bytes.length)],
      ["String pool strings", String(stringCount)],
      ["Resource IDs", String(resourceIds)],
      ["Start tags", String(startTags)],
      ["End tags", String(endTags)],
      ["Namespace chunks", String(namespaces)],
      ["Max depth", String(maxDepth)],
      ["Total attributes", String(totalAttrs)],
      ["Max attributes/tag", String(maxAttrs)],
      ["Chunk types", Object.entries(chunkTypes).map(([type, count]) => `${type}:${count}`).join(", ")]
    );
    if (declaredSize && declaredSize !== bytes.length) findings.push({ level: "warn", title: "AXML size mismatch", detail: `Header declares ${formatBytes(declaredSize)}, file has ${formatBytes(bytes.length)}.` });
    if (startTags !== endTags) findings.push({ level: "warn", title: "AXML tag count mismatch", detail: `start=${startTags}, end=${endTags}. Decoder may have recovered partial structure.` });
  } catch (error) {
    findings.push({ level: "danger", title: "AXML inspection failed", detail: error instanceof Error ? error.message : String(error) });
  }
  return { rows, findings };
}

function decodeAndroidManifestBytes(bytes: Uint8Array) {
  const trimmed = previewText(bytes, Math.min(bytes.length, 1024)).trim();
  if (trimmed.startsWith("<")) return new TextDecoder().decode(bytes);
  return decodeAndroidBinaryXml(bytes);
}

function classifyAndroidApkEntry(name: string, bytes: Uint8Array): AndroidApkEntry {
  const lower = name.toLowerCase();
  const directory = name.includes("/") ? name.slice(0, name.lastIndexOf("/")) : "/";
  const extension = archiveExtension(name);
  const signature = fileSignatureForBytes(bytes)?.label ?? (bytes.length ? "Unknown" : "Directory/empty");
  const role = /^classes\d*\.dex$/i.test(name)
    ? "DEX bytecode"
    : /^lib\/[^/]+\/.+\.so$/i.test(name)
      ? "Native library"
      : /^META-INF\/.+\.(RSA|DSA|EC|SF)$/i.test(name)
        ? "APK signature metadata"
        : /^assets\//i.test(name)
          ? "Asset"
          : /^res\/raw\//i.test(name)
            ? "Raw resource"
            : /^res\//i.test(name)
              ? "Resource"
              : lower === "androidmanifest.xml"
                ? "Manifest"
                : "Package entry";
  const risk = [
    /^lib\/[^/]+\/.+\.so$/i.test(name) ? "native code" : "",
    /^assets\//i.test(name) || /^res\/raw\//i.test(name) ? "opaque app content" : "",
    /\.(exe|dll|scr|js|vbs|ps1|bat|cmd|hta|jar|dex|so)$/i.test(name) && !/^classes\d*\.dex$/i.test(name) ? "executable-like entry" : "",
    /\.\.\//.test(name) || name.startsWith("/") ? "path traversal marker" : "",
    signature !== "Unknown" && extension && !fileSignatures.some((item) => item.label === signature && item.extensions.includes(extension)) && !/xml|arsc|dex|so/i.test(extension) ? "extension/signature mismatch" : "",
    bytes.length > 25 * 1024 * 1024 ? "large payload" : "",
    bytes.length && shannonEntropy(bytes.slice(0, Math.min(bytes.length, 1024 * 1024))) > 7.55 ? "high entropy sample" : ""
  ].filter(Boolean);
  return {
    name,
    directory,
    extension: extension || "--",
    size: bytes.length,
    signature,
    role,
    risk,
    preview: previewText(bytes, 600)
  };
}

function inspectAndroidArchive(bytes: Uint8Array) {
  const outerFiles = unzipSync(bytes);
  let files = outerFiles;
  let manifest = files["AndroidManifest.xml"];
  let selectedNestedApkName = "";
  let selectedNestedApkBytes: Uint8Array | null = null;
  const wrapperRows: Array<[string, string]> = [];
  const wrapperFindings: Array<{ level: string; title: string; detail: string }> = [];
  if (!manifest) {
    const apkCandidates = Object.keys(outerFiles)
      .filter((name) => /\.apk$/i.test(name))
      .sort((left, right) => {
        const score = (name: string) => {
          const lower = name.toLowerCase();
          return [
            /(^|\/)base\.apk$/.test(lower) ? 0 : 10,
            /(^|\/)universal\.apk$/.test(lower) ? 0 : 5,
            /split_config/i.test(lower) ? 8 : 0,
            -outerFiles[name].length / (1024 * 1024)
          ].reduce((sum, value) => sum + value, 0);
        };
        return score(left) - score(right);
      });
    for (const name of apkCandidates) {
      try {
        const nestedFiles = unzipSync(outerFiles[name]);
        const nestedManifest = nestedFiles["AndroidManifest.xml"];
        if (!nestedManifest) continue;
        selectedNestedApkName = name;
        selectedNestedApkBytes = outerFiles[name];
        files = nestedFiles;
        manifest = nestedManifest;
        break;
      } catch {
        // Keep trying other APK entries in split/xapk containers.
      }
    }
    if (!manifest) throw new Error("APK/APKS/XAPK archive does not contain a readable AndroidManifest.xml");
    wrapperRows.push(
      ["Outer archive entries", String(Object.keys(outerFiles).length)],
      ["Selected nested APK", selectedNestedApkName],
      ["Selected nested APK size", selectedNestedApkBytes ? formatBytes(selectedNestedApkBytes.length) : "--"]
    );
    wrapperFindings.push({
      level: "info",
      title: "Nested APK container",
      detail: `Outer archive contains ${apkCandidates.length} APK candidate(s); parsed ${selectedNestedApkName}.`
    });
    if (apkCandidates.length > 1) {
      wrapperFindings.push({
        level: "info",
        title: "Split APK set",
        detail: apkCandidates.slice(0, 12).join(", ")
      });
    }
  }
  if (!manifest) throw new Error("APK archive does not contain AndroidManifest.xml");
  const entries = Object.keys(files);
  const apkEntries = entries.map((name) => classifyAndroidApkEntry(name, files[name])).sort((a, b) => Number(Boolean(b.risk.length)) - Number(Boolean(a.risk.length)) || b.size - a.size);
  const dexEntries = entries.filter((name) => /^classes\d*\.dex$/i.test(name));
  const nativeLibs = entries.filter((name) => /^lib\/[^/]+\/.+\.so$/i.test(name));
  const certEntries = entries.filter((name) => /^META-INF\/.+\.(RSA|DSA|EC|SF)$/i.test(name));
  const assetEntries = entries.filter((name) => /^assets\//i.test(name));
  const rawEntries = entries.filter((name) => /^res\/raw\//i.test(name));
  const riskyEntries = entries.filter((name) => {
    const normalDex = /^classes\d*\.dex$/i.test(name);
    const normalNativeLib = /^lib\/[^/]+\/.+\.so$/i.test(name);
    const activeScript = /\.(exe|dll|scr|js|vbs|ps1|bat|cmd|hta|jar)$/i.test(name);
    const unusualDexOrSo = /\.(dex|so)$/i.test(name) && !normalDex && !normalNativeLib;
    return activeScript || unusualDexOrSo || /\.\.\//.test(name);
  });
  const riskyApkEntries = apkEntries.filter((entry) => entry.risk.length);
  const rows: Array<[string, string]> = [
    ...wrapperRows,
    ["APK entries", String(entries.length)],
    ["DEX files", dexEntries.join(", ") || "--"],
    ["Native libraries", nativeLibs.length ? `${nativeLibs.length} (${nativeLibs.slice(0, 8).join(", ")})` : "--"],
    ["Certificate / signature files", certEntries.join(", ") || "--"],
    ["Assets", String(assetEntries.length)],
    ["res/raw", String(rawEntries.length)],
    ["Review entries", String(riskyApkEntries.length)]
  ];
  const findings = [
    ...wrapperFindings,
    !certEntries.length ? { level: "warn", title: "No META-INF signature files", detail: "APK may rely on newer signature schemes or be unsigned/repacked; verify with an external signer when needed." } : null,
    nativeLibs.length ? { level: "info", title: "Native code present", detail: nativeLibs.slice(0, 12).join(", ") } : null,
    dexEntries.length > 1 ? { level: "info", title: "Multidex APK", detail: dexEntries.join(", ") } : null,
    riskyEntries.length ? { level: "warn", title: "Executable-like archive entries", detail: riskyEntries.slice(0, 12).join(", ") } : null,
    riskyApkEntries.length ? { level: "warn", title: "APK entry notes", detail: riskyApkEntries.slice(0, 12).map((entry) => `${entry.name}: ${entry.risk.join(", ")}`).join(" | ") } : null
  ].filter(Boolean) as Array<{ level: string; title: string; detail: string }>;
  return { manifest, rows, findings, entries: apkEntries };
}

function androidAttr(element: Element | null | undefined, name: string) {
  if (!element) return "--";
  return element.getAttributeNS(androidNamespace, name) ?? element.getAttribute(`android:${name}`) ?? element.getAttribute(name) ?? "--";
}

function normalizeAndroidName(name: string, packageName: string) {
  if (!name || name === "--") return "--";
  if (name.startsWith(".")) return `${packageName}${name}`;
  if (!name.includes(".") && packageName) return `${packageName}.${name}`;
  return name;
}

function getDirectChildren(parent: Element | null | undefined, tagName: string) {
  if (!parent) return [];
  return Array.from(parent.children).filter((child) => child.tagName === tagName);
}

function analyzeAndroidPermission(permission: string): AndroidManifestInfo["permissionRows"][number] {
  const { shortName, info, known } = resolveAndroidPermission(permission);
  const categoryMeta = PERM_CATEGORY_META[info.category];
  const risk = [
    info.severity === "dangerous" ? "dangerous permission" : "",
    info.severity === "special" ? "special capability" : "",
    info.severity === "signature" ? "system/signature permission" : "",
    !permission.startsWith("android.permission.") ? "custom permission" : "",
    !known && permission.startsWith("android.permission.") ? "uncatalogued permission" : ""
  ].filter(Boolean);
  return {
    permission,
    shortName,
    labelZh: info.zh,
    labelEn: info.en,
    descZh: info.descZh,
    descEn: info.descEn,
    // `category` keeps a stable English key for CSV/back-compat + security rows.
    category: categoryMeta.en,
    categoryKey: info.category,
    categoryZh: categoryMeta.zh,
    categoryEn: categoryMeta.en,
    severity: info.severity,
    known,
    risk
  };
}

function componentExportedEffective(component: Pick<AndroidComponent, "exported" | "actions" | "categories">, targetSdk: string) {
  if (component.exported === "true" || component.exported === "false") return component.exported;
  if (component.actions.length || component.categories.length) return Number(targetSdk) >= 31 ? "implicit/invalid-on-31+" : "implicit-true";
  return "false";
}

function buildAndroidComponentRisk(component: Omit<AndroidComponent, "risk">, targetSdk: string) {
  const effectiveExported = componentExportedEffective(component, targetSdk);
  const risk = [
    effectiveExported === "true" && component.permission === "--" ? "exported without permission" : "",
    effectiveExported === "implicit-true" ? "implicit exported via intent-filter" : "",
    effectiveExported === "implicit/invalid-on-31+" ? "missing explicit exported on Android 12+" : "",
    component.type === "provider" && effectiveExported !== "false" && component.permission === "--" ? "exported provider without permission" : "",
    component.actions.some((action) => /BOOT_COMPLETED|SMS_RECEIVED|PACKAGE_ADDED|USER_PRESENT|MEDIA_MOUNTED/i.test(action)) ? "sensitive broadcast/action" : "",
    component.data.some((item) => /scheme=https?|host=|mime=/i.test(item)) ? "deep link / external data filter" : "",
    component.enabled === "false" ? "disabled" : ""
  ].filter(Boolean);
  return risk;
}

function parseAndroidComponent(element: Element, type: string, packageName: string): AndroidComponent {
  const intentFilters = getDirectChildren(element, "intent-filter");
  const actions = intentFilters.flatMap((filter) =>
    getDirectChildren(filter, "action")
      .map((item) => androidAttr(item, "name"))
      .filter((item) => item !== "--")
  );
  const categories = intentFilters.flatMap((filter) =>
    getDirectChildren(filter, "category")
      .map((item) => androidAttr(item, "name"))
      .filter((item) => item !== "--")
  );
  const data = intentFilters.flatMap((filter) =>
    getDirectChildren(filter, "data")
      .map((item) => {
        const scheme = androidAttr(item, "scheme");
        const host = androidAttr(item, "host");
        const port = androidAttr(item, "port");
        const path = androidAttr(item, "path");
        const pathPrefix = androidAttr(item, "pathPrefix");
        const pathPattern = androidAttr(item, "pathPattern");
        const pathAdvancedPattern = androidAttr(item, "pathAdvancedPattern");
        const mime = androidAttr(item, "mimeType");
        return [
          scheme !== "--" ? `scheme=${scheme}` : "",
          host !== "--" ? `host=${host}` : "",
          port !== "--" ? `port=${port}` : "",
          path !== "--" ? `path=${path}` : "",
          pathPrefix !== "--" ? `pathPrefix=${pathPrefix}` : "",
          pathPattern !== "--" ? `pathPattern=${pathPattern}` : "",
          pathAdvancedPattern !== "--" ? `pathAdvancedPattern=${pathAdvancedPattern}` : "",
          mime !== "--" ? `mime=${mime}` : ""
        ].filter(Boolean).join(" ");
      })
      .filter(Boolean)
  );
  const componentPermission = [
    androidAttr(element, "permission"),
    androidAttr(element, "readPermission"),
    androidAttr(element, "writePermission")
  ].filter((item, index, items) => item !== "--" && items.indexOf(item) === index).join(" / ") || "--";

  const component = {
    type,
    name: normalizeAndroidName(androidAttr(element, "name"), packageName),
    exported: androidAttr(element, "exported"),
    enabled: androidAttr(element, "enabled"),
    permission: componentPermission,
    actions,
    categories,
    data
  };
  return { ...component, risk: buildAndroidComponentRisk(component, "") };
}

function parseAndroidManifest(xml: string, name: string, size: number, archiveInfo?: { rows: Array<[string, string]>; findings: Array<{ level: string; title: string; detail: string }>; entries?: AndroidApkEntry[]; axmlRows?: Array<[string, string]>; axmlFindings?: Array<{ level: string; title: string; detail: string }> }): AndroidManifestInfo {
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  const parseError = doc.querySelector("parsererror");
  if (parseError) throw new Error(parseError.textContent?.trim() || "Invalid XML");

  const manifest = doc.documentElement;
  if (manifest.tagName !== "manifest") throw new Error("Root element is not <manifest>");
  const packageName = manifest.getAttribute("package") ?? "--";
  const usesSdk = doc.querySelector("uses-sdk");
  const application = doc.querySelector("application");
  const permissions = Array.from(doc.querySelectorAll("uses-permission, uses-permission-sdk-23, uses-permission-sdk-m"))
    .map((item) => androidAttr(item, "name"))
    .filter((item, index, items) => item !== "--" && items.indexOf(item) === index);
  const permissionRows = permissions.map(analyzeAndroidPermission);
  const features = Array.from(doc.querySelectorAll("uses-feature"))
    .map((item) => {
      const featureName = androidAttr(item, "name");
      const required = androidAttr(item, "required");
      const glEsVersion = androidAttr(item, "glEsVersion");
      const parts = [
        featureName !== "--" ? featureName : "",
        glEsVersion !== "--" ? `glEsVersion=${glEsVersion}` : "",
        required !== "--" ? `required=${required}` : ""
      ].filter(Boolean);
      return parts.join(" ");
    })
    .filter(Boolean);
  const declaredPermissions = [
    ...Array.from(doc.querySelectorAll("permission")).map((item) => {
      const permissionName = androidAttr(item, "name");
      const protection = androidAttr(item, "protectionLevel");
      const group = androidAttr(item, "permissionGroup");
      return [
        permissionName,
        protection !== "--" ? `protection=${protection}` : "",
        group !== "--" ? `group=${group}` : ""
      ].filter(Boolean).join(" ");
    }),
    ...Array.from(doc.querySelectorAll("permission-group")).map((item) => `permission-group:${androidAttr(item, "name")}`),
    ...Array.from(doc.querySelectorAll("permission-tree")).map((item) => `permission-tree:${androidAttr(item, "name")}`)
  ].filter((item) => item && !item.endsWith(":--"));
  const declaredLegacyPermissions = Array.from(doc.querySelectorAll("permission"))
    .map((item) => {
      const permissionName = androidAttr(item, "name");
      const protection = androidAttr(item, "protectionLevel");
      return protection === "--" ? permissionName : `${permissionName} (${protection})`;
    })
    .filter((item) => item !== "--");
  const libraries = Array.from(doc.querySelectorAll("uses-library"))
    .map((item) => {
      const libraryName = androidAttr(item, "name");
      const required = androidAttr(item, "required");
      return required === "--" ? libraryName : `${libraryName} (required=${required})`;
    })
    .filter((item) => item !== "--");
  const queries = [
    ...Array.from(doc.querySelectorAll("queries > package")).map((item) => `package:${androidAttr(item, "name")}`),
    ...Array.from(doc.querySelectorAll("queries > provider")).map((item) => `provider:${androidAttr(item, "authorities")}`),
    ...Array.from(doc.querySelectorAll("queries intent")).map((intent) => {
      const actions = getDirectChildren(intent, "action").map((item) => androidAttr(item, "name")).filter((item) => item !== "--");
      const categories = getDirectChildren(intent, "category").map((item) => androidAttr(item, "name")).filter((item) => item !== "--");
      const data = getDirectChildren(intent, "data").map((item) => [
        androidAttr(item, "scheme") !== "--" ? `scheme=${androidAttr(item, "scheme")}` : "",
        androidAttr(item, "host") !== "--" ? `host=${androidAttr(item, "host")}` : "",
        androidAttr(item, "mimeType") !== "--" ? `mime=${androidAttr(item, "mimeType")}` : ""
      ].filter(Boolean).join(" ")).filter(Boolean);
      return `intent:${[...actions, ...categories, ...data].join(" / ") || "--"}`;
    })
  ].filter((item) => !item.endsWith(":--"));
  const componentSpecs: Array<[string, string]> = [
    ["activity", "activity"],
    ["activity-alias", "activity-alias"],
    ["service", "service"],
    ["receiver", "receiver"],
    ["provider", "provider"]
  ];
  const components = componentSpecs.flatMap(([tag, type]) =>
    Array.from(doc.querySelectorAll(tag)).map((item) => parseAndroidComponent(item, type, packageName))
  );
  const targetSdk = androidAttr(usesSdk, "targetSdkVersion");
  components.forEach((component) => {
    component.risk = buildAndroidComponentRisk(component, targetSdk);
  });
  const launcher = components.find(
    (component) =>
      component.actions.includes("android.intent.action.MAIN") &&
      component.categories.includes("android.intent.category.LAUNCHER")
  );
  const exportedComponents = components.filter((component) => componentExportedEffective(component, targetSdk) !== "false");
  const unprotectedExported = exportedComponents.filter((component) => component.permission === "--");
  const componentRows: Array<[string, string]> = [
    ["Activities", String(components.filter((component) => component.type === "activity" || component.type === "activity-alias").length)],
    ["Services", String(components.filter((component) => component.type === "service").length)],
    ["Receivers", String(components.filter((component) => component.type === "receiver").length)],
    ["Providers", String(components.filter((component) => component.type === "provider").length)],
    ["Exported / implicit exported", String(exportedComponents.length)],
    ["Exported without permission", String(unprotectedExported.length)],
    ["Deep link components", String(components.filter((component) => component.risk.some((risk) => /deep link/i.test(risk))).length)],
    ["Sensitive action components", String(components.filter((component) => component.risk.some((risk) => /sensitive broadcast/i.test(risk))).length)],
    ["Declared custom permissions", declaredPermissions.join(", ") || "--"],
    ["Package visibility queries", queries.join(", ") || "--"],
    ["Uses libraries", libraries.join(", ") || "--"]
  ];

  const findings = [
    ...permissionRows.filter((row) => row.risk.length).slice(0, 12).map((row) => ({ level: "warn", title: "Permission worth review", detail: `${row.permission}: ${row.risk.join(", ")}` })),
    application && androidAttr(application, "debuggable") === "true" ? { level: "warn", title: "Debuggable enabled", detail: "android:debuggable=true exposes debug surface in non-test builds." } : null,
    application && androidAttr(application, "allowBackup") !== "false" ? { level: "warn", title: "Backup may be allowed", detail: `android:allowBackup=${androidAttr(application, "allowBackup")}` } : null,
    application && androidAttr(application, "usesCleartextTraffic") === "true" ? { level: "warn", title: "Cleartext traffic allowed", detail: "android:usesCleartextTraffic=true" } : null,
    manifest.hasAttribute("android:sharedUserId") || manifest.hasAttribute("sharedUserId") ? { level: "warn", title: "sharedUserId declared", detail: androidAttr(manifest, "sharedUserId") } : null,
    Number(targetSdk) > 0 && Number(targetSdk) < 28 ? { level: "warn", title: "Old target SDK", detail: `targetSdkVersion=${targetSdk}` } : null,
    declaredPermissions.some((permission) => /signature|privileged|dangerous|permission-group|permission-tree/i.test(permission)) ? { level: "info", title: "Custom permission declarations", detail: declaredPermissions.join(", ") } : null,
    queries.length ? { level: "info", title: "Android package visibility queries", detail: queries.slice(0, 20).join(", ") } : null,
    libraries.length ? { level: "info", title: "uses-library declarations", detail: libraries.slice(0, 20).join(", ") } : null,
    components.some((component) => component.risk.some((item) => /exported without permission|exported provider/i.test(item))) ? { level: "warn", title: "Exported component without permission", detail: components.filter((component) => component.risk.some((item) => /exported without permission|exported provider/i.test(item))).slice(0, 12).map((component) => `${component.type}:${component.name}`).join(", ") } : null,
    components.some((component) => component.risk.some((item) => /deep link/i.test(item))) ? { level: "warn", title: "External deep link surface", detail: components.filter((component) => component.risk.some((item) => /deep link/i.test(item))).slice(0, 12).map((component) => component.name).join(", ") } : null,
    ...(archiveInfo?.findings ?? []),
    ...(archiveInfo?.axmlFindings ?? [])
  ].filter(Boolean) as Array<{ level: string; title: string; detail: string }>;
  if (!findings.length) findings.push({ level: "info", title: "No obvious manifest review marker", detail: "No special permission, exported unprotected component, debug flag, backup flag, or cleartext flag was detected locally." });

  return {
    name,
    size,
    sourceFormat: archiveInfo?.entries?.length ? "APK archive / binary manifest" : archiveInfo?.axmlRows?.length ? "Binary AXML / decoded XML" : xml.trim().startsWith("<") ? "XML / decoded AXML" : "Manifest",
    packageName,
    versionCode: androidAttr(manifest, "versionCode"),
    versionName: androidAttr(manifest, "versionName"),
    minSdk: androidAttr(usesSdk, "minSdkVersion"),
    targetSdk: androidAttr(usesSdk, "targetSdkVersion"),
    compileSdk: androidAttr(manifest, "compileSdkVersion"),
    appLabel: androidAttr(application, "label"),
    appIcon: androidAttr(application, "icon"),
    appTheme: androidAttr(application, "theme"),
    debuggable: androidAttr(application, "debuggable"),
    allowBackup: androidAttr(application, "allowBackup"),
    cleartextTraffic: androidAttr(application, "usesCleartextTraffic"),
    networkSecurityConfig: androidAttr(application, "networkSecurityConfig"),
    launcherActivity: launcher?.name ?? "--",
    permissions,
    permissionRows,
    features: Array.from(new Set([...features, ...declaredLegacyPermissions.map((item) => `declared-permission:${item}`)])),
    libraries,
    queries,
    componentRows,
    axmlRows: archiveInfo?.axmlRows ?? [],
    components,
    apkRows: archiveInfo?.rows ?? [],
    apkEntries: archiveInfo?.entries ?? [],
    findings
  };
}

function androidComponentsToCsv(components: AndroidComponent[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["type", "name", "exported", "enabled", "permission", "actions", "categories", "data", "risk"].join(","),
    ...components.map((component) => [
      component.type,
      component.name,
      component.exported,
      component.enabled,
      component.permission,
      component.actions.join("; "),
      component.categories.join("; "),
      component.data.join("; "),
      component.risk.join("; ")
    ].map(escape).join(","))
  ].join("\n");
}

function androidPermissionsToCsv(rows: AndroidManifestInfo["permissionRows"]) {
  const escape = (value: string) => /[",\n\r]/.test(value) ? `"${value.replace(/"/g, "\"\"")}"` : value;
  return [
    ["permission", "name_zh", "name_en", "category", "severity", "risk", "description"].join(","),
    ...rows.map((row) => [row.permission, row.labelZh, row.labelEn, row.categoryEn, row.severity, row.risk.join("; "), row.descEn].map(escape).join(","))
  ].join("\n");
}

function androidApkEntriesToCsv(entries: AndroidApkEntry[]) {
  const escape = (value: unknown) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["name", "directory", "extension", "role", "size", "signature", "preview"].join(","),
    ...entries.map((entry) => [
      entry.name,
      entry.directory,
      entry.extension,
      entry.role,
      entry.size,
      entry.signature,
      entry.preview
    ].map(escape).join(","))
  ].join("\n");
}

function androidManifestSecurityRows(info: AndroidManifestInfo) {
  const exported = info.components.filter((component) => componentExportedEffective(component, info.targetSdk) !== "false");
  const unprotected = exported.filter((component) => component.permission === "--");
  const deepLinks = info.components.filter((component) => component.risk.some((risk) => /deep link/i.test(risk)));
  const sensitiveActions = info.components.filter((component) => component.risk.some((risk) => /sensitive broadcast/i.test(risk)));
  const riskyPermissions = info.permissionRows.filter((row) => row.risk.length);
  const highPermissions = info.permissionRows.filter((row) => row.risk.includes("special capability"));
  const riskyEntries = info.apkEntries.filter((entry) => entry.risk.length);
  const nativeEntries = info.apkEntries.filter((entry) => entry.role === "Native library");
  const opaqueEntries = info.apkEntries.filter((entry) => entry.risk.includes("opaque app content"));
  const axmlRisks = info.findings.filter((finding) => /AXML/i.test(`${finding.title} ${finding.detail}`));
  return [
    {
      area: "Identity",
      count: 1,
      primary: `${info.packageName} / ${info.versionName} (${info.versionCode}) / launcher=${info.launcherActivity}`,
      risk: [info.packageName === "--" ? "missing package" : "", info.launcherActivity === "--" ? "no launcher activity" : ""].filter(Boolean).join(", ") || "--",
      action: "Confirm package/version/launcher against evidence source and report app identity."
    },
    {
      area: "SDK / Platform",
      count: Number(info.targetSdk) || 0,
      primary: `min=${info.minSdk}, target=${info.targetSdk}, compile=${info.compileSdk}`,
      risk: Number(info.targetSdk) > 0 && Number(info.targetSdk) < 28 ? "old target SDK" : "--",
      action: "Use target SDK to interpret exported defaults and Android 12 exported requirements."
    },
    {
      area: "Application Flags",
      count: 4,
      primary: `debuggable=${info.debuggable}; allowBackup=${info.allowBackup}; cleartext=${info.cleartextTraffic}; networkSecurity=${info.networkSecurityConfig}`,
      risk: [
        info.debuggable === "true" ? "debuggable" : "",
        info.allowBackup !== "false" ? "backup may be allowed" : "",
        info.cleartextTraffic === "true" ? "cleartext traffic allowed" : "",
        info.networkSecurityConfig !== "--" ? "network security config referenced" : ""
      ].filter(Boolean).join(", ") || "--",
      action: "Review debug/backup/cleartext flags and pull referenced network security config when present."
    },
    {
      area: "Permissions",
      count: info.permissions.length,
      primary: riskyPermissions.slice(0, 8).map((row) => `${row.permission} (${row.category})`).join(" / ") || "--",
      risk: `${riskyPermissions.length} note(s); ${highPermissions.length} special`,
      action: "Export permission CSV and verify whether requested capabilities match app purpose."
    },
    {
      area: "Exported Components",
      count: exported.length,
      primary: exported.slice(0, 8).map((component) => `${component.type}:${component.name}`).join(" / ") || "--",
      risk: `${unprotected.length} unprotected exported component(s)`,
      action: "Prioritize exported activities/services/receivers/providers without permission for attack-surface review."
    },
    {
      area: "Deep Links / Intent Filters",
      count: deepLinks.length,
      primary: deepLinks.slice(0, 8).map((component) => `${component.name}: ${component.data.join("; ") || component.actions.join("; ")}`).join(" / ") || "--",
      risk: `${deepLinks.length} external data filter component(s)`,
      action: "Review scheme/host/path filters and test whether external apps can invoke sensitive flows."
    },
    {
      area: "Sensitive Broadcasts",
      count: sensitiveActions.length,
      primary: sensitiveActions.slice(0, 8).map((component) => `${component.name}: ${component.actions.join("; ")}`).join(" / ") || "--",
      risk: sensitiveActions.length ? "sensitive broadcast/action receiver" : "--",
      action: "Review BOOT/SMS/package/user-present/media receivers for persistence or data collection behavior."
    },
    {
      area: "APK Contents",
      count: info.apkEntries.length,
      primary: `${nativeEntries.length} native; ${opaqueEntries.length} opaque asset/raw; ${riskyEntries.length} review-marked`,
      risk: riskyEntries.slice(0, 8).map((entry) => `${entry.name}: ${entry.risk.join("/")}`).join(" / ") || "--",
      action: "Export APK entry index; send native/opaque/review-marked entries to file ID, strings, YARA, archive, or hash tools."
    },
    {
      area: "AXML Structure",
      count: info.axmlRows.length,
      primary: info.axmlRows.map(([key, value]) => `${key}=${value}`).slice(0, 5).join("; ") || "--",
      risk: axmlRisks.map((finding) => finding.title).join(", ") || "--",
      action: "Use AXML rows to document binary manifest structure and possible partial decode/chunk anomalies."
    },
    {
      area: "Visibility / Queries",
      count: info.queries.length,
      primary: info.queries.slice(0, 10).join(" / ") || "--",
      risk: info.queries.length ? "package visibility declared" : "--",
      action: "Review package/provider/action queries to infer app discovery targets."
    }
  ];
}

function androidComponentKey(component: AndroidComponent) {
  return [component.type, component.name, component.exported, component.permission, component.actions.join("|"), component.data.join("|")].join("::");
}

export { androidComponentKey, androidManifestSecurityRows, componentExportedEffective, parseAndroidManifest, inspectAndroidArchive, inspectAndroidBinaryXml, decodeAndroidManifestBytes, androidComponentsToCsv, androidPermissionsToCsv, androidApkEntriesToCsv };
