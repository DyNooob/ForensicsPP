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
import { Spin } from "antd";
import { ToolWorkspaceFrame } from "./ui";
import type { ToolId } from "../config/app";
import type { Lang } from "../models";
import { copy } from "../i18n";
import { analyzeEntropy, entropyBlockKey, entropyBlocksToCsv, entropyRangesToCsv } from "../features/entropy/analyzer";
import { androidApkEntriesToCsv, androidComponentKey, androidComponentsToCsv, androidManifestSecurityRows, androidPermissionsToCsv, componentExportedEffective, parseAndroidManifest } from "../features/android/analyzer";
import { annotateBatchHashMatches, parseExpectedHashSet } from "../features/hash/matching";
import { extractJwtTokens, inspectJwtToken, jwtCryptoAlgorithm, signJwtHS256, verifyJwtAsymmetricSignature } from "../features/jwt/analyzer";
import { mysqlNativePassword, passwordRowsToCsv, randomSalt, verifyPasswordCandidates } from "../features/password/analyzer";
import { classifyQrPayload, parseQrPayloadDetails, qrGeometryRows, qrPointRow } from "../features/qr/analyzer";
import { defaultYaraSample, yaraBatchRowsToCsv, yaraHitsToCsv, yaraRuleTemplates } from "../features/yara/analyzer";
import { extractPrintableStrings, stringRowKey, stringsToCsv } from "../features/strings/analyzer";
import { analyzeWindowsArtifact } from "../features/windows/analyzer";
import { analyzeFileBytes, binaryHexDumpRows, parseByteOffset } from "../features/file/analyzer";
import { buildAutoRevealPreviews, bytesToDataUrl, createChannelPreviews, createImageAnalysisPixels, detectImageFormat, emptyImageChannels, guessImageDimensions, imageExtensionForMime, imageMimeForFormat, imagePlaceholderDataUrl, loadBrowserImage, revokeImageObjectUrls } from "../features/image/analyzer";
import { analyzePngEvidence } from "../features/png/analyzer";
import { base64DecodeLoose, transformText } from "../features/codec/analyzer";
import { affine, atbash, baconDecode, baconEncode, caesar, morseDecode, morseEncode, railFence, railFenceDecode, rot47, vigenere } from "../features/crypto/algorithms";
import { parseTimestampCandidates } from "../features/timestamp/analyzer";
import { analyzeIocs, iocRisk } from "../features/ioc/analyzer";
import { base64UrlDecode } from "../utils/base64";

const CyberChefTool = React.lazy(() => import("../tools/CyberChefTool").then((module) => ({ default: module.CyberChefTool })));
const BaseConvertTool = React.lazy(() => import("../tools/BaseConvertTool").then((module) => ({ default: module.BaseConvertTool })));
const UuidTool = React.lazy(() => import("../tools/UuidTool").then((module) => ({ default: module.UuidTool })));
const RegexTool = React.lazy(() => import("../tools/RegexTool").then((module) => ({ default: module.RegexTool })));
const JsonTool = React.lazy(() => import("../tools/JsonTool").then((module) => ({ default: module.JsonTool })));
const SqlTool = React.lazy(() => import("../tools/SqlTool").then((module) => ({ default: module.SqlTool })));
const HomeTool = React.lazy(() => import("../tools/HomeTool").then((module) => ({ default: module.HomeTool })));
const SqliteTool = React.lazy(() => import("../tools/SqliteTool").then((module) => ({ default: module.SqliteTool })));
const RegistryTool = React.lazy(() => import("../tools/RegistryTool").then((module) => ({ default: module.RegistryTool })));
const PlistTool = React.lazy(() => import("../tools/PlistTool").then((module) => ({ default: module.PlistTool })));
const BrowserArtifactTool = React.lazy(() => import("../tools/BrowserArtifactTool").then((module) => ({ default: module.BrowserArtifactTool })));
const EvtxTool = React.lazy(() => import("../tools/EvtxTool").then((module) => ({ default: module.EvtxTool })));
const DocumentForensicsTool = React.lazy(() => import("../tools/DocumentForensicsTool").then((module) => ({ default: module.DocumentForensicsTool })));
const IocTool = React.lazy(() => import("../tools/IocTool").then((module) => ({ default: module.IocTool })));
const EmailTool = React.lazy(() => import("../tools/EmailTool").then((module) => ({ default: module.EmailTool })));
const TimestampTool = React.lazy(() => import("../tools/TimestampTool").then((module) => ({ default: module.TimestampTool })));
const TimelineTool = React.lazy(() => import("../tools/TimelineTool").then((module) => ({ default: module.TimelineTool })));
const PcapTool = React.lazy(() => import("../tools/PcapSimpleTool").then((module) => ({ default: module.PcapTool })));
const ImageTool = React.lazy(() => import("../tools/ImageTool").then((module) => ({ default: module.ImageTool })));
const CryptoTool = React.lazy(() => import("../tools/CryptoTool").then((module) => ({ default: module.CryptoTool })));
const CodecTool = React.lazy(() => import("../tools/CodecTool").then((module) => ({ default: module.CodecTool })));
const HashTool = React.lazy(() => import("../tools/HashTool").then((module) => ({ default: module.HashTool })));
const JwtTool = React.lazy(() => import("../tools/JwtTool").then((module) => ({ default: module.JwtTool })));
const PasswordTool = React.lazy(() => import("../tools/PasswordTool").then((module) => ({ default: module.PasswordTool })));
const AndroidManifestTool = React.lazy(() => import("../tools/AndroidManifestTool").then((module) => ({ default: module.AndroidManifestTool })));
const QrTool = React.lazy(() => import("../tools/QrTool").then((module) => ({ default: module.QrTool })));
const YaraTool = React.lazy(() => import("../tools/YaraTool").then((module) => ({ default: module.YaraTool })));
const StringsTool = React.lazy(() => import("../tools/StringsTool").then((module) => ({ default: module.StringsTool })));
const EntropyTool = React.lazy(() => import("../tools/EntropyTool").then((module) => ({ default: module.EntropyTool })));
const FileIdTool = React.lazy(() => import("../tools/FileIdTool").then((module) => ({ default: module.FileIdTool })));
const BinaryTool = React.lazy(() => import("../tools/BinaryTool").then((module) => ({ default: module.BinaryTool })));
const HttpTool = React.lazy(() => import("../tools/HttpTool").then((module) => ({ default: module.HttpTool })));
const WindowsArtifactTool = React.lazy(() => import("../tools/WindowsArtifactTool").then((module) => ({ default: module.WindowsArtifactTool })));
const PngTool = React.lazy(() => import("../tools/PngTool").then((module) => ({ default: module.PngTool })));
const UrlTool = React.lazy(() => import("../tools/UrlTool").then((module) => ({ default: module.UrlTool })));
const ArchiveTool = React.lazy(() => import("../tools/ArchiveTool").then((module) => ({ default: module.ArchiveTool })));

const services = {
  png: { analyzePngEvidence },
  windows: { analyzeWindowsArtifact },
  binary: { analyzeFileBytes, binaryHexDumpRows, parseByteOffset },
  strings: { extractPrintableStrings, stringRowKey, stringsToCsv },
  entropy: { analyzeEntropy, entropyBlockKey, entropyBlocksToCsv, entropyRangesToCsv },
  yara: { defaultYaraSample, yaraBatchRowsToCsv, yaraHitsToCsv, yaraRuleTemplates },
  qr: { classifyQrPayload, detectImageFormat, parseQrPayloadDetails, qrGeometryRows, qrPointRow },
  android: { androidComponentKey, androidManifestSecurityRows, componentExportedEffective, parseAndroidManifest, androidComponentsToCsv, androidPermissionsToCsv, androidApkEntriesToCsv },
  password: { mysqlNativePassword, randomSalt, verifyPasswordCandidates, passwordRowsToCsv },
  jwt: { inspectJwtToken, extractJwtTokens, jwtCryptoAlgorithm, verifyJwtAsymmetricSignature, signJwtHS256 },
  hash: { annotateBatchHashMatches, parseExpectedHashSet },
  codec: { transformText },
  crypto: { caesar, atbash, rot47, vigenere, affine, morseEncode, morseDecode, baconEncode, baconDecode, railFence, railFenceDecode },
  image: { buildAutoRevealPreviews, bytesToDataUrl, createChannelPreviews, createImageAnalysisPixels, detectImageFormat, emptyImageChannels, guessImageDimensions, imageExtensionForMime, imageMimeForFormat, imagePlaceholderDataUrl, loadBrowserImage, revokeImageObjectUrls }
};

type ToolHostProps = {
  toolId: ToolId;
  active: boolean;
  t: (typeof copy)["zh"];
  lang: Lang;
  recentTools: ToolId[];
  setActiveTool: (tool: ToolId, options?: { replaceHash?: boolean }) => void;
  setToolDirty: (tool: ToolId, dirty: boolean) => void;
};

export function ToolHost({ toolId, active, t, lang, recentTools, setActiveTool, setToolDirty }: ToolHostProps) {
  const handleDirtyChange = React.useCallback((dirty: boolean) => setToolDirty(toolId, dirty), [setToolDirty, toolId]);
  return (
    <div className="tool-retained-view" data-tool-id={toolId} hidden={!active}>
      {toolId === "home" ? (
        <HomeTool t={t} lang={lang} recentTools={recentTools} setActiveTool={setActiveTool} />
      ) : (
        <ToolWorkspaceFrame>
          <React.Suspense fallback={<div className="tool-loading-state" role="status" aria-live="polite"><Spin size="small" /><span>{t.loadingTool}</span></div>}>
            {toolId === "cyberchef" && <CyberChefTool t={t} />}
            {toolId === "image" && <ImageTool t={t} services={services.image} />}
            {toolId === "codec" && <CodecTool t={t} services={services.codec} />}
            {toolId === "crypto" && <CryptoTool t={t} services={services.crypto} />}
            {toolId === "jwt" && <JwtTool t={t} services={services.jwt} />}
            {toolId === "password" && <PasswordTool t={t} services={services.password} />}
            {toolId === "sql" && <SqlTool t={t} />}
            {toolId === "sqlite" && <SqliteTool t={t} onDirtyChange={handleDirtyChange} />}
            {toolId === "registry" && <RegistryTool t={t} />}
            {toolId === "plist" && <PlistTool t={t} />}
            {toolId === "browserartifacts" && <BrowserArtifactTool t={t} />}
            {toolId === "evtx" && <EvtxTool t={t} />}
            {toolId === "documentforensics" && <DocumentForensicsTool t={t} />}
            {toolId === "android" && <AndroidManifestTool t={t} services={services.android} />}
            {toolId === "ioc" && <IocTool t={t} />}
            {toolId === "email" && <EmailTool t={t} />}
            {toolId === "urltool" && <UrlTool t={t} />}
            {toolId === "http" && <HttpTool t={t} />}
            {toolId === "qr" && <QrTool t={t} services={services.qr} />}
            {toolId === "fileid" && <FileIdTool t={t} />}
            {toolId === "png" && <PngTool t={t} services={services.png} />}
            {toolId === "archive" && <ArchiveTool t={t} />}
            {toolId === "binary" && <BinaryTool t={t} services={services.binary} />}
            {toolId === "windows" && <WindowsArtifactTool t={t} services={services.windows} />}
            {toolId === "strings" && <StringsTool t={t} services={services.strings} />}
            {toolId === "entropy" && <EntropyTool t={t} services={services.entropy} />}
            {toolId === "hash" && <HashTool t={t} services={services.hash} />}
            {toolId === "timestamp" && <TimestampTool t={t} />}
            {toolId === "timeline" && <TimelineTool t={t} />}
            {toolId === "baseconvert" && <BaseConvertTool t={t} />}
            {toolId === "uuid" && <UuidTool t={t} />}
            {toolId === "json" && <JsonTool t={t} analyzeIocs={analyzeIocs} parseTimestampCandidates={parseTimestampCandidates} decodeBase64Url={base64UrlDecode} decodeBase64Loose={base64DecodeLoose} />}
            {toolId === "regex" && <RegexTool t={t} classifyIocRisk={iocRisk} />}
            {toolId === "pcap" && <PcapTool t={t} />}
            {toolId === "yara" && <YaraTool t={t} services={services.yara} />}
          </React.Suspense>
        </ToolWorkspaceFrame>
      )}
    </div>
  );
}
