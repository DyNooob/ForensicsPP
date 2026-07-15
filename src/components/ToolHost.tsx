/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import React from "react";
import { Spin } from "antd";
import { ToolWorkspaceFrame } from "./ui";
import { ToolErrorBoundary } from "./ToolErrorBoundary";
import type { ToolId } from "../config/app";
import type { Lang } from "../models";
import { copy } from "../i18n";

const CyberChefTool = React.lazy(() => import("../tools/CyberChefTool").then((module) => ({ default: module.CyberChefTool })));
const BaseConvertTool = React.lazy(() => import("../tools/BaseConvertTool").then((module) => ({ default: module.BaseConvertTool })));
const UuidTool = React.lazy(() => import("../tools/UuidTool").then((module) => ({ default: module.UuidTool })));
const RegexTool = React.lazy(async () => {
  const [{ RegexTool }, ioc] = await Promise.all([import("../tools/RegexTool"), import("../features/ioc/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof RegexTool>, "classifyIocRisk">) => <RegexTool {...props} classifyIocRisk={ioc.iocRisk} /> };
});
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
const ImageTool = React.lazy(async () => {
  const [{ ImageTool }, services] = await Promise.all([import("../tools/ImageTool"), import("../features/image/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof ImageTool>, "services">) => <ImageTool {...props} services={services} /> };
});
const CryptoTool = React.lazy(async () => {
  const [{ CryptoTool }, services] = await Promise.all([import("../tools/CryptoTool"), import("../features/crypto/algorithms")]);
  return { default: (props: Omit<React.ComponentProps<typeof CryptoTool>, "services">) => <CryptoTool {...props} services={services} /> };
});
const CodecTool = React.lazy(async () => {
  const [{ CodecTool }, services] = await Promise.all([import("../tools/CodecTool"), import("../features/codec/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof CodecTool>, "services">) => <CodecTool {...props} services={services} /> };
});
const HashTool = React.lazy(async () => {
  const [{ HashTool }, services] = await Promise.all([import("../tools/HashTool"), import("../features/hash/matching")]);
  return { default: (props: Omit<React.ComponentProps<typeof HashTool>, "services">) => <HashTool {...props} services={services} /> };
});
const JwtTool = React.lazy(async () => {
  const [{ JwtTool }, services] = await Promise.all([import("../tools/JwtTool"), import("../features/jwt/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof JwtTool>, "services">) => <JwtTool {...props} services={services} /> };
});
const PasswordTool = React.lazy(async () => {
  const [{ PasswordTool }, services] = await Promise.all([import("../tools/PasswordTool"), import("../features/password/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof PasswordTool>, "services">) => <PasswordTool {...props} services={services} /> };
});
const AndroidManifestTool = React.lazy(async () => {
  const [{ AndroidManifestTool }, services] = await Promise.all([import("../tools/AndroidManifestTool"), import("../features/android/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof AndroidManifestTool>, "services">) => <AndroidManifestTool {...props} services={services} /> };
});
const QrTool = React.lazy(async () => {
  const [{ QrTool }, qr, image] = await Promise.all([import("../tools/QrTool"), import("../features/qr/analyzer"), import("../features/image/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof QrTool>, "services">) => <QrTool {...props} services={{ ...qr, detectImageFormat: image.detectImageFormat }} /> };
});
const YaraTool = React.lazy(async () => {
  const [{ YaraTool }, services] = await Promise.all([import("../tools/YaraTool"), import("../features/yara/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof YaraTool>, "services">) => <YaraTool {...props} services={services} /> };
});
const StringsTool = React.lazy(async () => {
  const [{ StringsTool }, services] = await Promise.all([import("../tools/StringsTool"), import("../features/strings/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof StringsTool>, "services">) => <StringsTool {...props} services={services} /> };
});
const EntropyTool = React.lazy(async () => {
  const [{ EntropyTool }, services] = await Promise.all([import("../tools/EntropyTool"), import("../features/entropy/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof EntropyTool>, "services">) => <EntropyTool {...props} services={services} /> };
});
const FileIdTool = React.lazy(() => import("../tools/FileIdTool").then((module) => ({ default: module.FileIdTool })));
const BinaryTool = React.lazy(async () => {
  const [{ BinaryTool }, services] = await Promise.all([import("../tools/BinaryTool"), import("../features/file/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof BinaryTool>, "services">) => <BinaryTool {...props} services={services} /> };
});
const HttpTool = React.lazy(() => import("../tools/HttpTool").then((module) => ({ default: module.HttpTool })));
const WindowsArtifactTool = React.lazy(() => import("../tools/WindowsArtifactTool").then((module) => ({ default: module.WindowsArtifactTool })));
const PngTool = React.lazy(() => import("../tools/PngTool").then((module) => ({ default: module.PngTool })));
const UrlTool = React.lazy(() => import("../tools/UrlTool").then((module) => ({ default: module.UrlTool })));
const ArchiveTool = React.lazy(() => import("../tools/ArchiveTool").then((module) => ({ default: module.ArchiveTool })));

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
      <ToolErrorBoundary title={t.toolErrorTitle} detail={t.toolErrorDetail} retryLabel={t.retryTool}>
      {toolId === "home" ? (
        <HomeTool t={t} lang={lang} recentTools={recentTools} setActiveTool={setActiveTool} />
      ) : (
        <ToolWorkspaceFrame>
          <React.Suspense fallback={<div className="tool-loading-state" role="status" aria-live="polite"><Spin size="small" /><span>{t.loadingTool}</span></div>}>
            {toolId === "cyberchef" && <CyberChefTool t={t} />}
            {toolId === "image" && <ImageTool t={t} active={active} />}
            {toolId === "codec" && <CodecTool t={t} active={active} />}
            {toolId === "crypto" && <CryptoTool t={t} />}
            {toolId === "jwt" && <JwtTool t={t} active={active} />}
            {toolId === "password" && <PasswordTool t={t} active={active} />}
            {toolId === "sql" && <SqlTool t={t} active={active} />}
            {toolId === "sqlite" && <SqliteTool t={t} active={active} onDirtyChange={handleDirtyChange} />}
            {toolId === "registry" && <RegistryTool t={t} active={active} />}
            {toolId === "plist" && <PlistTool t={t} active={active} />}
            {toolId === "browserartifacts" && <BrowserArtifactTool t={t} active={active} />}
            {toolId === "evtx" && <EvtxTool t={t} active={active} />}
            {toolId === "documentforensics" && <DocumentForensicsTool t={t} active={active} />}
            {toolId === "android" && <AndroidManifestTool t={t} active={active} />}
            {toolId === "ioc" && <IocTool t={t} active={active} />}
            {toolId === "email" && <EmailTool t={t} active={active} />}
            {toolId === "urltool" && <UrlTool t={t} />}
            {toolId === "http" && <HttpTool t={t} active={active} />}
            {toolId === "qr" && <QrTool t={t} active={active} />}
            {toolId === "fileid" && <FileIdTool t={t} active={active} />}
            {toolId === "png" && <PngTool t={t} active={active} />}
            {toolId === "archive" && <ArchiveTool t={t} active={active} />}
            {toolId === "binary" && <BinaryTool t={t} active={active} />}
            {toolId === "windows" && <WindowsArtifactTool t={t} active={active} />}
            {toolId === "strings" && <StringsTool t={t} active={active} />}
            {toolId === "entropy" && <EntropyTool t={t} active={active} />}
            {toolId === "hash" && <HashTool t={t} active={active} />}
            {toolId === "timestamp" && <TimestampTool t={t} active={active} />}
            {toolId === "timeline" && <TimelineTool t={t} active={active} />}
            {toolId === "baseconvert" && <BaseConvertTool t={t} />}
            {toolId === "uuid" && <UuidTool t={t} />}
            {toolId === "json" && <JsonTool t={t} active={active} />}
            {toolId === "regex" && <RegexTool t={t} active={active} />}
            {toolId === "pcap" && <PcapTool t={t} active={active} />}
            {toolId === "yara" && <YaraTool t={t} active={active} />}
          </React.Suspense>
        </ToolWorkspaceFrame>
      )}
      </ToolErrorBoundary>
    </div>
  );
}
