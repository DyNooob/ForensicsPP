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

import React from "react";
import type { ComponentType, LazyExoticComponent } from "react";
import { Spin } from "antd";
import { ToolWorkspaceFrame } from "./ui";
import { ToolErrorBoundary } from "./ToolErrorBoundary";
import type { ToolId } from "../config/app";
import type { Lang } from "../models";
import { copy } from "../i18n";

// Single registration table: one lazy component per tool (with service injection where needed).
// The `Record<ToolId, ...>` constraint guarantees every tool id is registered here — adding a
// tool now means adding one entry here instead of editing three separate places.
// Tools are named exports, so each loader maps `module.XxxTool` to the default React.lazy expects.
const toolRegistry: Record<ToolId, LazyExoticComponent<any>> = {
  home: React.lazy(() => import("../tools/HomeTool").then((m) => ({ default: m.HomeTool }))),
  cyberchef: React.lazy(() => import("../tools/CyberChefTool").then((m) => ({ default: m.CyberChefTool }))),
  baseconvert: React.lazy(() => import("../tools/BaseConvertTool").then((m) => ({ default: m.BaseConvertTool }))),
  uuid: React.lazy(() => import("../tools/UuidTool").then((m) => ({ default: m.UuidTool }))),
  regex: React.lazy(async () => {
    const [{ RegexTool }, ioc] = await Promise.all([import("../tools/RegexTool"), import("../features/ioc/analyzer")]);
    return { default: (props: any) => <RegexTool {...props} classifyIocRisk={ioc.iocRisk} /> };
  }),
  json: React.lazy(() => import("../tools/JsonTool").then((m) => ({ default: m.JsonTool }))),
  sql: React.lazy(() => import("../tools/SqlTool").then((m) => ({ default: m.SqlTool }))),
  sqlite: React.lazy(() => import("../tools/SqliteTool").then((m) => ({ default: m.SqliteTool }))),
  registry: React.lazy(() => import("../tools/RegistryTool").then((m) => ({ default: m.RegistryTool }))),
  plist: React.lazy(() => import("../tools/PlistTool").then((m) => ({ default: m.PlistTool }))),
  browserartifacts: React.lazy(() => import("../tools/BrowserArtifactTool").then((m) => ({ default: m.BrowserArtifactTool }))),
  evtx: React.lazy(() => import("../tools/EvtxTool").then((m) => ({ default: m.EvtxTool }))),
  documentforensics: React.lazy(() => import("../tools/DocumentForensicsTool").then((m) => ({ default: m.DocumentForensicsTool }))),
  ioc: React.lazy(() => import("../tools/IocTool").then((m) => ({ default: m.IocTool }))),
  email: React.lazy(() => import("../tools/EmailTool").then((m) => ({ default: m.EmailTool }))),
  timestamp: React.lazy(() => import("../tools/TimestampTool").then((m) => ({ default: m.TimestampTool }))),
  timeline: React.lazy(() => import("../tools/TimelineTool").then((m) => ({ default: m.TimelineTool }))),
  pcap: React.lazy(() => import("../tools/PcapSimpleTool").then((m) => ({ default: m.PcapTool }))),
  image: React.lazy(async () => {
    const [{ ImageTool }, services] = await Promise.all([import("../tools/ImageTool"), import("../features/image/analyzer")]);
    return { default: (props: any) => <ImageTool {...props} services={services} /> };
  }),
  crypto: React.lazy(async () => {
    const [{ CryptoTool }, services] = await Promise.all([import("../tools/CryptoTool"), import("../features/crypto/algorithms")]);
    return { default: (props: any) => <CryptoTool {...props} services={services} /> };
  }),
  codec: React.lazy(async () => {
    const [{ CodecTool }, services] = await Promise.all([import("../tools/CodecTool"), import("../features/codec/analyzer")]);
    return { default: (props: any) => <CodecTool {...props} services={services} /> };
  }),
  hash: React.lazy(async () => {
    const [{ HashTool }, services] = await Promise.all([import("../tools/HashTool"), import("../features/hash/matching")]);
    return { default: (props: any) => <HashTool {...props} services={services} /> };
  }),
  jwt: React.lazy(async () => {
    const [{ JwtTool }, services] = await Promise.all([import("../tools/JwtTool"), import("../features/jwt/analyzer")]);
    return { default: (props: any) => <JwtTool {...props} services={services} /> };
  }),
  password: React.lazy(async () => {
    const [{ PasswordTool }, services] = await Promise.all([import("../tools/PasswordTool"), import("../features/password/analyzer")]);
    return { default: (props: any) => <PasswordTool {...props} services={services} /> };
  }),
  android: React.lazy(async () => {
    const [{ AndroidManifestTool }, services] = await Promise.all([import("../tools/AndroidManifestTool"), import("../features/android/analyzer")]);
    return { default: (props: any) => <AndroidManifestTool {...props} services={services} /> };
  }),
  qr: React.lazy(async () => {
    const [{ QrTool }, qr, image] = await Promise.all([
      import("../tools/QrTool"),
      import("../features/qr/analyzer"),
      import("../features/image/analyzer")
    ]);
    return { default: (props: any) => <QrTool {...props} services={{ ...qr, detectImageFormat: image.detectImageFormat }} /> };
  }),
  yara: React.lazy(async () => {
    const [{ YaraTool }, services] = await Promise.all([import("../tools/YaraTool"), import("../features/yara/analyzer")]);
    return { default: (props: any) => <YaraTool {...props} services={services} /> };
  }),
  strings: React.lazy(async () => {
    const [{ StringsTool }, services] = await Promise.all([import("../tools/StringsTool"), import("../features/strings/analyzer")]);
    return { default: (props: any) => <StringsTool {...props} services={services} /> };
  }),
  entropy: React.lazy(async () => {
    const [{ EntropyTool }, services] = await Promise.all([import("../tools/EntropyTool"), import("../features/entropy/analyzer")]);
    return { default: (props: any) => <EntropyTool {...props} services={services} /> };
  }),
  fileid: React.lazy(() => import("../tools/FileIdTool").then((m) => ({ default: m.FileIdTool }))),
  binary: React.lazy(async () => {
    const [{ BinaryTool }, services] = await Promise.all([import("../tools/BinaryTool"), import("../features/file/analyzer")]);
    return { default: (props: any) => <BinaryTool {...props} services={services} /> };
  }),
  http: React.lazy(() => import("../tools/HttpTool").then((m) => ({ default: m.HttpTool }))),
  windows: React.lazy(() => import("../tools/WindowsArtifactTool").then((m) => ({ default: m.WindowsArtifactTool }))),
  png: React.lazy(() => import("../tools/PngTool").then((m) => ({ default: m.PngTool }))),
  urltool: React.lazy(() => import("../tools/UrlTool").then((m) => ({ default: m.UrlTool }))),
  archive: React.lazy(() => import("../tools/ArchiveTool").then((m) => ({ default: m.ArchiveTool })))
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

// Memoized so unrelated global state changes (theme toggle, sidebar collapse, search query)
// don't re-render retained tool views. `setActiveTool`/`setToolDirty`/`t`/`lang` are stable
// references, so only an actual `active`/data change triggers a re-render.
function ToolHostImpl({ toolId, active, t, lang, recentTools, setActiveTool, setToolDirty }: ToolHostProps) {
  const handleDirtyChange = React.useCallback((dirty: boolean) => setToolDirty(toolId, dirty), [setToolDirty, toolId]);
  const ToolComponent = toolRegistry[toolId] as ComponentType<any>;
  if (!ToolComponent) return null;

  if (toolId === "home") {
    return (
      <div className="tool-retained-view" data-tool-id={toolId} hidden={!active}>
        <ToolErrorBoundary title={t.toolErrorTitle} detail={t.toolErrorDetail} retryLabel={t.retryTool}>
          <ToolComponent t={t} lang={lang} recentTools={recentTools} setActiveTool={setActiveTool} />
        </ToolErrorBoundary>
      </div>
    );
  }

  return (
    <div className="tool-retained-view" data-tool-id={toolId} hidden={!active}>
      <ToolErrorBoundary title={t.toolErrorTitle} detail={t.toolErrorDetail} retryLabel={t.retryTool}>
        <ToolWorkspaceFrame>
          <React.Suspense
            fallback={
              <div className="tool-loading-state" role="status" aria-live="polite">
                <Spin size="small" />
                <span>{t.loadingTool}</span>
              </div>
            }
          >
            {toolId === "sqlite" ? (
              <ToolComponent t={t} active={active} onDirtyChange={handleDirtyChange} />
            ) : (
              <ToolComponent t={t} active={active} />
            )}
          </React.Suspense>
        </ToolWorkspaceFrame>
      </ToolErrorBoundary>
    </div>
  );
}

export const ToolHost = React.memo(ToolHostImpl);
