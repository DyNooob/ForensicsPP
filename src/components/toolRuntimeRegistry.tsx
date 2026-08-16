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
  const [{ ImageTool }, image, qr] = await Promise.all([import("../tools/ImageTool"), import("../features/image/analyzer"), import("../features/qr/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof ImageTool>, "services">) => <ImageTool {...props} services={{ ...image, ...qr }} /> };
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




const BinaryTool = React.lazy(async () => {
  const [{ BinaryTool }, file, yara] = await Promise.all([import("../tools/BinaryTool"), import("../features/file/analyzer"), import("../features/yara/analyzer")]);
  return { default: (props: Omit<React.ComponentProps<typeof BinaryTool>, "services">) => <BinaryTool {...props} services={{ ...file, yaraRuleTemplates: yara.yaraRuleTemplates }} /> };
});
const HttpTool = React.lazy(() => import("../tools/HttpTool").then((module) => ({ default: module.HttpTool })));
const WindowsArtifactTool = React.lazy(() => import("../tools/WindowsArtifactTool").then((module) => ({ default: module.WindowsArtifactTool })));
const FirmwareAnalyzerTool = React.lazy(() => import("../tools/FirmwareAnalyzerTool").then((module) => ({ default: module.FirmwareAnalyzerTool })));
const DiskImageTool = React.lazy(() => import("../tools/DiskImageTool").then((module) => ({ default: module.DiskImageTool })));
const MemoryTriageTool = React.lazy(() => import("../tools/MemoryTriageTool").then((module) => ({ default: module.MemoryTriageTool })));
const BulkArtifactTool = React.lazy(() => import("../tools/BulkArtifactTool").then((module) => ({ default: module.BulkArtifactTool })));
const UrlTool = React.lazy(() => import("../tools/UrlTool").then((module) => ({ default: module.UrlTool })));
const ArchiveTool = React.lazy(() => import("../tools/ArchiveTool").then((module) => ({ default: module.ArchiveTool })));

type RuntimeProps = {
  t: (typeof copy)["zh"];
  lang: Lang;
  active: boolean;
  recentTools: ToolId[];
  setActiveTool: (tool: ToolId, options?: { replaceHash?: boolean }) => void;
  onDirtyChange: (dirty: boolean) => void;
};

type RuntimeRenderer = (props: RuntimeProps) => React.ReactNode;

export const toolRuntimeRegistry: Record<ToolId, RuntimeRenderer> = {
  home: ({ t, lang, recentTools, setActiveTool }) => <HomeTool t={t} lang={lang} recentTools={recentTools} setActiveTool={setActiveTool} />,
  cyberchef: ({ t, active }) => <CyberChefTool t={t} active={active} />,
  image: ({ t, active }) => <ImageTool t={t} active={active} />,
  codec: ({ t, active }) => <CodecTool t={t} active={active} />,
  crypto: ({ t, active }) => <CryptoTool t={t} active={active} />,
  jwt: ({ t, active }) => <JwtTool t={t} active={active} />,
  password: ({ t, active }) => <PasswordTool t={t} active={active} />,
  sql: ({ t, active }) => <SqlTool t={t} active={active} />,
  sqlite: ({ t, active, onDirtyChange }) => <SqliteTool t={t} active={active} onDirtyChange={onDirtyChange} />,
  registry: ({ t, active }) => <RegistryTool t={t} active={active} />,
  plist: ({ t, active }) => <PlistTool t={t} active={active} />,
  browserartifacts: ({ t, active }) => <BrowserArtifactTool t={t} active={active} />,
  evtx: ({ t, active }) => <EvtxTool t={t} active={active} />,
  documentforensics: ({ t, active }) => <DocumentForensicsTool t={t} active={active} />,
  android: ({ t, active }) => <AndroidManifestTool t={t} active={active} />,
  ioc: ({ t, active }) => <IocTool t={t} active={active} />,
  email: ({ t, active }) => <EmailTool t={t} active={active} />,
  urltool: ({ t, active }) => <UrlTool t={t} active={active} />,
  http: ({ t, active }) => <HttpTool t={t} active={active} />,
  qr: ({ t, active }) => <ImageTool t={t} active={active} />,
  fileid: ({ t, active, setActiveTool }) => <BinaryTool t={t} active={active} setActiveTool={setActiveTool} />,
  png: ({ t, active }) => <ImageTool t={t} active={active} />,
  archive: ({ t, active }) => <ArchiveTool t={t} active={active} />,
  binary: ({ t, active, setActiveTool }) => <BinaryTool t={t} active={active} setActiveTool={setActiveTool} />,
  firmware: ({ t, active, setActiveTool }) => <FirmwareAnalyzerTool t={t} active={active} setActiveTool={setActiveTool} />,
  disk: ({ t, active }) => <DiskImageTool t={t} active={active} />,
  windows: ({ t, active }) => <WindowsArtifactTool t={t} active={active} />,
  memory: ({ t, active }) => <MemoryTriageTool t={t} active={active} />,
  strings: ({ t, active, setActiveTool }) => <BinaryTool t={t} active={active} setActiveTool={setActiveTool} />,
  bulk: ({ t, active }) => <BulkArtifactTool t={t} active={active} />,
  entropy: ({ t, active, setActiveTool }) => <BinaryTool t={t} active={active} setActiveTool={setActiveTool} />,
  hash: ({ t, active }) => <HashTool t={t} active={active} />,
  timestamp: ({ t, active }) => <TimestampTool t={t} active={active} />,
  timeline: ({ t, active }) => <TimelineTool t={t} active={active} />,
  baseconvert: ({ t, active }) => <BaseConvertTool t={t} active={active} />,
  uuid: ({ t, active }) => <UuidTool t={t} active={active} />,
  json: ({ t, active }) => <JsonTool t={t} active={active} />,
  regex: ({ t, active }) => <RegexTool t={t} active={active} />,
  pcap: ({ t, active }) => <PcapTool t={t} active={active} />,
  yara: ({ t, active, setActiveTool }) => <BinaryTool t={t} active={active} setActiveTool={setActiveTool} />
};
