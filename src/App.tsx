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
import { ConfigProvider, Spin, theme as antdTheme } from "antd";
import { CodeOutlined, LinkOutlined, MenuFoldOutlined, MenuUnfoldOutlined, SettingOutlined } from "@ant-design/icons";
import { AButton, AList, AListItem, AListSubheader, ASegmentedButton, ASegmentedGroup, ATextField, ToolWorkspaceFrame } from "./components/ui";
import { GithubIconButton } from "./components/GithubIconButton";
import { CommandPalette } from "./components/CommandPalette";
import { SettingsModal } from "./components/SettingsModal";
import { analyzeEntropy, entropyBlockKey, entropyBlocksToCsv, entropyRangesToCsv } from "./features/entropy/analyzer";
import { androidApkEntriesToCsv, androidComponentKey, androidComponentsToCsv, androidManifestSecurityRows, androidPermissionsToCsv, componentExportedEffective, decodeAndroidManifestBytes, inspectAndroidArchive, inspectAndroidBinaryXml, parseAndroidManifest } from "./features/android/analyzer";
import { annotateBatchHashMatches, parseExpectedHashSet } from "./features/hash/matching";
import { extractJwtTokens, inspectJwtToken, jwtCryptoAlgorithm, signJwtHS256, verifyJwtAsymmetricSignature } from "./features/jwt/analyzer";
import { mysqlNativePassword, passwordRowsToCsv, randomSalt, verifyPasswordCandidates } from "./features/password/analyzer";
import { classifyQrPayload, parseQrPayloadDetails, qrGeometryRows, qrPointRow } from "./features/qr/analyzer";
import { defaultYaraSample, runYaraScan, yaraBatchRowsToCsv, yaraHitsToCsv, yaraRuleTemplates } from "./features/yara/analyzer";
import { extractPrintableStrings, stringRowKey, stringsToCsv } from "./features/strings/analyzer";
import { analyzeWindowsArtifact } from "./features/windows/analyzer";
import { analyzeFileBytes, binaryHexDumpRows, parseByteOffset } from "./features/file/analyzer";
import { analyzeImageBytes, analyzeUndecodedImageBytes, buildAutoRevealPreviews, buildHiddenPayloadPreviews, buildImageDecodedSignals, buildImageRepairCandidates, bytesToDataUrl, createChannelPreviews, createNormalizedImageDataUrl, detectImageFormat, emptyImageChannels, guessImageDimensions, imageEvidenceReportText, imageExtensionForMime, imageMimeForFormat, imagePlaceholderDataUrl, loadBrowserImage, revokeImageObjectUrls, tryRebuildPngContainer } from "./features/image/analyzer";
import { analyzePngEvidence } from "./features/png/analyzer";
import { base64DecodeLoose, transformText } from "./features/codec/analyzer";
import { affine, atbash, baconDecode, baconEncode, caesar, morseDecode, morseEncode, railFence, railFenceDecode, rot47, vigenere } from "./features/crypto/algorithms";
import { parseTimestampCandidates } from "./features/timestamp/analyzer";
import { analyzeIocs, iocRisk } from "./features/ioc/analyzer";
import { getToolTitle as resolveToolTitle, legalVersion, maxRecentTools, themePresets, toolTitleOverrides, toolIdFromHash, tools, writeToolHash } from "./config/app";
import type { ToolId } from "./config/app";
import { copy } from "./i18n";
import { base64UrlDecode } from "./utils/base64";
import { clearForensicsStorage, useStoredState } from "./utils/storage";
import type { Lang, ThemeMode, AppCommand } from "./models";

const CyberChefTool = React.lazy(() => import("./tools/CyberChefTool").then((module) => ({ default: module.CyberChefTool })));
const BaseConvertTool = React.lazy(() => import("./tools/BaseConvertTool").then((module) => ({ default: module.BaseConvertTool })));
const UuidTool = React.lazy(() => import("./tools/UuidTool").then((module) => ({ default: module.UuidTool })));
const RegexTool = React.lazy(() => import("./tools/RegexTool").then((module) => ({ default: module.RegexTool })));
const JsonTool = React.lazy(() => import("./tools/JsonTool").then((module) => ({ default: module.JsonTool })));
const SqlTool = React.lazy(() => import("./tools/SqlTool").then((module) => ({ default: module.SqlTool })));
const HomeTool = React.lazy(() => import("./tools/HomeTool").then((module) => ({ default: module.HomeTool })));
const SqliteTool = React.lazy(() => import("./tools/SqliteTool").then((module) => ({ default: module.SqliteTool })));
const IocTool = React.lazy(() => import("./tools/IocTool").then((module) => ({ default: module.IocTool })));
const EmailTool = React.lazy(() => import("./tools/EmailTool").then((module) => ({ default: module.EmailTool })));
const TimestampTool = React.lazy(() => import("./tools/TimestampTool").then((module) => ({ default: module.TimestampTool })));
const TimelineTool = React.lazy(() => import("./tools/TimelineTool").then((module) => ({ default: module.TimelineTool })));
const PcapTool = React.lazy(() => import("./tools/PcapSimpleTool").then((module) => ({ default: module.PcapTool })));
const ImageTool = React.lazy(() => import("./tools/ImageTool").then((module) => ({ default: module.ImageTool })));
const CryptoTool = React.lazy(() => import("./tools/CryptoTool").then((module) => ({ default: module.CryptoTool })));
const CodecTool = React.lazy(() => import("./tools/CodecTool").then((module) => ({ default: module.CodecTool })));
const HashTool = React.lazy(() => import("./tools/HashTool").then((module) => ({ default: module.HashTool })));
const JwtTool = React.lazy(() => import("./tools/JwtTool").then((module) => ({ default: module.JwtTool })));
const PasswordTool = React.lazy(() => import("./tools/PasswordTool").then((module) => ({ default: module.PasswordTool })));
const AndroidManifestTool = React.lazy(() => import("./tools/AndroidManifestTool").then((module) => ({ default: module.AndroidManifestTool })));
const QrTool = React.lazy(() => import("./tools/QrTool").then((module) => ({ default: module.QrTool })));
const YaraTool = React.lazy(() => import("./tools/YaraTool").then((module) => ({ default: module.YaraTool })));
const StringsTool = React.lazy(() => import("./tools/StringsTool").then((module) => ({ default: module.StringsTool })));
const EntropyTool = React.lazy(() => import("./tools/EntropyTool").then((module) => ({ default: module.EntropyTool })));
const FileIdTool = React.lazy(() => import("./tools/FileIdTool").then((module) => ({ default: module.FileIdTool })));
const BinaryTool = React.lazy(() => import("./tools/BinaryTool").then((module) => ({ default: module.BinaryTool })));
const HttpTool = React.lazy(() => import("./tools/HttpTool").then((module) => ({ default: module.HttpTool })));
const WindowsArtifactTool = React.lazy(() => import("./tools/WindowsArtifactTool").then((module) => ({ default: module.WindowsArtifactTool })));
const PngTool = React.lazy(() => import("./tools/PngTool").then((module) => ({ default: module.PngTool })));
const UrlTool = React.lazy(() => import("./tools/UrlTool").then((module) => ({ default: module.UrlTool })));
const ArchiveTool = React.lazy(() => import("./tools/ArchiveTool").then((module) => ({ default: module.ArchiveTool })));

const pngToolServices = {
  analyzePngEvidence
};

const windowsArtifactToolServices = {
  analyzeWindowsArtifact
};

const binaryToolServices = {
  analyzeFileBytes,
  binaryHexDumpRows,
  parseByteOffset
};

const stringsToolServices = {
  extractPrintableStrings,
  stringRowKey,
  stringsToCsv
};

const entropyToolServices = {
  analyzeEntropy,
  entropyBlockKey,
  entropyBlocksToCsv,
  entropyRangesToCsv
};

function getYaraToolServices() {
  return {
  defaultYaraSample,
  runYaraScan,
  yaraBatchRowsToCsv,
  yaraHitsToCsv,
  yaraRuleTemplates
  };
}

const qrToolServices = {
  classifyQrPayload,
  detectImageFormat,
  parseQrPayloadDetails,
  qrGeometryRows,
  qrPointRow
};

const androidManifestToolServices = {
  androidComponentKey,
  androidManifestSecurityRows,
  componentExportedEffective,
  parseAndroidManifest,
  inspectAndroidArchive,
  inspectAndroidBinaryXml,
  decodeAndroidManifestBytes,
  androidComponentsToCsv,
  androidPermissionsToCsv,
  androidApkEntriesToCsv
};

const passwordToolServices = {
  mysqlNativePassword,
  randomSalt,
  verifyPasswordCandidates,
  passwordRowsToCsv
};

const jwtToolServices = {
  inspectJwtToken,
  extractJwtTokens,
  jwtCryptoAlgorithm,
  verifyJwtAsymmetricSignature,
  signJwtHS256
};

const hashToolServices = {
  annotateBatchHashMatches,
  parseExpectedHashSet,
};

const codecToolServices = {
  transformText
};

const cryptoToolServices = {
  caesar,
  atbash,
  rot47,
  vigenere,
  affine,
  morseEncode,
  morseDecode,
  baconEncode,
  baconDecode,
  railFence,
  railFenceDecode
};

const imageToolServices = {
  analyzeImageBytes,
  analyzeUndecodedImageBytes,
  buildAutoRevealPreviews,
  buildHiddenPayloadPreviews,
  buildImageDecodedSignals,
  buildImageRepairCandidates,
  bytesToDataUrl,
  createChannelPreviews,
  createNormalizedImageDataUrl,
  detectImageFormat,
  emptyImageChannels,
  guessImageDimensions,
  imageEvidenceReportText,
  imageExtensionForMime,
  imageMimeForFormat,
  imagePlaceholderDataUrl,
  loadBrowserImage,
  revokeImageObjectUrls,
  tryRebuildPngContainer
};


function getToolTitle(tool: (typeof tools)[number], lang: Lang) {
  return resolveToolTitle(tool, lang, copy[lang]);
}



function normalizeHexColor(value: string) {
  const normalized = value.trim().startsWith("#") ? value.trim() : `#${value.trim()}`;
  return /^#[0-9a-fA-F]{6}$/.test(normalized) ? normalized.toUpperCase() : null;
}

function hexToRgb(value: string) {
  const normalized = normalizeHexColor(value);
  if (!normalized) return null;
  const hex = normalized.slice(1);
  return {
    r: Number.parseInt(hex.slice(0, 2), 16),
    g: Number.parseInt(hex.slice(2, 4), 16),
    b: Number.parseInt(hex.slice(4, 6), 16)
  };
}

function mixHexColors(base: string, target: string, amount: number) {
  const from = hexToRgb(base);
  const to = hexToRgb(target);
  if (!from || !to) return base;
  const mix = (start: number, end: number) => Math.round(start + (end - start) * amount);
  const toHex = (value: number) => value.toString(16).padStart(2, "0").toUpperCase();
  return `#${toHex(mix(from.r, to.r))}${toHex(mix(from.g, to.g))}${toHex(mix(from.b, to.b))}`;
}

function relativeLuminance(hex: string) {
  const rgb = hexToRgb(hex);
  if (!rgb) return 0;
  const channel = (value: number) => {
    const normalized = value / 255;
    return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(rgb.r) + 0.7152 * channel(rgb.g) + 0.0722 * channel(rgb.b);
}

function contrastRatio(first: string, second: string) {
  const lighter = Math.max(relativeLuminance(first), relativeLuminance(second));
  const darker = Math.min(relativeLuminance(first), relativeLuminance(second));
  return (lighter + 0.05) / (darker + 0.05);
}

function themeDisplayColor(hex: string, mode: "light" | "dark") {
  const normalized = normalizeHexColor(hex) ?? themePresets[0].hex;
  if (mode === "light") return normalized;
  const darkSurface = "#1D2A38";
  if (contrastRatio(normalized, darkSurface) >= 4.5) return normalized;
  for (let amount = 0.08; amount <= 0.8; amount += 0.04) {
    const candidate = mixHexColors(normalized, "#FFFFFF", amount);
    if (contrastRatio(candidate, darkSurface) >= 4.5) return candidate;
  }
  return mixHexColors(normalized, "#FFFFFF", 0.8);
}

function themeSoftColor(hex: string, mode: "light" | "dark") {
  const rgb = hexToRgb(hex);
  if (!rgb) {
    return mode === "dark" ? "rgba(8, 126, 164, 0.15)" : "rgba(8, 126, 164, 0.08)";
  }
  return `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${mode === "dark" ? "0.15" : "0.08"})`;
}




export function App() {
  const [lang, setLang] = useStoredState<Lang>("app.lang", "zh");
  const [storedActiveTool, setStoredActiveTool] = useStoredState<ToolId>("app.activeTool", "home");
  const [routeTool, setRouteTool] = React.useState<ToolId | null>(() => toolIdFromHash());
  const [recentTools, setRecentTools] = useStoredState<ToolId[]>("app.recentTools", []);
  const [favoriteTools, setFavoriteTools] = useStoredState<ToolId[]>("app.favoriteTools", []);
  const [query, setQuery] = useStoredState("app.query", "");
  const [themeMode, setThemeMode] = useStoredState<ThemeMode>("app.themeMode", "light");
  const [themeColor, setThemeColor] = useStoredState("app.themeColor", themePresets[0].hex);
  const [acceptedLegalVersion, setAcceptedLegalVersion] = useStoredState("legal.acceptedVersion", "");
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  const [cacheClearArmed, setCacheClearArmed] = React.useState(false);
  const [commandOpen, setCommandOpen] = React.useState(false);
  const [commandQuery, setCommandQuery] = React.useState("");
  const modalOpenGuardRef = React.useRef({ settings: 0, command: 0 });
  const [toolLinkMessage, setToolLinkMessage] = React.useState("");
  const [sidebarCollapsed, setSidebarCollapsed] = useStoredState("app.sidebarCollapsed", false);
  const [isNarrowShell, setIsNarrowShell] = React.useState(() => {
    if (typeof window === "undefined") return false;
    return window.matchMedia("(max-width: 900px)").matches;
  });
  const [systemTheme, setSystemTheme] = React.useState<"light" | "dark">(() => {
    if (typeof window === "undefined") return "light";
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  const [detailsExpanded, setDetailsExpanded] = React.useState(false);
  const t = copy[lang];
  const resolvedThemeColor = React.useMemo(
    () => normalizeHexColor(themeColor) ?? themePresets[0].hex,
    [themeColor]
  );
  const appliedTheme = themeMode === "auto" ? systemTheme : themeMode === "dark" ? "dark" : "light";
  const displayThemeColor = React.useMemo(
    () => themeDisplayColor(resolvedThemeColor, appliedTheme),
    [appliedTheme, resolvedThemeColor]
  );
  const activeTool = routeTool ?? (tools.some((tool) => tool.id === storedActiveTool) ? storedActiveTool : "home");
  const rememberToolUse = (tool: ToolId) => {
    if (tool === "home") return;
    setRecentTools((items) => [tool, ...items.filter((item) => item !== tool && tools.some((known) => known.id === item))].slice(0, maxRecentTools));
  };
  const setActiveTool = (tool: ToolId, options?: { replaceHash?: boolean }) => {
    setRouteTool(tool);
    setStoredActiveTool(tool);
    rememberToolUse(tool);
    writeToolHash(tool, options?.replaceHash);
    if (isNarrowShell) setSidebarCollapsed(true);
  };
  const active = tools.find((tool) => tool.id === activeTool) ?? tools[0];
  const favoriteIds = new Set(favoriteTools.filter((id) => id !== "home" && tools.some((tool) => tool.id === id)));
  const activeIsFavorite = favoriteIds.has(activeTool);
  const toggleFavoriteTool = (tool: ToolId) => {
    if (tool === "home") return;
    setFavoriteTools((items) => {
      const normalized = items.filter((item) => item !== "home" && tools.some((known) => known.id === item));
      return normalized.includes(tool) ? normalized.filter((item) => item !== tool) : [tool, ...normalized].slice(0, maxRecentTools);
    });
  };
  const detailsToggleLabel = detailsExpanded ? (lang === "zh" ? "精简" : "Compact") : (lang === "zh" ? "详情" : "Details");
  const filteredTools = tools.filter((tool) => {
    const text = [
      copy.zh[tool.name],
      copy.zh[tool.desc],
      copy.zh[tool.category],
      copy.en[tool.name],
      copy.en[tool.desc],
      copy.en[tool.category]
    ].join(" ").toLowerCase();
    return text.includes(query.toLowerCase());
  });
  const favoriteNavTools = favoriteTools
    .map((id) => filteredTools.find((tool) => tool.id === id))
    .filter((tool): tool is (typeof tools)[number] => Boolean(tool))
    .filter((tool) => tool.id !== "home");
  const groupedTools = (["featured", "analysis", "transform", "network"] as Array<keyof typeof copy.zh>)
    .map((category) => ({
      category,
      items: filteredTools.filter((tool) => tool.category === category && !favoriteIds.has(tool.id))
    }))
    .filter((group) => group.items.length);
  React.useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const handleChange = () => setSystemTheme(media.matches ? "dark" : "light");
    handleChange();
    media.addEventListener("change", handleChange);
    return () => media.removeEventListener("change", handleChange);
  }, []);

  React.useEffect(() => {
    if (themeColor !== resolvedThemeColor) {
      setThemeColor(resolvedThemeColor);
    }
  }, [resolvedThemeColor, setThemeColor, themeColor]);

  React.useLayoutEffect(() => {
    document.documentElement.dataset.themeMode = appliedTheme;
    document.body.dataset.themeMode = appliedTheme;
    document.documentElement.style.colorScheme = appliedTheme;
    document.body.style.colorScheme = appliedTheme;
    document.documentElement.style.backgroundColor = appliedTheme === "dark" ? "#0f1722" : "#f5f7fa";
    document.body.style.backgroundColor = appliedTheme === "dark" ? "#0f1722" : "#f5f7fa";
    document.documentElement.style.setProperty("--app-primary", displayThemeColor);
    document.documentElement.style.setProperty("--app-primary-soft", themeSoftColor(displayThemeColor, appliedTheme));
    document.documentElement.style.setProperty("--app-primary-contrast", appliedTheme === "dark" ? "#0F1822" : "#FFFFFF");
    document.body.style.setProperty("--app-primary", displayThemeColor);
    document.body.style.setProperty("--app-primary-soft", themeSoftColor(displayThemeColor, appliedTheme));
    document.body.style.setProperty("--app-primary-contrast", appliedTheme === "dark" ? "#0F1822" : "#FFFFFF");
    const rootNode = document.getElementById("root");
    if (rootNode) {
      rootNode.dataset.themeMode = appliedTheme;
      rootNode.style.colorScheme = appliedTheme;
      rootNode.style.setProperty("--app-primary", displayThemeColor);
      rootNode.style.setProperty("--app-primary-soft", themeSoftColor(displayThemeColor, appliedTheme));
      rootNode.style.setProperty("--app-primary-contrast", appliedTheme === "dark" ? "#0F1822" : "#FFFFFF");
    }
    let themeMeta = document.querySelector("meta[name='theme-color']");
    if (!themeMeta) {
      themeMeta = document.createElement("meta");
      themeMeta.setAttribute("name", "theme-color");
      document.head.appendChild(themeMeta);
    }
    themeMeta.setAttribute("content", appliedTheme === "dark" ? "#0f1722" : "#f5f7fa");
  }, [appliedTheme, displayThemeColor]);

  React.useEffect(() => {
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    document.title = activeTool === "home" ? "Forensics++ Workbench | Open-source DFIR tools" : `${getToolTitle(active, lang)} - Forensics++`;
  }, [active.name, activeTool, lang, t]);

  React.useEffect(() => {
    const hashedTool = toolIdFromHash();
    if (hashedTool) {
      setRouteTool(hashedTool);
      setStoredActiveTool(hashedTool);
      rememberToolUse(hashedTool);
      return;
    }
    writeToolHash(activeTool, true);
  }, []);

  React.useEffect(() => {
    const handleHashChange = () => {
      const nextTool = toolIdFromHash();
      if (!nextTool) return;
      setRouteTool(nextTool);
      setStoredActiveTool(nextTool);
      rememberToolUse(nextTool);
    };
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  React.useEffect(() => {
    setDetailsExpanded(false);
  }, [activeTool]);

  React.useEffect(() => {
    const media = window.matchMedia("(max-width: 900px)");
    const handleChange = () => {
      setIsNarrowShell(media.matches);
      if (media.matches) setSidebarCollapsed(true);
    };
    handleChange();
    media.addEventListener("change", handleChange);
    return () => media.removeEventListener("change", handleChange);
  }, []);

  React.useEffect(() => {
    if (!toolLinkMessage) return undefined;
    const timer = window.setTimeout(() => setToolLinkMessage(""), 2200);
    return () => window.clearTimeout(timer);
  }, [toolLinkMessage]);

  React.useEffect(() => {
    if (window.location.protocol === "https:" && "serviceWorker" in navigator) {
      navigator.serviceWorker.register("/sw.js").catch(() => undefined);
    }
  }, []);


  React.useEffect(() => {
    if (!settingsOpen) setCacheClearArmed(false);
  }, [settingsOpen]);

  React.useEffect(() => {
    if (!cacheClearArmed) return;
    const timer = window.setTimeout(() => setCacheClearArmed(false), 4000);
    return () => window.clearTimeout(timer);
  }, [cacheClearArmed]);

  const openSettingsPanel = React.useCallback(() => {
    modalOpenGuardRef.current.settings = performance.now();
    setSettingsOpen(true);
  }, []);

  const openCommandPalette = React.useCallback(() => {
    modalOpenGuardRef.current.command = performance.now();
    setCommandOpen(true);
  }, []);

  const shouldIgnoreBackdropClick = React.useCallback((modal: "settings" | "command") => (
    performance.now() - modalOpenGuardRef.current[modal] < 220
  ), []);

  const commands = React.useMemo<AppCommand[]>(() => {
    const toolCommands = tools.map((tool) => ({
      id: `tool:${tool.id}`,
      group: t.commandGroupTools,
      label: getToolTitle(tool, lang),
      hint: t[tool.desc],
      meta: t[tool.category],
      keywords: `${tool.id} ${copy.zh[tool.name]} ${copy.en[tool.name]} ${copy.zh[tool.desc]} ${copy.en[tool.desc]} ${toolTitleOverrides[tool.id]?.zh ?? ""} ${toolTitleOverrides[tool.id]?.en ?? ""}`,
      run: () => setActiveTool(tool.id)
    }));
    const actionCommands: AppCommand[] = [
      {
        id: "action:settings",
        group: t.commandGroupActions,
        label: t.openSettings,
        hint: t.settings,
        meta: t.commandGroupActions,
        keywords: "settings preference 设置 主题",
        run: () => openSettingsPanel()
      },
      {
        id: "action:sidebar",
        group: t.commandGroupActions,
        label: t.toggleSidebarCommand,
        hint: sidebarCollapsed ? t.expandSidebar : t.collapseSidebar,
        meta: "Ctrl/⌘ B",
        keywords: "sidebar collapse expand navigation nav 侧栏 折叠 展开",
        run: () => setSidebarCollapsed(!sidebarCollapsed)
      },
      {
        id: "action:details",
        group: t.commandGroupActions,
        label: t.toggleDetailsCommand,
        hint: detailsToggleLabel,
        meta: "Ctrl/⌘ .",
        keywords: "details compact advanced detailed 精简 详细",
        run: () => {
          if (activeTool !== "home") setDetailsExpanded(!detailsExpanded);
        }
      },
      {
        id: "action:clear",
        group: t.commandGroupActions,
        label: t.clearWorkspace,
        hint: t.localCache,
        meta: "localStorage",
        keywords: "clear reset cache localStorage 清空 缓存",
        run: () => {
          clearForensicsStorage();
          setRecentTools([]);
          setFavoriteTools([]);
          setQuery("");
          setActiveTool("home");
        }
      },
      {
        id: "theme:dark",
        group: t.commandGroupActions,
        label: t.themeDarkCommand,
        hint: t.themeMode,
        meta: t.themeMode,
        keywords: "theme dark 黑暗",
        run: () => setThemeMode("dark")
      },
      {
        id: "theme:light",
        group: t.commandGroupActions,
        label: t.themeLightCommand,
        hint: t.themeMode,
        meta: t.themeMode,
        keywords: "theme light 明亮",
        run: () => setThemeMode("light")
      },
      {
        id: "theme:auto",
        group: t.commandGroupActions,
        label: t.themeAutoCommand,
        hint: t.themeMode,
        meta: t.themeMode,
        keywords: "theme auto system follow 系统 自动",
        run: () => setThemeMode("auto")
      }
    ];
    return [...actionCommands, ...toolCommands];
  }, [activeTool, detailsExpanded, detailsToggleLabel, lang, openSettingsPanel, sidebarCollapsed, t]);

  const filteredCommands = React.useMemo(() => {
    const value = commandQuery.trim().toLowerCase();
    if (!value) return commands;
    return commands.filter((command) => [command.label, command.hint, command.keywords].join(" ").toLowerCase().includes(value));
  }, [commandQuery, commands]);

  React.useEffect(() => {
    const handleKeydown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        openCommandPalette();
        return;
      }
      const target = event.target as HTMLElement | null;
      const isEditableTarget = Boolean(target?.closest("input, textarea, select, [contenteditable='true']"));
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "b" && !isEditableTarget) {
        event.preventDefault();
        setSidebarCollapsed((value) => !value);
        return;
      }
      if ((event.metaKey || event.ctrlKey) && event.key === "." && !isEditableTarget && activeTool !== "home") {
        event.preventDefault();
        setDetailsExpanded((value) => !value);
        return;
      }
      if (event.key === "Escape" && commandOpen) {
        setCommandOpen(false);
        return;
      }
      if (event.key === "Escape" && settingsOpen) {
        setSettingsOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeydown);
    return () => window.removeEventListener("keydown", handleKeydown);
  }, [activeTool, commandOpen, openCommandPalette, settingsOpen]);

  const applyThemeColor = (hex: string) => {
    const normalized = normalizeHexColor(hex);
    if (!normalized) return;
    setThemeColor(normalized);
  };

  const resetThemeAppearance = () => {
    const fallback = themePresets[0].hex;
    setThemeColor(fallback);
  };

  const clearLocalWorkspace = () => {
    if (!cacheClearArmed) {
      setCacheClearArmed(true);
      return;
    }
    clearForensicsStorage();
    window.location.hash = "#home";
    window.location.reload();
  };

  const copyCurrentToolLink = () => {
    const url = `${window.location.origin}${window.location.pathname}${window.location.search}#${activeTool}`;
    if (navigator.clipboard?.writeText) {
      void navigator.clipboard.writeText(url)
        .then(() => setToolLinkMessage(t.toolLinkCopied))
        .catch(() => setToolLinkMessage(url));
      return;
    }
    setToolLinkMessage(url);
  };

  return (
    <ConfigProvider
      button={{ autoInsertSpace: false }}
      theme={{
        algorithm: appliedTheme === "dark" ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
        cssVar: { key: "forensicspp" },
        token: {
          colorPrimary: displayThemeColor,
          colorTextLightSolid: appliedTheme === "dark" ? "#0f1822" : "#ffffff",
          borderRadius: 6,
          fontFamily: "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans SC', sans-serif",
          fontSize: 14,
          controlHeight: 38,
          controlHeightSM: 34,
          colorBgContainer: appliedTheme === "dark" ? "#182330" : "#ffffff",
          colorBgElevated: appliedTheme === "dark" ? "#182330" : "#ffffff",
          colorBgLayout: appliedTheme === "dark" ? "#0f1722" : "#f5f7fa",
          colorBorder: appliedTheme === "dark" ? "#2e4154" : "#d8e0e8",
          colorText: appliedTheme === "dark" ? "#e7edf5" : "#162130",
          colorTextSecondary: appliedTheme === "dark" ? "#a6b8ca" : "#66768a"
        },
        components: {
          Button: {
            borderRadius: 6,
            controlHeight: 38,
            controlHeightSM: 34,
            defaultBorderColor: appliedTheme === "dark" ? "#2e4154" : "#d8e0e8",
            defaultColor: appliedTheme === "dark" ? "#e7edf5" : "#162130",
            defaultBg: appliedTheme === "dark" ? "#182330" : "#ffffff"
          },
          Input: {
            borderRadius: 6,
            activeBorderColor: displayThemeColor,
            hoverBorderColor: displayThemeColor
          },
          Segmented: {
            trackBg: appliedTheme === "dark" ? "#182330" : "#f3f6fa",
            itemColor: appliedTheme === "dark" ? "#a6b8ca" : "#617285",
            itemHoverColor: appliedTheme === "dark" ? "#e7edf5" : "#162130",
            itemHoverBg: appliedTheme === "dark" ? "rgba(255,255,255,0.04)" : "#ffffff",
            itemSelectedBg: appliedTheme === "dark" ? "rgba(255,255,255,0.06)" : "#ffffff",
            itemSelectedColor: appliedTheme === "dark" ? "#e7edf5" : "#162130"
          },
          Card: {
            borderRadiusLG: 8
          },
          Modal: {
            borderRadiusLG: 10
          }
        }
      }}
    >
    <div
      className={[
        "workbench-shell",
        acceptedLegalVersion !== legalVersion ? "consent-active" : "",
        settingsOpen || commandOpen ? "overlay-open" : "",
        sidebarCollapsed ? "sidebar-collapsed" : "",
        isNarrowShell ? "shell-narrow" : ""
      ].filter(Boolean).join(" ")}
    >
      <a className="skip-link" href="#main-content">
        {t.skipToContent}
      </a>
      <aside
        className="tool-sidebar"
        aria-hidden={sidebarCollapsed && !isNarrowShell ? true : undefined}
        inert={sidebarCollapsed && !isNarrowShell ? true : undefined}
      >
        <div className="sidebar-inner">
        <div className="sidebar-head">
          <a className="brand" href="#home" title="Forensics++">
            <span>F++</span>
            <strong>{t.product}</strong>
            <small>{t.subtitle}</small>
          </a>
          <button
            className="sidebar-toggle"
            type="button"
            aria-label={sidebarCollapsed ? t.expandSidebar : t.collapseSidebar}
            title={sidebarCollapsed ? t.expandSidebar : t.collapseSidebar}
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          >
            {sidebarCollapsed ? <MenuUnfoldOutlined aria-hidden="true" /> : <MenuFoldOutlined aria-hidden="true" />}
          </button>
        </div>
        {!sidebarCollapsed && (
          <>
            <ATextField
              className="tool-search"
              variant="outlined"
              type="search"
              clearable
              placeholder={t.search}
              value={query}
              aria-label={t.search}
              onChange={(event) => setQuery(event.currentTarget.value)}
            />
            <nav className="tool-nav" aria-label={t.toolDirectory}>
              {favoriteNavTools.length ? (
                <AList className="favorite-tool-section tool-nav-list">
                  <AListSubheader>{t.favoriteTools}</AListSubheader>
                  {favoriteNavTools.map((tool) => (
                    <AListItem
                      className={tool.id === activeTool ? "active favorite-tool-item" : "favorite-tool-item"}
                      key={`favorite-${tool.id}`}
                      rounded
                      active={tool.id === activeTool}
                      description={t[tool.category]}
                      description-line={1}
                      title={`${getToolTitle(tool, lang)} - ${t[tool.desc]}`}
                      aria-current={tool.id === activeTool ? "page" : undefined}
                      onClick={() => setActiveTool(tool.id)}
                    >
                      {getToolTitle(tool, lang)}
                    </AListItem>
                  ))}
                </AList>
              ) : null}
              {groupedTools.map((group) => (
                <AList className="tool-nav-list" key={group.category}>
                  <AListSubheader>{t[group.category]}</AListSubheader>
                  {group.items.map((tool) => (
                    <AListItem
                      className={tool.id === activeTool ? "active" : ""}
                      key={tool.id}
                      rounded
                      active={tool.id === activeTool}
                      description={t[tool.category]}
                      description-line={1}
                      title={`${t[tool.name]} - ${t[tool.desc]}`}
                      aria-current={tool.id === activeTool ? "page" : undefined}
                      onClick={() => setActiveTool(tool.id)}
                    >
                      {t[tool.name]}
                    </AListItem>
                  ))}
                </AList>
              ))}
              {!groupedTools.length && <div className="nav-empty">{t.noToolMatches}</div>}
            </nav>
          </>
        )}
        <div className="sidebar-footer">
          <AButton variant="outlined" aria-label={t.openCommandPalette} title={t.openCommandPalette} onClick={openCommandPalette}>
            <CodeOutlined className="sidebar-action-icon" aria-hidden="true" />
            <strong>{t.openCommandPalette}</strong>
          </AButton>
          <AButton variant="outlined" aria-label={t.settings} onClick={() => openSettingsPanel()}>
            <SettingOutlined className="sidebar-action-icon" aria-hidden="true" />
            <strong>{t.settings}</strong>
          </AButton>
        </div>
        </div>
      </aside>

      <main className="tool-main" id="main-content" tabIndex={-1}>
        <header className={`tool-topbar ${activeTool === "home" ? "home-topbar" : ""}`}>
          <div className="tool-topbar-frame">
            <button
              className="top-action-icon top-menu-toggle"
              type="button"
              aria-label={sidebarCollapsed ? t.expandSidebar : t.collapseSidebar}
              title={sidebarCollapsed ? t.expandSidebar : t.collapseSidebar}
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            >
              {sidebarCollapsed ? <MenuUnfoldOutlined aria-hidden="true" /> : <MenuFoldOutlined aria-hidden="true" />}
            </button>
            <div className="tool-title-block">
              <span className="tool-kicker">{t[active.category]}</span>
              <strong className="page-title">{getToolTitle(active, lang)}</strong>
              <span className="tool-subtitle">{t[active.desc]}</span>
              {toolLinkMessage && <span className="tool-link-feedback">{toolLinkMessage}</span>}
            </div>
            <div className="top-actions">
              <div className="top-action-group">
                <GithubIconButton label={t.repositoryLabel} />
                {activeTool !== "home" && (
                  <button
                    className="top-action-icon link-toggle"
                    type="button"
                    aria-label={t.copyToolLink}
                    title={t.copyToolLink}
                    onClick={copyCurrentToolLink}
                  >
                    <LinkOutlined aria-hidden="true" />
                  </button>
                )}
                <button
                  className="top-action-icon settings-toggle"
                  type="button"
                  aria-label={t.settings}
                  title={t.settings}
                  onClick={() => openSettingsPanel()}
                >
                  <SettingOutlined aria-hidden="true" />
                </button>
                <button
                  className="top-action-icon command-toggle"
                  type="button"
                  aria-label={t.openCommandPalette}
                  title={t.openCommandPalette}
                  onClick={openCommandPalette}
                >
                  <CodeOutlined aria-hidden="true" />
                </button>
              </div>
              <ASegmentedGroup className="language-switch" value={lang} selects="single" aria-label={t.language}>
                <ASegmentedButton value="zh" onClick={() => setLang("zh")}>
                  中文
                </ASegmentedButton>
                <ASegmentedButton value="en" onClick={() => setLang("en")}>
                  EN
                </ASegmentedButton>
              </ASegmentedGroup>
            </div>
          </div>
        </header>

        <section className={detailsExpanded || activeTool === "home" ? "tool-body" : "tool-body compact-results"}>
          {activeTool === "home" ? (
            <HomeTool
              t={t}
              lang={lang}
              recentTools={recentTools}
              setActiveTool={setActiveTool}
            />
          ) : (
            <ToolWorkspaceFrame>
              <React.Suspense fallback={(
                <div className="tool-loading-state" role="status" aria-live="polite">
                  <Spin size="small" />
                  <span>{t.loadingTool}</span>
                </div>
              )}>
              {activeTool === "cyberchef" && <CyberChefTool t={t} />}
              {activeTool === "image" && <ImageTool t={t} services={imageToolServices} />}
              {activeTool === "codec" && <CodecTool t={t} services={codecToolServices} />}
              {activeTool === "crypto" && <CryptoTool t={t} services={cryptoToolServices} />}
              {activeTool === "jwt" && <JwtTool t={t} services={jwtToolServices} />}
              {activeTool === "password" && <PasswordTool t={t} services={passwordToolServices} />}
              {activeTool === "sql" && <SqlTool t={t} />}
              {activeTool === "sqlite" && <SqliteTool t={t} />}
              {activeTool === "android" && <AndroidManifestTool t={t} services={androidManifestToolServices} />}
              {activeTool === "ioc" && <IocTool t={t} />}
              {activeTool === "email" && <EmailTool t={t} />}
              {activeTool === "urltool" && <UrlTool t={t} />}
              {activeTool === "http" && <HttpTool t={t} />}
              {activeTool === "qr" && <QrTool t={t} services={qrToolServices} />}
              {activeTool === "fileid" && <FileIdTool t={t} />}
              {activeTool === "png" && <PngTool t={t} services={pngToolServices} />}
              {activeTool === "archive" && <ArchiveTool t={t} />}
              {activeTool === "binary" && <BinaryTool t={t} services={binaryToolServices} />}
              {activeTool === "windows" && <WindowsArtifactTool t={t} services={windowsArtifactToolServices} />}
              {activeTool === "strings" && <StringsTool t={t} services={stringsToolServices} />}
              {activeTool === "entropy" && <EntropyTool t={t} services={entropyToolServices} />}
              {activeTool === "hash" && <HashTool t={t} services={hashToolServices} />}
              {activeTool === "timestamp" && <TimestampTool t={t} />}
              {activeTool === "timeline" && <TimelineTool t={t} />}
              {activeTool === "baseconvert" && <BaseConvertTool t={t} />}
              {activeTool === "uuid" && <UuidTool t={t} />}
              {activeTool === "json" && (
                <JsonTool
                  t={t}
                  analyzeIocs={analyzeIocs}
                  parseTimestampCandidates={parseTimestampCandidates}
                  decodeBase64Url={base64UrlDecode}
                  decodeBase64Loose={base64DecodeLoose}
                />
              )}
              {activeTool === "regex" && <RegexTool t={t} classifyIocRisk={iocRisk} />}
              {activeTool === "pcap" && <PcapTool t={t} />}
              {activeTool === "yara" && <YaraTool t={t} services={getYaraToolServices()} />}
              </React.Suspense>
            </ToolWorkspaceFrame>
          )}
          {acceptedLegalVersion !== legalVersion && activeTool === "home" && (
            <div className="consent-inline-panel" role="status" aria-live="polite" aria-labelledby="legal-consent-title">
              <div className="consent-inline-copy">
                <strong id="legal-consent-title">{t.legalNoticeTitle}</strong>
                <span>{t.legalNoticeBody}</span>
              </div>
              <div className="consent-actions">
                <AButton href="/legal.html" target="_blank" variant="outlined">
                  {t.viewFullTerms}
                </AButton>
                <AButton variant="filled" onClick={() => setAcceptedLegalVersion(legalVersion)}>
                  {t.acceptTerms}
                </AButton>
              </div>
            </div>
          )}
        </section>
      </main>

      <SettingsModal
        open={settingsOpen}
        lang={lang}
        t={t}
        themeMode={themeMode}
        themeColor={resolvedThemeColor}
        cacheClearArmed={cacheClearArmed}
        onClose={() => setSettingsOpen(false)}
        onThemeModeChange={setThemeMode}
        onThemeColorChange={applyThemeColor}
        onResetAppearance={resetThemeAppearance}
        onClearWorkspace={clearLocalWorkspace}
      />
      {commandOpen && (
        <CommandPalette
          t={t}
          query={commandQuery}
          commands={filteredCommands}
          onQueryChange={setCommandQuery}
          onClose={() => setCommandOpen(false)}
          shouldIgnoreBackdropClose={() => shouldIgnoreBackdropClick("command")}
          onRun={(command) => {
            command.run();
            setCommandOpen(false);
            setCommandQuery("");
          }}
        />
      )}
    </div>
    </ConfigProvider>
  );
}
