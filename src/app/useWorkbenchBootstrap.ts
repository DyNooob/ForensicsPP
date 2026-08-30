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
import { getToolTitle as resolveToolTitle } from "../config/app";
import type { ToolDefinition, ToolId } from "../config/app";
import { copy } from "../i18n";
import { clearLegacyEvidenceStorage } from "../utils/storage";
import { setCopyToastLabel } from "../utils/clipboard";
import { rememberEvidenceFiles } from "../features/reporter/evidence";
import { captureEvidence } from "../core/evidence/inbox";
import type { Lang } from "../models";

function getToolTitle(tool: ToolDefinition, lang: Lang) {
  return resolveToolTitle(tool, lang, copy[lang]);
}

export function useWorkbenchBootstrap({
  active,
  activeTool,
  lang,
  detailsExpanded,
  setDetailsExpanded,
  toolLinkMessage,
  setToolLinkMessage,
}: {
  active: ToolDefinition;
  activeTool: ToolId;
  lang: Lang;
  detailsExpanded: boolean;
  setDetailsExpanded: React.Dispatch<React.SetStateAction<boolean>>;
  toolLinkMessage: string;
  setToolLinkMessage: React.Dispatch<React.SetStateAction<string>>;
}) {
  const t = copy[lang];
  React.useEffect(() => {
    clearLegacyEvidenceStorage();
  }, []);
  React.useEffect(() => {
    setCopyToastLabel(t.copyDone);
  }, [t]);
  // Keep a live ref to the active tool so the file-capture delegation below
  // (installed once with `[]` deps) can stamp each loaded file with the tool it
  // was loaded into without re-binding global listeners on every navigation.
  const activeToolRef = React.useRef(activeTool);
  React.useEffect(() => {
    activeToolRef.current = activeTool;
  }, [activeTool]);
  React.useEffect(() => {
    const rememberInputFiles = (event: Event) => {
      const target = event.target;
      if (target instanceof HTMLInputElement && target.type === "file" && target.files?.length) {
        rememberEvidenceFiles(target, target.files);
        captureEvidence(target.files, "upload", activeToolRef.current);
      }
    };
    const rememberDroppedFiles = (event: DragEvent) => {
      if (event.dataTransfer?.files.length) {
        rememberEvidenceFiles(event.target, event.dataTransfer.files);
        captureEvidence(event.dataTransfer.files, "drop", activeToolRef.current);
      }
    };
    document.addEventListener("change", rememberInputFiles, true);
    document.addEventListener("drop", rememberDroppedFiles, true);
    return () => {
      document.removeEventListener("change", rememberInputFiles, true);
      document.removeEventListener("drop", rememberDroppedFiles, true);
    };
  }, []);
  React.useEffect(() => {
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    document.title = activeTool === "home" ? "Forensics++ Workbench | Open-source DFIR tools" : `${getToolTitle(active, lang)} - Forensics++`;
  }, [active.name, activeTool, lang, t]);

  React.useEffect(() => {
    setDetailsExpanded(false);
  }, [activeTool]);

  React.useEffect(() => {
    if (!toolLinkMessage) return undefined;
    const timer = window.setTimeout(() => setToolLinkMessage(""), 2200);
    return () => window.clearTimeout(timer);
  }, [toolLinkMessage]);
}
