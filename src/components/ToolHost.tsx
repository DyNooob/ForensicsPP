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
import { Spin } from "antd";
import { ToolWorkspaceFrame } from "./ui";
import { ToolErrorBoundary } from "./ToolErrorBoundary";
import { toolRuntimeRegistry } from "./toolRuntimeRegistry";
import type { ToolId } from "../config/app";
import type { Lang } from "../models";
import { copy } from "../i18n";

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
  const renderTool = toolRuntimeRegistry[toolId];
  const content = renderTool({ t, lang, active, recentTools, setActiveTool, onDirtyChange: handleDirtyChange });
  return (
    <div className="tool-retained-view" data-tool-id={toolId} hidden={!active}>
      <ToolErrorBoundary title={t.toolErrorTitle} detail={t.toolErrorDetail} retryLabel={t.retryTool}>
        {toolId === "home" ? (
          <React.Suspense fallback={<div className="tool-loading-state" role="status" aria-live="polite"><Spin size="small" /><span>{t.loadingTool}</span></div>}>
            {content}
          </React.Suspense>
        ) : (
          <ToolWorkspaceFrame>
            <React.Suspense fallback={<div className="tool-loading-state" role="status" aria-live="polite"><Spin size="small" /><span>{t.loadingTool}</span></div>}>
              {content}
            </React.Suspense>
          </ToolWorkspaceFrame>
        )}
      </ToolErrorBoundary>
    </div>
  );
}
