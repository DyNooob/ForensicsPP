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
import { useStoredState } from "../utils/storage";
import { compactReportText, defaultCaseReportMeta, isBooleanValue, isCaseNotesValue, isCaseReportMetaValue, isStringValue } from "../utils/appGuards";
import type { CaseNote, CaseReportMeta, Lang } from "../models";
import { fingerprintEvidenceFiles, rememberedEvidenceFiles } from "../features/reporter/evidence";
import { rememberedTimelineEvents } from "../features/reporter/timeline";
import { currentAnalysisResult, subscribeAnalysisResult } from "../features/analysis/resultStore";
import { analysisResultText, envelopeReportMarkdown } from "../features/analysis/result";

function getToolTitle(tool: ToolDefinition, lang: Lang) {
  return resolveToolTitle(tool, lang, copy[lang]);
}

export function useCaseReport({
  activeTool,
  active,
  lang,
  setReporterOpen,
  setToolLinkMessage,
}: {
  activeTool: ToolId;
  active: ToolDefinition;
  lang: Lang;
  setReporterOpen: React.Dispatch<React.SetStateAction<boolean>>;
  setToolLinkMessage: React.Dispatch<React.SetStateAction<string>>;
}) {
  const t = copy[lang];
  const [reportAddBusy, setReportAddBusy] = React.useState(false);
  const reportAddAbortRef = React.useRef<AbortController | null>(null);
  const [caseNotes, setCaseNotes] = useStoredState<CaseNote[]>("report.notes", [], isCaseNotesValue);
  const [caseReportMeta, setCaseReportMeta] = useStoredState<CaseReportMeta>("report.meta", defaultCaseReportMeta(), isCaseReportMetaValue);
  const [defaultExportFormat, setDefaultExportFormat] = useStoredState("app.defaultExportFormat", "md", isStringValue);
  const [autoSaveEvidence, setAutoSaveEvidence] = useStoredState("app.autoSaveEvidence", false, isBooleanValue);
  const capturedRunIds = React.useRef<Set<string>>(new Set());
  React.useEffect(() => () => {
    reportAddAbortRef.current?.abort();
  }, []);

  const addCurrentToolToReport = async () => {
    if (reportAddBusy) return;
    if (activeTool === "home") {
      setReporterOpen(true);
      return;
    }
    const toolView = Array.from(document.querySelectorAll<HTMLElement>(".tool-retained-view"))
      .find((element) => element.dataset.toolId === activeTool);
    const structuredResult = currentAnalysisResult(activeTool);
    if (structuredResult?.run.runId) capturedRunIds.current.add(structuredResult.run.runId);
    const structuredContent = structuredResult ? compactReportText(analysisResultText(structuredResult)) : "";
    const domContent = compactReportText(toolView?.innerText || toolView?.textContent || "");
    const content = structuredContent || domContent;
    const hasFilledControl = Boolean(toolView && Array.from(toolView.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(
      'input:not([type="file"]), textarea'
    )).some((control) => control.value.trim()));
    const hasLoadedFile = Boolean(toolView && Array.from(toolView.querySelectorAll<HTMLInputElement>('input[type="file"]'))
      .some((control) => Boolean(control.files?.length)));
    const hasRenderedOutput = Boolean(toolView && Array.from(toolView.querySelectorAll<HTMLElement>(
      "table tbody tr, pre, code, img, .tool-result, .result-panel, [data-report-output]"
    )).some((element) => {
      const rect = element.getBoundingClientRect();
      return !element.hidden && rect.width > 0 && rect.height > 0 && (element.textContent?.trim() || element.tagName === "IMG");
    }));
    if (!content || (!structuredResult && !hasFilledControl && !hasLoadedFile && !hasRenderedOutput)) {
      setReporterOpen(true);
      return;
    }
    setReportAddBusy(true);
    reportAddAbortRef.current?.abort();
    const controller = new AbortController();
    reportAddAbortRef.current = controller;
    try {
      const selectedFiles = Array.from(toolView?.querySelectorAll<HTMLInputElement>('input[type="file"]') ?? [])
        .flatMap((input) => Array.from(input.files ?? []));
      const fingerprintedFiles = await fingerprintEvidenceFiles([
        ...selectedFiles,
        ...(toolView ? rememberedEvidenceFiles(toolView) : [])
      ], { signal: controller.signal });
      if (controller.signal.aborted) return;
      const evidenceFiles = Array.from(new Map([
        ...(structuredResult?.source ?? []).map((file) => [`${file.name}:${file.size}`, {
          name: file.name,
          size: file.size,
          type: file.type,
          ...(file.lastModified ? { lastModified: file.lastModified } : {}),
          ...(file.sha256 ? { sha256: file.sha256 } : {})
        }] as const),
        ...fingerprintedFiles.map((file) => [`${file.name}:${file.size}`, file] as const)
      ]).values());
      const timelineEvents = structuredResult?.timeline.length
        ? structuredResult.timeline
        : toolView ? rememberedTimelineEvents(toolView) : [];
      const createdAt = new Date().toISOString();
      const note: CaseNote = {
        id: `${activeTool}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        tool: getToolTitle(active, lang),
        title: structuredResult?.summary.title || `${getToolTitle(active, lang)} · ${createdAt.slice(0, 10)}`,
        content,
        summary: structuredResult?.summary.text || content.replace(/\s+/g, " ").slice(0, 420),
        markdown: structuredResult
          ? envelopeReportMarkdown(structuredResult, t)
          : ["```text", content, "```"].join("\n"),
        description: t[active.desc],
        route: `#${activeTool}`,
        sourceUrl: window.location.href,
        ...(evidenceFiles.length ? { evidenceFiles } : {}),
        ...(timelineEvents.length ? { timelineEvents } : {}),
        ...(structuredResult?.findings.length ? { findings: structuredResult.findings } : {}),
        ...(structuredResult?.indicators.length ? { indicators: structuredResult.indicators } : {}),
        ...(structuredResult?.artifacts.length ? { artifacts: structuredResult.artifacts } : {}),
        createdAt
      };
      setCaseNotes((current) => [note, ...current].slice(0, 40));
      setReporterOpen(true);
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) {
        setToolLinkMessage(t.reportAddFailed);
      }
    } finally {
      if (reportAddAbortRef.current === controller) {
        reportAddAbortRef.current = null;
        setReportAddBusy(false);
      }
    }
  };

  const updateCaseNote = (id: string, patch: Partial<CaseNote>) => {
    setCaseNotes((current) => current.map((note) => note.id === id ? { ...note, ...patch } : note));
  };
  const deleteCaseNote = (id: string) => {
    setCaseNotes((current) => current.filter((note) => note.id !== id));
  };
  const clearCaseNotes = () => setCaseNotes([]);
  React.useEffect(() => {
    if (!autoSaveEvidence) return;
    const unsubscribe = subscribeAnalysisResult("*", () => {
      const result = currentAnalysisResult(activeTool);
      const runId = result?.run.runId;
      if (!result || !runId || capturedRunIds.current.has(runId)) return;
      capturedRunIds.current.add(runId);
      const createdAt = new Date().toISOString();
      const note: CaseNote = {
        id: `${activeTool}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        tool: getToolTitle(active, lang),
        title: result.summary.title,
        content: analysisResultText(result, t),
        summary: result.summary.text,
        markdown: envelopeReportMarkdown(result, t),
        description: active ? t[active.desc] : "",
        route: `#${activeTool}`,
        sourceUrl: window.location.href,
        ...(result.source.length ? {
          evidenceFiles: result.source.map((file) => ({
            name: file.name,
            size: file.size,
            type: file.type,
            ...(file.lastModified ? { lastModified: file.lastModified } : {}),
            ...(file.sha256 ? { sha256: file.sha256 } : {})
          }))
        } : {}),
        ...(result.timeline.length ? { timelineEvents: result.timeline } : {}),
        ...(result.findings.length ? { findings: result.findings } : {}),
        ...(result.indicators.length ? { indicators: result.indicators } : {}),
        ...(result.artifacts.length ? { artifacts: result.artifacts } : {}),
        createdAt
      };
      setCaseNotes((current) => [note, ...current].slice(0, 40));
    });
    return unsubscribe;
  }, [autoSaveEvidence, activeTool, lang, t, active, setCaseNotes]);

  return {
    reportAddBusy,
    reportAddAbortRef,
    setReportAddBusy,
    caseNotes,
    setCaseNotes,
    caseReportMeta,
    setCaseReportMeta,
    defaultExportFormat,
    setDefaultExportFormat,
    autoSaveEvidence,
    setAutoSaveEvidence,
    addCurrentToolToReport,
    updateCaseNote,
    deleteCaseNote,
    clearCaseNotes,
  };
}
