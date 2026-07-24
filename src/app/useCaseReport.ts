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
import { useStoredState } from "../utils/storage";
import { compactReportText, defaultCaseReportMeta, isCaseNotesValue, isCaseReportMetaValue } from "../utils/appGuards";
import { fingerprintEvidenceFiles, rememberedEvidenceFiles } from "../features/reporter/evidence";
import { rememberedTimelineEvents } from "../features/reporter/timeline";
import { tools } from "../config/app";
import { getToolTitle } from "./toolTitle";
import type { CaseNote, CaseReportMeta, Lang } from "../models";
import type { Translation } from "../i18n";
import type { ToolId } from "../config/app";

type SetBool = (value: boolean | ((previous: boolean) => boolean)) => void;

interface ReportBundle {
  notes: CaseNote[];
  meta: CaseReportMeta;
}

export function useCaseReport(
  activeTool: ToolId,
  lang: Lang,
  t: Translation,
  setReporterOpen: SetBool,
  setToolLinkMessage: (message: string) => void
) {
  const [caseNotes, setCaseNotes] = useStoredState<CaseNote[]>("report.notes", [], isCaseNotesValue);
  const [caseReportMeta, setCaseReportMeta] = useStoredState<CaseReportMeta>("report.meta", defaultCaseReportMeta(), isCaseReportMetaValue);
  const [reportAddBusy, setReportAddBusy] = React.useState(false);
  const reportAddAbortRef = React.useRef<AbortController | null>(null);

  React.useEffect(() => () => {
    reportAddAbortRef.current?.abort();
  }, []);

  const addCurrentToolToReport = React.useCallback(async () => {
    if (reportAddBusy) return;
    if (activeTool === "home") {
      setReporterOpen(true);
      return;
    }
    const active = tools.find((tool) => tool.id === activeTool) ?? tools[0];
    const toolView = Array.from(document.querySelectorAll<HTMLElement>(".tool-retained-view"))
      .find((element) => element.dataset.toolId === activeTool);
    const content = compactReportText(toolView?.innerText || toolView?.textContent || "");
    const hasFilledControl = Boolean(
      toolView &&
        Array.from(toolView.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('input:not([type="file"]), textarea')).some(
          (control) => control.value.trim()
        )
    );
    const hasLoadedFile = Boolean(
      toolView && Array.from(toolView.querySelectorAll<HTMLInputElement>('input[type="file"]')).some((control) => Boolean(control.files?.length))
    );
    const hasRenderedOutput = Boolean(
      toolView &&
        Array.from(
          toolView.querySelectorAll<HTMLElement>("table tbody tr, pre, code, img, .tool-result, .result-panel, [data-report-output]")
        ).some((element) => {
          const rect = element.getBoundingClientRect();
          return !element.hidden && rect.width > 0 && rect.height > 0 && (element.textContent?.trim() || element.tagName === "IMG");
        })
    );
    if (!content || (!hasFilledControl && !hasLoadedFile && !hasRenderedOutput)) {
      setReporterOpen(true);
      return;
    }
    setReportAddBusy(true);
    reportAddAbortRef.current?.abort();
    const controller = new AbortController();
    reportAddAbortRef.current = controller;
    try {
      const selectedFiles = Array.from(toolView?.querySelectorAll<HTMLInputElement>('input[type="file"]') ?? []).flatMap((input) =>
        Array.from(input.files ?? [])
      );
      const evidenceFiles = await fingerprintEvidenceFiles(
        [...selectedFiles, ...(toolView ? rememberedEvidenceFiles(toolView) : [])],
        { signal: controller.signal }
      );
      if (controller.signal.aborted) return;
      const timelineEvents = toolView ? rememberedTimelineEvents(toolView) : [];
      const createdAt = new Date().toISOString();
      const note: CaseNote = {
        id: `${activeTool}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        tool: getToolTitle(active, lang),
        title: `${getToolTitle(active, lang)} · ${createdAt.slice(0, 10)}`,
        content,
        summary: content.replace(/\s+/g, " ").slice(0, 420),
        markdown: ["```text", content, "```"].join("\n"),
        description: t[active.desc],
        route: `#${activeTool}`,
        sourceUrl: window.location.href,
        ...(evidenceFiles.length ? { evidenceFiles } : {}),
        ...(timelineEvents.length ? { timelineEvents } : {}),
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
  }, [activeTool, lang, reportAddBusy, setCaseNotes, setReporterOpen, setToolLinkMessage, t]);

  const updateCaseNote = React.useCallback(
    (id: string, patch: Partial<CaseNote>) => {
      setCaseNotes((current) => current.map((note) => (note.id === id ? { ...note, ...patch } : note)));
    },
    [setCaseNotes]
  );

  const deleteCaseNote = React.useCallback(
    (id: string) => {
      setCaseNotes((current) => current.filter((note) => note.id !== id));
    },
    [setCaseNotes]
  );

  const clearCaseNotes = React.useCallback(() => setCaseNotes([]), [setCaseNotes]);

  const importReport = React.useCallback(
    (bundle: ReportBundle) => {
      setCaseNotes(bundle.notes);
      setCaseReportMeta(bundle.meta);
    },
    [setCaseNotes, setCaseReportMeta]
  );

  const onReporterClose = React.useCallback(() => {
    reportAddAbortRef.current?.abort();
    reportAddAbortRef.current = null;
    setReportAddBusy(false);
    setReporterOpen(false);
  }, [setReporterOpen]);

  return {
    caseNotes,
    caseReportMeta,
    setCaseReportMeta,
    reportAddBusy,
    addCurrentToolToReport,
    updateCaseNote,
    deleteCaseNote,
    clearCaseNotes,
    importReport,
    onReporterClose
  };
}
