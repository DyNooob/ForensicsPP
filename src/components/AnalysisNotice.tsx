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
import { localizeAnalysisText, findingPresentation, severityLabel, type NoticeLevel, type PresentedFinding } from "../core/analysisPresentation";
import { getUiLang } from "../uiLang";
export function AnalysisNotice({ level, title, children, english = getUiLang() === "en" }: { level: NoticeLevel; title: string; children?: React.ReactNode; english?: boolean }) {
  return <div className={`analysis-notice finding-item ${level}`} data-severity={level}>
    <div className="analysis-notice-heading"><span className="analysis-severity">{severityLabel(level, english)}</span><strong>{title}</strong></div>
    {children && <div className="analysis-notice-body">{children}</div>}
  </div>;
}
export function FindingCard({ finding, english = getUiLang() === "en" }: { finding: PresentedFinding; english?: boolean }) {
  const item = findingPresentation(finding, english);
  return <AnalysisNotice level={item.level} title={item.title} english={english}>
    {item.explanation && item.explanation !== item.detail && <p>{item.explanation}</p>}
    {item.detail && <div className="analysis-evidence">{item.detail}</div>}
  </AnalysisNotice>;
}

export function WarningNotice({ text, level = "warn", english = getUiLang() === "en" }: { text: string; level?: NoticeLevel; english?: boolean }) {
  return <AnalysisNotice level={level} title={english ? (level === "info" ? "Analysis scope" : "Review required") : (level === "info" ? "分析范围说明" : "请关注此项")} english={english}>{localizeAnalysisText(text, english)}</AnalysisNotice>;
}

export function ErrorNotice({ message, english = getUiLang() === "en" }: { message: string; english?: boolean }) {
  const translated = localizeAnalysisText(message, english);
  const needsExplanation = !english && !/[\u3400-\u9fff]/.test(translated);
  return <div role="alert"><AnalysisNotice level="danger" title={english ? "Operation failed" : "操作未完成"} english={english}>
    {needsExplanation ? "当前操作未能完成，请检查输入格式、文件完整性或所选参数后重试。具体原因可查看下方原始错误信息。" : translated}
    {needsExplanation && <details className="analysis-error-detail"><summary>原始错误信息</summary><code>{message}</code></details>}
  </AnalysisNotice></div>;
}
