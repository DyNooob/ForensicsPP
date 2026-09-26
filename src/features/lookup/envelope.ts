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

import { appVersion } from "../../config/app";
import type { AnalysisEnvelope, AnalysisFinding } from "../analysis/result";
import type { LookupKind, LookupResult } from "./rules";

export function buildLookupEnvelope(
  results: LookupResult[],
  options: { lang: "zh" | "en"; kind: LookupKind; startedAt: string; completedAt?: string }
): AnalysisEnvelope<LookupResult[]> {
  const zh = options.lang === "zh";
  const valid = results.filter((result) => result.valid).length;
  const matched = results.filter((result) => result.matched).length;
  const invalid = results.length - valid;
  const unmatched = results.filter((result) => result.valid && !result.matched).length;

  return {
    schemaVersion: "1",
    id: `lookup-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "lookup", version: appVersion },
    source: [],
    run: {
      startedAt: options.startedAt,
      completedAt: options.completedAt ?? new Date().toISOString(),
      parameters: { mode: options.kind, count: results.length, localOnly: true }
    },
    summary: {
      title: zh ? "归属地与规则核验" : "Attribution and rule checks",
      text: zh
        ? `完成 ${results.length} 条查询：${matched} 条数据命中，${unmatched} 条规则通过但库未命中，${invalid} 条规则未通过。`
        : `Completed ${results.length} lookup(s): ${matched} data match(es), ${unmatched} rule-valid value(s) without a data match, and ${invalid} invalid value(s).`,
      metrics: [
        { label: zh ? "总数" : "Total", value: String(results.length) },
        { label: zh ? "规则通过" : "Rule-valid", value: String(valid) },
        { label: zh ? "数据命中" : "Data matches", value: String(matched) },
        { label: zh ? "规则未通过" : "Invalid", value: String(invalid) }
      ]
    },
    findings: results.flatMap<AnalysisFinding>((result, index) => {
      if (!result.valid) {
        return [{
          id: `lookup-invalid-${index}`,
          code: `lookup.${result.kind}.invalid`,
          level: "warn",
          title: zh ? `${result.kind.toUpperCase()} 规则未通过` : `${result.kind.toUpperCase()} rule check failed`,
          detail: `${result.normalized || result.input}: ${result.summary}`,
          category: "lookup-validation",
          confidence: "high" as const
        }];
      }
      if (!result.matched) {
        return [{
          id: `lookup-unmatched-${index}`,
          code: `lookup.${result.kind}.unmatched`,
          level: "info",
          title: zh ? "规则通过，静态库未命中" : "Rule-valid; static pack not matched",
          detail: `${result.normalized}: ${result.summary}`,
          category: "lookup-coverage",
          review: true,
          confidence: "medium" as const
        }];
      }
      return [];
    }),
    indicators: results
      .filter((result) => result.kind === "ip" || result.kind === "phone")
      .map((result) => ({
        type: result.kind === "ip" ? "ip" : "phone",
        value: result.input,
        normalized: result.normalized,
        source: result.source,
        context: result.summary
      })),
    artifacts: [],
    timeline: [],
    limitations: [
      {
        code: "lookup.static_snapshot",
        detail: zh
          ? "数据为固定版本快照。号段、携号转网、行政区划和 IP 分配变化可能导致结果滞后。"
          : "Attribution comes from pinned static snapshots and can become stale as prefixes, portability, divisions, or IP allocation change."
      },
      {
        code: "lookup.not_identity_verification",
        detail: zh
          ? "规则校验范围不包含号码分配状态、账户状态和身份真实性。"
          : "A passing rule check only confirms structure, date, or check digits; it does not prove assignment, account existence, or holder identity."
      },
      {
        code: "lookup.not_live_location",
        detail: zh
          ? "IP、手机号与银行卡 BIN 数据不提供设备、人员或开户支行的实时位置。"
          : "IP, phone-prefix, and BIN attribution is not the live location of a device, person, or account branch."
      }
    ],
    data: results
  };
}
