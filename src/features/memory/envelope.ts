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
import type { CaseEvidenceFile } from "../../models";
import type { AnalysisArtifact, AnalysisEnvelope, AnalysisFinding, AnalysisLimitation } from "../analysis/result";
import type { MemoryTriage } from "./analyzer";

export type MemoryEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
};

const PE_HIT_CAP = 200;

/**
 * Map a memory/minidump triage to a unified AnalysisEnvelope (beta.6 P0-2).
 *
 * Triage parses Minidump metadata and performs bounded PE-header discovery;
 * it is not a kernel-object parser, so the envelope summarizes modules,
 * discovered PE images, and the explicit scope warning.
 */
export function buildMemoryEnvelope(analysis: MemoryTriage, meta: MemoryEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const modules = analysis.modules ?? [];
  const peHits = analysis.peHits ?? [];
  const machines = Array.from(new Set(peHits.map((hit) => hit.machine).filter(Boolean)));

  const findings: AnalysisFinding[] = [];
  for (const warning of analysis.warnings) {
    findings.push({ level: "info", title: "Memory triage note", detail: warning, category: "memory-scope", confidence: "high" });
  }
  if (peHits.length > 0) {
    findings.push({
      level: "warn",
      title: "PE headers discovered",
      detail: `${peHits.length} PE image header(s) located in the dump${machines.length ? ` (architectures: ${machines.join(", ")})` : ""}; candidate injected/DLL material for follow-up extraction.`,
      category: "memory-pe",
      confidence: "medium"
    });
  }
  if (modules.length > 0) {
    findings.push({
      level: "info",
      title: "Loaded modules",
      detail: `${modules.length} module(s) enumerated from the minidump module list.`,
      category: "memory-modules",
      confidence: "high"
    });
  }

  const artifacts: AnalysisArtifact[] = peHits.slice(0, PE_HIT_CAP).map((hit, index) => ({
    id: `pe-${index}`,
    label: `PE header @ 0x${hit.offset.toString(16).toUpperCase()} (${hit.machine})`,
    kind: "pe-header",
    offset: hit.offset,
    size: hit.peOffset,
    confidence: "medium"
  }));

  const limitations: AnalysisLimitation[] = [
    { code: "MEMORY_TRIAGE_SCOPE", detail: "Triage parses Minidump metadata and performs bounded PE-header discovery; it is not a Volatility-compatible kernel-object parser." }
  ];

  const source: CaseEvidenceFile = {
    name: analysis.name,
    size: analysis.size,
    type: "application/octet-stream",
    lastModified: ""
  };

  return {
    schemaVersion: "1",
    id: `memory-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "memory", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { format: analysis.format } },
    summary: {
      title: "Memory / minidump triage",
      text: `${analysis.format} · ${modules.length} module(s), ${peHits.length} PE header(s) discovered.`,
      metrics: [
        { label: "Format", value: analysis.format },
        { label: "Size", value: `${analysis.size} B` },
        { label: "Modules", value: String(modules.length) },
        { label: "PE headers", value: String(peHits.length) }
      ]
    },
    findings: findings.map((f) => ({ ...f, code: f.code ?? f.category ?? "memory.finding" })),
    indicators: [],
    artifacts,
    timeline: [],
    limitations,
    data: {
      format: analysis.format,
      moduleCount: modules.length,
      peHitCount: peHits.length,
      machines
    }
  };
}
