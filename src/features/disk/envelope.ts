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
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import { appVersion } from "../../config/app";
import type { CaseEvidenceFile } from "../../models";
import type { AnalysisArtifact, AnalysisEnvelope, AnalysisFinding, AnalysisLimitation } from "../analysis/result";
import type { DiskAnalysis } from "./analyzer";

export type DiskEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
};

const DELETED_ENTRY_CAP = 200;

/**
 * Map a disk-image analysis to a unified AnalysisEnvelope (beta.6 P0-2).
 *
 * The workbench reads partitions and root directories randomly (the whole
 * image is never loaded), so the envelope summarizes the partition map and
 * any deleted entries discovered in directory listings.
 */
export function buildDiskImageEnvelope(analysis: DiskAnalysis, meta: DiskEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const partitions = analysis.partitions ?? [];
  const fileSystems = Array.from(new Set(partitions.map((partition) => partition.filesystem).filter(Boolean)));
  const deletedEntries = partitions.flatMap((partition) => partition.entries.filter((entry) => entry.deleted));
  const bootable = partitions.filter((partition) => partition.bootable);

  const findings: AnalysisFinding[] = [];
  for (const warning of analysis.warnings) {
    findings.push({ level: "warn", title: "Disk analysis warning", detail: warning, category: "disk-warning", confidence: "medium" });
  }
  if (deletedEntries.length > 0) {
    findings.push({
      level: "info",
      title: "Deleted entries found",
      detail: `${deletedEntries.length} deleted file/directory entry(ies) found in partition root listings; recoverable via carving.`,
      category: "disk-deleted",
      confidence: "medium"
    });
  }
  if (bootable.length > 0) {
    findings.push({
      level: "info",
      title: "Bootable partition",
      detail: `${bootable.length} bootable partition(s): ${bootable.map((partition) => partition.name || partition.type).join(", ")}.`,
      category: "disk-boot",
      confidence: "high"
    });
  }

  const artifacts: AnalysisArtifact[] = [
    ...partitions.map((partition, index) => ({
      id: `partition-${index}`,
      label: `${partition.scheme} #${partition.index} · ${partition.filesystem || partition.type}`,
      kind: "partition",
      offset: partition.startOffset,
      size: partition.size,
      confidence: "high" as const
    })),
    ...deletedEntries.slice(0, DELETED_ENTRY_CAP).map((entry, index) => ({
      id: `deleted-${index}`,
      label: `Deleted: ${entry.name}`,
      kind: "deleted-entry",
      size: entry.size,
      confidence: "medium" as const
    }))
  ];

  const limitations: AnalysisLimitation[] = [
    { code: "DISK_RANDOM_ACCESS", detail: "Partitions and root directories are read randomly; the whole image is not loaded into memory. Deep file recovery requires carving tools." }
  ];

  const source: CaseEvidenceFile = {
    name: analysis.name,
    size: analysis.size,
    type: "application/octet-stream",
    lastModified: ""
  };

  return {
    schemaVersion: "1",
    id: `disk-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "disk", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { scheme: analysis.scheme, sectorSize: analysis.sectorSize } },
    summary: {
      title: "Disk image analysis",
      text: `${analysis.scheme} scheme, ${partitions.length} partition(s), ${fileSystems.join("/") || "unknown"} filesystem(s).`,
      metrics: [
        { label: "Scheme", value: analysis.scheme },
        { label: "Sector size", value: `${analysis.sectorSize} B` },
        { label: "Size", value: `${analysis.size} B` },
        { label: "Partitions", value: String(partitions.length) },
        { label: "Filesystems", value: fileSystems.join(", ") || "--" },
        { label: "Deleted entries", value: String(deletedEntries.length) }
      ]
    },
    findings: findings.map((f) => ({ ...f, code: f.code ?? f.category ?? "disk.finding" })),
    indicators: [],
    artifacts,
    timeline: [],
    limitations,
    data: {
      scheme: analysis.scheme,
      sectorSize: analysis.sectorSize,
      partitionCount: partitions.length,
      fileSystems,
      deletedEntryCount: deletedEntries.length
    }
  };
}
