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

export function downloadTextFile(filename: string, content: string, type = "text/markdown;charset=utf-8") {
  downloadBlob(filename, new Blob([content], { type }));
}

export function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function formatBytes(bytes: number) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}

export function archiveExtension(name: string) {
  const base = name.split(/[\\/]/).pop() ?? name;
  const index = base.lastIndexOf(".");
  return index >= 0 ? base.slice(index + 1).toLowerCase() : "";
}

export function limitReportText(value: string, max = 6000) {
  const normalized = value.replace(/\u00a0/g, " ").replace(/[ \t]+\n/g, "\n").trim();
  return normalized.length > max ? `${normalized.slice(0, max)}\n\n[truncated ${normalized.length - max} chars]` : normalized;
}

export function markdownEscapeCell(value: string) {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, "<br>");
}

function tableToMarkdown(table: HTMLTableElement) {
  const rows = Array.from(table.rows).map((row) => Array.from(row.cells).map((cell) => markdownEscapeCell(limitReportText(cell.textContent ?? "", 900))));
  if (!rows.length) return "";
  const width = Math.max(...rows.map((row) => row.length));
  const normalized = rows.map((row) => [...row, ...Array.from({ length: width - row.length }, () => "")]);
  const [head, ...body] = normalized;
  return [
    `| ${head.join(" | ")} |`,
    `| ${Array.from({ length: width }, () => "---").join(" | ")} |`,
    ...body.map((row) => `| ${row.join(" | ")} |`)
  ].join("\n");
}

export function collectToolReportMarkdown(root: Element, title: string, description: string) {
  const sections: string[] = [`# ${title}`, "", description, ""].filter(Boolean);
  const panels = Array.from(root.querySelectorAll<HTMLElement>(".tool-panel, .sql-workbench, .sqlite-panel"));
  const targets = panels.length ? panels : [root as HTMLElement];
  const seen = new Set<string>();
  for (const panel of targets.slice(0, 40)) {
    const heading = panel.querySelector(".panel-title, h2, h3, .text-panel-title strong")?.textContent?.trim();
    const parts: string[] = [];
    for (const table of Array.from(panel.querySelectorAll("table")).slice(0, 4)) {
      const markdown = tableToMarkdown(table);
      if (markdown) parts.push(markdown);
    }
    for (const field of Array.from(panel.querySelectorAll("textarea, pre, .result-box, .finding-item, .empty-state")).slice(0, 12)) {
      const value = field instanceof HTMLTextAreaElement ? field.value : (field.textContent ?? "");
      const cleaned = limitReportText(value, 2400);
      if (cleaned && cleaned !== "--" && !seen.has(cleaned)) {
        seen.add(cleaned);
        parts.push(`\`\`\`text\n${cleaned}\n\`\`\``);
      }
    }
    if (!parts.length) {
      const text = limitReportText(panel.textContent ?? "", 1600);
      if (text && text !== heading && !seen.has(text)) {
        seen.add(text);
        parts.push(text);
      }
    }
    if (parts.length) sections.push(`## ${heading || "Panel"}`, "", parts.join("\n\n"), "");
  }
  return limitReportText(sections.join("\n"), 30000);
}
