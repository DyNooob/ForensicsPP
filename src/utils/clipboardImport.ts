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

export function filesFromClipboard(data: Pick<DataTransfer, "files" | "items"> | null): File[] {
  if (!data) return [];
  if (data.files.length) return Array.from(data.files);
  return Array.from(data.items).filter((item) => item.kind === "file").map((item) => item.getAsFile()).filter((file): file is File => Boolean(file));
}

export function acceptsClipboardFile(accept: string, file: Pick<File, "name" | "type">): boolean {
  if (!accept.trim()) return true;
  return accept.toLowerCase().split(",").map((part) => part.trim()).some((part) =>
    part === "*/*" || part.startsWith(".") && file.name.toLowerCase().endsWith(part) ||
    part.endsWith("/*") && file.type.toLowerCase().startsWith(part.slice(0, -1)) || part === file.type.toLowerCase()
  );
}

export async function readClipboardPayload(): Promise<{ files: File[]; text: string }> {
  if (!navigator.clipboard) throw new Error("unsupported");
  if (!navigator.clipboard.read) return { files: [], text: await navigator.clipboard.readText() };
  const items = await navigator.clipboard.read();
  const files: File[] = [];
  let text = "";
  for (const item of items) {
    // One ClipboardItem can contain PNG + HTML representations of the same
    // screenshot. Import it once, with image bytes preferred over markup.
    const type = item.types.find((type) => type.startsWith("image/")) ?? item.types.find((type) => !type.startsWith("text/"));
    if (type) {
      const blob = await item.getType(type);
      const extension = ({ "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "application/pdf": "pdf" } as Record<string, string>)[type] ?? "bin";
      files.push(new File([blob], `clipboard-${Date.now()}-${files.length + 1}.${extension}`, { type: blob.type || type }));
    } else if (item.types.includes("text/plain")) text += await (await item.getType("text/plain")).text();
  }
  return { files, text };
}

export function insertClipboardText(element: HTMLTextAreaElement | HTMLInputElement, text: string) {
  const start = element.selectionStart ?? element.value.length;
  const end = element.selectionEnd ?? start;
  const value = element.value.slice(0, start) + text + element.value.slice(end);
  const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(prototype, "value")?.set?.call(element, value);
  element.dispatchEvent(new Event("input", { bubbles: true }));
  element.focus();
  element.setSelectionRange(start + text.length, start + text.length);
}

export function requestClipboardImport() {
  window.dispatchEvent(new Event("forensicspp:clipboard-import"));
}
