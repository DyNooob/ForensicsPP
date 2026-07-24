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

export const MAX_EMAIL_HTML_PREVIEW_CHARS = 2 * 1024 * 1024;

export function limitEmailHtmlPreview(value: string) {
  return value.slice(0, MAX_EMAIL_HTML_PREVIEW_CHARS);
}

// Strips active content from untrusted email HTML so it can be rendered inside a
// sandboxed iframe. Removes script/iframe/object/embed/form/input/link/meta/style,
// strips all event-handler and remote-resource attributes, neutralizes dangerous
// inline styles, and rewrites external links to "#".
export function sanitizeEmailHtml(value: string) {
  if (!value.trim()) return "";
  const truncated = value.length > MAX_EMAIL_HTML_PREVIEW_CHARS;
  const document = new DOMParser().parseFromString(limitEmailHtmlPreview(value), "text/html");
  document
    .querySelectorAll("script, iframe, object, embed, form, input, button, link, meta, style")
    .forEach((node) => node.remove());
  document.querySelectorAll<HTMLElement>("*").forEach((node) => {
    for (const attribute of Array.from(node.attributes)) {
      if (/^on/i.test(attribute.name)) node.removeAttribute(attribute.name);
      if (/^(src|srcset|background|poster|action|formaction)$/i.test(attribute.name)) node.removeAttribute(attribute.name);
      if (attribute.name === "style" && /url\s*\(|expression\s*\(|behavior\s*:/i.test(attribute.value))
        node.removeAttribute(attribute.name);
      if (attribute.name === "href" && !/^(?:#|mailto:|tel:)/i.test(attribute.value.trim())) node.setAttribute("href", "#");
    }
  });
  if (truncated) {
    const notice = document.createElement("p");
    notice.textContent = "[HTML preview truncated]";
    notice.setAttribute("data-preview-limit", "true");
    document.body.append(notice);
  }
  const baseStyle =
    "body{margin:0;padding:18px;color:#182230;background:#fff;font:14px/1.65 system-ui,sans-serif;overflow-wrap:anywhere}img{max-width:100%;height:auto}pre{white-space:pre-wrap}table{max-width:100%;border-collapse:collapse}td,th{padding:6px;border:1px solid #d9e0e8}";
  return `<!doctype html><html><head><meta charset="utf-8"><style>${baseStyle}</style></head><body>${document.body.innerHTML}</body></html>`;
}
