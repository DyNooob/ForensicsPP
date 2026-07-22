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

/** Transient, dependency-free "copied" confirmation shown after a successful copy. */
let copyToastLabel = "已复制";
let copyToastTimer: ReturnType<typeof setTimeout> | undefined;

/** Lets the app supply a localized label (e.g. on locale change). */
export function setCopyToastLabel(label: string) {
  if (label) copyToastLabel = label;
}

function showCopyToast(label?: string) {
  if (typeof document === "undefined" || !document.body) return;
  const probe = document.createElement("div");
  // Guard against non-DOM mocks (e.g. unit tests stub document.createElement).
  if (!("classList" in probe)) return;

  let el = document.getElementById("copy-toast") as HTMLDivElement | null;
  if (!el) {
    el = probe;
    el.id = "copy-toast";
    el.className = "copy-toast";
    el.setAttribute("role", "status");
    el.setAttribute("aria-live", "polite");
    document.body.appendChild(el);
  }
  el.textContent = "✓ " + (label || copyToastLabel);
  // Restart the enter animation on repeated copies.
  el.classList.remove("copy-toast--show");
  void el.offsetWidth;
  el.classList.add("copy-toast--show");
  if (copyToastTimer) clearTimeout(copyToastTimer);
  copyToastTimer = setTimeout(() => el?.classList.remove("copy-toast--show"), 1500);
}

/** Copy text in secure contexts and fall back for static file:// releases. */
export async function copyText(value: string, opts?: { feedback?: boolean }) {
  if (!value) return false;
  const wantFeedback = opts?.feedback !== false;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      if (wantFeedback) showCopyToast();
      return true;
    }
  } catch {
    // The legacy path below can still work when clipboard permission is denied.
  }

  if (typeof document === "undefined" || typeof document.execCommand !== "function") return false;
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.top = "-1000px";
  textarea.style.left = "-1000px";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  try {
    const ok = document.execCommand("copy");
    if (ok && wantFeedback) showCopyToast();
    return ok;
  } finally {
    textarea.remove();
  }
}
