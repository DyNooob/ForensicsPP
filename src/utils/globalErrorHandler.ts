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

import { message } from "antd";

let installed = false;
const seen = new Set<string>();

/**
 * Surfaces otherwise-silent async/render failures as a non-blocking toast so a
 * forensic operation that throws outside a tool's own try/catch is never lost.
 * AbortError (intentional cancellations) and duplicate messages are ignored.
 */
export function installGlobalErrorHandler(): void {
  if (installed || typeof window === "undefined") return;
  installed = true;

  const report = (error: unknown, kind: string) => {
    const normalized = error instanceof Error ? error : new Error(typeof error === "string" ? error : "Unknown error");
    if (normalized.name === "AbortError") return;
    const text = `${kind}: ${normalized.message || normalized.name}`.slice(0, 240);
    if (seen.has(text)) return;
    seen.add(text);
    window.setTimeout(() => seen.delete(text), 5000);
    message.error({ content: text, duration: 4 });
  };

  window.addEventListener("unhandledrejection", (event) => {
    report(event.reason, "Unhandled rejection");
  });
  window.addEventListener("error", (event) => {
    report(event.error ?? event.message, "Runtime error");
  });
}
