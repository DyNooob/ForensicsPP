/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

type ModernUint8Array = Uint8Array & { toHex?: () => string; toBase64?: () => string };
type ModernUint8ArrayPrototype = Uint8Array & { toHex?: (this: Uint8Array) => string; toBase64?: (this: Uint8Array) => string };

const prototype = Uint8Array.prototype as ModernUint8ArrayPrototype;
prototype.toHex ??= function toHex(this: Uint8Array) {
  return Array.from(this, (value) => value.toString(16).padStart(2, "0")).join("");
};
prototype.toBase64 ??= function toBase64(this: Uint8Array) {
  let binary = "";
  for (let offset = 0; offset < this.length; offset += 0x8000) binary += String.fromCharCode(...this.subarray(offset, offset + 0x8000));
  return btoa(binary);
};

void (Uint8Array.prototype as ModernUint8Array);
const mapPrototype = Map.prototype as unknown as { getOrInsertComputed?: (this: Map<unknown, unknown>, key: unknown, callback: (key: unknown) => unknown) => unknown };
mapPrototype.getOrInsertComputed ??= function getOrInsertComputed(this: Map<unknown, unknown>, key: unknown, callback: (key: unknown) => unknown) {
  if (this.has(key)) return this.get(key);
  const value = callback(key);
  this.set(key, value);
  return value;
};
await import("pdfjs-dist/build/pdf.worker.mjs");

export {};
