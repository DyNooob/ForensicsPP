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

/**
 * Browser shim for node's `crypto` builtin.
 *
 * Some dependencies (e.g. bcryptjs' ESM entry) do `import nodeCrypto from "crypto"`
 * at module top level. bcryptjs ships a `browser: { "crypto": false }` hint, but that
 * hint is ignored because the package also defines an `exports` map, which Vite honors
 * instead. As a result the node `crypto` builtin leaks into the browser bundle and the
 * bundler emits a runtime "Could not dynamically require 'crypto'" throw.
 *
 * bcryptjs only ever uses `crypto.randomBytes` as a fallback; in the browser it prefers
 * the Web Crypto API (`globalThis.crypto.getRandomValues`). This shim supplies a
 * node-style `randomBytes` backed by Web Crypto so bcryptjs works fully offline in the
 * browser without pulling in any node core module.
 */

export function randomBytes(size: number): Uint8Array {
  if (!Number.isSafeInteger(size) || size < 0) throw new RangeError("Invalid random byte count");
  const webCrypto = globalThis.crypto;
  if (!webCrypto?.getRandomValues) throw new Error("Secure random number generation is unavailable");
  const out = new Uint8Array(size);
  // Web Crypto limits each call to 65,536 bytes.
  for (let offset = 0; offset < size; offset += 65_536) {
    webCrypto.getRandomValues(out.subarray(offset, Math.min(size, offset + 65_536)));
  }
  return out;
}

const nodeCryptoShim = {
  randomBytes,
  getRandomValues: globalThis.crypto?.getRandomValues?.bind(globalThis.crypto),
  subtle: globalThis.crypto?.subtle
};

export default nodeCryptoShim;
