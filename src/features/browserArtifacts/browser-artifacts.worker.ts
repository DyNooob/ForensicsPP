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

import initSqlJs from "sql.js";
import sqlWasmUrl from "sql.js/dist/sql-wasm.wasm?url";
import { analyzeBrowserArtifacts, type BrowserArtifactInput } from "./analyzer";

type WorkerInput = Omit<BrowserArtifactInput, "bytes"> & { bytes: ArrayBuffer };

self.onmessage = async (event: MessageEvent<{ inputs: WorkerInput[] }>) => {
  try {
    const SQL = await initSqlJs({ locateFile: () => sqlWasmUrl });
    const inputs: BrowserArtifactInput[] = event.data.inputs.map((input) => ({ ...input, bytes: new Uint8Array(input.bytes) }));
    self.postMessage({ type: "result", result: analyzeBrowserArtifacts(inputs, SQL) });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};
