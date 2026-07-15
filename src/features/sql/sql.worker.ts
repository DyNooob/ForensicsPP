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

import { minifySqlText, parseSqlDump } from "./analyzer";
import type { SqlParseResult } from "../../models";

export type SqlWorkerRequest =
  | { mode: "parse"; text: string; name: string; size: number }
  | { mode: "minify"; text: string }
  | { mode: "format"; text: string; dialect: string };

export type SqlWorkerResult = SqlParseResult | { text: string };

self.onmessage = async (event: MessageEvent<SqlWorkerRequest>) => {
  try {
    const request = event.data;
    let result: SqlWorkerResult;
    if (request.mode === "parse") {
      result = parseSqlDump(request.text, request.name, request.size);
    } else if (request.mode === "minify") {
      result = { text: minifySqlText(request.text) };
    } else {
      const formatter = await import("sql-formatter");
      result = { text: formatter.format(request.text, { language: request.dialect as never }) };
    }
    self.postMessage({ type: "result", result });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};
