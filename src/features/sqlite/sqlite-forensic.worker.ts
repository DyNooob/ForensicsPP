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

import { inspectSqliteDatabase } from "./forensic";

type SqliteForensicWorkerRequest = {
  database: ArrayBuffer;
  wal?: ArrayBuffer;
};
self.onmessage = (event: MessageEvent<SqliteForensicWorkerRequest>) => {
  try {
    const result = inspectSqliteDatabase(
      new Uint8Array(event.data.database),
      event.data.wal ? new Uint8Array(event.data.wal) : null
    );
    self.postMessage({ type: "result", result });
  } catch (error) {
    self.postMessage({ type: "error", error: error instanceof Error ? error.message : String(error) });
  }
};
