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

export interface ToolSample {
  zh: string;
  en: string;
}

export const toolSamples: Record<string, ToolSample> = {
  json: {
    zh: `{
  "case": "2026-DFIR-014",
  "host": { "name": "WIN-7K2Q", "os": "Windows 10" },
  "events": [
    { "time": "2026-03-14T08:21:11Z", "type": "login", "user": "admin" },
    { "time": "2026-03-14T08:25:02Z", "type": "file-access", "path": "C:\\\\temp\\\\svchost.bin" }
  ],
  "tags": ["incident", "ransomware"],
  "score": 0.87
}`,
    en: `{
  "case": "2026-DFIR-014",
  "host": { "name": "WIN-7K2Q", "os": "Windows 10" },
  "events": [
    { "time": "2026-03-14T08:21:11Z", "type": "login", "user": "admin" },
    { "time": "2026-03-14T08:25:02Z", "type": "file-access", "path": "C:\\\\temp\\\\svchost.bin" }
  ],
  "tags": ["incident", "ransomware"],
  "score": 0.87
}`
  },
  codec: {
    zh: "SGVsbG8sIEZvcmVuc2ljcysr",
    en: "SGVsbG8sIEZvcmVuc2ljcysr"
  },
  hash: {
    zh: "The quick brown fox jumps over the lazy dog",
    en: "The quick brown fox jumps over the lazy dog"
  },
  baseconvert: {
    zh: "255",
    en: "255"
  },
  crypto: {
    zh: "KHOOR ZRUOG",
    en: "KHOOR ZRUOG"
  }
};
