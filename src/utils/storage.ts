/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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

import React from "react";
import { storagePrefix } from "../config/app";

export function useStoredState<T>(key: string, initialValue: T) {
  const storageKey = `${storagePrefix}${key}`;
  const [value, setValue] = React.useState<T>(() => {
    if (typeof window === "undefined") return initialValue;
    try {
      const stored = window.localStorage.getItem(storageKey);
      return stored == null ? initialValue : (JSON.parse(stored) as T);
    } catch {
      return initialValue;
    }
  });

  React.useEffect(() => {
    try {
      window.localStorage.setItem(storageKey, JSON.stringify(value));
    } catch {
      // Ignore storage quota and private-mode failures.
    }
  }, [storageKey, value]);

  return [value, setValue] as const;
}

export function clearForensicsStorage() {
  Object.keys(window.localStorage)
    .filter((key) => key.startsWith(storagePrefix))
    .forEach((key) => window.localStorage.removeItem(key));
}

const legacyEvidenceKeys = [
  "baseconvert.value.v2",
  "codec.input",
  "codec.output",
  "crypto.input",
  "crypto.output",
  "crypto.key",
  "entropy.text.v2",
  "hash.text",
  "hash.expectedHash",
  "http.text.v3",
  "regex.text.v2",
  "sqlite.queryHistory",
  "sql.formatInput",
  "sql.formatOutput",
  "timeline.input.v2",
  "timeline.source",
  "timestamp.input",
  "timestamp.batchInput.v2",
  "url.input.v3",
  "uuid.value",
  "yara.sample.v2"
];

const legacyEvidenceCleanupVersion = "2026-07-13-v1";
const legacyEvidenceCleanupKey = `${storagePrefix}storage.legacyEvidenceCleanupVersion`;

export function clearLegacyEvidenceStorage() {
  if (typeof window === "undefined") return;
  if (window.localStorage.getItem(legacyEvidenceCleanupKey) === JSON.stringify(legacyEvidenceCleanupVersion)) return;
  legacyEvidenceKeys.forEach((key) => window.localStorage.removeItem(`${storagePrefix}${key}`));
  window.localStorage.setItem(legacyEvidenceCleanupKey, JSON.stringify(legacyEvidenceCleanupVersion));
}
