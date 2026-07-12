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
