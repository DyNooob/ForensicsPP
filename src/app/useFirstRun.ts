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

import React from "react";
import { useStoredState } from "../utils/storage";
import { isBooleanValue } from "../utils/appGuards";

const FIRST_RUN_KEY = "fpp.firstRunSeen";

export function useFirstRun() {
  const [seen, setSeen] = useStoredState<boolean>(FIRST_RUN_KEY, false, isBooleanValue);
  const [open, setOpen] = React.useState<boolean>(!seen);

  const dismissFirstRun = React.useCallback(() => {
    setSeen(true);
    setOpen(false);
  }, [setSeen]);

  const reopenFirstRun = React.useCallback(() => {
    setOpen(true);
  }, []);

  return {
    firstRunOpen: open,
    isFirstRunDone: seen,
    dismissFirstRun,
    reopenFirstRun,
  };
}
