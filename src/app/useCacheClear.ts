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
import { clearForensicsStorage } from "../utils/storage";
import { writeRoute } from "../core/routeAdapter";

export function useCacheClear(settingsOpen: boolean) {
  const [cacheClearArmed, setCacheClearArmed] = React.useState(false);
  const [cacheClearError, setCacheClearError] = React.useState(false);

  React.useEffect(() => {
    if (!settingsOpen) {
      setCacheClearArmed(false);
      setCacheClearError(false);
    }
  }, [settingsOpen]);

  React.useEffect(() => {
    if (!cacheClearArmed) return;
    const timer = window.setTimeout(() => setCacheClearArmed(false), 4000);
    return () => window.clearTimeout(timer);
  }, [cacheClearArmed]);

  const clearLocalWorkspace = async () => {
    if (!cacheClearArmed) {
      setCacheClearArmed(true);
      return;
    }
    try {
      await clearForensicsStorage();
      writeRoute("home", { replace: true });
      window.location.reload();
    } catch {
      setCacheClearArmed(false);
      setCacheClearError(true);
    }
  };

  return { cacheClearArmed, cacheClearError, setCacheClearError, clearLocalWorkspace };
}
