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
import { isStringValue, isBooleanValue } from "../utils/appGuards";

export function useShellLayout() {
  const [query, setQuery] = useStoredState("app.query", "", isStringValue);
  const [sidebarCollapsed, setSidebarCollapsed] = useStoredState("app.sidebarCollapsed", false, isBooleanValue);
  const [isNarrowShell, setIsNarrowShell] = React.useState(() => {
    if (typeof window === "undefined") return false;
    return window.matchMedia("(max-width: 1120px)").matches;
  });
  const [detailsExpanded, setDetailsExpanded] = React.useState(false);

  React.useEffect(() => {
    const media = window.matchMedia("(max-width: 1120px)");
    const handleChange = () => {
      setIsNarrowShell(media.matches);
      if (media.matches) setSidebarCollapsed(true);
    };
    handleChange();
    media.addEventListener("change", handleChange);
    return () => media.removeEventListener("change", handleChange);
  }, []);

  return { query, setQuery, sidebarCollapsed, setSidebarCollapsed, isNarrowShell, detailsExpanded, setDetailsExpanded };
}
