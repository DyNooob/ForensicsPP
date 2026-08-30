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
import { appReleaseDate } from "../config/app";

// Stale-version notice: warn when the installed version is over 90 days old.
const STALE_VERSION_DAYS = 90;
const DAY_MS = 86400000;

export function useStaleVersion() {
  const releaseTime = React.useMemo(() => Date.parse(appReleaseDate), [appReleaseDate]);
  // Fully computed staleness check: once `releaseDate + 90 days` passes the
  // current date, the version is stale. No hardcoded expiry date to maintain —
  // only the release date constant in src/config/app.ts needs bumping.
  const isVersionStale = Number.isFinite(releaseTime) && Date.now() > releaseTime + STALE_VERSION_DAYS * DAY_MS;
  // Session-only dismissal: a fresh refresh shows the banner again; switching
  // tools within the session must NOT resurrect it (no persistence).
  const [staleBannerDismissed, setStaleBannerDismissed] = React.useState(false);
  const showStaleBanner = isVersionStale && !staleBannerDismissed;
  const dismissStaleBanner = () => setStaleBannerDismissed(true);
  return { showStaleBanner, dismissStaleBanner };
}
