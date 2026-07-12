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
import { AButton } from "../components/ui";
import type { Translation } from "../i18n";

export function CyberChefTool({ t }: { t: Translation }) {
  const cyberChefUrl = "/cyberchef/CyberChef_v10.19.4.html";
  const [loaded, setLoaded] = React.useState(false);
  const [showFallback, setShowFallback] = React.useState(false);
  const [frameKey, setFrameKey] = React.useState(0);

  React.useEffect(() => {
    const timeout = window.setTimeout(() => {
      if (!loaded) setShowFallback(true);
    }, 6500);
    return () => window.clearTimeout(timeout);
  }, [loaded]);

  return (
    <div className="cyberchef-panel">
      <div className={`chef-toolbar ${showFallback ? "warn" : ""}`}>
        <span>{showFallback ? t.cyberChefHint : t.cyberchefDesc}</span>
        <div className="button-row compact-buttons">
          <AButton href={cyberChefUrl} target="_blank" variant="outlined">
            {t.openCyberChef}
          </AButton>
          <AButton
            variant="text"
            onClick={() => {
              setLoaded(false);
              setShowFallback(false);
              setFrameKey((value) => value + 1);
            }}
          >
            Reload
          </AButton>
        </div>
      </div>
      <iframe key={frameKey} title="CyberChef" src={cyberChefUrl} loading="lazy" onLoad={() => setLoaded(true)} />
    </div>
  );
}
