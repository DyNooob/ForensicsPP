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
import { AButton } from "../components/ui";
import type { Translation } from "../i18n";

export function CyberChefTool({ t, active = true }: { t: Translation; active?: boolean }) {
  const cyberChefUrl = "./cyberchef/CyberChef_v10.19.4.html";
  const [loaded, setLoaded] = React.useState(false);
  const [showFallback, setShowFallback] = React.useState(false);
  const [frameKey, setFrameKey] = React.useState(0);
  // Defer mounting the ~12MB CyberChef iframe until the tool is actually opened,
  // so it is only fetched when the user navigates to this page.
  const [hasActivated, setHasActivated] = React.useState(active);

  React.useEffect(() => {
    if (active) setHasActivated(true);
  }, [active]);

  React.useEffect(() => {
    if (!hasActivated || loaded) return;
    const timeout = window.setTimeout(() => {
      if (!loaded) setShowFallback(true);
    }, 8000);
    return () => window.clearTimeout(timeout);
  }, [hasActivated, loaded, frameKey]);

  const reload = () => {
    setLoaded(false);
    setShowFallback(false);
    setFrameKey((value) => value + 1);
  };

  return (
    <div className="cyberchef-panel">
      <div className={`chef-toolbar ${showFallback ? "warn" : ""}`}>
        <span>{showFallback ? t.cyberChefHint : t.cyberchefDesc}</span>
        <div className="button-row compact-buttons">
          <AButton href={cyberChefUrl} target="_blank" variant="outlined">
            {t.openCyberChef}
          </AButton>
          <AButton variant="text" onClick={reload}>
            {t.cyberChefReload}
          </AButton>
        </div>
      </div>
      <div className="cyberchef-stage">
        {hasActivated && (
          <iframe
            key={frameKey}
            className={loaded ? "is-loaded" : ""}
            title="CyberChef"
            src={cyberChefUrl}
            onLoad={() => setLoaded(true)}
          />
        )}
        {hasActivated && !loaded && (
          <div className="cyberchef-loader" role="status" aria-live="polite">
            <div className="chef-loader-orbit" aria-hidden="true">
              <span className="chef-loader-ring" />
              <span className="chef-loader-ring chef-loader-ring-2" />
              <svg className="chef-loader-glyph" viewBox="0 0 48 48" fill="none">
                <path
                  d="M24 5c-5.5 0-10 4.2-10.4 9.5C9.9 15.7 7 19 7 23.1 7 28 11.2 32 16.4 32h15.2C36.8 32 41 28 41 23.1c0-4.1-2.9-7.4-6.6-8.6C34 9.2 29.5 5 24 5Z"
                  fill="var(--app-primary)" opacity="0.18"
                />
                <path
                  d="M24 5c-5.5 0-10 4.2-10.4 9.5C9.9 15.7 7 19 7 23.1 7 28 11.2 32 16.4 32h15.2C36.8 32 41 28 41 23.1c0-4.1-2.9-7.4-6.6-8.6C34 9.2 29.5 5 24 5Z"
                  stroke="var(--app-primary)" strokeWidth="2.2" strokeLinejoin="round"
                />
                <path d="M16 32v5.5A3.5 3.5 0 0 0 19.5 41h9a3.5 3.5 0 0 0 3.5-3.5V32" stroke="var(--app-primary)" strokeWidth="2.2" strokeLinecap="round" />
                <circle className="chef-loader-spark" cx="24" cy="20" r="2.6" fill="var(--app-primary)" />
              </svg>
            </div>
            <div className="chef-loader-text">
              <strong>{t.cyberChefLoading}</strong>
              <span>{t.cyberChefLoadingHint}</span>
            </div>
            <div className="chef-loader-bar" aria-hidden="true"><span /></div>
          </div>
        )}
      </div>
    </div>
  );
}
