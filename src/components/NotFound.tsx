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
import type { Lang } from "../models";
import type { Translation } from "../i18n";

interface NotFoundProps {
  t: Translation;
  lang: Lang;
  onGoHome: () => void;
}

/**
 * Shown when the URL explicitly names a tool route that does not exist
 * (e.g. `/tools/not-a-real-tool/`). This is a real 404 state for the SPA —
 * distinct from "no tool selected" (which renders Home). It must never
 * silently fall back to Home and pretend the URL was valid.
 */
export function NotFound({ t, lang, onGoHome }: NotFoundProps) {
  const requested =
    typeof window !== "undefined" && window.location.pathname && window.location.pathname !== "/"
      ? window.location.pathname
      : null;

  return (
    <div
      className="tool-notfound"
      role="alert"
      style={{
        minHeight: "60vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "flex-start",
        justifyContent: "center",
        gap: 12,
        padding: "32px 40px",
        maxWidth: 720,
      }}
    >
      <div
        aria-hidden="true"
        style={{
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
          fontSize: 13,
          fontWeight: 700,
          letterSpacing: "0.08em",
          color: "var(--fpp-accent, #245F73)",
        }}
      >
        404
      </div>
      <h1 style={{ margin: 0, fontSize: 22, lineHeight: 1.3 }}>{t.notFoundTitle}</h1>
      <p style={{ margin: 0, color: "var(--fpp-text-secondary, #66768a)", maxWidth: 560 }}>{t.notFoundBody}</p>
      {requested && (
        <code
          style={{
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
            fontSize: 13,
            background: "var(--fpp-surface, #eef2f7)",
            border: "1px solid var(--fpp-border, #dde5ee)",
            borderRadius: 6,
            padding: "4px 10px",
          }}
        >
          {requested}
        </code>
      )}
      <p style={{ margin: 0, color: "var(--fpp-text-secondary, #66768a)", fontSize: 14 }}>{t.notFoundHint}</p>
      <button
        type="button"
        onClick={onGoHome}
        style={{
          marginTop: 8,
          height: 38,
          padding: "0 18px",
          borderRadius: 6,
          border: "1px solid var(--fpp-accent, #245F73)",
          background: "var(--fpp-accent, #245F73)",
          color: "#fff",
          fontSize: 14,
          fontWeight: 600,
          cursor: "pointer",
        }}
      >
        {t.notFoundHome}
      </button>
    </div>
  );
}
