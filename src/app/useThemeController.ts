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
import { isBooleanValue, isStringValue, isThemeModeValue } from "../utils/appGuards";
import { normalizeHexColor, themeDisplayColor, themeSoftColor } from "../utils/themeColors";
import { themePresets } from "../config/app";
import type { ThemeMode } from "../models";

export function useThemeController() {
  const [themeMode, setThemeMode] = useStoredState<ThemeMode>("app.themeMode", "light", isThemeModeValue);
  const [themeColor, setThemeColor] = useStoredState("app.themeColor", themePresets[0].hex, isStringValue);
  const [themeDefaultMigrated, setThemeDefaultMigrated] = useStoredState("app.themeDefaultV070", false, isBooleanValue);
  const [systemTheme, setSystemTheme] = React.useState<"light" | "dark">(() =>
    typeof window === "undefined"
      ? "light"
      : window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light"
  );

  const resolvedThemeColor = React.useMemo(() => {
    const normalized = normalizeHexColor(themeColor) ?? themePresets[0].hex;
    return !themeDefaultMigrated && normalized === "#245F73" ? themePresets[0].hex : normalized;
  }, [themeColor, themeDefaultMigrated]);

  const appliedTheme = themeMode === "auto" ? systemTheme : themeMode === "dark" ? "dark" : "light";

  const displayThemeColor = React.useMemo(
    () => themeDisplayColor(resolvedThemeColor, appliedTheme),
    [appliedTheme, resolvedThemeColor]
  );

  React.useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const handleChange = () => setSystemTheme(media.matches ? "dark" : "light");
    handleChange();
    media.addEventListener("change", handleChange);
    return () => media.removeEventListener("change", handleChange);
  }, []);

  React.useEffect(() => {
    if (themeDefaultMigrated) return;
    if (themeColor.toUpperCase() === "#245F73") setThemeColor(themePresets[0].hex);
    setThemeDefaultMigrated(true);
  }, [setThemeColor, setThemeDefaultMigrated, themeColor, themeDefaultMigrated]);

  React.useEffect(() => {
    if (themeColor !== resolvedThemeColor) {
      setThemeColor(resolvedThemeColor);
    }
  }, [resolvedThemeColor, setThemeColor, themeColor]);

  React.useLayoutEffect(() => {
    document.documentElement.dataset.themeMode = appliedTheme;
    document.body.dataset.themeMode = appliedTheme;
    document.documentElement.style.colorScheme = appliedTheme;
    document.body.style.colorScheme = appliedTheme;
    document.documentElement.style.backgroundColor = appliedTheme === "dark" ? "#0f1722" : "#f5f7fa";
    document.body.style.backgroundColor = appliedTheme === "dark" ? "#0f1722" : "#f5f7fa";
    document.documentElement.style.setProperty("--app-primary", displayThemeColor);
    document.documentElement.style.setProperty("--app-primary-soft", themeSoftColor(displayThemeColor, appliedTheme));
    document.documentElement.style.setProperty("--app-primary-contrast", appliedTheme === "dark" ? "#0F1822" : "#FFFFFF");
    document.body.style.setProperty("--app-primary", displayThemeColor);
    document.body.style.setProperty("--app-primary-soft", themeSoftColor(displayThemeColor, appliedTheme));
    document.body.style.setProperty("--app-primary-contrast", appliedTheme === "dark" ? "#0F1822" : "#FFFFFF");
    const rootNode = document.getElementById("root");
    if (rootNode) {
      rootNode.dataset.themeMode = appliedTheme;
      rootNode.style.colorScheme = appliedTheme;
      rootNode.style.setProperty("--app-primary", displayThemeColor);
      rootNode.style.setProperty("--app-primary-soft", themeSoftColor(displayThemeColor, appliedTheme));
      rootNode.style.setProperty("--app-primary-contrast", appliedTheme === "dark" ? "#0F1822" : "#FFFFFF");
    }
    let themeMeta = document.querySelector("meta[name='theme-color']");
    if (!themeMeta) {
      themeMeta = document.createElement("meta");
      themeMeta.setAttribute("name", "theme-color");
      document.head.appendChild(themeMeta);
    }
    themeMeta.setAttribute("content", appliedTheme === "dark" ? "#0f1722" : "#f5f7fa");
  }, [appliedTheme, displayThemeColor]);

  const applyThemeColor = React.useCallback((hex: string) => {
    const normalized = normalizeHexColor(hex);
    if (!normalized) return;
    setThemeColor(normalized);
  }, [setThemeColor]);

  const resetThemeAppearance = React.useCallback(() => {
    setThemeColor(themePresets[0].hex);
  }, [setThemeColor]);

  return {
    themeMode,
    setThemeMode,
    themeColor: resolvedThemeColor,
    displayThemeColor,
    appliedTheme,
    applyThemeColor,
    resetThemeAppearance
  };
}
