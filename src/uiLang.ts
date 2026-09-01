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

import type { Lang } from "./models";

/**
 * Process-wide UI language holder. `InfoTable` and other shared presentational
 * components render row/column labels that originate as English strings inside
 * analyzer output; they need the active locale without prop-drilling through
 * every tool. `App` publishes the current `lang` here on change.
 */
let uiLang: Lang = "zh";

export function setUiLang(lang: Lang): void {
  uiLang = lang;
}

export function getUiLang(): Lang {
  return uiLang;
}
