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

import { describe, expect, it } from "vitest";
import { copy } from "../src/i18n";

const FIRST_RUN_KEYS = [
  "firstRunTitle",
  "firstRunSkip",
  "firstRunBack",
  "firstRunNext",
  "firstRunStart",
  "firstRunShowAgain",
  "firstRun_welcome_label",
  "firstRun_privacy_label",
  "firstRun_evidence_label",
  "firstRun_tools_label",
  "firstRun_welcome_title",
  "firstRun_welcome_body",
  "firstRun_privacy_title",
  "firstRun_privacy_body",
  "firstRun_evidence_title",
  "firstRun_evidence_body",
  "firstRun_tools_title",
  "firstRun_tools_body",
];

describe("first-run guide i18n", () => {
  for (const locale of ["zh", "en"] as const) {
    describe(locale, () => {
      for (const key of FIRST_RUN_KEYS) {
        it(`has a non-empty value for ${key}`, () => {
          const value = copy[locale][key];
          expect(typeof value).toBe("string");
          expect(value.trim().length).toBeGreaterThan(0);
        });
      }
    });
  }

  it("zh and en expose the same first-run keys", () => {
    const zhKeys = Object.keys(copy.zh).filter((key) => key.startsWith("firstRun"));
    const enKeys = Object.keys(copy.en).filter((key) => key.startsWith("firstRun"));
    expect(zhKeys.sort()).toEqual(enKeys.sort());
  });
});
