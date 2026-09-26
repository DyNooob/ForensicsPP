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
import { buildLookupEnvelope } from "../src/features/lookup/envelope";
import type { LookupResult } from "../src/features/lookup/rules";

const results: LookupResult[] = [
  { input: "8.8.8.8", normalized: "8.8.8.8", kind: "ip", valid: true, matched: true, summary: "United States", fields: {}, notes: [], source: "ip2region", dataVersion: "test" },
  { input: "4111111111111111", normalized: "4111111111111111", kind: "bank", valid: true, matched: false, summary: "Visa · BIN not found", fields: {}, notes: [], source: "bankcard", dataVersion: "test" },
  { input: "bad", normalized: "", kind: "id", valid: false, matched: false, summary: "Invalid", fields: {}, notes: [], source: "rules", dataVersion: "built-in" }
];

describe("lookup analysis envelope", () => {
  it("keeps rule validity separate from static-pack coverage", () => {
    const envelope = buildLookupEnvelope(results, { lang: "en", kind: "auto", startedAt: "2026-09-26T00:00:00.000Z", completedAt: "2026-09-26T00:00:01.000Z" });
    expect(envelope.summary.metrics).toEqual(expect.arrayContaining([
      { label: "Rule-valid", value: "2" },
      { label: "Data matches", value: "1" },
      { label: "Invalid", value: "1" }
    ]));
    expect(envelope.findings.map((finding) => finding.code)).toEqual(expect.arrayContaining(["lookup.bank.unmatched", "lookup.id.invalid"]));
  });

  it("publishes only IP and phone values as indicators", () => {
    const envelope = buildLookupEnvelope(results, { lang: "zh", kind: "auto", startedAt: "2026-09-26T00:00:00.000Z" });
    expect(envelope.indicators.map((indicator) => indicator.type)).toEqual(["ip"]);
    expect(envelope.limitations.map((item) => item.code)).toContain("lookup.not_live_location");
  });
});
