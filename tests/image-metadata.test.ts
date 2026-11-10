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
import { hasMetadataValue, metadataHighlights, sortedMetadataEntries } from "../src/features/image/metadata";

describe("image metadata presentation", () => {
  it("prioritizes populated capture fields while preserving zero and false", () => {
    const metadata = { empty: " ", missing: null, unknown: "data", Software: "Photos", Model: "iPhone", DateTimeOriginal: "2026:11:10 12:00:00", latitude: 0, flag: false };
    expect(sortedMetadataEntries(metadata).map(([key]) => key)).toEqual(["DateTimeOriginal", "Model", "latitude", "Software", "unknown", "flag", "empty", "missing"]);
    expect(hasMetadataValue(0)).toBe(true);
    expect(hasMetadataValue(false)).toBe(true);
    expect(hasMetadataValue([null, ""])).toBe(false);
    expect(hasMetadataValue(new Uint8Array())).toBe(false);
  });
  it("shows only extracted highlights and preserves the original capture time", () => {
    const rows = metadataHighlights({ DateTimeOriginal: "2026:11:10 12:00:00", Model: "iPhone", latitude: 0, longitude: 0 }, false);
    expect(rows.map((row) => row.label)).toEqual(["拍摄时间", "拍摄设备", "拍摄位置"]);
    expect(rows[0].value).toBe("2026:11:10 12:00:00");
    expect(rows[2].value).toBe("0.000000, 0.000000");
    expect(metadataHighlights({}, false)).toEqual([]);
    expect(metadataHighlights({ latitude: 120, longitude: 200 }, true)).toEqual([]);
  });
});
