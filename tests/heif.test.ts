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
import { inspectHeif, readIsoBoxes } from "../src/features/image/heif";
import { detectImageFormat, getImageLogicalEnd, guessImageDimensions, parseHeifStructure } from "../src/features/image/analyzer";

function join(...parts: Uint8Array[]) { const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0)); let offset = 0; for (const part of parts) { out.set(part, offset); offset += part.length; } return out; }
const ascii = (text: string) => new TextEncoder().encode(text);
function uint32(...values: number[]) { const bytes = new Uint8Array(values.length * 4); values.forEach((value, i) => new DataView(bytes.buffer).setUint32(i * 4, value)); return bytes; }
const box = (type: string, data: Uint8Array) => join(uint32(data.length + 8), ascii(type), data);
const ftyp = box("ftyp", join(ascii("mif1"), uint32(0), ascii("heic")));

describe("HEIF container boundaries", () => {
  it("includes meta and mdat in the image instead of reporting them as appended data", () => {
    const file = join(ftyp, box("meta", uint32(0)), box("mdat", new Uint8Array(12)));
    expect(detectImageFormat(file, "")).toBe("HEIF/AVIF");
    expect(getImageLogicalEnd(file, "HEIF/AVIF")).toBe(file.length);
    expect(getImageLogicalEnd(join(file, ascii("TRAILER")), "HEIF/AVIF")).toBe(file.length);
  });
  it("reads nested ispe dimensions and limits brands to the ftyp box", () => {
    const ispe = box("ispe", uint32(0, 4032, 3024));
    const file = join(ftyp, box("meta", join(uint32(0), box("iprp", box("ipco", ispe)))), box("mdat", ascii("FAKE")));
    expect(guessImageDimensions(file, "HEIF/AVIF")).toEqual({ width: 4032, height: 3024 });
    expect(parseHeifStructure(file).heif.compatibleBrands).toEqual(["heic"]);
    expect(inspectHeif(file).hasMeta).toBe(true);
  });
  it("handles extended-size, zero-size and truncated boxes safely", () => {
    const extended = join(uint32(1), ascii("mdat"), uint32(0, 20), uint32(0));
    expect(readIsoBoxes(extended)[0].end).toBe(20);
    const zero = join(uint32(0), ascii("mdat"), ascii("data"));
    expect(readIsoBoxes(zero)[0].end).toBe(zero.length);
    expect(readIsoBoxes(extended.subarray(0, 19))).toEqual([]);
    expect(() => inspectHeif(box("ispe", uint32(0)))).not.toThrow();
    expect(inspectHeif(new Uint8Array()).logicalEnd).toBe(-1);
  });
});
