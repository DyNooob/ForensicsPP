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

import { afterEach, describe, expect, it, vi } from "vitest";
import { revokeImagePreviewUrls } from "../src/features/image/analyzer";
import type { ImageInfo } from "../src/models";

describe("image preview resource cleanup", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("releases generated blob URLs without touching data URLs", () => {
    const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    const channels = {
      red: "blob:red",
      green: "data:image/png;base64,placeholder",
      blue: "",
      alpha: "",
      lsb: "",
      lsbRed: "",
      lsbGreen: "",
      lsbBlue: "",
      lowBitHeatmap: "",
      noiseMap: "",
      bitPlanes: [{ label: "R bit 0", src: "blob:plane" }]
    } as ImageInfo["channelDataUrls"];

    revokeImagePreviewUrls(channels);

    expect(revoke.mock.calls.map(([url]) => url)).toEqual(["blob:red", "blob:plane"]);
    expect(revoke).not.toHaveBeenCalledWith("data:image/png;base64,placeholder");
  });
});
