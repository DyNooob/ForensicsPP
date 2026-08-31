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

// B6-B0 — Object URL lifecycle verification (spec point 4).
//
// Owning object URLs by React component state is a known leak source. The image
// analyzer tracks its blob: URLs in a MODULE-LEVEL Set (imageObjectUrls), never in
// component state. This test proves the create→track→revoke chain with spies, so
// a regression that drops a revoke (or moves ownership into React state) fails here.
//
// Components that self-manage (QrTool, PngTool, ArchiveTool, CaseReporter) use
// ref/state with replace+clear+unmount cleanup and bounded deferred revoke for
// resources still in active use (download/print). Those are audited by reading
// the source, not here; this test locks the canonical module-owned path.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  bytesToDataUrl,
  revokeImageObjectUrls,
  revokeImagePreviewUrl,
} from "../../src/features/image/analyzer";

describe("object URL lifecycle — image analyzer module-level ownership", () => {
  afterEach(() => {
    revokeImageObjectUrls();
    vi.restoreAllMocks();
  });

  it("tracks large (>4MB) image blob URLs in a module-level Set and revokes them", async () => {
    const createSpy = vi.spyOn(URL, "createObjectURL").mockImplementation(
      () => "blob:tracked-large",
    );
    const revokeSpy = vi.spyOn(URL, "revokeObjectURL").mockImplementation(
      () => undefined,
    );

    const big = new Uint8Array(5 * 1024 * 1024);
    const url = await bytesToDataUrl(big, "image/png");

    expect(createSpy).toHaveBeenCalledTimes(1);
    expect(url).toBe("blob:tracked-large");

    // The decisive property: a module-level sweep revokes exactly the tracked URL.
    revokeImageObjectUrls();
    expect(revokeSpy).toHaveBeenCalledTimes(1);
    expect(revokeSpy).toHaveBeenCalledWith("blob:tracked-large");
  });

  it("revokeImagePreviewUrl revokes a single tracked URL without sweeping others", async () => {
    const createSpy = vi.spyOn(URL, "createObjectURL").mockImplementation(
      (id: number) => `blob:single-${id}`,
    );
    const revokeSpy = vi.spyOn(URL, "revokeObjectURL").mockImplementation(
      () => undefined,
    );

    const big = new Uint8Array(5 * 1024 * 1024);
    const url = await bytesToDataUrl(big, "image/png");

    revokeImagePreviewUrl(url);
    expect(revokeSpy).toHaveBeenCalledWith(url);
  });

  it("does NOT create object URLs for small images (data: path, no revoke needed)", async () => {
    if (typeof FileReader === "undefined") return; // node env lacks FileReader
    const createSpy = vi.spyOn(URL, "createObjectURL");
    const small = new Uint8Array(1024);
    const url = await bytesToDataUrl(small, "image/png");
    expect(createSpy).not.toHaveBeenCalled();
    expect(url.startsWith("data:")).toBe(true);
  });
});
