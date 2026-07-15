/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { downloadBlob } from "../src/utils/files";

describe("browser downloads", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sanitizes the suggested name and delays object URL cleanup", () => {
    const anchor = {
      href: "",
      download: "",
      click: vi.fn(),
      remove: vi.fn()
    };
    const revokeObjectURL = vi.fn();
    const schedule = vi.fn();
    vi.stubGlobal("URL", { createObjectURL: vi.fn(() => "blob:test"), revokeObjectURL });
    vi.stubGlobal("document", {
      createElement: vi.fn(() => anchor),
      body: { append: vi.fn() }
    });
    vi.stubGlobal("window", { setTimeout: schedule });

    downloadBlob("../case:01?.txt", new Blob(["evidence"]));

    expect(anchor.download).toBe(".._case_01_.txt");
    expect(anchor.click).toHaveBeenCalledOnce();
    expect(revokeObjectURL).not.toHaveBeenCalled();
    expect(schedule).toHaveBeenCalledWith(expect.any(Function), 1000);
    schedule.mock.calls[0][0]();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:test");
  });
});
