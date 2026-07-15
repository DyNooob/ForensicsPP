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
import { copyText } from "../src/utils/clipboard";

describe("clipboard fallback", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("uses the browser clipboard when available", async () => {
    const writeText = vi.fn(async () => undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });

    await expect(copyText("evidence")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("evidence");
  });

  it("uses a legacy textarea when the browser clipboard is unavailable", async () => {
    const textarea = {
      value: "",
      style: {} as Record<string, string>,
      setAttribute: vi.fn(),
      focus: vi.fn(),
      select: vi.fn(),
      remove: vi.fn()
    };
    const documentMock = {
      createElement: vi.fn(() => textarea),
      body: { appendChild: vi.fn() },
      execCommand: vi.fn(() => true)
    };
    vi.stubGlobal("navigator", {});
    vi.stubGlobal("document", documentMock);

    await expect(copyText("static release")).resolves.toBe(true);
    expect(textarea.value).toBe("static release");
    expect(documentMock.execCommand).toHaveBeenCalledWith("copy");
    expect(textarea.remove).toHaveBeenCalled();
  });
});
