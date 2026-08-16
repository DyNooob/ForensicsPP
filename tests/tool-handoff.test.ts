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
import { clearToolHandoff, dispatchToolHandoff, pendingToolHandoffCount, subscribeToolHandoff, takeToolHandoff } from "../src/core/toolHandoff";

afterEach(() => {
  for (const id of ["sqlite", "archive", "image", "android", "documentforensics", "binary"] as const) clearToolHandoff(id);
});

describe("inter-tool artifact handoff", () => {
  it("notifies the target and consumes an in-memory carved File exactly once", () => {
    const listener = vi.fn();
    const unsubscribe = subscribeToolHandoff("sqlite", listener);
    const file = new File([Uint8Array.from([1, 2, 3])], "carved.sqlite", { type: "application/vnd.sqlite3" });
    dispatchToolHandoff({ sourceTool: "binary", targetTool: "sqlite", label: "SQLite @ 0x100", file });
    expect(listener).toHaveBeenCalledTimes(1);
    expect(takeToolHandoff("sqlite")?.file).toBe(file);
    expect(takeToolHandoff("sqlite")).toBeNull();
    unsubscribe();
  });

  it("queues multiple carved artifacts for the same target instead of overwriting them", () => {
    const first = new File([Uint8Array.from([1])], "first.sqlite");
    const second = new File([Uint8Array.from([2])], "second.sqlite");
    dispatchToolHandoff({ sourceTool: "firmware", targetTool: "sqlite", label: "first", file: first });
    dispatchToolHandoff({ sourceTool: "firmware", targetTool: "sqlite", label: "second", file: second });
    expect(pendingToolHandoffCount("sqlite")).toBe(2);
    expect(takeToolHandoff("sqlite")?.file.name).toBe("first.sqlite");
    expect(takeToolHandoff("sqlite")?.file.name).toBe("second.sqlite");
  });
});
