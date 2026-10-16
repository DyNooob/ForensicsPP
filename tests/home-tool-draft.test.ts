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

import { afterEach, describe, expect, it } from "vitest";
import { readHomeToolDraft, saveHomeToolDraft, consumeHomeToolDraft, clearHomeToolDrafts } from "../src/app/useHomeToolDraft";

afterEach(clearHomeToolDrafts);

describe("home tool draft handoff", () => {
  it("reads a structured draft without changing the input", () => {
    const serialized = JSON.stringify({ input: "https://example.com/report?id=42", createdAt: 1 });
    const storage = { getItem: () => serialized };
    expect(readHomeToolDraft("urltool", storage)).toEqual({ serialized, input: "https://example.com/report?id=42" });
  });

  it("accepts the earlier raw-text payload format", () => {
    const storage = { getItem: () => "https://example.com/legacy" };
    expect(readHomeToolDraft("urltool", storage)).toEqual({ serialized: "https://example.com/legacy", input: "https://example.com/legacy" });
  });

  it("ignores empty or missing drafts", () => {
    expect(readHomeToolDraft("json", { getItem: () => null })).toBeNull();
    expect(readHomeToolDraft("json", { getItem: () => JSON.stringify({ input: "   " }) })).toBeNull();
  });
});

describe("transient handoff safety", () => {
  it("delivers inputs even when browser storage is unavailable", () => {
    const blocked = { getItem: () => { throw new Error("blocked"); } };
    saveHomeToolDraft("lookup", "13800138000");
    expect(readHomeToolDraft("lookup", blocked)?.input).toBe("13800138000");
    expect(readHomeToolDraft("json", blocked)).toBeNull();
  });
  it("does not consume a newer input from an older deferred callback", () => {
    saveHomeToolDraft("jwt", "old token");
    const old = readHomeToolDraft("jwt")!;
    saveHomeToolDraft("jwt", "new token");
    consumeHomeToolDraft("jwt", old.serialized);
    const latest = readHomeToolDraft("jwt")!;
    expect(latest.input).toBe("new token");
    consumeHomeToolDraft("jwt", latest.serialized);
    expect(readHomeToolDraft("jwt")).toBeNull();
  });
});
