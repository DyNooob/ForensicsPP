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

import { describe, expect, it, beforeEach } from "vitest";
import {
  captureEvidence,
  clearEvidenceInbox,
  getEvidenceInboxSnapshot,
  noteEvidenceUsed,
  subscribeEvidenceInbox
} from "../src/core/evidence/inbox";

beforeEach(() => clearEvidenceInbox());

describe("evidence inbox store", () => {
  it("captures a file and stamps it with the loading tool", () => {
    const file = new File(["hello"], "hello.bin", { type: "application/octet-stream" });
    captureEvidence([file], "upload", "binary");
    const snap = getEvidenceInboxSnapshot();
    expect(snap).toHaveLength(1);
    expect(snap[0].name).toBe("hello.bin");
    expect(snap[0].usedByTools).toEqual(["binary"]);
    expect(snap[0].source).toBe("upload");
  });

  it("dedups by name:size:lastModified and merges usedByTools", () => {
    const file = new File(["x"], "a.bin", { type: "application/octet-stream" });
    captureEvidence([file], "upload", "binary");
    captureEvidence([file], "drop", "image");
    const snap = getEvidenceInboxSnapshot();
    expect(snap).toHaveLength(1);
    expect(snap[0].usedByTools).toEqual(["binary", "image"]);
  });

  it("orders items newest-acquired first", async () => {
    const a = new File(["1"], "a.bin", { lastModified: 1000 });
    const b = new File(["2"], "b.bin", { lastModified: 2000 });
    captureEvidence([a], "upload", "binary");
    await new Promise((resolve) => setTimeout(resolve, 5));
    captureEvidence([b], "upload", "disk");
    const snap = getEvidenceInboxSnapshot();
    expect(snap.map((item) => item.name)).toEqual(["b.bin", "a.bin"]);
  });

  it("noteEvidenceUsed adds a tool without duplication", () => {
    const file = new File(["y"], "c.bin", { type: "application/octet-stream" });
    captureEvidence([file], "upload", "binary");
    const key = getEvidenceInboxSnapshot()[0].key;
    noteEvidenceUsed(key, "sqlite");
    noteEvidenceUsed(key, "sqlite");
    expect(getEvidenceInboxSnapshot()[0].usedByTools).toEqual(["binary", "sqlite"]);
  });

  it("clearEvidenceInbox empties the store and notifies subscribers", () => {
    const file = new File(["z"], "d.bin", { type: "application/octet-stream" });
    captureEvidence([file], "upload", "binary");
    let notified = false;
    const unsub = subscribeEvidenceInbox(() => {
      notified = true;
    });
    clearEvidenceInbox();
    unsub();
    expect(getEvidenceInboxSnapshot()).toHaveLength(0);
    expect(notified).toBe(true);
  });
});
