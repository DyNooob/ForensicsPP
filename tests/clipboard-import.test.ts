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
import { acceptsClipboardFile, filesFromClipboard, readClipboardPayload } from "../src/utils/clipboardImport";

afterEach(() => vi.unstubAllGlobals());

describe("clipboard import", () => {
  it("respects the current tool's file types before routing to another analyzer", () => {
    expect(acceptsClipboardFile(".img,.raw", { name: "disk.IMG", type: "" })).toBe(true);
    expect(acceptsClipboardFile("image/*,.bin", { name: "screenshot.png", type: "image/png" })).toBe(true);
    expect(acceptsClipboardFile(".db,.sqlite", { name: "screenshot.png", type: "image/png" })).toBe(false);
    expect(acceptsClipboardFile("", { name: "SYSTEM", type: "" })).toBe(true);
  });
  it("prefers the file list and does not import item representations twice", () => {
    const file = new File(["hello"], "sample.txt");
    const data = { files: [file], items: [{ kind: "file", getAsFile: () => file }] };
    expect(filesFromClipboard(data as unknown as DataTransfer)).toEqual([file]);
  });
  it("falls back to file items without consuming text paste", () => {
    const file = new File(["image"], "image.png");
    const data = { files: [], items: [{ kind: "string", getAsFile: () => null }, { kind: "file", getAsFile: () => file }] };
    expect(filesFromClipboard(data as unknown as DataTransfer)).toEqual([file]);
    expect(filesFromClipboard(null)).toEqual([]);
  });
  it("imports one image when the clipboard also offers HTML", async () => {
    const getType = vi.fn(async () => new Blob(["png bytes"], { type: "image/png" }));
    vi.stubGlobal("navigator", { clipboard: { read: async () => [{ types: ["text/html", "image/png"], getType }] } });
    const payload = await readClipboardPayload();
    expect(payload.files).toHaveLength(1);
    expect(payload.files[0].name).toMatch(/\.png$/);
    expect(await payload.files[0].text()).toBe("png bytes");
    expect(getType).toHaveBeenCalledExactlyOnceWith("image/png");
    expect(payload.text).toBe("");
  });
  it("preserves arbitrary exposed file bytes and handles text-only browsers", async () => {
    vi.stubGlobal("navigator", { clipboard: { read: async () => [{ types: ["application/pdf"], getType: async () => new Blob(["%PDF-1.7"], { type: "application/pdf" }) }] } });
    expect((await readClipboardPayload()).files[0].name).toMatch(/\.pdf$/);
    vi.stubGlobal("navigator", { clipboard: { readText: async () => "clipboard text" } });
    expect(await readClipboardPayload()).toEqual({ files: [], text: "clipboard text" });
  });
  it("leaves clipboard permission errors available for UI feedback", async () => {
    vi.stubGlobal("navigator", { clipboard: { read: async () => { throw new DOMException("Denied", "NotAllowedError"); } } });
    await expect(readClipboardPayload()).rejects.toMatchObject({ name: "NotAllowedError" });
  });
});
