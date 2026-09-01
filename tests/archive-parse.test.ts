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
import { gzipSync, zipSync } from "fflate";
import { parseArchive } from "../src/features/archive/archiveParse";
import { parseTar } from "../src/features/archive/tar";
import { parseCpio } from "../src/features/archive/cpio";
import { extractEntry } from "../src/features/archive/archive.worker";
import { buildArchiveEnvelope } from "../src/features/archive/envelope";
import type { ZipDirectoryEntry } from "../src/features/archive/zipDirectory";

const enc = new TextEncoder();

function octalChars(value: number, length: number): string {
  return value.toString(8).padStart(length - 1, "0").slice(0, length - 1) + "\0";
}

function hex8(value: number): string {
  return value.toString(16).padStart(8, "0").slice(-8);
}

/* ------------------------------------------------------------------ */
/* Minimal tar (ustar) builder                                        */
/* ------------------------------------------------------------------ */

type TarEntrySpec = { name: string; type?: string; mode?: number; mtime?: number; content?: Uint8Array };

function makeTar(entries: TarEntrySpec[]): Uint8Array {
  const out: number[] = [];
  const push = (bytes: number[]) => out.push(...bytes);

  for (const entry of entries) {
    const header = new Uint8Array(512);
    const nameBytes = enc.encode(entry.name);
    for (let index = 0; index < Math.min(100, nameBytes.length); index += 1) header[index] = nameBytes[index];
    const writeOctal = (offset: number, length: number, value: number) => {
      const text = octalChars(value, length);
      for (let index = 0; index < text.length; index += 1) header[offset + index] = text.charCodeAt(index);
    };
    writeOctal(100, 8, entry.mode ?? 0o644);
    writeOctal(108, 8, 0);
    writeOctal(116, 8, 0);
    writeOctal(124, 12, entry.content?.length ?? 0);
    writeOctal(136, 12, entry.mtime ?? 0);
    for (let index = 148; index < 156; index += 1) header[index] = 0x20;
    header[156] = (entry.type ?? "0").charCodeAt(0);
    const magic = "ustar\0";
    for (let index = 0; index < 6; index += 1) header[257 + index] = magic.charCodeAt(index);
    header[263] = 0x30;
    header[264] = 0x30;

    let sum = 0;
    for (let index = 0; index < 512; index += 1) sum += header[index];
    const chks = octalChars(sum, 8);
    for (let index = 0; index < chks.length; index += 1) header[148 + index] = chks.charCodeAt(index);

    push(Array.from(header));
    if (entry.content && entry.content.length > 0) {
      const data = Array.from(entry.content);
      while (data.length % 512 !== 0) data.push(0);
      push(data);
    }
  }
  push(new Array(512).fill(0));
  return new Uint8Array(out);
}

/* ------------------------------------------------------------------ */
/* Minimal cpio newc (070701) builder                                 */
/* ------------------------------------------------------------------ */

type CpioEntrySpec = { name: string; mode: number; mtime?: number; content?: Uint8Array };

function makeCpioNewc(entries: CpioEntrySpec[]): Uint8Array {
  const out: number[] = [];
  const push = (bytes: number[]) => out.push(...bytes);
  let ino = 1;
  for (const entry of entries) {
    const nameBytes = enc.encode(entry.name + "\0");
    const data = entry.content ?? new Uint8Array(0);
    const header =
      "070701" +
      hex8(ino) + hex8(entry.mode) + hex8(0) + hex8(0) + hex8(1) +
      hex8(entry.mtime ?? 0) + hex8(data.length) + hex8(0) + hex8(0) + hex8(0) + hex8(0) +
      hex8(nameBytes.length) + hex8(0);
    for (const ch of header) out.push(ch.charCodeAt(0));
    push(Array.from(nameBytes));
    while (out.length % 4 !== 0) out.push(0);
    push(Array.from(data));
    while (out.length % 4 !== 0) out.push(0);
    ino += 1;
  }
  const trailerName = enc.encode("TRAILER!!!\0");
  const trailer =
    "070701" + hex8(0) + hex8(0) + hex8(0) + hex8(0) + hex8(1) + hex8(0) + hex8(0) + hex8(0) + hex8(0) + hex8(0) + hex8(0) + hex8(trailerName.length) + hex8(0);
  for (const ch of trailer) out.push(ch.charCodeAt(0));
  push(Array.from(trailerName));
  while (out.length % 4 !== 0) out.push(0);
  return new Uint8Array(out);
}

/* ------------------------------------------------------------------ */
/* Minimal cpio odc (070707) builder                                  */
/* ------------------------------------------------------------------ */

function makeCpioOdc(entries: CpioEntrySpec[]): Uint8Array {
  const out: number[] = [];
  const push = (bytes: number[]) => out.push(...bytes);
  const oct6 = (value: number) => value.toString(8).padStart(6, "0").slice(-6);
  const oct11 = (value: number) => value.toString(8).padStart(11, "0").slice(-11);
  let dev = 1;
  let ino = 1;
  for (const entry of entries) {
    const nameBytes = enc.encode(entry.name + "\0");
    const data = entry.content ?? new Uint8Array(0);
    const header =
      "070707" +
      oct6(dev) + oct6(ino) + oct6(entry.mode) + oct6(0) + oct6(0) + oct6(1) + oct6(0) +
      oct11(entry.mtime ?? 0) + oct6(nameBytes.length) + oct11(data.length);
    for (const ch of header) out.push(ch.charCodeAt(0));
    push(Array.from(nameBytes));
    while (out.length % 2 !== 0) out.push(0);
    push(Array.from(data));
    while (out.length % 2 !== 0) out.push(0);
    ino += 1;
  }
  const trailerName = enc.encode("TRAILER!!!\0");
  const trailer = "070707" + oct6(0).repeat(7) + oct11(0) + oct6(trailerName.length) + oct11(0);
  for (const ch of trailer) out.push(ch.charCodeAt(0));
  push(Array.from(trailerName));
  while (out.length % 2 !== 0) out.push(0);
  return new Uint8Array(out);
}

/* ------------------------------------------------------------------ */

describe("parseArchive format detection", () => {
  it("detects ZIP via the central directory", () => {
    const zip = zipSync({ "readme.txt": enc.encode("hello"), "dir/": new Uint8Array(0) });
    const result = parseArchive(zip);
    expect(result?.format).toBe("zip");
    expect(result?.entries.map((entry) => entry.name).sort()).toEqual(["dir/", "readme.txt"]);
    expect(result?.gzipped).toBe(false);
  });

  it("detects TAR (ustar) and keeps store-type entries", () => {
    const tar = makeTar([
      { name: "docs/", type: "5" },
      { name: "docs/seed.bin", content: enc.encode("payload-data") }
    ]);
    const result = parseArchive(tar);
    expect(result?.format).toBe("tar");
    const files = result?.entries ?? [];
    expect(files.some((entry) => entry.name === "docs/")).toBe(true);
    expect(files.some((entry) => entry.name === "docs/seed.bin")).toBe(true);
    const file = files.find((entry) => entry.name === "docs/seed.bin");
    expect(file?.uncompressed).toBe("payload-data".length);
  });

  it("detects cpio newc and normalizes directory names with a trailing slash", () => {
    const cpio = makeCpioNewc([
      { name: "etc", mode: 0o40755 },
      { name: "etc/passwd", mode: 0o100644, content: enc.encode("root:x:0:0") }
    ]);
    const result = parseArchive(cpio);
    expect(result?.format).toBe("cpio");
    expect(result?.entries.map((entry) => entry.name)).toEqual(["etc/", "etc/passwd"]);
  });

  it("detects cpio odc (070707) with hex/decimal fields", () => {
    const cpio = makeCpioOdc([
      { name: "bin", mode: 0o40755 },
      { name: "bin/sh", mode: 0o100755, content: enc.encode("#!/bin/sh") }
    ]);
    const result = parseArchive(cpio);
    expect(result?.format).toBe("cpio");
    expect(result?.entries.some((entry) => entry.name === "bin/sh")).toBe(true);
  });

  it("unwraps gzip transparently and reports gzipped=true", () => {
    const tar = makeTar([{ name: "note.txt", content: enc.encode("compressed-then-archived") }]);
    const gz = gzipSync(tar);
    expect(gz[0]).toBe(0x1f);
    expect(gz[1]).toBe(0x8b);
    const result = parseArchive(gz);
    expect(result?.format).toBe("tar");
    expect(result?.gzipped).toBe(true);
    expect(result?.entries[0]?.name).toBe("note.txt");
  });

  it("returns null for empty or non-archive bytes", () => {
    expect(parseArchive(new Uint8Array(0))).toBeNull();
    expect(parseArchive(enc.encode("just some random text that is not any container"))).toBeNull();
  });
});

describe("tar edge cases", () => {
  it("honors GNU long names (type 'L')", () => {
    const longName = "deeply/nested/path/with/a/very/long/file/name/that/exceeds/one/hundred/characters/limit/of/ustar/headers.conf";
    const tar = makeTar([
      { name: longName, type: "L", content: enc.encode(longName + "\0") },
      { name: "", content: enc.encode("long-named payload") }
    ]);
    const parsed = parseTar(tar);
    expect(parsed.entries.some((entry) => entry.name === longName)).toBe(true);
  });

  it("exposes dataOffset/dataLength for lazy extraction", () => {
    const content = enc.encode("0123456789abcdef");
    const tar = makeTar([{ name: "blob.bin", content }]);
    const parsed = parseTar(tar);
    const entry = parsed.entries[0];
    expect(entry.dataOffset).toBeGreaterThan(0);
    expect(entry.dataLength).toBe(content.length);
    const slice = tar.subarray(entry.dataOffset, entry.dataOffset + entry.dataLength);
    expect(Array.from(slice)).toEqual(Array.from(content));
  });
});

describe("cpio edge cases", () => {
  it("exposes dataOffset/dataLength and stops at TRAILER!!!", () => {
    const cpio = makeCpioNewc([
      { name: "a.txt", mode: 0o100644, content: enc.encode("alpha") },
      { name: "b.txt", mode: 0o100644, content: enc.encode("beta") }
    ]);
    const parsed = parseCpio(cpio);
    expect(parsed.entries).toHaveLength(2);
    const first = parsed.entries[0];
    expect(first.dataOffset).toBeGreaterThan(0);
    const slice = cpio.subarray(first.dataOffset, first.dataOffset + first.dataLength);
    expect(new TextDecoder().decode(slice)).toBe("alpha");
  });
});

describe("archive.worker extractEntry", () => {
  it("extracts a single ZIP entry via fflate", () => {
    const payload = enc.encode("zip-entry-content");
    const zip = zipSync({ "a.txt": payload, "b.txt": enc.encode("other") });
    const result = extractEntry({ bytes: zip.buffer, entryName: "a.txt", format: "zip" });
    expect(result).not.toBeNull();
    expect(Array.from(result as Uint8Array)).toEqual(Array.from(payload));
  });

  it("slices a TAR entry by offset/length", () => {
    const payload = enc.encode("tar-entry-payload-bytes");
    const tar = makeTar([{ name: "data.bin", content: payload }]);
    const parsed = parseArchive(tar);
    const entry = parsed?.entries[0] as ZipDirectoryEntry;
    const result = extractEntry({ bytes: tar.buffer, entryName: entry.name, format: "tar", dataOffset: entry.dataOffset, dataLength: entry.dataLength });
    expect(result).not.toBeNull();
    expect(Array.from(result as Uint8Array)).toEqual(Array.from(payload));
  });

  it("slices a cpio entry by offset/length after gzip unwrap", () => {
    const payload = enc.encode("cpio-payload");
    const cpio = makeCpioNewc([{ name: "log.txt", mode: 0o100644, content: payload }]);
    const gz = gzipSync(cpio);
    const parsed = parseArchive(gz);
    const entry = parsed?.entries[0] as ZipDirectoryEntry;
    expect(parsed?.format).toBe("cpio");
    const result = extractEntry({ bytes: parsed?.contentBytes.buffer as ArrayBuffer, entryName: entry.name, format: "cpio", dataOffset: entry.dataOffset, dataLength: entry.dataLength });
    expect(Array.from(result as Uint8Array)).toEqual(Array.from(payload));
  });

  it("returns null when the entry cannot be located", () => {
    const zip = zipSync({ "only.txt": enc.encode("x") });
    expect(extractEntry({ bytes: zip.buffer, entryName: "missing.txt", format: "zip" })).toBeNull();
  });
});

describe("archive envelope by format", () => {
  it("labels a TAR analysis with the tar source type and limitation", () => {
    const tar = makeTar([{ name: "f.txt", content: enc.encode("abc") }]);
    const parsed = parseArchive(tar) as NonNullable<ReturnType<typeof parseArchive>>;
    const envelope = buildArchiveEnvelope({ name: "sample.tar", size: tar.length, kind: "TAR", entries: parsed.entries, skipped: 0, format: parsed.format });
    expect(envelope.summary.title).toBe("Archive (TAR) analysis");
    expect(envelope.source[0].type).toBe("application/x-tar");
    expect(envelope.limitations[0].detail).toContain("TAR");
  });

  it("labels a CPIO analysis distinctly from ZIP", () => {
    const cpio = makeCpioNewc([{ name: "f.txt", mode: 0o100644, content: enc.encode("abc") }]);
    const parsed = parseArchive(cpio) as NonNullable<ReturnType<typeof parseArchive>>;
    const envelope = buildArchiveEnvelope({ name: "sample.cpio", size: cpio.length, kind: "CPIO", entries: parsed.entries, skipped: 0, format: parsed.format });
    expect(envelope.summary.title).toBe("Archive (CPIO) analysis");
    expect(envelope.source[0].type).toBe("application/x-cpio");
  });
});
