/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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

import * as CFB from "cfb";
import { zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { analyzeOle, analyzeOoxml, isOle, isPdf, isZip } from "../src/features/document/analyzer";

const encoder = new TextEncoder();

function minimalPdf() {
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
    "<< /Length 0 >>\nstream\n\nendstream",
    "<< /Title (Fixture PDF) /Author (Forensics++) >>"
  ];
  let pdf = "%PDF-1.7\n";
  const offsets = [0];
  objects.forEach((body, index) => {
    offsets.push(encoder.encode(pdf).byteLength);
    pdf += `${index + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = encoder.encode(pdf).byteLength;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let index = 1; index <= objects.length; index += 1) pdf += `${String(offsets[index]).padStart(10, "0")} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R /Info 5 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return encoder.encode(pdf);
}

describe("Office and PDF container detection", () => {
  it("recognizes supported file signatures", () => {
    expect(isPdf(encoder.encode("%PDF-1.7"))).toBe(true);
    expect(isZip(new Uint8Array([0x50, 0x4b, 0x03, 0x04]))).toBe(true);
    expect(isOle(new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))).toBe(true);
  });

  it("opens a valid PDF and reads its page and information dictionary", async () => {
    const canvas = await import("@napi-rs/canvas");
    Object.assign(globalThis, { DOMMatrix: canvas.DOMMatrix, ImageData: canvas.ImageData, Path2D: canvas.Path2D });
    const { analyzePdf } = await import("../src/features/document/pdf");
    const promiseConstructor = Promise as unknown as { try?: unknown };
    const nativePromiseTry = promiseConstructor.try;
    delete promiseConstructor.try;
    try {
      const result = await analyzePdf(minimalPdf(), "fixture.pdf");
      expect(result.pages).toBe(1);
      expect(result.revisions).toBe(1);
      expect(result.metadata).toContainEqual(["Title", "Fixture PDF"]);
    } finally {
      if (nativePromiseTry) promiseConstructor.try = nativePromiseTry;
      else delete promiseConstructor.try;
    }
  }, 20_000);
});

describe("OOXML analysis", () => {
  it("extracts metadata, external relationships, embedded objects and VBA projects", () => {
    const bytes = zipSync({
      "[Content_Types].xml": encoder.encode("<Types></Types>"),
      "word/document.xml": encoder.encode("<w:document xmlns:w=\"urn:w\"><w:body/></w:document>"),
      "docProps/core.xml": encoder.encode("<cp:coreProperties xmlns:cp=\"urn:cp\" xmlns:dc=\"urn:dc\"><dc:title>Fixture report</dc:title><dc:creator>Analyst</dc:creator><cp:lastModifiedBy>Reviewer</cp:lastModifiedBy></cp:coreProperties>"),
      "word/_rels/document.xml.rels": encoder.encode("<Relationships><Relationship Id=\"rId1\" Type=\"http://schemas.test/hyperlink\" Target=\"https://external.test/path\" TargetMode=\"External\"/></Relationships>"),
      "word/embeddings/oleObject1.bin": new Uint8Array([1, 2, 3, 4]),
      "word/vbaProject.bin": new Uint8Array([5, 6, 7, 8])
    });
    const result = analyzeOoxml(bytes, "fixture.docm");

    expect(result.subtype).toBe("Word OOXML");
    expect(result.metadata).toContainEqual(["Title", "Fixture report"]);
    expect(result.findings.some((finding) => finding.category === "external" && finding.detail === "https://external.test/path")).toBe(true);
    expect(result.findings.some((finding) => finding.category === "macro" && finding.location === "word/vbaProject.bin")).toBe(true);
    expect(result.extracts.map((extract) => extract.name)).toEqual(expect.arrayContaining(["oleObject1.bin", "vbaProject.bin"]));
  });

  it("rejects ordinary ZIP files and truncated containers", () => {
    const ordinaryZip = zipSync({ "readme.txt": encoder.encode("not an Office package") });
    expect(() => analyzeOoxml(ordinaryZip, "ordinary.zip")).toThrow("not an OOXML package");
    expect(() => analyzeOoxml(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x00]), "truncated.docx")).toThrow();
  });
});

describe("OLE analysis", () => {
  it("enumerates VBA and embedded-object streams", () => {
    const container = CFB.utils.cfb_new();
    CFB.utils.cfb_add(container, "VBA/Module1", encoder.encode("fixture-vba-stream"));
    CFB.utils.cfb_add(container, "ObjectPool/Ole10Native", new Uint8Array([1, 2, 3]));
    const written = CFB.write(container, { type: "array", fileType: "cfb" }) as number[];
    const result = analyzeOle(new Uint8Array(written), "fixture.doc");

    expect(result.entries.some((entry) => /Module1/.test(entry.name))).toBe(true);
    expect(result.findings.some((finding) => finding.category === "macro")).toBe(true);
    expect(result.findings.some((finding) => finding.category === "embedded")).toBe(true);
  });
});
