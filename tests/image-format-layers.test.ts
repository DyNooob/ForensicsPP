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

import { describe, it, expect } from "vitest";
import {
  buildFormatLayer,
  parseBmpStructure,
  parseGifStructure,
  parseHeifStructure,
  parseJpegStructure,
  parseTiffStructure,
  parseWebpStructure
} from "../src/features/image/analyzer";

function u16le(arr: number[], n: number) {
  arr.push(n & 0xff, (n >> 8) & 0xff);
}
function u32le(arr: number[], n: number) {
  arr.push(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff);
}
function u32be(arr: number[], n: number) {
  arr.push((n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
}
function str(arr: number[], s: string) {
  for (const c of s) arr.push(c.charCodeAt(0));
}

describe("image format-layer parsers", () => {
  it("parses a GIF89a with two frames, NETSCAPE loop, and a comment", () => {
    const b: number[] = [];
    str(b, "GIF89a");
    u16le(b, 2); u16le(b, 2); // logical screen 2x2
    b.push(0xf7); // GCT present, size 256
    b.push(0, 0); // background index, aspect ratio
    for (let i = 0; i < 256 * 3; i += 1) b.push((i * 7) & 0xff); // global color table
    // NETSCAPE loop extension
    b.push(0x21, 0xff, 0x0b);
    str(b, "NETSCAPE2.0");
    b.push(0x03, 0x01);
    u16le(b, 0); // loop count 0 = infinite
    b.push(0x00);
    // Frame 1 graphic control + image
    b.push(0x21, 0xf9, 0x04, 0x04);
    b.push(0x0a, 0x00); // delay 10 cs
    b.push(0x00, 0x00);
    b.push(0x2c);
    u16le(b, 0); u16le(b, 0); u16le(b, 2); u16le(b, 2);
    b.push(0x00);
    b.push(0x02, 0x01, 0x00, 0x00); // LZW min code size + 1 sub-block + terminator
    // Frame 2 graphic control + image (transparent)
    b.push(0x21, 0xf9, 0x04, 0x05);
    b.push(0x14, 0x00); // delay 20 cs
    b.push(0x00, 0x00);
    b.push(0x2c);
    u16le(b, 0); u16le(b, 0); u16le(b, 2); u16le(b, 2);
    b.push(0x00);
    b.push(0x02, 0x01, 0x00, 0x00);
    // Comment extension
    b.push(0x21, 0xfe, 0x05);
    str(b, "hello");
    b.push(0x00);
    b.push(0x3b); // trailer

    const { gif, findings } = parseGifStructure(new Uint8Array(b));
    expect(gif.version).toBe("GIF89a");
    expect(gif.screenWidth).toBe(2);
    expect(gif.screenHeight).toBe(2);
    expect(gif.globalColorTable).toBe(true);
    expect(gif.frameCount).toBe(2);
    expect(gif.loopCount).toBe(0);
    expect(gif.commentCount).toBe(1);
    expect(gif.comments).toContain("hello");
    expect(gif.applicationExtensions.some((a) => /NETSCAPE/i.test(a))).toBe(true);
    expect(gif.frames[0].delayCentiseconds).toBe(10);
    expect(gif.frames[0].disposalMethod).toBe("leave-in-place");
    expect(gif.frames[1].transparentFlag).toBe(true);
    expect(gif.trailingBytes).toBe(0);
    expect(findings.some((f) => f.title === "GIF comment extension")).toBe(true);
  });

  it("flags data after the GIF trailer", () => {
    const b: number[] = [];
    str(b, "GIF89a");
    u16le(b, 1); u16le(b, 1);
    b.push(0xf7); b.push(0, 0);
    for (let i = 0; i < 256 * 3; i += 1) b.push(0);
    b.push(0x3b);
    b.push(0x41, 0x42, 0x43); // trailing "ABC"
    const { gif, findings } = parseGifStructure(new Uint8Array(b));
    expect(gif.trailingBytes).toBe(3);
    expect(findings.some((f) => f.title === "Data after GIF trailer")).toBe(true);
  });

  it("parses a BMP BITMAPINFOHEADER", () => {
    const b: number[] = [];
    b.push(0x42, 0x4d); // "BM"
    u32le(b, 54); // file size
    u32le(b, 0); // reserved
    u32le(b, 54); // pixel offset
    u32le(b, 40); // DIB header size
    u32le(b, 4); // width
    u32le(b, 4); // height
    b.push(0x01, 0x00); // planes
    b.push(0x18, 0x00); // bpp 24
    u32le(b, 0); // compression
    u32le(b, 0); u32le(b, 0); u32le(b, 0); u32le(b, 0); u32le(b, 0);
    const { bmp } = parseBmpStructure(new Uint8Array(b));
    expect(bmp.dibHeaderType).toBe("BITMAPINFOHEADER");
    expect(bmp.width).toBe(4);
    expect(bmp.height).toBe(4);
    expect(bmp.planes).toBe(1);
    expect(bmp.bpp).toBe(24);
    expect(bmp.compression).toBe(0);
    expect(bmp.compressionName).toContain("BI_RGB");
  });

  it("parses a little-endian TIFF IFD0 with ImageWidth", () => {
    const b: number[] = [];
    str(b, "II");
    u16le(b, 42); // magic
    u32le(b, 8); // IFD0 offset
    b.push(0x01, 0x00); // entry count = 1
    u16le(b, 256); // tag 256 ImageWidth
    u16le(b, 4); // type LONG
    u32le(b, 1); // count
    u32le(b, 4); // value 4
    u32le(b, 0); // next IFD = 0
    const { tiff } = parseTiffStructure(new Uint8Array(b));
    expect(tiff.endian).toBe("little");
    expect(tiff.magic).toBe(42);
    expect(tiff.entryCount).toBe(1);
    expect(tiff.entries[0].tag).toBe(256);
    expect(tiff.entries[0].value).toBe("4");
    expect(tiff.width).toBe(4);
    expect(tiff.height).toBe(null);
  });

  it("parses a minimal HEIF/AVIF ftyp with meta/mdia/ispe", () => {
    // ISO-BMFF (HEIF/AVIF) box sizes, version/flags, and ispe dimensions are
    // big-endian.
    const b: number[] = [];
    u32be(b, 20); // ftyp box size
    str(b, "ftyp");
    str(b, "avif"); // major brand
    u32be(b, 0); // minor version
    str(b, "avif"); // compatible brand
    u32be(b, 8); str(b, "meta"); // meta box (8 bytes)
    u32be(b, 8); str(b, "mdia"); // mdia box (8 bytes)
    u32be(b, 24); str(b, "ispe"); // ispe box: 8 header + 16 payload
    b.push(0, 0, 0, 0); // version/flags
    u32be(b, 8); // image_width
    u32be(b, 6); // image_height
    const { heif } = parseHeifStructure(new Uint8Array(b));
    expect(heif.majorBrand).toBe("avif");
    expect(heif.minorVersion).toBe(0);
    expect(heif.compatibleBrands).toContain("avif");
    expect(heif.hasMeta).toBe(true);
    expect(heif.hasMdia).toBe(true);
    expect(heif.width).toBe(8);
    expect(heif.height).toBe(6);
  });

  it("parses a baseline JPEG marker stream with JFIF and SOF", () => {
    const b: number[] = [];
    b.push(0xff, 0xd8); // SOI
    b.push(0xff, 0xe0); // APP0
    b.push(0x00, 0x10); // length 16
    str(b, "JFIF\0");
    b.push(0x01, 0x01); // version 1.1
    b.push(0x01); // units
    b.push(0x00, 0x48, 0x00, 0x48); // 72x72
    b.push(0x00, 0x00); // thumbnail
    b.push(0xff, 0xc0); // SOF0
    b.push(0x00, 0x11); // length 17
    b.push(0x08); // precision
    b.push(0x00, 0x04); // height 4
    b.push(0x00, 0x04); // width 4
    b.push(0x03); // components
    b.push(0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01);
    b.push(0xff, 0xda); // SOS
    b.push(0x00, 0x08);
    b.push(0x01, 0x01, 0x00, 0x00, 0x3f, 0x00);
    b.push(0xff, 0xd9); // EOI
    const { jpeg } = parseJpegStructure(new Uint8Array(b));
    expect(jpeg.app0?.version).toBe("1.1");
    expect(jpeg.sof?.width).toBe(4);
    expect(jpeg.sof?.height).toBe(4);
    expect(jpeg.sof?.components).toBe(3);
    expect(jpeg.markers.some((m) => m.label === "APP0")).toBe(true);
    expect(jpeg.markers.some((m) => m.label === "SOF")).toBe(true);
    expect(jpeg.hasExif).toBe(false);
    expect(jpeg.hasAdobe).toBe(null);
  });

  it("parses a WEBP VP8X with alpha and animation flags", () => {
    const b: number[] = [];
    str(b, "RIFF");
    u32le(b, 0); // file size placeholder
    str(b, "WEBP");
    str(b, "VP8X");
    u32le(b, 10); // chunk size
    b.push(0x12); // flags: alpha (0x10) + animation (0x02)
    b.push(0x00, 0x00, 0x00); // reserved
    b.push(0x03, 0x00, 0x00); // canvas width - 1 = 3
    b.push(0x03, 0x00, 0x00); // canvas height - 1 = 3
    const fileSize = b.length - 8;
    b[4] = fileSize & 0xff; b[5] = (fileSize >> 8) & 0xff; b[6] = (fileSize >> 16) & 0xff; b[7] = (fileSize >> 24) & 0xff;
    const { webp } = parseWebpStructure(new Uint8Array(b));
    expect(webp.hasVp8x).toBe(true);
    expect(webp.hasAlpha).toBe(true);
    expect(webp.isAnimation).toBe(true);
    expect(webp.canvasWidth).toBe(4);
    expect(webp.canvasHeight).toBe(4);
    expect(webp.chunkCount).toBe(1);
  });

  it("buildFormatLayer dispatches to the correct variant and returns null for unknown formats", () => {
    const gifBytes = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0xf7, 0, 0]);
    const gifLayer = buildFormatLayer(gifBytes, "GIF", new Uint8Array(0), []);
    expect(gifLayer).not.toBeNull();
    expect(gifLayer?.format).toBe("GIF");
    if (gifLayer?.format === "GIF") expect(gifLayer.gif.frameCount).toBe(0);

    const unknown = buildFormatLayer(gifBytes, "ICO", new Uint8Array(0), []);
    expect(unknown).toBeNull();
  });
});
