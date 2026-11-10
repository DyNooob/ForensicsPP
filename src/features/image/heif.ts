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

type IsoBox = { type: string; offset: number; dataOffset: number; end: number };

/** Bounded ISO BMFF box reader, including extended-size and end-of-file boxes. */
export function readIsoBoxes(bytes: Uint8Array, start = 0, end = bytes.length): IsoBox[] {
  const boxes: IsoBox[] = [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let offset = start; offset + 8 <= end && boxes.length < 10000;) {
    const type = String.fromCharCode(...bytes.subarray(offset + 4, offset + 8));
    if (!/^[\x20-\x7e]{4}$/.test(type)) break;
    let size = view.getUint32(offset);
    let header = 8;
    if (size === 1) {
      if (offset + 16 > end) break;
      size = Number(view.getBigUint64(offset + 8));
      header = 16;
    } else if (size === 0) size = end - offset;
    if (!Number.isSafeInteger(size) || size < header || offset + size > end) break;
    boxes.push({ type, offset, dataOffset: offset + header, end: offset + size });
    offset += size;
  }
  return boxes;
}

export function inspectHeif(bytes: Uint8Array) {
  const boxes = readIsoBoxes(bytes);
  const ftyp = boxes.find((box) => box.type === "ftyp");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const ascii = (offset: number) => String.fromCharCode(...bytes.subarray(offset, offset + 4));
  const majorBrand = ftyp && ftyp.dataOffset + 8 <= ftyp.end ? ascii(ftyp.dataOffset) : "";
  const minorVersion = majorBrand && ftyp ? view.getUint32(ftyp.dataOffset + 4) : 0;
  const compatibleBrands: string[] = [];
  if (ftyp) for (let offset = ftyp.dataOffset + 8; offset + 4 <= ftyp.end; offset += 4) compatibleBrands.push(ascii(offset));
  let width = 0, height = 0;
  let remaining = 10000;
  const visit = (items: IsoBox[], depth: number) => {
    if (depth > 8) return;
    for (const box of items) {
      if (--remaining < 0) return;
      if (box.type === "ispe" && box.dataOffset + 12 <= box.end) {
        const w = view.getUint32(box.dataOffset + 4), h = view.getUint32(box.dataOffset + 8);
        // Largest declared item is a conservative pre-decode allocation bound.
        if (w * h > width * height) { width = w; height = h; }
      }
      if (["meta", "iprp", "ipco", "moov", "trak", "mdia"].includes(box.type)) {
        visit(readIsoBoxes(bytes, box.dataOffset + (box.type === "meta" ? 4 : 0), box.end), depth + 1);
      }
    }
  };
  visit(boxes, 0);
  return { majorBrand, minorVersion, compatibleBrands, width, height,
    hasMeta: boxes.some((box) => box.type === "meta"), hasMdia: boxes.some((box) => box.type === "mdia"),
    logicalEnd: boxes[boxes.length - 1]?.end ?? -1,
    isHeif: [majorBrand, ...compatibleBrands].some((brand) => /^(heic|heix|hevc|hevx|heim|heis|hevm|hevs|mif1|msf1|avif|avis)$/.test(brand)) };
}
