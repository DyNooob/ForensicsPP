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

const priority = ["DateTimeOriginal", "OffsetTimeOriginal", "CreateDate", "ModifyDate", "Make", "Model", "LensModel", "latitude", "longitude", "GPSLatitude", "GPSLongitude", "GPSAltitude", "Software", "Artist", "Copyright", "ImageDescription", "UserComment", "ImageWidth", "ImageHeight", "ExifImageWidth", "ExifImageHeight", "Orientation", "ExposureTime", "FNumber", "ISO", "FocalLength"];

export function hasMetadataValue(value: unknown): boolean {
  if (value == null) return false;
  if (typeof value === "string") return Boolean(value.trim());
  if (typeof value === "number") return Number.isFinite(value);
  if (value instanceof Date) return Number.isFinite(value.getTime());
  if (ArrayBuffer.isView(value)) return value.byteLength > 0;
  if (Array.isArray(value)) return value.some(hasMetadataValue);
  if (typeof value === "object") return Object.values(value).some(hasMetadataValue);
  return true;
}

export function sortedMetadataEntries(metadata: Record<string, unknown>) {
  const rank = (key: string) => { const index = priority.indexOf(key); return index < 0 ? priority.length : index; };
  return Object.entries(metadata).sort(([a, av], [b, bv]) => Number(hasMetadataValue(bv)) - Number(hasMetadataValue(av)) || rank(a) - rank(b));
}

export function metadataHighlights(metadata: Record<string, unknown>, english: boolean) {
  const rows: Array<{ label: string; value: string; note: string }> = [];
  const text = (key: string) => hasMetadataValue(metadata[key]) ? String(metadata[key]) : "";
  const add = (zh: string, en: string, value: string, zhNote: string, enNote: string) => {
    if (value) rows.push({ label: english ? en : zh, value, note: english ? enNote : zhNote });
  };
  add("拍摄时间", "Captured", text("DateTimeOriginal"), "照片记录的时间；时区以原始字段为准", "Time recorded in the photo; consult the original timezone field");
  add("拍摄设备", "Camera", [text("Make"), text("Model")].filter(Boolean).join(" · "), "照片中记录的品牌与型号", "Make and model recorded in the photo");
  add("镜头", "Lens", text("LensModel"), "拍摄时使用的镜头", "Lens recorded in the photo");
  const lat = metadata.latitude, lon = metadata.longitude;
  if (typeof lat === "number" && Number.isFinite(lat) && Math.abs(lat) <= 90 && typeof lon === "number" && Number.isFinite(lon) && Math.abs(lon) <= 180) {
    add("拍摄位置", "Location", `${lat.toFixed(6)}, ${lon.toFixed(6)}`, "纬度、经度（GPS）；不联网查询地址", "Latitude, longitude (GPS); no online address lookup");
  }
  add("编辑软件", "Software", text("Software"), "记录的软件名称，不能单独证明照片被修改", "Recorded software alone does not prove an image was edited");
  add("作者", "Author", text("Artist") || text("Creator"), "照片中声明的作者", "Author declared in the photo");
  add("图片说明", "Description", text("ImageDescription") || text("UserComment"), "照片附带的文字内容", "Text attached to the photo");
  return rows;
}
