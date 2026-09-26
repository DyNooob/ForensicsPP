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

import { cardNetwork, classifySpecialIpv4, detectLookupKind, luhnCheck, parseIpv4, validateChineseId, validatePhone } from "./rules";
import type { LookupKind, LookupResult, ResolvedLookupKind } from "./rules";
import { LOOKUP_DATA_CACHE, LOOKUP_DATA_PACKS } from "./dataPacks";

type WorkerRequest = { requestId: number; kind: LookupKind; values: string[]; lang: "zh" | "en" };
type AreaRecord = {
  code: string;
  name: string;
  path: string;
  province: string;
  city: string;
  status: string;
  start_year: string;
  end_year: string;
  new_code: string;
};

let ipData: Uint8Array | null = null;
let phoneData: Uint8Array | null = null;
let areaData: Record<string, AreaRecord[]> | null = null;

function sendProgress(requestId: number, pack: ResolvedLookupKind, state: "loading" | "ready" | "error", detail = "") {
  self.postMessage({ type: "progress", requestId, pack, state, detail });
}

async function fetchPinned(url: string) {
  const request = new Request(url, { mode: "cors" });
  let cache: Cache | null = null;
  if (typeof caches !== "undefined") {
    try {
      cache = await caches.open(LOOKUP_DATA_CACHE);
      const cached = await cache.match(request);
      if (cached) return cached;
    } catch {
      // CacheStorage is an optimization; private browsing, quota limits, or
      // browser policy must not prevent a fresh network lookup.
      cache = null;
    }
  }
  const response = await fetch(request, { cache: "force-cache" });
  if (!response.ok) throw new Error(`data pack request failed (${response.status})`);
  if (cache) {
    try {
      await cache.put(request, response.clone());
    } catch (caught) {
      // Some CDN responses cannot be persisted by CacheStorage. The original
      // response is still valid for this lookup, so keep using it in memory.
      console.warn("Lookup data pack could not be cached", new URL(url).host, caught);
    }
  }
  return response;
}

async function loadPack<T>(requestId: number, pack: ResolvedLookupKind, load: () => Promise<T>) {
  sendProgress(requestId, pack, "loading");
  try {
    return await load();
  } catch (caught) {
    const detail = caught instanceof Error ? caught.message : String(caught);
    sendProgress(requestId, pack, "error", detail);
    throw caught;
  }
}

async function loadIp(requestId: number) {
  if (ipData) return ipData;
  ipData = await loadPack(requestId, "ip", async () => {
    const response = await fetchPinned(LOOKUP_DATA_PACKS.ip.url);
    return new Uint8Array(await response.arrayBuffer());
  });
  sendProgress(requestId, "ip", "ready", `${ipData.byteLength}`);
  return ipData;
}

async function loadPhone(requestId: number) {
  if (phoneData) return phoneData;
  phoneData = await loadPack(requestId, "phone", async () => {
    const response = await fetchPinned(LOOKUP_DATA_PACKS.phone.url);
    return new Uint8Array(await response.arrayBuffer());
  });
  sendProgress(requestId, "phone", "ready", `${phoneData.byteLength}`);
  return phoneData;
}

async function loadAreas(requestId: number) {
  if (areaData) return areaData;
  areaData = await loadPack(requestId, "id", async () => {
    const response = await fetchPinned(LOOKUP_DATA_PACKS.id.url);
    const payload = await response.json() as { areas?: Record<string, AreaRecord[]> };
    if (!payload.areas || typeof payload.areas !== "object") throw new Error("invalid GB/T 2260 data pack");
    return payload.areas;
  });
  sendProgress(requestId, "id", "ready", `${Object.keys(areaData).length}`);
  return areaData;
}

function readUint32LE(data: Uint8Array, offset: number) {
  return new DataView(data.buffer, data.byteOffset + offset, 4).getUint32(0, true);
}

function readUint16LE(data: Uint8Array, offset: number) {
  return new DataView(data.buffer, data.byteOffset + offset, 2).getUint16(0, true);
}

function compareIpv4ToLittleEndian(input: Uint8Array, data: Uint8Array, offset: number) {
  for (let index = 0; index < 4; index += 1) {
    const candidate = data[offset + 3 - index];
    if (input[index] < candidate) return -1;
    if (input[index] > candidate) return 1;
  }
  return 0;
}

function searchIpXdb(data: Uint8Array, ip: Uint8Array) {
  const vectorOffset = 256 + (ip[0] * 256 + ip[1]) * 8;
  if (vectorOffset + 8 > data.length) return "";
  const start = readUint32LE(data, vectorOffset);
  const end = readUint32LE(data, vectorOffset + 4);
  if (!start || !end || end < start) return "";
  const indexSize = 14;
  let low = 0;
  let high = Math.floor((end - start) / indexSize);
  while (low <= high) {
    const middle = (low + high) >> 1;
    const offset = start + middle * indexSize;
    if (offset + indexSize > data.length) break;
    if (compareIpv4ToLittleEndian(ip, data, offset) < 0) high = middle - 1;
    else if (compareIpv4ToLittleEndian(ip, data, offset + 4) > 0) low = middle + 1;
    else {
      const length = readUint16LE(data, offset + 8);
      const pointer = readUint32LE(data, offset + 10);
      if (!length || pointer + length > data.length) return "";
      return new TextDecoder().decode(data.subarray(pointer, pointer + length));
    }
  }
  return "";
}

function phoneCarrier(code: number, lang: "zh" | "en") {
  const zh = ["未知", "中国移动", "中国联通", "中国电信", "中国电信虚拟运营商", "中国联通虚拟运营商", "中国移动虚拟运营商", "中国广电", "中国广电虚拟运营商"];
  const en = ["Unknown", "China Mobile", "China Unicom", "China Telecom", "China Telecom MVNO", "China Unicom MVNO", "China Mobile MVNO", "China Broadnet", "China Broadnet MVNO"];
  return (lang === "zh" ? zh : en)[code] || (lang === "zh" ? "未知" : "Unknown");
}

function searchPhoneDat(data: Uint8Array, phone: string, lang: "zh" | "en") {
  if (data.length < 17) return null;
  const indexStart = readUint32LE(data, 4);
  const count = Math.floor((data.length - indexStart) / 9);
  const prefix = Number(phone.slice(0, 7));
  let low = 0;
  let high = count - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const offset = indexStart + middle * 9;
    const candidate = readUint32LE(data, offset);
    if (prefix < candidate) high = middle - 1;
    else if (prefix > candidate) low = middle + 1;
    else {
      const recordOffset = readUint32LE(data, offset + 4);
      const carrier = phoneCarrier(data[offset + 8], lang);
      let end = recordOffset;
      while (end < data.length && data[end] !== 0) end += 1;
      const [province = "", city = "", zipCode = "", areaCode = ""] = new TextDecoder().decode(data.subarray(recordOffset, end)).split("|");
      return { province, city, zipCode, areaCode, carrier };
    }
  }
  return null;
}

async function lookupIp(input: string, requestId: number, lang: "zh" | "en"): Promise<LookupResult> {
  const normalized = input.trim();
  const ip = parseIpv4(normalized);
  if (!ip) return { input, normalized, kind: "ip", valid: false, matched: false, summary: lang === "zh" ? "IPv4 格式无效" : "Invalid IPv4 address", fields: {}, notes: [lang === "zh" ? "当前离线数据库先支持 IPv4；IPv6 将在后续数据包加入。" : "The current offline pack supports IPv4; IPv6 will follow."], source: "Rule validation", dataVersion: "built-in" };
  const special = classifySpecialIpv4(ip);
  if (special) return { input, normalized, kind: "ip", valid: true, matched: true, summary: special, fields: { scope: special }, notes: [lang === "zh" ? "数据属性：特殊用途地址，无公网地理归属。" : "Data type: special-use address with no public geolocation."], source: "IANA special-use rules", dataVersion: "built-in" };
  const data = await loadIp(requestId);
  const region = searchIpXdb(data, ip);
  const [country = "", province = "", city = "", isp = "", countryCode = ""] = region.split("|").map((part) => part === "0" ? "" : part);
  const summary = [country, province, city].filter(Boolean).join(" / ") || (lang === "zh" ? "未命中" : "No match");
  return { input, normalized, kind: "ip", valid: true, matched: Boolean(region), summary, fields: { country, province, city, isp, countryCode }, notes: [lang === "zh" ? "数据属性：静态网段归属，非实时定位。" : "Data type: static network attribution, not live positioning."], source: LOOKUP_DATA_PACKS.ip.source, dataVersion: LOOKUP_DATA_PACKS.ip.version };
}

async function lookupPhone(input: string, requestId: number, lang: "zh" | "en"): Promise<LookupResult> {
  const rule = validatePhone(input);
  if (!rule.valid) return { input, normalized: rule.normalized, kind: "phone", valid: false, matched: false, summary: lang === "zh" ? "手机号格式无效" : "Invalid mobile number", fields: {}, notes: [], source: "Rule validation", dataVersion: "built-in" };
  const data = await loadPhone(requestId);
  const match = searchPhoneDat(data, rule.normalized, lang);
  return { input, normalized: rule.normalized, kind: "phone", valid: true, matched: Boolean(match), summary: match ? [match.province, match.city, match.carrier].filter(Boolean).join(" / ") : (lang === "zh" ? "号段未命中" : "Prefix not found"), fields: match ?? {}, notes: [lang === "zh" ? "数据属性：原始号段归属；携号转网可能改变当前运营商。" : "Data type: original prefix attribution; number portability may change the current carrier."], source: LOOKUP_DATA_PACKS.phone.source, dataVersion: LOOKUP_DATA_PACKS.phone.version };
}

async function lookupId(input: string, requestId: number, lang: "zh" | "en"): Promise<LookupResult> {
  const rule = validateChineseId(input);
  const fields: Record<string, string> = {
    birthDate: rule.birthDate,
    gender: rule.gender === "male" ? (lang === "zh" ? "男" : "Male") : rule.gender === "female" ? (lang === "zh" ? "女" : "Female") : "--",
    regionCode: rule.regionCode,
    checkCode: rule.checkCode,
    expectedCheckCode: rule.expectedCheckCode
  };
  if (!rule.valid) return { input, normalized: rule.normalized, kind: "id", valid: false, matched: false, summary: lang === "zh" ? "身份证规则校验未通过" : "ID rule validation failed", fields: { ...fields, reason: rule.reason }, notes: [], source: "GB 11643 checksum and date rules", dataVersion: "built-in" };
  const areas = await loadAreas(requestId);
  const history = areas[rule.regionCode] ?? [];
  const area = history.find((record) => record.status === "active") ?? history[history.length - 1];
  if (area) {
    fields.region = area.path || [area.province, area.city, area.name].filter(Boolean).join("/");
    fields.regionStatus = area.status;
    fields.regionYears = [area.start_year, area.end_year || "now"].filter(Boolean).join("–");
    if (area.new_code) fields.newRegionCode = area.new_code;
  }
  return { input, normalized: rule.normalized, kind: "id", valid: true, matched: Boolean(area), summary: area?.path || (lang === "zh" ? "规则有效，区划代码未命中" : "Valid rules; region code not found"), fields, notes: [rule.legacy ? (lang === "zh" ? "15 位旧号码已换算为 18 位格式。" : "Legacy 15-digit ID converted to the 18-digit form.") : "", lang === "zh" ? "校验范围：号码结构、出生日期、顺序码、校验位、行政区划。" : "Validation scope: structure, birth date, sequence, checksum, and administrative division."].filter(Boolean), source: LOOKUP_DATA_PACKS.id.source, dataVersion: LOOKUP_DATA_PACKS.id.version };
}

async function lookupBank(input: string, lang: "zh" | "en"): Promise<LookupResult> {
  const luhn = luhnCheck(input);
  const network = cardNetwork(luhn.normalized);
  if (!/^\d{12,19}$/.test(luhn.normalized)) return { input, normalized: luhn.normalized, kind: "bank", valid: false, matched: false, summary: lang === "zh" ? "银行卡号格式无效" : "Invalid card-number format", fields: { network }, notes: [], source: "Rule validation", dataVersion: "built-in" };
  const bankcard = await import("bankcard");
  const info = bankcard.searchCardBin(luhn.normalized);
  const fields: Record<string, string> = {
    network,
    luhn: luhn.valid ? (lang === "zh" ? "通过" : "Pass") : (lang === "zh" ? "未通过或该卡不采用 Luhn" : "Fail or card does not use Luhn"),
    length: String(luhn.normalized.length)
  };
  if (info) {
    fields.bank = info.bankName;
    fields.bankCode = info.bankCode;
    fields.cardType = info.cardTypeName;
    fields.bin = info.cardBin;
    fields.expectedLength = String(info.len);
  }
  // Rule validity and BIN coverage are separate signals. A Luhn-valid card
  // number must not be reported as invalid merely because this static BIN
  // snapshot has no issuer entry for it.
  const valid = luhn.valid || Boolean(info && info.len === luhn.normalized.length);
  return { input, normalized: luhn.normalized, kind: "bank", valid, matched: Boolean(info), summary: info ? `${info.bankName} / ${info.cardTypeName}` : (lang === "zh" ? `${network} · BIN 未命中` : `${network} · BIN not found`), fields, notes: [lang === "zh" ? "数据范围：发卡机构与卡种。开户支行、开户地、持卡人信息不在 BIN 数据内；部分卡号不采用 Luhn。" : "Data scope: issuer and card type. BIN data excludes account branch, account location, and cardholder details; some cards do not use Luhn."], source: "bankcard 3.1.9 (MIT)", dataVersion: "3.1.9" };
}

async function resolveOne(input: string, kind: LookupKind, requestId: number, lang: "zh" | "en") {
  const resolved = kind === "auto" ? detectLookupKind(input) : kind;
  if (resolved === "ip") return lookupIp(input, requestId, lang);
  if (resolved === "phone") return lookupPhone(input, requestId, lang);
  if (resolved === "id") return lookupId(input, requestId, lang);
  return lookupBank(input, lang);
}

self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const { requestId, kind, values, lang } = event.data;
  try {
    const results: LookupResult[] = [];
    for (let index = 0; index < values.length; index += 1) {
      results.push(await resolveOne(values[index], kind, requestId, lang));
      if (index > 0 && index % 250 === 0) self.postMessage({ type: "batch-progress", requestId, completed: index, total: values.length });
    }
    self.postMessage({ type: "result", requestId, results });
  } catch (caught) {
    self.postMessage({ type: "error", requestId, error: caught instanceof Error ? caught.message : String(caught) });
  }
};
