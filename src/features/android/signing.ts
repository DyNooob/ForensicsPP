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

import { sha256Bytes } from "../../utils/hash";
import type { AndroidSigningCertificate, AndroidSigningInfo, AndroidSigningSigner } from "../../models";

const APK_SIG_MAGIC = "APK Sig Block 42";
const APK_V2_ID = 0x7109871a;
const APK_V3_ID = 0xf05368c0;
const APK_V31_ID = 0x1b93ad61;
const MAX_SIGNING_BLOCK = 64 * 1024 * 1024;
const MAX_SIGNERS = 32;
const MAX_CERTIFICATES = 32;

const signingAttributeLabels: Record<number, string> = {
  0x3ba06f8c: "proof-of-rotation"
};

const signatureAlgorithms: Record<number, string> = {
  0x0101: "RSASSA-PSS SHA-256",
  0x0102: "RSASSA-PSS SHA-512",
  0x0103: "RSA PKCS#1 v1.5 SHA-256",
  0x0104: "RSA PKCS#1 v1.5 SHA-512",
  0x0201: "ECDSA SHA-256",
  0x0202: "ECDSA SHA-512",
  0x0301: "DSA SHA-256",
  0x0421: "verity RSA PKCS#1 v1.5 SHA-256",
  0x0423: "verity ECDSA SHA-256",
  0x0425: "verity DSA SHA-256"
};

type Slice = { start: number; end: number };
type DerNode = { tag: number; start: number; contentStart: number; end: number };

function viewFor(bytes: Uint8Array) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function ascii(bytes: Uint8Array, offset: number, length: number) {
  if (offset < 0 || offset + length > bytes.length) return "";
  return String.fromCharCode(...bytes.subarray(offset, offset + length));
}

function readU32(bytes: Uint8Array, offset: number) {
  if (offset < 0 || offset + 4 > bytes.length) throw new Error("APK signing block is truncated.");
  return viewFor(bytes).getUint32(offset, true);
}

function readU64Number(bytes: Uint8Array, offset: number) {
  if (offset < 0 || offset + 8 > bytes.length) throw new Error("APK signing block is truncated.");
  const value = viewFor(bytes).getBigUint64(offset, true);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("APK signing block length exceeds safe browser integer range.");
  return Number(value);
}

function findEocd(bytes: Uint8Array) {
  const minimum = Math.max(0, bytes.length - 22 - 0xffff);
  for (let offset = bytes.length - 22; offset >= minimum; offset -= 1) {
    if (bytes[offset] !== 0x50 || bytes[offset + 1] !== 0x4b || bytes[offset + 2] !== 0x05 || bytes[offset + 3] !== 0x06) continue;
    const commentLength = viewFor(bytes).getUint16(offset + 20, true);
    if (offset + 22 + commentLength !== bytes.length) continue;
    return offset;
  }
  return -1;
}

function readLengthPrefixed(bytes: Uint8Array, cursor: number, end: number): { slice: Slice; next: number } {
  if (cursor + 4 > end) throw new Error("Length-prefixed APK signer field is truncated.");
  const length = readU32(bytes, cursor);
  const start = cursor + 4;
  const fieldEnd = start + length;
  if (length > MAX_SIGNING_BLOCK || fieldEnd > end || fieldEnd < start) throw new Error("Length-prefixed APK signer field has an invalid size.");
  return { slice: { start, end: fieldEnd }, next: fieldEnd };
}

function iterateLengthPrefixed(bytes: Uint8Array, slice: Slice, limit: number) {
  const result: Slice[] = [];
  let cursor = slice.start;
  while (cursor < slice.end && result.length < limit) {
    const field = readLengthPrefixed(bytes, cursor, slice.end);
    if (field.next <= cursor) throw new Error("APK signer sequence did not advance.");
    result.push(field.slice);
    cursor = field.next;
  }
  if (cursor !== slice.end) throw new Error(result.length >= limit ? "APK signer sequence exceeds safety limit." : "APK signer sequence has trailing bytes.");
  return result;
}

function hex(bytes: Uint8Array, offset: number, length: number, maximum = 64) {
  const visible = bytes.subarray(offset, Math.min(bytes.length, offset + Math.min(length, maximum)));
  return Array.from(visible, (byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join("") + (length > visible.length ? "…" : "");
}

function algorithmName(id: number) {
  return signatureAlgorithms[id] ?? `Unknown (0x${id.toString(16).padStart(4, "0").toUpperCase()})`;
}

function parseAlgorithmRecords(bytes: Uint8Array, sequence: Slice) {
  return iterateLengthPrefixed(bytes, sequence, 64).map((record) => {
    if (record.end - record.start < 4) throw new Error("APK signature algorithm record is truncated.");
    const id = readU32(bytes, record.start);
    const valueField = readLengthPrefixed(bytes, record.start + 4, record.end);
    if (valueField.next !== record.end) throw new Error("APK signature algorithm record has trailing bytes.");
    return {
      id,
      name: algorithmName(id),
      size: valueField.slice.end - valueField.slice.start,
      preview: hex(bytes, valueField.slice.start, valueField.slice.end - valueField.slice.start, 20)
    };
  });
}

function readDerNode(bytes: Uint8Array, offset: number, limit: number): DerNode | null {
  if (offset < 0 || offset + 2 > limit || limit > bytes.length) return null;
  const tag = bytes[offset];
  let cursor = offset + 1;
  const firstLength = bytes[cursor++];
  let length = 0;
  if ((firstLength & 0x80) === 0) length = firstLength;
  else {
    const count = firstLength & 0x7f;
    if (!count || count > 4 || cursor + count > limit) return null;
    for (let index = 0; index < count; index += 1) length = length * 256 + bytes[cursor + index];
    cursor += count;
  }
  const end = cursor + length;
  if (end > limit || end < cursor) return null;
  return { tag, start: offset, contentStart: cursor, end };
}

function derChildren(bytes: Uint8Array, node: DerNode) {
  const output: DerNode[] = [];
  let cursor = node.contentStart;
  while (cursor < node.end && output.length < 256) {
    const child = readDerNode(bytes, cursor, node.end);
    if (!child || child.end <= cursor) return [];
    output.push(child);
    cursor = child.end;
  }
  return cursor === node.end ? output : [];
}

function decodeOid(bytes: Uint8Array, node: DerNode) {
  if (node.tag !== 0x06 || node.contentStart >= node.end) return "";
  const first = bytes[node.contentStart];
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let cursor = node.contentStart + 1; cursor < node.end; cursor += 1) {
    value = value * 128 + (bytes[cursor] & 0x7f);
    if ((bytes[cursor] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

const oidLabels: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "1.2.840.113549.1.9.1": "emailAddress"
};

function decodeDerString(bytes: Uint8Array, node: DerNode) {
  const raw = bytes.subarray(node.contentStart, node.end);
  try {
    if (node.tag === 0x1e) return new TextDecoder("utf-16be").decode(raw);
    if (node.tag === 0x0c) return new TextDecoder("utf-8").decode(raw);
  } catch {
    // Fall back to byte-preserving ASCII-ish decoding below.
  }
  return Array.from(raw, (byte) => byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : "").join("");
}

function decodeName(bytes: Uint8Array, node: DerNode) {
  if (node.tag !== 0x30) return "--";
  const parts: string[] = [];
  for (const set of derChildren(bytes, node)) {
    for (const sequence of derChildren(bytes, set)) {
      const fields = derChildren(bytes, sequence);
      if (fields.length < 2) continue;
      const oid = decodeOid(bytes, fields[0]);
      const value = decodeDerString(bytes, fields[1]);
      if (value) parts.push(`${oidLabels[oid] ?? oid}=${value}`);
    }
  }
  return parts.join(", ") || "--";
}

function decodeTime(bytes: Uint8Array, node: DerNode) {
  const raw = ascii(bytes, node.contentStart, node.end - node.contentStart);
  const utc = raw.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);
  const general = raw.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);
  try {
    if (utc) {
      const yearValue = Number(utc[1]);
      const year = yearValue >= 50 ? 1900 + yearValue : 2000 + yearValue;
      return new Date(Date.UTC(year, Number(utc[2]) - 1, Number(utc[3]), Number(utc[4]), Number(utc[5]), Number(utc[6] ?? 0))).toISOString();
    }
    if (general) return new Date(Date.UTC(Number(general[1]), Number(general[2]) - 1, Number(general[3]), Number(general[4]), Number(general[5]), Number(general[6] ?? 0))).toISOString();
  } catch {
    // Keep the DER time string if a malformed date cannot be normalized.
  }
  return raw || "--";
}

function parseX509Certificate(certificate: Uint8Array): Omit<AndroidSigningCertificate, "sha256" | "size"> {
  const root = readDerNode(certificate, 0, certificate.length);
  if (!root || root.tag !== 0x30 || root.end !== certificate.length) return { subject: "--", issuer: "--", serial: "--", validFrom: "--", validTo: "--" };
  const rootChildren = derChildren(certificate, root);
  const tbs = rootChildren[0];
  if (!tbs || tbs.tag !== 0x30) return { subject: "--", issuer: "--", serial: "--", validFrom: "--", validTo: "--" };
  const fields = derChildren(certificate, tbs);
  let cursor = fields[0]?.tag === 0xa0 ? 1 : 0;
  const serialNode = fields[cursor++];
  cursor += 1; // signature AlgorithmIdentifier
  const issuerNode = fields[cursor++];
  const validityNode = fields[cursor++];
  const subjectNode = fields[cursor++];
  const validity = validityNode ? derChildren(certificate, validityNode) : [];
  return {
    serial: serialNode?.tag === 0x02 ? hex(certificate, serialNode.contentStart, serialNode.end - serialNode.contentStart, 128) : "--",
    issuer: issuerNode ? decodeName(certificate, issuerNode) : "--",
    subject: subjectNode ? decodeName(certificate, subjectNode) : "--",
    validFrom: validity[0] ? decodeTime(certificate, validity[0]) : "--",
    validTo: validity[1] ? decodeTime(certificate, validity[1]) : "--"
  };
}

function parseCertificates(bytes: Uint8Array, sequence: Slice) {
  return iterateLengthPrefixed(bytes, sequence, MAX_CERTIFICATES).map((certificateSlice): AndroidSigningCertificate => {
    const certificate = bytes.subarray(certificateSlice.start, certificateSlice.end);
    return {
      size: certificate.length,
      sha256: sha256Bytes(certificate),
      ...parseX509Certificate(certificate)
    };
  });
}

function parseAdditionalAttributes(bytes: Uint8Array, sequence: Slice) {
  return iterateLengthPrefixed(bytes, sequence, 128).map((attribute) => {
    if (attribute.end - attribute.start < 4) throw new Error("APK signer attribute is truncated.");
    const id = readU32(bytes, attribute.start);
    const label = signingAttributeLabels[id];
    return `0x${id.toString(16).padStart(8, "0").toUpperCase()}${label ? ` ${label}` : ""} (${attribute.end - attribute.start - 4} B)`;
  });
}

function parseSignedData(bytes: Uint8Array, signedData: Slice, scheme: "v2" | "v3" | "v3.1") {
  let cursor = signedData.start;
  const digestsField = readLengthPrefixed(bytes, cursor, signedData.end); cursor = digestsField.next;
  const certificatesField = readLengthPrefixed(bytes, cursor, signedData.end); cursor = certificatesField.next;
  let minSdk: number | null = null;
  let maxSdk: number | null = null;
  if (scheme !== "v2") {
    if (cursor + 8 > signedData.end) throw new Error("APK v3 signed-data SDK range is truncated.");
    minSdk = readU32(bytes, cursor); maxSdk = readU32(bytes, cursor + 4); cursor += 8;
  }
  const attrsField = readLengthPrefixed(bytes, cursor, signedData.end); cursor = attrsField.next;
  if (cursor !== signedData.end) throw new Error(`APK ${scheme} signed-data has trailing bytes.`);
  return {
    digests: parseAlgorithmRecords(bytes, digestsField.slice),
    certificates: parseCertificates(bytes, certificatesField.slice),
    attributes: parseAdditionalAttributes(bytes, attrsField.slice),
    minSdk,
    maxSdk
  };
}

function parseSigner(bytes: Uint8Array, signer: Slice, scheme: "v2" | "v3" | "v3.1", index: number): AndroidSigningSigner {
  let cursor = signer.start;
  const signedDataField = readLengthPrefixed(bytes, cursor, signer.end); cursor = signedDataField.next;
  let minSdk: number | null = null;
  let maxSdk: number | null = null;
  if (scheme !== "v2") {
    if (cursor + 8 > signer.end) throw new Error("APK v3 signer SDK range is truncated.");
    minSdk = readU32(bytes, cursor); maxSdk = readU32(bytes, cursor + 4); cursor += 8;
  }
  const signaturesField = readLengthPrefixed(bytes, cursor, signer.end); cursor = signaturesField.next;
  const publicKeyField = readLengthPrefixed(bytes, cursor, signer.end); cursor = publicKeyField.next;
  if (cursor !== signer.end) throw new Error(`APK ${scheme} signer has trailing bytes.`);

  const signed = parseSignedData(bytes, signedDataField.slice, scheme);
  const notes: string[] = [];
  if (scheme !== "v2" && (signed.minSdk !== minSdk || signed.maxSdk !== maxSdk)) notes.push("Signer SDK range differs from the signed-data SDK range.");
  if (!signed.certificates.length) notes.push("No X.509 certificate was present in signer signed-data.");
  return {
    index,
    scheme,
    minSdk,
    maxSdk,
    digests: signed.digests,
    signatures: parseAlgorithmRecords(bytes, signaturesField.slice),
    certificates: signed.certificates,
    publicKeySize: publicKeyField.slice.end - publicKeyField.slice.start,
    publicKeySha256: sha256Bytes(bytes.subarray(publicKeyField.slice.start, publicKeyField.slice.end)),
    attributes: signed.attributes,
    notes
  };
}

function parseScheme(bytes: Uint8Array, value: Slice, scheme: "v2" | "v3" | "v3.1") {
  const signersField = readLengthPrefixed(bytes, value.start, value.end);
  if (signersField.next !== value.end) throw new Error(`APK ${scheme} scheme block has trailing bytes.`);
  return iterateLengthPrefixed(bytes, signersField.slice, MAX_SIGNERS).map((signer, index) => parseSigner(bytes, signer, scheme, index + 1));
}

export function inspectApkSigningBlock(bytes: Uint8Array): AndroidSigningInfo {
  const empty: AndroidSigningInfo = {
    present: false,
    blockOffset: null,
    blockSize: 0,
    centralDirectoryOffset: null,
    schemes: [],
    signers: [],
    unknownPairIds: [],
    warnings: [],
    verified: false
  };
  try {
    const eocd = findEocd(bytes);
    if (eocd < 0) return { ...empty, warnings: ["ZIP EOCD was not found; APK Signing Block could not be located."] };
    const centralDirectoryOffset = readU32(bytes, eocd + 16);
    if (centralDirectoryOffset < 24 || centralDirectoryOffset > eocd || centralDirectoryOffset > bytes.length) {
      return { ...empty, centralDirectoryOffset, warnings: ["ZIP Central Directory offset is invalid; APK Signing Block was not parsed."] };
    }
    if (ascii(bytes, centralDirectoryOffset - 16, 16) !== APK_SIG_MAGIC) return { ...empty, centralDirectoryOffset };
    const footerSize = readU64Number(bytes, centralDirectoryOffset - 24);
    const totalSize = footerSize + 8;
    if (totalSize < 32 || totalSize > MAX_SIGNING_BLOCK || totalSize > centralDirectoryOffset) throw new Error("APK Signing Block size is invalid or exceeds the safety limit.");
    const blockOffset = centralDirectoryOffset - totalSize;
    const headerSize = readU64Number(bytes, blockOffset);
    if (headerSize !== footerSize) throw new Error("APK Signing Block leading and trailing size fields do not match.");
    const pairsEnd = centralDirectoryOffset - 24;
    const schemes: Array<"v2" | "v3" | "v3.1"> = [];
    const signers: AndroidSigningSigner[] = [];
    const unknownPairIds: string[] = [];
    let cursor = blockOffset + 8;
    while (cursor < pairsEnd) {
      if (cursor + 8 > pairsEnd) throw new Error("APK Signing Block pair length is truncated.");
      const pairLength = readU64Number(bytes, cursor);
      const pairStart = cursor + 8;
      const pairEnd = pairStart + pairLength;
      if (pairLength < 4 || pairEnd > pairsEnd || pairEnd < pairStart) throw new Error("APK Signing Block contains an invalid ID-value pair.");
      const id = readU32(bytes, pairStart);
      const value = { start: pairStart + 4, end: pairEnd };
      if (id === APK_V2_ID) {
        schemes.push("v2");
        signers.push(...parseScheme(bytes, value, "v2"));
      } else if (id === APK_V3_ID) {
        schemes.push("v3");
        signers.push(...parseScheme(bytes, value, "v3"));
      } else if (id === APK_V31_ID) {
        schemes.push("v3.1");
        signers.push(...parseScheme(bytes, value, "v3.1"));
      } else {
        unknownPairIds.push(`0x${id.toString(16).padStart(8, "0").toUpperCase()}`);
      }
      cursor = pairEnd;
    }
    if (cursor !== pairsEnd) throw new Error("APK Signing Block pair area has trailing bytes.");
    return {
      present: true,
      blockOffset,
      blockSize: totalSize,
      centralDirectoryOffset,
      schemes: Array.from(new Set(schemes)),
      signers,
      unknownPairIds: Array.from(new Set(unknownPairIds)),
      warnings: schemes.length ? [] : ["APK Signing Block exists, but no v2/v3 signer block was parsed."],
      verified: false
    };
  } catch (error) {
    return { ...empty, warnings: [error instanceof Error ? error.message : String(error)] };
  }
}
