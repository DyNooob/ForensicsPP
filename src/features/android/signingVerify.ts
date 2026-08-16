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

import type {
  AndroidSigningInfo,
  AndroidSigningSignerVerification,
  AndroidSigningVerification
} from "../../models";
import { inspectApkSigningBlock } from "./signing";
import { verifyJarV1Signature } from "./v1Verify";

const APK_SIG_MAGIC = "APK Sig Block 42";
const APK_V2_ID = 0x7109871a;
const APK_V3_ID = 0xf05368c0;
const APK_V31_ID = 0x1b93ad61;
const CHUNK_SIZE = 1024 * 1024;
const MAX_SIGNERS = 32;
const MAX_RECORDS = 128;

type Slice = { start: number; end: number };
type RawRecord = { id: number; value: Uint8Array };
type RawSigner = {
  scheme: "v2" | "v3" | "v3.1";
  index: number;
  signedData: Uint8Array;
  digests: RawRecord[];
  signatures: RawRecord[];
  certificates: Uint8Array[];
  publicKey: Uint8Array;
  minSdk: number | null;
  maxSdk: number | null;
  signedMinSdk: number | null;
  signedMaxSdk: number | null;
};
type ApkLayout = {
  eocdOffset: number;
  centralDirectoryOffset: number;
  blockOffset: number;
  blockEnd: number;
  signers: RawSigner[];
};

type DerNode = { tag: number; start: number; contentStart: number; end: number };

function viewFor(bytes: Uint8Array) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function ascii(bytes: Uint8Array, offset: number, length: number) {
  if (offset < 0 || offset + length > bytes.length) return "";
  return String.fromCharCode(...bytes.subarray(offset, offset + length));
}

function readU32(bytes: Uint8Array, offset: number) {
  if (offset < 0 || offset + 4 > bytes.length) throw new Error("APK signature structure is truncated.");
  return viewFor(bytes).getUint32(offset, true);
}

function readU64Number(bytes: Uint8Array, offset: number) {
  if (offset < 0 || offset + 8 > bytes.length) throw new Error("APK signature structure is truncated.");
  const value = viewFor(bytes).getBigUint64(offset, true);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("APK signature structure exceeds safe browser integer range.");
  return Number(value);
}

function findEocd(bytes: Uint8Array) {
  const minimum = Math.max(0, bytes.length - 22 - 0xffff);
  for (let offset = bytes.length - 22; offset >= minimum; offset -= 1) {
    if (bytes[offset] !== 0x50 || bytes[offset + 1] !== 0x4b || bytes[offset + 2] !== 0x05 || bytes[offset + 3] !== 0x06) continue;
    const commentLength = viewFor(bytes).getUint16(offset + 20, true);
    if (offset + 22 + commentLength === bytes.length) return offset;
  }
  return -1;
}

function readLengthPrefixed(bytes: Uint8Array, cursor: number, end: number) {
  if (cursor + 4 > end) throw new Error("Length-prefixed APK field is truncated.");
  const length = readU32(bytes, cursor);
  const start = cursor + 4;
  const fieldEnd = start + length;
  if (fieldEnd < start || fieldEnd > end) throw new Error("Length-prefixed APK field has an invalid size.");
  return { slice: { start, end: fieldEnd }, next: fieldEnd };
}

function iterateLengthPrefixed(bytes: Uint8Array, slice: Slice, limit = MAX_RECORDS) {
  const output: Slice[] = [];
  let cursor = slice.start;
  while (cursor < slice.end && output.length < limit) {
    const field = readLengthPrefixed(bytes, cursor, slice.end);
    if (field.next <= cursor) throw new Error("APK sequence did not advance.");
    output.push(field.slice);
    cursor = field.next;
  }
  if (cursor !== slice.end) throw new Error(output.length >= limit ? "APK sequence exceeds safety limit." : "APK sequence has trailing bytes.");
  return output;
}

function rawAlgorithmRecords(bytes: Uint8Array, sequence: Slice) {
  return iterateLengthPrefixed(bytes, sequence).map((record): RawRecord => {
    if (record.end - record.start < 8) throw new Error("APK algorithm record is truncated.");
    const id = readU32(bytes, record.start);
    const value = readLengthPrefixed(bytes, record.start + 4, record.end);
    if (value.next !== record.end) throw new Error("APK algorithm record has trailing bytes.");
    return { id, value: bytes.slice(value.slice.start, value.slice.end) };
  });
}

function rawCertificates(bytes: Uint8Array, sequence: Slice) {
  return iterateLengthPrefixed(bytes, sequence, 32).map((item) => bytes.slice(item.start, item.end));
}

function parseRawSignedData(bytes: Uint8Array, signedData: Slice, scheme: "v2" | "v3" | "v3.1") {
  let cursor = signedData.start;
  const digests = readLengthPrefixed(bytes, cursor, signedData.end); cursor = digests.next;
  const certificates = readLengthPrefixed(bytes, cursor, signedData.end); cursor = certificates.next;
  let minSdk: number | null = null;
  let maxSdk: number | null = null;
  if (scheme !== "v2") {
    if (cursor + 8 > signedData.end) throw new Error("APK v3 signed-data SDK range is truncated.");
    minSdk = readU32(bytes, cursor);
    maxSdk = readU32(bytes, cursor + 4);
    cursor += 8;
  }
  const attrs = readLengthPrefixed(bytes, cursor, signedData.end); cursor = attrs.next;
  if (cursor !== signedData.end) throw new Error(`APK ${scheme} signed-data has trailing bytes.`);
  void attrs;
  return {
    digests: rawAlgorithmRecords(bytes, digests.slice),
    certificates: rawCertificates(bytes, certificates.slice),
    minSdk,
    maxSdk
  };
}

function parseRawSigner(bytes: Uint8Array, signer: Slice, scheme: "v2" | "v3" | "v3.1", index: number): RawSigner {
  let cursor = signer.start;
  const signedDataField = readLengthPrefixed(bytes, cursor, signer.end); cursor = signedDataField.next;
  let minSdk: number | null = null;
  let maxSdk: number | null = null;
  if (scheme !== "v2") {
    if (cursor + 8 > signer.end) throw new Error("APK v3 signer SDK range is truncated.");
    minSdk = readU32(bytes, cursor);
    maxSdk = readU32(bytes, cursor + 4);
    cursor += 8;
  }
  const signatures = readLengthPrefixed(bytes, cursor, signer.end); cursor = signatures.next;
  const publicKey = readLengthPrefixed(bytes, cursor, signer.end); cursor = publicKey.next;
  if (cursor !== signer.end) throw new Error(`APK ${scheme} signer has trailing bytes.`);
  const signed = parseRawSignedData(bytes, signedDataField.slice, scheme);
  return {
    scheme,
    index,
    signedData: bytes.slice(signedDataField.slice.start, signedDataField.slice.end),
    digests: signed.digests,
    signatures: rawAlgorithmRecords(bytes, signatures.slice),
    certificates: signed.certificates,
    publicKey: bytes.slice(publicKey.slice.start, publicKey.slice.end),
    minSdk,
    maxSdk,
    signedMinSdk: signed.minSdk,
    signedMaxSdk: signed.maxSdk
  };
}

function parseRawScheme(bytes: Uint8Array, value: Slice, scheme: "v2" | "v3" | "v3.1") {
  const signers = readLengthPrefixed(bytes, value.start, value.end);
  if (signers.next !== value.end) throw new Error(`APK ${scheme} scheme block has trailing bytes.`);
  return iterateLengthPrefixed(bytes, signers.slice, MAX_SIGNERS).map((signer, index) => parseRawSigner(bytes, signer, scheme, index + 1));
}

function locateApk(bytes: Uint8Array): ApkLayout {
  const eocdOffset = findEocd(bytes);
  if (eocdOffset < 0) throw new Error("ZIP EOCD was not found.");
  const centralDirectoryOffset = readU32(bytes, eocdOffset + 16);
  if (centralDirectoryOffset < 24 || centralDirectoryOffset > eocdOffset) throw new Error("ZIP Central Directory offset is invalid.");
  if (ascii(bytes, centralDirectoryOffset - 16, 16) !== APK_SIG_MAGIC) throw new Error("APK Signing Block was not found.");
  const footerSize = readU64Number(bytes, centralDirectoryOffset - 24);
  const totalSize = footerSize + 8;
  const blockOffset = centralDirectoryOffset - totalSize;
  if (blockOffset < 0 || readU64Number(bytes, blockOffset) !== footerSize) throw new Error("APK Signing Block size fields do not match.");
  const pairsEnd = centralDirectoryOffset - 24;
  const signers: RawSigner[] = [];
  let cursor = blockOffset + 8;
  while (cursor < pairsEnd) {
    const pairLength = readU64Number(bytes, cursor);
    const pairStart = cursor + 8;
    const pairEnd = pairStart + pairLength;
    if (pairLength < 4 || pairEnd > pairsEnd || pairEnd < pairStart) throw new Error("APK Signing Block pair is malformed.");
    const id = readU32(bytes, pairStart);
    const value = { start: pairStart + 4, end: pairEnd };
    if (id === APK_V2_ID) signers.push(...parseRawScheme(bytes, value, "v2"));
    if (id === APK_V3_ID) signers.push(...parseRawScheme(bytes, value, "v3"));
    if (id === APK_V31_ID) signers.push(...parseRawScheme(bytes, value, "v3.1"));
    cursor = pairEnd;
  }
  return { eocdOffset, centralDirectoryOffset, blockOffset, blockEnd: centralDirectoryOffset, signers };
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
  return end <= limit && end >= cursor ? { tag, start: offset, contentStart: cursor, end } : null;
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
    if ((bytes[cursor] & 0x80) === 0) { parts.push(value); value = 0; }
  }
  return parts.join(".");
}

function certificateSpki(certificate: Uint8Array) {
  const root = readDerNode(certificate, 0, certificate.length);
  if (!root || root.tag !== 0x30 || root.end !== certificate.length) return null;
  const tbs = derChildren(certificate, root)[0];
  if (!tbs || tbs.tag !== 0x30) return null;
  const fields = derChildren(certificate, tbs);
  let cursor = fields[0]?.tag === 0xa0 ? 1 : 0;
  cursor += 5; // serial, signature, issuer, validity, subject
  const spki = fields[cursor];
  return spki?.tag === 0x30 ? certificate.slice(spki.start, spki.end) : null;
}

function curveForSpki(spki: Uint8Array) {
  const root = readDerNode(spki, 0, spki.length);
  const children = root ? derChildren(spki, root) : [];
  const algorithm = children[0];
  const parts = algorithm ? derChildren(spki, algorithm) : [];
  const curveOid = parts[1] ? decodeOid(spki, parts[1]) : "";
  if (curveOid === "1.2.840.10045.3.1.7") return { name: "P-256", bytes: 32 };
  if (curveOid === "1.3.132.0.34") return { name: "P-384", bytes: 48 };
  if (curveOid === "1.3.132.0.35") return { name: "P-521", bytes: 66 };
  return null;
}

function equalBytes(left: Uint8Array, right: Uint8Array) {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) diff |= left[index] ^ right[index];
  return diff === 0;
}

function concatBytes(parts: Uint8Array[]) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(total);
  let cursor = 0;
  for (const part of parts) { output.set(part, cursor); cursor += part.length; }
  return output;
}

function u32le(value: number) {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, true);
  return output;
}

async function digest(hash: "SHA-256" | "SHA-512", bytes: Uint8Array) {
  const copy = Uint8Array.from(bytes);
  return new Uint8Array(await crypto.subtle.digest(hash, copy.buffer));
}

async function apkContentDigest(bytes: Uint8Array, layout: ApkLayout, hash: "SHA-256" | "SHA-512") {
  const eocd = bytes.slice(layout.eocdOffset);
  new DataView(eocd.buffer, eocd.byteOffset, eocd.byteLength).setUint32(16, layout.blockOffset, true);
  const sections = [
    bytes.subarray(0, layout.blockOffset),
    bytes.subarray(layout.centralDirectoryOffset, layout.eocdOffset),
    eocd
  ];
  const chunkDigests: Uint8Array[] = [];
  for (const section of sections) {
    for (let offset = 0; offset < section.length; offset += CHUNK_SIZE) {
      const chunk = section.subarray(offset, Math.min(section.length, offset + CHUNK_SIZE));
      chunkDigests.push(await digest(hash, concatBytes([new Uint8Array([0xa5]), u32le(chunk.length), chunk])));
    }
  }
  return digest(hash, concatBytes([new Uint8Array([0x5a]), u32le(chunkDigests.length), ...chunkDigests]));
}

type SupportedAlgorithm = {
  id: number;
  hash: "SHA-256" | "SHA-512";
  strength: number;
  key: "rsa-pkcs1" | "rsa-pss" | "ecdsa";
  saltLength?: number;
};

const supportedAlgorithms: Record<number, SupportedAlgorithm> = {
  0x0101: { id: 0x0101, hash: "SHA-256", strength: 230, key: "rsa-pss", saltLength: 32 },
  0x0102: { id: 0x0102, hash: "SHA-512", strength: 330, key: "rsa-pss", saltLength: 64 },
  0x0103: { id: 0x0103, hash: "SHA-256", strength: 220, key: "rsa-pkcs1" },
  0x0104: { id: 0x0104, hash: "SHA-512", strength: 320, key: "rsa-pkcs1" },
  0x0201: { id: 0x0201, hash: "SHA-256", strength: 240, key: "ecdsa" },
  0x0202: { id: 0x0202, hash: "SHA-512", strength: 340, key: "ecdsa" }
};

function algorithmName(id: number) {
  const names: Record<number, string> = {
    0x0101: "RSASSA-PSS SHA-256",
    0x0102: "RSASSA-PSS SHA-512",
    0x0103: "RSA PKCS#1 v1.5 SHA-256",
    0x0104: "RSA PKCS#1 v1.5 SHA-512",
    0x0201: "ECDSA SHA-256",
    0x0202: "ECDSA SHA-512"
  };
  return names[id] ?? `0x${id.toString(16).padStart(4, "0")}`;
}


export type AndroidApkSigningMaterial = {
  scheme: "v2" | "v3" | "v3.1";
  signerIndex: number;
  certificates: Uint8Array[];
  publicKey: Uint8Array;
  digests: Array<{ id: number; value: Uint8Array }>;
};

export function getApkSigningMaterials(bytes: Uint8Array): AndroidApkSigningMaterial[] {
  return locateApk(bytes).signers.map((signer) => ({
    scheme: signer.scheme,
    signerIndex: signer.index,
    certificates: signer.certificates.map((certificate) => Uint8Array.from(certificate)),
    publicKey: Uint8Array.from(signer.publicKey),
    digests: signer.digests.map((record) => ({ id: record.id, value: Uint8Array.from(record.value) }))
  }));
}

export function getCertificateSpki(certificate: Uint8Array) {
  const value = certificateSpki(certificate);
  return value ? Uint8Array.from(value) : null;
}

export function getApkSignatureAlgorithmName(id: number) {
  return algorithmName(id);
}

export async function verifyApkSignatureAlgorithm(id: number, spki: Uint8Array, signature: Uint8Array, signedData: Uint8Array) {
  const algorithm = supportedAlgorithms[id];
  if (!algorithm) throw new Error(`Unsupported APK signature algorithm 0x${id.toString(16)}.`);
  return verifySignedData(algorithm, spki, signature, signedData);
}

function derIntegerToFixed(bytes: Uint8Array, node: DerNode, width: number) {
  let raw = bytes.subarray(node.contentStart, node.end);
  while (raw.length > 1 && raw[0] === 0) raw = raw.subarray(1);
  if (raw.length > width) return null;
  const output = new Uint8Array(width);
  output.set(raw, width - raw.length);
  return output;
}

function ecdsaDerToRaw(signature: Uint8Array, width: number) {
  const root = readDerNode(signature, 0, signature.length);
  const children = root ? derChildren(signature, root) : [];
  if (!root || root.tag !== 0x30 || root.end !== signature.length || children.length !== 2 || children.some((node) => node.tag !== 0x02)) return null;
  const r = derIntegerToFixed(signature, children[0], width);
  const s = derIntegerToFixed(signature, children[1], width);
  return r && s ? concatBytes([r, s]) : null;
}

async function verifySignedData(algorithm: SupportedAlgorithm, spki: Uint8Array, signature: Uint8Array, signedData: Uint8Array) {
  const data = Uint8Array.from(signedData);
  const sig = Uint8Array.from(signature);
  if (algorithm.key === "rsa-pkcs1") {
    const key = await crypto.subtle.importKey("spki", Uint8Array.from(spki).buffer, { name: "RSASSA-PKCS1-v1_5", hash: algorithm.hash }, false, ["verify"]);
    return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, sig.buffer, data.buffer);
  }
  if (algorithm.key === "rsa-pss") {
    const key = await crypto.subtle.importKey("spki", Uint8Array.from(spki).buffer, { name: "RSA-PSS", hash: algorithm.hash }, false, ["verify"]);
    return crypto.subtle.verify({ name: "RSA-PSS", saltLength: algorithm.saltLength ?? 32 }, key, sig.buffer, data.buffer);
  }
  const curve = curveForSpki(spki);
  if (!curve) throw new Error("Unsupported or unrecognized ECDSA curve.");
  const key = await crypto.subtle.importKey("spki", Uint8Array.from(spki).buffer, { name: "ECDSA", namedCurve: curve.name }, false, ["verify"]);
  const raw = ecdsaDerToRaw(sig, curve.bytes);
  if (raw && await crypto.subtle.verify({ name: "ECDSA", hash: algorithm.hash }, key, raw.buffer, data.buffer)) return true;
  return crypto.subtle.verify({ name: "ECDSA", hash: algorithm.hash }, key, sig.buffer, data.buffer).catch(() => false);
}

async function verifySigner(bytes: Uint8Array, layout: ApkLayout, signer: RawSigner, digestCache: Map<string, Promise<Uint8Array>>): Promise<AndroidSigningSignerVerification> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const certificateSpkiBytes = signer.certificates[0] ? certificateSpki(signer.certificates[0]) : null;
  const publicKeyMatchesCertificate = Boolean(certificateSpkiBytes && equalBytes(certificateSpkiBytes, signer.publicKey));
  if (!signer.certificates.length) errors.push("Signer contains no certificate.");
  else if (!certificateSpkiBytes) errors.push("The first signer certificate SubjectPublicKeyInfo could not be parsed.");
  else if (!publicKeyMatchesCertificate) errors.push("Signer public key does not match the first X.509 certificate public key.");
  if (signer.scheme !== "v2" && (signer.minSdk !== signer.signedMinSdk || signer.maxSdk !== signer.signedMaxSdk)) {
    errors.push("v3 signer SDK range differs from the range protected by signed-data.");
  }

  const digestIds = signer.digests.map((item) => item.id);
  const signatureIds = signer.signatures.map((item) => item.id);
  if (digestIds.length !== signatureIds.length || digestIds.some((id, index) => id !== signatureIds[index])) {
    errors.push("Digest and signature algorithm ID sequences do not match.");
  }

  const candidates = signer.signatures
    .map((record) => ({ record, algorithm: supportedAlgorithms[record.id] }))
    .filter((item): item is { record: RawRecord; algorithm: SupportedAlgorithm } => Boolean(item.algorithm))
    .sort((left, right) => right.algorithm.strength - left.algorithm.strength);
  if (!candidates.length) errors.push("No browser-supported v2/v3 signature algorithm was found (RSA/ECDSA SHA-256/SHA-512 are supported).");

  let signatureVerified = false;
  let contentDigestVerified = false;
  let selectedAlgorithmId: number | null = null;
  let selectedAlgorithm = "--";
  let expectedDigest = "";
  let actualDigest = "";

  if (candidates.length && certificateSpkiBytes && publicKeyMatchesCertificate) {
    const selected = candidates[0];
    selectedAlgorithmId = selected.algorithm.id;
    selectedAlgorithm = algorithmName(selected.algorithm.id);
    try {
      signatureVerified = await verifySignedData(selected.algorithm, signer.publicKey, selected.record.value, signer.signedData);
      if (!signatureVerified) errors.push(`${selectedAlgorithm} signature over signer signed-data did not verify.`);
    } catch (error) {
      errors.push(`Signature verification failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    const digestRecord = signer.digests.find((record) => record.id === selected.algorithm.id);
    if (!digestRecord) errors.push(`No content digest record exists for ${selectedAlgorithm}.`);
    else {
      expectedDigest = Array.from(digestRecord.value, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
      try {
        const cacheKey = selected.algorithm.hash;
        if (!digestCache.has(cacheKey)) digestCache.set(cacheKey, apkContentDigest(bytes, layout, selected.algorithm.hash));
        const calculated = await digestCache.get(cacheKey)!;
        actualDigest = Array.from(calculated, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
        contentDigestVerified = equalBytes(calculated, digestRecord.value);
        if (!contentDigestVerified) errors.push(`${selected.algorithm.hash} APK content digest does not match signed-data.`);
      } catch (error) {
        errors.push(`APK content digest calculation failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  for (const record of signer.signatures) if (!supportedAlgorithms[record.id]) warnings.push(`Signature algorithm 0x${record.id.toString(16)} is not verified by the browser verifier.`);
  const verified = signatureVerified && contentDigestVerified && publicKeyMatchesCertificate && !errors.length;
  return {
    scheme: signer.scheme,
    signerIndex: signer.index,
    verified,
    signatureVerified,
    contentDigestVerified,
    publicKeyMatchesCertificate,
    selectedAlgorithmId,
    selectedAlgorithm,
    expectedDigest,
    actualDigest,
    errors,
    warnings
  };
}

export async function verifyApkSignatures(bytes: Uint8Array, parsed?: AndroidSigningInfo): Promise<AndroidSigningInfo> {
  const signing = parsed ?? inspectApkSigningBlock(bytes);
  const started = Date.now();
  const jarV1 = await verifyJarV1Signature(bytes);
  if (!signing.present || !signing.schemes.length) {
    if (jarV1.present) {
      const verification: AndroidSigningVerification = {
        status: jarV1.verified ? "verified" : "failed",
        verified: jarV1.verified,
        checkedSchemes: ["v1"],
        durationMs: Date.now() - started,
        signerResults: [],
        jarV1,
        errors: jarV1.errors,
        warnings: [...jarV1.warnings, "APK Signature Scheme v4 requires a separate .idsig companion file and is not embedded in the APK."]
      };
      return { ...signing, verified: verification.verified, verification };
    }
    const verification: AndroidSigningVerification = {
      status: "not-signed",
      verified: false,
      checkedSchemes: [],
      durationMs: Date.now() - started,
      signerResults: [],
      jarV1,
      errors: ["No APK Signature Scheme v1/v2/v3 signature is available for cryptographic verification."],
      warnings: ["APK Signature Scheme v4 requires a separate .idsig companion file and is not embedded in the APK."]
    };
    return { ...signing, verified: false, verification };
  }
  try {
    const layout = locateApk(bytes);
    const digestCache = new Map<string, Promise<Uint8Array>>();
    const signerResults: AndroidSigningSignerVerification[] = [];
    for (const signer of layout.signers) signerResults.push(await verifySigner(bytes, layout, signer, digestCache));
    const errors = signerResults.flatMap((result) => result.errors.map((message) => `${result.scheme} signer ${result.signerIndex}: ${message}`));
    const warnings = signerResults.flatMap((result) => result.warnings.map((message) => `${result.scheme} signer ${result.signerIndex}: ${message}`));
    if (jarV1.present) {
      errors.push(...jarV1.errors.map((message) => `v1/JAR: ${message}`));
      warnings.push(...jarV1.warnings.map((message) => `v1/JAR: ${message}`));
      if (!jarV1.verified) errors.push("v1/JAR signature is present but did not verify.");
      if (jarV1.signerCertificateSha256) {
        const signingCertificates = new Set(signing.signers.flatMap((signer) => signer.certificates.map((certificate) => certificate.sha256.toUpperCase())));
        if (signingCertificates.size && !signingCertificates.has(jarV1.signerCertificateSha256.toUpperCase())) errors.push("v1/JAR signer certificate does not match the v2/v3 signer certificate identity.");
      }
    }
    warnings.push("APK Signature Scheme v4 is stored in a separate .idsig companion file; this APK-only verifier cannot validate v4 without that file.");
    const verified = signerResults.length > 0 && signerResults.every((result) => result.verified) && (!jarV1.present || jarV1.verified) && !errors.length;
    const checkedSchemes: Array<"v1" | "v2" | "v3" | "v3.1"> = [...(jarV1.present ? ["v1" as const] : []), ...Array.from(new Set(signerResults.map((result) => result.scheme)))];
    const verification: AndroidSigningVerification = {
      status: verified ? "verified" : "failed",
      verified,
      checkedSchemes,
      durationMs: Date.now() - started,
      signerResults,
      jarV1,
      errors,
      warnings
    };
    return { ...signing, verified, verification };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ...signing,
      verified: false,
      verification: {
        status: "failed",
        verified: false,
        checkedSchemes: jarV1.present ? ["v1"] : [],
        durationMs: Date.now() - started,
        signerResults: [],
        jarV1,
        errors: [message, ...jarV1.errors],
        warnings: [...jarV1.warnings, "APK Signature Scheme v4 requires a separate .idsig companion file and is not embedded in the APK."]
      }
    };
  }
}
