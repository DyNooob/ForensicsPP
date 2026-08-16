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

import { unzipSync, zipSync } from "fflate";
import { validateZipExpansion } from "../archive/zipDirectory";
import { inspectApkSigningBlock } from "./signing";
import { verifyApkSignatures } from "./signingVerify";
import type { AndroidSigningInfo } from "../../models";

const APK_SIG_MAGIC = new TextEncoder().encode("APK Sig Block 42");
const APK_V2_ID = 0x7109871a;
const APK_ALG_RSA_PKCS1_SHA256 = 0x0103;
const CHUNK_SIZE = 1024 * 1024;

export type ApkRepairIdentity = {
  privateKey: CryptoKey;
  certificate: Uint8Array;
  publicKeySpki: Uint8Array;
  privateKeyPkcs8?: Uint8Array;
  label: string;
  generated: boolean;
};

export type ApkRepairResult = {
  bytes: Uint8Array;
  signing: AndroidSigningInfo;
  identity: ApkRepairIdentity;
  removedExistingSigningBlock: boolean;
  strippedJarSignatures: string[];
  rebuiltZip: boolean;
  warnings: string[];
};

function viewFor(bytes: Uint8Array) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
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

function u32le(value: number) {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, true);
  return output;
}

function u64le(value: number) {
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, BigInt(value), true);
  return output;
}

function concatBytes(parts: Uint8Array[]) {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let cursor = 0;
  for (const part of parts) { output.set(part, cursor); cursor += part.length; }
  return output;
}

function lp(bytes: Uint8Array) {
  return concatBytes([u32le(bytes.length), bytes]);
}

function equalBytes(left: Uint8Array, right: Uint8Array) {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) diff |= left[index] ^ right[index];
  return diff === 0;
}

async function digest(hash: "SHA-256", bytes: Uint8Array) {
  const copy = Uint8Array.from(bytes);
  return new Uint8Array(await crypto.subtle.digest(hash, copy.buffer));
}

async function chunkedDigestUnsignedApk(bytes: Uint8Array) {
  const eocdOffset = findEocd(bytes);
  if (eocdOffset < 0) throw new Error("ZIP EOCD was not found.");
  const centralDirectoryOffset = viewFor(bytes).getUint32(eocdOffset + 16, true);
  if (centralDirectoryOffset > eocdOffset || centralDirectoryOffset < 0) throw new Error("ZIP Central Directory offset is invalid.");
  const sections = [bytes.subarray(0, centralDirectoryOffset), bytes.subarray(centralDirectoryOffset, eocdOffset), bytes.subarray(eocdOffset)];
  const chunks: Uint8Array[] = [];
  for (const section of sections) {
    for (let offset = 0; offset < section.length; offset += CHUNK_SIZE) {
      const chunk = section.subarray(offset, Math.min(section.length, offset + CHUNK_SIZE));
      chunks.push(await digest("SHA-256", concatBytes([new Uint8Array([0xa5]), u32le(chunk.length), chunk])));
    }
  }
  return digest("SHA-256", concatBytes([new Uint8Array([0x5a]), u32le(chunks.length), ...chunks]));
}

function stripExistingSigningBlock(bytes: Uint8Array) {
  const info = inspectApkSigningBlock(bytes);
  if (!info.present || info.blockOffset == null || info.centralDirectoryOffset == null) return { bytes, removed: false };
  const eocdOffset = findEocd(bytes);
  if (eocdOffset < 0) throw new Error("ZIP EOCD was not found while removing the existing APK Signing Block.");
  const blockSize = info.centralDirectoryOffset - info.blockOffset;
  const output = concatBytes([bytes.subarray(0, info.blockOffset), bytes.subarray(info.centralDirectoryOffset)]);
  const newEocdOffset = eocdOffset - blockSize;
  new DataView(output.buffer, output.byteOffset, output.byteLength).setUint32(newEocdOffset + 16, info.blockOffset, true);
  return { bytes: output, removed: true };
}

const jarSignaturePattern = /^META-INF\/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))$/i;

function stripJarSignatures(bytes: Uint8Array) {
  validateZipExpansion(bytes, {
    maxEntries: 12_000,
    maxEntryUncompressed: 128 * 1024 * 1024,
    maxTotalUncompressed: 512 * 1024 * 1024,
    maxCompressionRatio: 500,
    ratioGuardMinimum: 16 * 1024 * 1024
  });
  const files = unzipSync(bytes);
  const removed = Object.keys(files).filter((name) => jarSignaturePattern.test(name));
  if (!removed.length) return { bytes, removed, rebuilt: false };
  for (const name of removed) delete files[name];
  return { bytes: zipSync(files, { level: 6 }), removed, rebuilt: true };
}

function encodeLength(length: number) {
  if (length < 0x80) return new Uint8Array([length]);
  const bytes: number[] = [];
  let value = length;
  while (value > 0) { bytes.unshift(value & 0xff); value = Math.floor(value / 256); }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function der(tag: number, content: Uint8Array) {
  return concatBytes([new Uint8Array([tag]), encodeLength(content.length), content]);
}

function derSequence(...items: Uint8Array[]) { return der(0x30, concatBytes(items)); }
function derSet(...items: Uint8Array[]) { return der(0x31, concatBytes(items)); }
function derNull() { return der(0x05, new Uint8Array()); }
function derUtf8(value: string) { return der(0x0c, new TextEncoder().encode(value)); }
function derBitString(value: Uint8Array) { return der(0x03, concatBytes([new Uint8Array([0]), value])); }

function oidBytes(oid: string) {
  const parts = oid.split(".").map(Number);
  if (parts.length < 2) throw new Error("OID is invalid.");
  const output = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    if (!Number.isFinite(part) || part < 0) throw new Error("OID is invalid.");
    const stack = [part & 0x7f];
    let value = Math.floor(part / 128);
    while (value) { stack.unshift((value & 0x7f) | 0x80); value = Math.floor(value / 128); }
    output.push(...stack);
  }
  return new Uint8Array(output);
}

function derOid(oid: string) { return der(0x06, oidBytes(oid)); }

function derIntegerBytes(rawValue: Uint8Array) {
  let raw = rawValue;
  while (raw.length > 1 && raw[0] === 0) raw = raw.subarray(1);
  if (raw[0] & 0x80) raw = concatBytes([new Uint8Array([0]), raw]);
  return der(0x02, raw);
}

function derInteger(value: number) {
  const bytes: number[] = [];
  let current = value;
  do { bytes.unshift(current & 0xff); current = Math.floor(current / 256); } while (current > 0);
  return derIntegerBytes(new Uint8Array(bytes));
}

function utcTime(date: Date) {
  const yy = String(date.getUTCFullYear() % 100).padStart(2, "0");
  const value = `${yy}${String(date.getUTCMonth() + 1).padStart(2, "0")}${String(date.getUTCDate()).padStart(2, "0")}${String(date.getUTCHours()).padStart(2, "0")}${String(date.getUTCMinutes()).padStart(2, "0")}${String(date.getUTCSeconds()).padStart(2, "0")}Z`;
  return der(0x17, new TextEncoder().encode(value));
}

function distinguishedName(commonName: string) {
  return derSequence(derSet(derSequence(derOid("2.5.4.3"), derUtf8(commonName))));
}

function sha256WithRsaAlgorithm() {
  return derSequence(derOid("1.2.840.113549.1.1.11"), derNull());
}

async function createSelfSignedCertificate(privateKey: CryptoKey, spki: Uint8Array, commonName: string) {
  const now = new Date();
  const notBefore = new Date(now.getTime() - 5 * 60_000);
  const notAfter = new Date(now.getTime() + 10 * 365 * 24 * 60 * 60_000);
  const serial = crypto.getRandomValues(new Uint8Array(16));
  serial[0] &= 0x7f;
  const name = distinguishedName(commonName);
  const algorithm = sha256WithRsaAlgorithm();
  const tbs = derSequence(
    der(0xa0, derInteger(2)),
    derIntegerBytes(serial),
    algorithm,
    name,
    derSequence(utcTime(notBefore), utcTime(notAfter)),
    name,
    spki
  );
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, Uint8Array.from(tbs).buffer));
  return derSequence(tbs, algorithm, derBitString(signature));
}

function pemToDer(input: Uint8Array) {
  const text = new TextDecoder().decode(input);
  if (!text.includes("-----BEGIN")) return Uint8Array.from(input);
  const base64 = text.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s+/g, "");
  const binary = atob(base64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function readDerNode(bytes: Uint8Array, offset: number, limit: number): { tag: number; start: number; contentStart: number; end: number } | null {
  if (offset + 2 > limit) return null;
  const tag = bytes[offset];
  let cursor = offset + 1;
  const first = bytes[cursor++];
  let length = 0;
  if ((first & 0x80) === 0) length = first;
  else {
    const count = first & 0x7f;
    if (!count || count > 4 || cursor + count > limit) return null;
    for (let index = 0; index < count; index += 1) length = length * 256 + bytes[cursor + index];
    cursor += count;
  }
  const end = cursor + length;
  return end <= limit ? { tag, start: offset, contentStart: cursor, end } : null;
}

function derChildren(bytes: Uint8Array, node: { contentStart: number; end: number }) {
  const result: Array<{ tag: number; start: number; contentStart: number; end: number }> = [];
  let cursor = node.contentStart;
  while (cursor < node.end) {
    const child = readDerNode(bytes, cursor, node.end);
    if (!child || child.end <= cursor) return [];
    result.push(child);
    cursor = child.end;
  }
  return result;
}

function certificateSpki(certificate: Uint8Array) {
  const root = readDerNode(certificate, 0, certificate.length);
  const tbs = root ? derChildren(certificate, root)[0] : null;
  if (!root || root.tag !== 0x30 || !tbs || tbs.tag !== 0x30) throw new Error("X.509 certificate could not be parsed.");
  const fields = derChildren(certificate, tbs);
  let cursor = fields[0]?.tag === 0xa0 ? 1 : 0;
  cursor += 5;
  const spki = fields[cursor];
  if (!spki || spki.tag !== 0x30) throw new Error("X.509 certificate does not contain a readable SubjectPublicKeyInfo.");
  return certificate.slice(spki.start, spki.end);
}

export async function createTemporaryRepairIdentity(commonName = "Forensics++ Local APK Repair") : Promise<ApkRepairIdentity> {
  const keyPair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const publicKeySpki = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
  const privateKeyPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  const certificate = await createSelfSignedCertificate(keyPair.privateKey, publicKeySpki, commonName);
  return { privateKey: keyPair.privateKey, certificate, publicKeySpki, privateKeyPkcs8, label: commonName, generated: true };
}

export async function importRepairIdentity(privateKeyBytes: Uint8Array, certificateBytes: Uint8Array, label = "Imported APK repair signer"): Promise<ApkRepairIdentity> {
  const pkcs8 = pemToDer(privateKeyBytes);
  const certificate = pemToDer(certificateBytes);
  const publicKeySpki = certificateSpki(certificate);
  const privateKey = await crypto.subtle.importKey("pkcs8", Uint8Array.from(pkcs8).buffer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, true, ["sign"]);
  const publicKey = await crypto.subtle.importKey("spki", Uint8Array.from(publicKeySpki).buffer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const probe = crypto.getRandomValues(new Uint8Array(32));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, Uint8Array.from(probe).buffer));
  const matches = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, publicKey, signature.buffer, Uint8Array.from(probe).buffer);
  if (!matches) throw new Error("The imported PKCS#8 private key does not match the X.509 certificate public key.");
  return { privateKey, certificate, publicKeySpki, privateKeyPkcs8: pkcs8, label, generated: false };
}

function makeV2SigningBlock(signedData: Uint8Array, signature: Uint8Array, certificate: Uint8Array, publicKeySpki: Uint8Array) {
  const signatureRecord = concatBytes([u32le(APK_ALG_RSA_PKCS1_SHA256), lp(signature)]);
  const signatures = lp(signatureRecord);
  const signer = concatBytes([lp(signedData), lp(signatures), lp(publicKeySpki)]);
  const signers = lp(signer);
  const schemeValue = lp(signers);
  const pair = concatBytes([u64le(4 + schemeValue.length), u32le(APK_V2_ID), schemeValue]);
  const size = pair.length + 24;
  return concatBytes([u64le(size), pair, u64le(size), APK_SIG_MAGIC]);
}

function buildSignedData(contentDigest: Uint8Array, certificate: Uint8Array) {
  const digestRecord = concatBytes([u32le(APK_ALG_RSA_PKCS1_SHA256), lp(contentDigest)]);
  const digestSequence = lp(digestRecord);
  const certificates = lp(certificate);
  const attributes = new Uint8Array();
  return concatBytes([lp(digestSequence), lp(certificates), lp(attributes)]);
}

function insertSigningBlock(unsignedApk: Uint8Array, signingBlock: Uint8Array) {
  const eocdOffset = findEocd(unsignedApk);
  if (eocdOffset < 0) throw new Error("ZIP EOCD was not found while inserting the APK Signing Block.");
  const centralDirectoryOffset = viewFor(unsignedApk).getUint32(eocdOffset + 16, true);
  const tail = unsignedApk.slice(centralDirectoryOffset);
  const relativeEocd = eocdOffset - centralDirectoryOffset;
  new DataView(tail.buffer, tail.byteOffset, tail.byteLength).setUint32(relativeEocd + 16, centralDirectoryOffset + signingBlock.length, true);
  return concatBytes([unsignedApk.subarray(0, centralDirectoryOffset), signingBlock, tail]);
}

export async function resignApkV2(input: Uint8Array, identity: ApkRepairIdentity, options: { stripJarSignatures?: boolean } = {}): Promise<ApkRepairResult> {
  const warnings: string[] = [];
  let working = Uint8Array.from(input);
  const strippedBlock = stripExistingSigningBlock(working);
  working = strippedBlock.bytes;
  let strippedJarSignatures: string[] = [];
  let rebuiltZip = false;
  if (options.stripJarSignatures) {
    const stripped = stripJarSignatures(working);
    working = stripped.bytes;
    strippedJarSignatures = stripped.removed;
    rebuiltZip = stripped.rebuilt;
    if (rebuiltZip) warnings.push("JAR/v1 signature entries were removed by rebuilding the ZIP. Entry compression/alignment may differ from the source APK; use this as a repair/analysis output and validate installation compatibility separately.");
  } else {
    warnings.push("Existing JAR/v1 signature entries, if present, were preserved. If they belong to a different signer, Android cross-scheme signer checks may reject the APK.");
  }

  const contentDigest = await chunkedDigestUnsignedApk(working);
  const signedData = buildSignedData(contentDigest, identity.certificate);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, identity.privateKey, Uint8Array.from(signedData).buffer));
  const block = makeV2SigningBlock(signedData, signature, identity.certificate, identity.publicKeySpki);
  const output = insertSigningBlock(working, block);
  const signing = await verifyApkSignatures(output);
  if (!signing.verified) throw new Error(`Re-signed APK failed Forensics++ v2 self-verification: ${signing.verification?.errors.join(" | ") || "unknown verification error"}`);
  if (identity.generated) warnings.push("A new local signing identity was generated. The APK no longer has the original developer identity and cannot update an installed app signed by the original key.");
  return {
    bytes: output,
    signing,
    identity,
    removedExistingSigningBlock: strippedBlock.removed,
    strippedJarSignatures,
    rebuiltZip,
    warnings
  };
}

export function repairIdentityPem(identity: ApkRepairIdentity) {
  const wrap = (label: string, bytes: Uint8Array) => {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    const base64 = btoa(binary).match(/.{1,64}/g)?.join("\n") ?? "";
    return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----\n`;
  };
  return {
    certificatePem: wrap("CERTIFICATE", identity.certificate),
    privateKeyPem: identity.privateKeyPkcs8 ? wrap("PRIVATE KEY", identity.privateKeyPkcs8) : ""
  };
}
