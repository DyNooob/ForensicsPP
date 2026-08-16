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

import {
  getApkSignatureAlgorithmName,
  getApkSigningMaterials,
  getCertificateSpki,
  verifyApkSignatureAlgorithm
} from "./signingVerify";

const V4_CURRENT_VERSION = 2;
const V4_HASH_SHA256 = 1;
const V4_LOG2_BLOCK_SIZE = 12;
const BLOCK_SIZE = 1 << V4_LOG2_BLOCK_SIZE;
const MAX_SIZED_FIELD = 512 * 1024 * 1024;

type Cursor = { offset: number };

export type AndroidV4Verification = {
  present: boolean;
  verified: boolean;
  version: number | null;
  complete: boolean;
  signatureAlgorithmId: number | null;
  signatureAlgorithm: string;
  signatureVerified: boolean;
  publicKeyMatchesCertificate: boolean;
  rootHashVerified: boolean;
  treeVerified: boolean | null;
  apkDigestMatchesV2V3: boolean;
  certificateMatchesV2V3: boolean;
  certificateSha256: string;
  expectedRootHash: string;
  actualRootHash: string;
  errors: string[];
  warnings: string[];
};

type HashingInfo = {
  hashAlgorithm: number;
  log2BlockSize: number;
  salt: Uint8Array;
  rawRootHash: Uint8Array;
};

type SigningInfo = {
  apkDigest: Uint8Array;
  certificate: Uint8Array;
  additionalData: Uint8Array;
  publicKey: Uint8Array;
  signatureAlgorithmId: number;
  signature: Uint8Array;
};

function view(bytes: Uint8Array) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function readI32(bytes: Uint8Array, cursor: Cursor) {
  if (cursor.offset + 4 > bytes.length) throw new Error("V4 signature is truncated.");
  const value = view(bytes).getInt32(cursor.offset, true);
  cursor.offset += 4;
  return value;
}

function readU32(bytes: Uint8Array, cursor: Cursor) {
  if (cursor.offset + 4 > bytes.length) throw new Error("V4 signature is truncated.");
  const value = view(bytes).getUint32(cursor.offset, true);
  cursor.offset += 4;
  return value;
}

function readSized(bytes: Uint8Array, cursor: Cursor, optional = false) {
  if (cursor.offset === bytes.length && optional) return null;
  const length = readI32(bytes, cursor);
  if (length < 0 || length > MAX_SIZED_FIELD || cursor.offset + length > bytes.length) throw new Error("V4 sized field has an invalid length.");
  const value = bytes.slice(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return value;
}

function parseHashingInfo(bytes: Uint8Array): HashingInfo {
  const cursor = { offset: 0 };
  const hashAlgorithm = readI32(bytes, cursor);
  if (cursor.offset >= bytes.length) throw new Error("V4 hashing_info is truncated.");
  const log2BlockSize = bytes[cursor.offset++];
  const salt = readSized(bytes, cursor) ?? new Uint8Array();
  const rawRootHash = readSized(bytes, cursor) ?? new Uint8Array();
  if (cursor.offset !== bytes.length) throw new Error("V4 hashing_info has trailing bytes.");
  return { hashAlgorithm, log2BlockSize, salt, rawRootHash };
}

function parseSigningInfo(bytes: Uint8Array): SigningInfo {
  const cursor = { offset: 0 };
  const apkDigest = readSized(bytes, cursor) ?? new Uint8Array();
  const certificate = readSized(bytes, cursor) ?? new Uint8Array();
  const additionalData = readSized(bytes, cursor) ?? new Uint8Array();
  const publicKey = readSized(bytes, cursor) ?? new Uint8Array();
  const signatureAlgorithmId = readU32(bytes, cursor);
  const signature = readSized(bytes, cursor) ?? new Uint8Array();
  if (cursor.offset !== bytes.length) throw new Error("V4 signing_info has trailing bytes.");
  return { apkDigest, certificate, additionalData, publicKey, signatureAlgorithmId, signature };
}

function u32(value: number) {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value >>> 0, true);
  return output;
}

function i64(value: number) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("APK size exceeds the supported browser integer range.");
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigInt64(0, BigInt(value), true);
  return output;
}

function sized(value: Uint8Array) {
  const output = new Uint8Array(4 + value.length);
  new DataView(output.buffer).setUint32(0, value.length, true);
  output.set(value, 4);
  return output;
}

function concat(parts: Uint8Array[]) {
  const output = new Uint8Array(parts.reduce((sum, item) => sum + item.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

function v4SignedData(fileSize: number, hashing: HashingInfo, signing: SigningInfo) {
  const body = concat([
    i64(fileSize),
    u32(hashing.hashAlgorithm),
    new Uint8Array([hashing.log2BlockSize]),
    sized(hashing.salt),
    sized(hashing.rawRootHash),
    sized(signing.apkDigest),
    sized(signing.certificate),
    sized(signing.additionalData)
  ]);
  // AOSP V4Signature.getSigningData stores the total serialized size, including this uint32 field.
  return concat([u32(body.length + 4), body]);
}

async function sha256(parts: Uint8Array[]) {
  const data = concat(parts);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(data).buffer));
}

function pad4096(bytes: Uint8Array) {
  const size = Math.max(BLOCK_SIZE, Math.ceil(bytes.length / BLOCK_SIZE) * BLOCK_SIZE);
  const output = new Uint8Array(size);
  output.set(bytes);
  return output;
}

export async function buildAndroidV4VerityTree(apk: Uint8Array, salt = new Uint8Array()) {
  if (!apk.length) throw new Error("Cannot build a v4 verity tree for an empty APK.");
  const leafDigests: Uint8Array[] = [];
  for (let offset = 0; offset < apk.length; offset += BLOCK_SIZE) {
    const block = new Uint8Array(BLOCK_SIZE);
    block.set(apk.subarray(offset, Math.min(apk.length, offset + BLOCK_SIZE)));
    leafDigests.push(await sha256(salt.length ? [salt, block] : [block]));
  }
  let level = pad4096(concat(leafDigests));
  const levels: Uint8Array[] = [level];
  while (level.length > BLOCK_SIZE) {
    const digests: Uint8Array[] = [];
    for (let offset = 0; offset < level.length; offset += BLOCK_SIZE) {
      digests.push(await sha256(salt.length ? [salt, level.subarray(offset, offset + BLOCK_SIZE)] : [level.subarray(offset, offset + BLOCK_SIZE)]));
    }
    level = pad4096(concat(digests));
    levels.push(level);
  }
  const rootHash = await sha256(salt.length ? [salt, level.subarray(0, BLOCK_SIZE)] : [level.subarray(0, BLOCK_SIZE)]);
  // AOSP stores the top level first and the leaf level last.
  return { rootHash, tree: concat([...levels].reverse()) };
}

function equal(left: Uint8Array, right: Uint8Array) {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) diff |= left[index] ^ right[index];
  return diff === 0;
}

function hex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

async function certSha256(cert: Uint8Array) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(cert).buffer)));
}

function digestRank(id: number) {
  if ([0x0102, 0x0104, 0x0202].includes(id)) return 3; // 1 MiB SHA-512
  if ([0x0421, 0x0423, 0x0425].includes(id)) return 2; // verity SHA-256
  if ([0x0101, 0x0103, 0x0201, 0x0301].includes(id)) return 1; // 1 MiB SHA-256
  return -1;
}

function bestApkDigest(apk: Uint8Array, certificate: Uint8Array) {
  const materials = getApkSigningMaterials(apk);
  const candidates = materials
    .map((signer) => ({
      signer,
      certMatches: Boolean(signer.certificates[0] && equal(signer.certificates[0], certificate)),
      schemeRank: signer.scheme === "v3.1" ? 3 : signer.scheme === "v3" ? 2 : 1,
      digest: [...signer.digests].sort((a, b) => digestRank(b.id) - digestRank(a.id))[0]
    }))
    .filter((item) => item.digest && digestRank(item.digest.id) >= 0)
    .sort((a, b) => Number(b.certMatches) - Number(a.certMatches) || b.schemeRank - a.schemeRank || digestRank(b.digest.id) - digestRank(a.digest.id));
  return candidates[0] ?? null;
}

export async function verifyAndroidV4Idsig(apk: Uint8Array, idsig: Uint8Array): Promise<AndroidV4Verification> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const base: AndroidV4Verification = {
    present: idsig.length > 0,
    verified: false,
    version: null,
    complete: false,
    signatureAlgorithmId: null,
    signatureAlgorithm: "--",
    signatureVerified: false,
    publicKeyMatchesCertificate: false,
    rootHashVerified: false,
    treeVerified: null,
    apkDigestMatchesV2V3: false,
    certificateMatchesV2V3: false,
    certificateSha256: "",
    expectedRootHash: "",
    actualRootHash: "",
    errors,
    warnings
  };
  if (!idsig.length) { errors.push("The .idsig file is empty."); return base; }
  try {
    const cursor = { offset: 0 };
    const version = readI32(idsig, cursor);
    base.version = version;
    const hashingBytes = readSized(idsig, cursor);
    const signingBytes = readSized(idsig, cursor);
    if (!hashingBytes || !signingBytes) throw new Error("V4 signature is missing hashing_info or signing_info.");
    const tree = readSized(idsig, cursor, true);
    if (cursor.offset !== idsig.length) throw new Error("V4 signature has trailing bytes after the optional Merkle tree.");
    base.complete = Boolean(tree?.length);
    if (version !== V4_CURRENT_VERSION) errors.push(`Unsupported APK Signature Scheme v4 format version ${version}; expected ${V4_CURRENT_VERSION}.`);
    const hashing = parseHashingInfo(hashingBytes);
    const signing = parseSigningInfo(signingBytes);
    base.signatureAlgorithmId = signing.signatureAlgorithmId;
    base.signatureAlgorithm = getApkSignatureAlgorithmName(signing.signatureAlgorithmId);
    base.certificateSha256 = signing.certificate.length ? await certSha256(signing.certificate) : "";
    if (hashing.hashAlgorithm !== V4_HASH_SHA256) errors.push(`Unsupported v4 hash algorithm ${hashing.hashAlgorithm}; Android v4 currently requires SHA-256.`);
    if (hashing.log2BlockSize !== V4_LOG2_BLOCK_SIZE) errors.push(`Unsupported v4 block size 2^${hashing.log2BlockSize}; Android v4 currently requires 4096-byte blocks.`);
    if (hashing.salt.length > 32) errors.push("V4 salt exceeds the 32-byte format limit.");
    if (hashing.rawRootHash.length !== 32) errors.push(`V4 root hash has ${hashing.rawRootHash.length} bytes; SHA-256 requires 32.`);

    const certSpki = signing.certificate.length ? getCertificateSpki(signing.certificate) : null;
    base.publicKeyMatchesCertificate = Boolean(certSpki && equal(certSpki, signing.publicKey));
    if (!certSpki) errors.push("V4 X.509 certificate SubjectPublicKeyInfo could not be parsed.");
    else if (!base.publicKeyMatchesCertificate) errors.push("V4 public key does not match the X.509 certificate public key.");

    if (certSpki && base.publicKeyMatchesCertificate) {
      try {
        base.signatureVerified = await verifyApkSignatureAlgorithm(signing.signatureAlgorithmId, signing.publicKey, signing.signature, v4SignedData(apk.length, hashing, signing));
        if (!base.signatureVerified) errors.push("V4 signature over signed data did not verify.");
      } catch (error) {
        errors.push(`V4 signature verification failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    if (hashing.hashAlgorithm === V4_HASH_SHA256 && hashing.log2BlockSize === V4_LOG2_BLOCK_SIZE && hashing.rawRootHash.length === 32) {
      const calculated = await buildAndroidV4VerityTree(apk, hashing.salt.slice());
      base.expectedRootHash = hex(hashing.rawRootHash);
      base.actualRootHash = hex(calculated.rootHash);
      base.rootHashVerified = equal(hashing.rawRootHash, calculated.rootHash);
      if (!base.rootHashVerified) errors.push("V4 Merkle-tree root hash does not match the APK bytes.");
      if (tree?.length) {
        base.treeVerified = equal(tree, calculated.tree);
        if (!base.treeVerified) errors.push("V4 embedded Merkle tree does not match the APK bytes.");
      }
    }

    try {
      const selected = bestApkDigest(apk, signing.certificate);
      if (!selected) errors.push("No compatible v2/v3/v3.1 APK content digest was found for v4 cross-checking.");
      else {
        base.certificateMatchesV2V3 = selected.certMatches;
        base.apkDigestMatchesV2V3 = equal(signing.apkDigest, selected.digest.value);
        if (!base.certificateMatchesV2V3) errors.push("V4 signer certificate does not match the selected v2/v3 signer certificate.");
        if (!base.apkDigestMatchesV2V3) errors.push("V4 apk_digest does not match the selected v2/v3 APK content digest.");
      }
    } catch (error) {
      errors.push(`V4 v2/v3 cross-check failed: ${error instanceof Error ? error.message : String(error)}`);
    }

    if (!tree?.length) warnings.push("This is a stripped v4 .idsig: the Merkle tree is absent and was recalculated from the APK.");
    base.verified = base.signatureVerified && base.publicKeyMatchesCertificate && base.rootHashVerified && (base.treeVerified !== false) && base.apkDigestMatchesV2V3 && base.certificateMatchesV2V3 && !errors.length;
    return base;
  } catch (error) {
    errors.push(error instanceof Error ? error.message : String(error));
    return base;
  }
}
