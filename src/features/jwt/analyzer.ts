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

import CryptoJS from "crypto-js";
import { uniqueValues } from "../../utils/collections";
import { base64UrlDecode, base64UrlEncode, base64UrlToBytes } from "../../utils/base64";

export const MAX_JWT_INPUT_CHARS = 8 * 1024 * 1024;
export const MAX_JWT_TOKEN_CHARS = 2 * 1024 * 1024;

export function signJwtHS256(header: string, payload: string, secret: string) {
  return signJwtHmac("HS256", header, payload, secret);
}

export type JwtAlgFamily = "HS" | "RS" | "PS" | "ES" | "none" | "unknown";

export function jwtAlgFamily(alg: string): JwtAlgFamily {
  if (alg.toLowerCase() === "none") return "none";
  if (/^HS/i.test(alg)) return "HS";
  if (/^RS/i.test(alg)) return "RS";
  if (/^PS/i.test(alg)) return "PS";
  if (/^ES/i.test(alg)) return "ES";
  return "unknown";
}

export function signJwtHmac(alg: string, header: string, payload: string, secret: string) {
  const data = `${base64UrlEncode(header)}.${base64UrlEncode(payload)}`;
  const normalized = alg.toUpperCase();
  let hash: CryptoJS.lib.WordArray;
  if (normalized === "HS256") hash = CryptoJS.HmacSHA256(data, secret);
  else if (normalized === "HS384") hash = CryptoJS.HmacSHA384(data, secret);
  else if (normalized === "HS512") hash = CryptoJS.HmacSHA512(data, secret);
  else throw new Error(`Unsupported HMAC alg: ${alg}`);
  return `${data}.${base64UrlEncode(hash)}`;
}

// --- PKCS#1 / SEC1 -> PKCS#8 conversion -------------------------------------
// Some PEM exports use the legacy PKCS#1 (RSA) or SEC1 (EC) formats instead of
// PKCS#8. WebCrypto's importKey("pkcs8", ...) requires a PKCS#8 PrivateKeyInfo
// envelope, so we re-wrap the legacy DER structures before importing. This keeps
// signJwtAsymmetric working for the common "RSA PRIVATE KEY" / "EC PRIVATE KEY"
// exports that tools like OpenSSL produce by default.
interface DerNode {
  tag: number;
  valueStart: number;
  valueEnd: number;
  fullStart: number;
  fullEnd: number;
  value: Uint8Array;
  raw: Uint8Array;
}

function readDer(data: Uint8Array, offset = 0): DerNode {
  const tag = data[offset];
  let pos = offset + 1;
  let len = data[pos];
  pos += 1;
  if (len & 0x80) {
    const numBytes = len & 0x7f;
    len = 0;
    for (let i = 0; i < numBytes; i++) {
      len = (len << 8) | data[pos];
      pos += 1;
    }
  }
  const valueStart = pos;
  const valueEnd = pos + len;
  return {
    tag,
    valueStart,
    valueEnd,
    fullStart: offset,
    fullEnd: valueEnd,
    value: data.subarray(valueStart, valueEnd),
    raw: data.subarray(offset, valueEnd)
  };
}

function derLengthBytes(length: number): number[] {
  if (length < 0x80) return [length];
  const out: number[] = [];
  let l = length;
  while (l > 0) {
    out.unshift(l & 0xff);
    l >>= 8;
  }
  return [0x80 | out.length, ...out];
}

function wrapDer(tag: number, content: number[] | Uint8Array): Uint8Array {
  const arr = content instanceof Uint8Array ? Array.from(content) : content;
  return new Uint8Array([tag, ...derLengthBytes(arr.length), ...arr]);
}

const RSA_ENCRYPTION_OID = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const EC_PUBLIC_KEY_OID = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256_OID = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384_OID = [0x06, 0x05, 0x2b, 0x81, 0x0c, 0x0a, 0x22];
const P521_OID = [0x06, 0x05, 0x2b, 0x81, 0x0c, 0x0a, 0x23];

function curveOidForAlg(alg: string): number[] {
  if (alg === "ES256") return [...P256_OID];
  if (alg === "ES384") return [...P384_OID];
  if (alg === "ES512") return [...P521_OID];
  return [...P256_OID];
}

function rsaPkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array {
  const algId = wrapDer(0x30, [...RSA_ENCRYPTION_OID, 0x05, 0x00]);
  const inner = [0x02, 0x01, 0x00, ...algId, ...wrapDer(0x04, pkcs1)];
  return wrapDer(0x30, inner);
}

function ecSec1ToPkcs8(sec1: Uint8Array, alg: string): Uint8Array {
  const node = readDer(sec1, 0);
  if (node.tag !== 0x30) throw new Error("Invalid SEC1 private key");
  let pos = node.valueStart;
  let curveOid: number[] | null = null;
  while (pos < node.valueEnd) {
    const child = readDer(sec1, pos);
    if (child.tag === 0xa0) {
      const inner = readDer(sec1, child.valueStart);
      curveOid = Array.from(inner.raw);
    }
    pos = child.fullEnd;
  }
  if (!curveOid) curveOid = curveOidForAlg(alg);
  const algId = wrapDer(0x30, [...EC_PUBLIC_KEY_OID, ...curveOid]);
  const inner = [0x02, 0x01, 0x00, ...algId, ...wrapDer(0x04, sec1)];
  return wrapDer(0x30, inner);
}

function pemKeyBytes(keyText: string, expectedLabels: string[]) {
  const match = keyText.match(/-----BEGIN ([^-]+)-----([\s\S]+?)-----END \1-----/);
  if (!match) throw new Error("Expected a PEM key block (-----BEGIN ...-----)");
  const label = match[1].trim().toUpperCase();
  if (!expectedLabels.includes(label)) throw new Error(`Expected ${expectedLabels.join(" / ")} PEM, found ${label}`);
  const body = match[2].replace(/\s+/g, "");
  return { label, bytes: Uint8Array.from(atob(body), (char) => char.charCodeAt(0)) };
}

async function importPrivateKeyForSign(keyText: string, alg: string) {
  const algorithm = jwtCryptoAlgorithm(alg);
  if (!algorithm) throw new Error(`Unsupported asymmetric alg ${alg}`);
  const trimmed = keyText.trim();
  if (!trimmed) throw new Error("Provide a private key (PEM/JWK) to sign");
  if (trimmed.startsWith("{")) {
    const jwk = JSON.parse(trimmed) as JsonWebKey;
    return crypto.subtle.importKey("jwk", jwk, algorithm as AlgorithmIdentifier, false, ["sign"]);
  }
  const { label, bytes } = pemKeyBytes(trimmed, ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"]);
  let importable = bytes;
  if (label === "RSA PRIVATE KEY") importable = rsaPkcs1ToPkcs8(bytes);
  else if (label === "EC PRIVATE KEY") importable = ecSec1ToPkcs8(bytes, alg);
  return crypto.subtle.importKey("pkcs8", importable, algorithm as AlgorithmIdentifier, false, ["sign"]);
}

function signParams(alg: string): RsaPssParams | EcdsaParams | Algorithm {
  if (/^RS/i.test(alg)) return { name: "RSASSA-PKCS1-v1_5" };
  if (/^PS/i.test(alg)) return { name: "RSA-PSS", saltLength: Number(alg.slice(2)) / 8 };
  if (/^ES/i.test(alg)) return { name: "ECDSA", hash: jwtHashForAlg(alg) };
  throw new Error(`Unsupported sign alg ${alg}`);
}

function bytesToBase64Url(bytes: Uint8Array) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export async function signJwtAsymmetric(alg: string, header: string, payload: string, privateKeyText: string) {
  const key = await importPrivateKeyForSign(privateKeyText, alg);
  const data = `${base64UrlEncode(header)}.${base64UrlEncode(payload)}`;
  const signature = await crypto.subtle.sign(signParams(alg), key, new TextEncoder().encode(data));
  return `${data}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

export function buildNoneToken(header: string, payload: string) {
  return `${base64UrlEncode(header)}.${base64UrlEncode(payload)}.`;
}

function parseJwtPart(part: string) {
  return JSON.parse(base64UrlDecode(part));
}

function formatJwtDate(value: unknown) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "--";
  const date = new Date(value * 1000);
  if (Number.isNaN(date.getTime())) return "--";
  return `${date.toISOString()} (${date.toLocaleString()})`;
}

function formatSecondsDuration(seconds: number) {
  const abs = Math.abs(seconds);
  const days = Math.floor(abs / 86400);
  const hours = Math.floor((abs % 86400) / 3600);
  const minutes = Math.floor((abs % 3600) / 60);
  const parts = [
    days ? `${days}d` : "",
    hours ? `${hours}h` : "",
    minutes ? `${minutes}m` : "",
    !days && !hours && !minutes ? `${abs}s` : ""
  ].filter(Boolean);
  return `${seconds < 0 ? "-" : ""}${parts.join(" ")}`;
}

function jwtHmacSignature(alg: string, data: string, secret: string) {
  if (alg === "HS256") return base64UrlEncode(CryptoJS.HmacSHA256(data, secret));
  if (alg === "HS384") return base64UrlEncode(CryptoJS.HmacSHA384(data, secret));
  if (alg === "HS512") return base64UrlEncode(CryptoJS.HmacSHA512(data, secret));
  return "";
}

function jwtHashForAlg(alg: string) {
  if (/(?:256)$/i.test(alg)) return "SHA-256";
  if (/(?:384)$/i.test(alg)) return "SHA-384";
  if (/(?:512)$/i.test(alg)) return "SHA-512";
  return "SHA-256";
}

function jwtCurveForAlg(alg: string) {
  if (alg === "ES256") return "P-256";
  if (alg === "ES384") return "P-384";
  if (alg === "ES512") return "P-521";
  return "P-256";
}

export function jwtCryptoAlgorithm(alg: string): RsaHashedImportParams | EcKeyImportParams | RsaPssParams | EcdsaParams | null {
  if (/^RS(?:256|384|512)$/.test(alg)) return { name: "RSASSA-PKCS1-v1_5", hash: jwtHashForAlg(alg) };
  if (/^PS(?:256|384|512)$/.test(alg)) return { name: "RSA-PSS", hash: jwtHashForAlg(alg), saltLength: Number(alg.slice(2)) / 8 };
  if (/^ES(?:256|384|512)$/.test(alg)) return { name: "ECDSA", namedCurve: jwtCurveForAlg(alg), hash: jwtHashForAlg(alg) };
  return null;
}

function pemBodyToBytes(keyText: string) {
  const match = keyText.match(/-----BEGIN ([^-]+)-----([\s\S]+?)-----END \1-----/);
  if (!match) return null;
  const label = match[1].trim().toUpperCase();
  const body = match[2].replace(/\s+/g, "");
  return { label, bytes: Uint8Array.from(atob(body), (char) => char.charCodeAt(0)) };
}

async function importJwtVerifyKey(keyText: string, alg: string) {
  const algorithm = jwtCryptoAlgorithm(alg);
  if (!algorithm) throw new Error(`Unsupported asymmetric alg ${alg}`);
  const trimmed = keyText.trim();
  if (!trimmed) throw new Error("No public key or JWK provided");
  if (trimmed.startsWith("{")) {
    const jwk = JSON.parse(trimmed) as JsonWebKey;
    return crypto.subtle.importKey("jwk", jwk, algorithm as AlgorithmIdentifier, false, ["verify"]);
  }
  const pem = pemBodyToBytes(trimmed);
  if (!pem) throw new Error("Expected PEM public key or JWK");
  if (pem.label !== "PUBLIC KEY") throw new Error("Use an SPKI PUBLIC KEY PEM or JWK for local verification");
  return crypto.subtle.importKey("spki", pem.bytes, algorithm as AlgorithmIdentifier, false, ["verify"]);
}

export async function verifyJwtAsymmetricSignature(token: string, keyText: string) {
  const parts = token.trim().split(".");
  if (parts.length !== 3) return { status: "idle", detail: "JWT must contain header.payload.signature" };
  const [encodedHeader, encodedPayload, signature] = parts;
  const headerObject = parseJwtPart(encodedHeader) as Record<string, unknown>;
  const alg = String(headerObject.alg ?? "");
  const algorithm = jwtCryptoAlgorithm(alg);
  if (!algorithm) return { status: "idle", detail: `No asymmetric verifier for alg=${alg || "--"}` };
  const key = await importJwtVerifyKey(keyText, alg);
  const data = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`);
  const ok = await crypto.subtle.verify(
    algorithm.name === "RSA-PSS"
      ? { name: "RSA-PSS", saltLength: Number(alg.slice(2)) / 8 }
      : algorithm.name === "ECDSA"
      ? { name: "ECDSA", hash: jwtHashForAlg(alg) }
      : { name: "RSASSA-PKCS1-v1_5" },
    key,
    base64UrlToBytes(signature),
    data
  );
  return { status: ok ? "valid" : "invalid", detail: `${alg} ${ok ? "valid with current key" : "did not match current key"}` };
}

function stringifyClaim(value: unknown) {
  if (value == null) return "--";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function inspectJwtToken(token: string, secret: string) {
  const trimmed = token.trim();
  if (!trimmed) {
    return {
      rows: [["JWT", "Paste or generate a token"]] as Array<[string, string]>,
      claimRows: [] as Array<[string, string]>,
      findings: [] as Array<{ level: string; title: string; detail: string }>,
      headerText: "",
      payloadText: "",
      headerObject: null as Record<string, unknown> | null,
      payloadObject: null as Record<string, unknown> | null,
      result: ""
    };
  }

  try {
    const parts = trimmed.split(".");
    if (parts.length < 2 || parts.length > 3) throw new Error("JWT should contain header.payload.signature");
    const [encodedHeader, encodedPayload, signature = ""] = parts;
    const headerObject = parseJwtPart(encodedHeader) as Record<string, unknown>;
    const payloadObject = parseJwtPart(encodedPayload) as Record<string, unknown>;
    const alg = String(headerObject.alg ?? "unknown");
    const rows: Array<[string, string]> = [
      ["alg", alg],
      ["typ", stringifyClaim(headerObject.typ)],
      ["kid", stringifyClaim(headerObject.kid)],
      ["cty", stringifyClaim(headerObject.cty)],
      ["sub", stringifyClaim(payloadObject.sub)],
      ["iss", stringifyClaim(payloadObject.iss)],
      ["aud", stringifyClaim(payloadObject.aud)],
      ["jti", stringifyClaim(payloadObject.jti)],
      ["scope", stringifyClaim(payloadObject.scope ?? payloadObject.scp)],
      ["azp / client_id", stringifyClaim(payloadObject.azp ?? payloadObject.client_id)],
      ["segments", String(parts.length)],
      ["header bytes", String(new Blob([base64UrlDecode(encodedHeader)]).size)],
      ["payload bytes", String(new Blob([base64UrlDecode(encodedPayload)]).size)],
      ["signature bytes", signature ? String(Math.floor(signature.length * 3 / 4)) : "0"]
    ];
    const registeredClaims = new Set(["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]);
    const claimRows: Array<[string, string]> = [
      ["iat", formatJwtDate(payloadObject.iat)],
      ["nbf", formatJwtDate(payloadObject.nbf)],
      ["exp", formatJwtDate(payloadObject.exp)],
      ...Object.entries(payloadObject)
        .filter(([key]) => !["iat", "nbf", "exp"].includes(key))
        .map(([key, value]) => [registeredClaims.has(key) ? `${key} (registered)` : key, stringifyClaim(value)] as [string, string])
    ];
    const messages: string[] = [];
    const findings: Array<{ level: string; title: string; detail: string }> = [];
    const nowSeconds = Math.floor(Date.now() / 1000);
    let expires = "--";
    let notBefore = "--";
    let signatureStatus = "--";

    if (typeof payloadObject.exp === "number") {
      const diff = payloadObject.exp - nowSeconds;
      expires = diff < 0 ? `expired ${formatSecondsDuration(diff)} ago` : `valid for ${formatSecondsDuration(diff)}`;
      messages.push(`exp: ${expires}`);
      if (diff < 0) findings.push({ level: "warn", title: "Token expired", detail: `exp=${formatJwtDate(payloadObject.exp)}` });
      if (typeof payloadObject.iat === "number" && payloadObject.exp - payloadObject.iat > 86400 * 30) findings.push({ level: "warn", title: "Long validity window", detail: `exp - iat = ${formatSecondsDuration(payloadObject.exp - payloadObject.iat)}` });
    } else {
      findings.push({ level: "warn", title: "Missing exp claim", detail: "No explicit expiration claim was found." });
    }
    if (typeof payloadObject.nbf === "number" && payloadObject.nbf > nowSeconds) {
      notBefore = `not valid for ${formatSecondsDuration(payloadObject.nbf - nowSeconds)}`;
      messages.push(`nbf: ${notBefore}`);
      findings.push({ level: "warn", title: "Token not valid yet", detail: `nbf=${formatJwtDate(payloadObject.nbf)}` });
    } else if (typeof payloadObject.nbf === "number") {
      notBefore = "valid";
    }
    if (typeof payloadObject.iat === "number" && payloadObject.iat > nowSeconds + 300) findings.push({ level: "warn", title: "Issued-at is in the future", detail: `iat=${formatJwtDate(payloadObject.iat)}` });
    if (alg.toLowerCase() === "none") {
      signatureStatus = "unsigned (alg=none)";
      messages.push("alg=none: unsigned token");
      findings.push({ level: "warn", title: "Unsigned JWT", detail: "Header alg is none." });
    }
    if (["HS256", "HS384", "HS512"].includes(alg) && signature) {
      if (!secret) {
        signatureStatus = `secret required (${alg})`;
        findings.push({ level: "info", title: "HMAC secret required", detail: `Enter the shared secret to verify ${alg}.` });
        messages.push(`${alg} signature present. Enter the shared secret to verify it.`);
      } else {
        const expected = jwtHmacSignature(alg, `${encodedHeader}.${encodedPayload}`, secret);
        signatureStatus = expected === signature ? `${alg} valid` : `${alg} invalid`;
        findings.push({ level: expected === signature ? "info" : "warn", title: expected === signature ? "HMAC signature valid" : "HMAC signature invalid", detail: `${alg} ${expected === signature ? "matched" : "did not match"} with the current secret.` });
        messages.push(expected === signature ? `${alg} signature: valid` : `${alg} signature: invalid\nExpected: ${expected}\nActual:   ${signature}`);
      }
    } else if (signature && jwtCryptoAlgorithm(alg)) {
      signatureStatus = `public key required (${alg})`;
      messages.push(`Signature present. Paste a matching public key or JWK to verify alg=${alg}.`);
      findings.push({ level: "info", title: "Public key required", detail: `${alg} signatures can be verified locally after a PEM public key or JWK is provided.` });
    } else if (signature) {
      signatureStatus = `unsupported local verify (${alg})`;
      messages.push(`Signature present, but local verification does not support alg=${alg}`);
      findings.push({ level: "warn", title: "Signature algorithm not supported", detail: `No local verifier is available for alg=${alg}.` });
    } else if (alg.toLowerCase() !== "none") {
      signatureStatus = "missing";
      messages.push("No signature segment");
      findings.push({ level: "warn", title: "Missing signature segment", detail: "Token has no signature segment while alg is not none." });
    }
    if (/(?:\.\.\/|%2e%2e%2f|\/|\\|https?:\/\/)/i.test(String(headerObject.kid ?? ""))) findings.push({ level: "warn", title: "kid header worth review", detail: String(headerObject.kid) });
    if (headerObject.jku || headerObject.x5u) findings.push({ level: "warn", title: "Remote key reference", detail: `jku=${stringifyClaim(headerObject.jku)} x5u=${stringifyClaim(headerObject.x5u)}` });
    if (headerObject.crit) findings.push({ level: "warn", title: "Critical header present", detail: stringifyClaim(headerObject.crit) });
    const sensitiveClaims = Object.entries(payloadObject).filter(([key, value]) => /(pass(word)?|secret|api[_-]?key|token|session|cookie|private[_-]?key)/i.test(key) || /(bearer\s+|AKIA[0-9A-Z]{16}|-----BEGIN)/i.test(String(value)));
    if (sensitiveClaims.length) findings.push({ level: "warn", title: "Sensitive-looking claim", detail: sensitiveClaims.slice(0, 8).map(([key]) => key).join(", ") });
    if (String(payloadObject.role ?? payloadObject.scope ?? payloadObject.scp ?? "").toLowerCase().includes("admin")) findings.push({ level: "info", title: "Privileged claim", detail: "role/scope contains admin-like text." });
    if (!payloadObject.iss) findings.push({ level: "warn", title: "Missing issuer", detail: "No iss claim was found." });
    if (!payloadObject.aud) findings.push({ level: "warn", title: "Missing audience", detail: "No aud claim was found." });
    if (!payloadObject.sub) findings.push({ level: "warn", title: "Missing subject", detail: "No sub claim was found." });
    if (typeof payloadObject.iat === "number" && typeof payloadObject.exp === "number" && payloadObject.iat > payloadObject.exp) findings.push({ level: "warn", title: "Invalid claim order", detail: "iat is later than exp." });
    if (String(payloadObject.scope ?? payloadObject.scp ?? "").split(/\s+/).filter(Boolean).length > 8) findings.push({ level: "warn", title: "Broad scope set", detail: stringifyClaim(payloadObject.scope ?? payloadObject.scp) });

    rows.push(["signature", signatureStatus], ["exp status", expires], ["nbf status", notBefore]);

    return {
      rows,
      claimRows,
      findings,
      headerText: JSON.stringify(headerObject, null, 2),
      payloadText: JSON.stringify(payloadObject, null, 2),
      headerObject,
      payloadObject,
      result: messages.join("\n")
    };
  } catch (error) {
    return {
      rows: [["JWT", error instanceof Error ? error.message : String(error)]] as Array<[string, string]>,
      claimRows: [] as Array<[string, string]>,
      findings: [{ level: "warn", title: "JWT parse failed", detail: error instanceof Error ? error.message : String(error) }],
      headerText: "",
      payloadText: "",
      headerObject: null as Record<string, unknown> | null,
      payloadObject: null as Record<string, unknown> | null,
      result: error instanceof Error ? error.message : String(error)
    };
  }
}

const JWT_CANDIDATE_RE = /\b[A-Za-z0-9_\-+/=]{4,}\.[A-Za-z0-9_\-+/=]{2,}(?:\.[A-Za-z0-9_\-+/=]+)?(?![A-Za-z0-9_\-+/=])/g;

/**
 * A token counts as a JWT only when its first two segments decode to JSON
 * objects. This accepts compact (eyJ...) and pretty-printed (ewog...) headers
 * alike, and rejects base64 pairs, version numbers, and other log noise.
 */
function isJwtShapedToken(token: string) {
  const parts = token.split(".");
  if (parts.length < 2 || parts.length > 3) return false;
  try {
    const header = JSON.parse(base64UrlDecode(parts[0]));
    const payload = JSON.parse(base64UrlDecode(parts[1]));
    return header !== null && typeof header === "object" && payload !== null && typeof payload === "object";
  } catch {
    return false;
  }
}

export function extractJwtTokens(text: string) {
  const candidates = text.match(JWT_CANDIDATE_RE) ?? [];
  return uniqueValues(
    candidates.slice(0, 1000).filter((token) => token.length <= MAX_JWT_TOKEN_CHARS && isJwtShapedToken(token)),
    200
  );
}
