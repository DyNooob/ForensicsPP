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
  const encodedHeader = base64UrlEncode(header);
  const encodedPayload = base64UrlEncode(payload);
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = CryptoJS.HmacSHA256(data, secret);
  return `${data}.${base64UrlEncode(signature)}`;
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
    if (["HS256", "HS512"].includes(alg) && signature) {
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

export function extractJwtTokens(text: string) {
  return uniqueValues(
    text.match(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?\b/g)?.filter((token) => token.length <= MAX_JWT_TOKEN_CHARS) ?? [],
    200
  );
}
