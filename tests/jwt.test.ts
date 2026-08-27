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
import { describe, expect, it } from "vitest";
import { base64UrlEncode } from "../src/utils/base64";
import {
  extractJwtTokens,
  inspectJwtToken,
  jwtCryptoAlgorithm,
  signJwtHS256,
  verifyJwtAsymmetricSignature
} from "../src/features/jwt/analyzer";

function bytesToB64Url(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function spkiToPem(spki: Uint8Array) {
  return `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...spki)).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

describe("JWT analyzer", () => {
  it("signJwtHS256 builds header.payload.signature with the correct HMAC", () => {
    const header = JSON.stringify({ alg: "HS256", typ: "JWT" });
    const payload = JSON.stringify({ sub: "1" });
    const secret = "s3cret";
    const token = signJwtHS256(header, payload, secret);
    const parts = token.split(".");
    expect(parts).toHaveLength(3);
    const data = `${base64UrlEncode(header)}.${base64UrlEncode(payload)}`;
    const expected = base64UrlEncode(CryptoJS.HmacSHA256(data, secret));
    expect(parts[2]).toBe(expected);
  });

  it("jwtCryptoAlgorithm maps RS/PS/ES and rejects non-asymmetric algs", () => {
    expect(jwtCryptoAlgorithm("RS256")).toEqual({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" });
    expect(jwtCryptoAlgorithm("ES512")).toEqual({ name: "ECDSA", namedCurve: "P-521", hash: "SHA-512" });
    expect(jwtCryptoAlgorithm("PS384")).toEqual({ name: "RSA-PSS", hash: "SHA-384", saltLength: 48 });
    expect(jwtCryptoAlgorithm("HS256")).toBeNull();
    expect(jwtCryptoAlgorithm("nope")).toBeNull();
  });

  it("extractJwtTokens pulls only well-formed tokens", () => {
    const text = "see eyJh.yWV9 and eyJhIn0 and not.a and eyJ!bad";
    const tokens = extractJwtTokens(text);
    expect(tokens).toContain("eyJh.yWV9");
    expect(tokens).not.toContain("eyJhIn0");
  });

  it("inspectJwtToken validates the HMAC with the right secret and flags wrong secret / alg=none", () => {
    const header = JSON.stringify({ alg: "HS256", typ: "JWT" });
    const payload = JSON.stringify({ sub: "user" });
    const secret = "key";
    const token = signJwtHS256(header, payload, secret);

    const ok = inspectJwtToken(token, secret);
    expect(ok.findings.some((f) => /HMAC signature valid/.test(f.title))).toBe(true);

    const bad = inspectJwtToken(token, "wrongkey");
    expect(bad.findings.some((f) => /HMAC signature invalid/.test(f.title))).toBe(true);

    const noneToken = `${base64UrlEncode(JSON.stringify({ alg: "none" }))}.${base64UrlEncode(JSON.stringify({ sub: "x" }))}.`;
    const noneIns = inspectJwtToken(noneToken, secret);
    expect(noneIns.findings.some((f) => /Unsigned JWT/.test(f.title))).toBe(true);
  });

  it("verifyJwtAsymmetricSignature verifies a locally signed RS256 token and rejects a wrong key", async () => {
    const kp = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"]
    );
    const header = base64UrlEncode(JSON.stringify({ alg: "RS256", typ: "JWT" }));
    const payload = base64UrlEncode(JSON.stringify({ sub: "subject" }));
    const data = new TextEncoder().encode(`${header}.${payload}`);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, kp.privateKey, data));
    const token = `${header}.${payload}.${bytesToB64Url(sig)}`;
    const pem = spkiToPem(new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey)));

    const result = await verifyJwtAsymmetricSignature(token, pem);
    expect(result.status).toBe("valid");

    const wrong = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"]
    );
    const wrongPem = spkiToPem(new Uint8Array(await crypto.subtle.exportKey("spki", wrong.publicKey)));
    const badResult = await verifyJwtAsymmetricSignature(token, wrongPem);
    expect(badResult.status).toBe("invalid");
  });
});
