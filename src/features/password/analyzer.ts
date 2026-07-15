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
import type { PasswordVerifyRow } from "../../models";
import { detectHashType } from "../../utils/hash";

function djangoPBKDF2(password: string, salt: string, iterations = 390000) {
  const hash = CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations,
    hasher: CryptoJS.algo.SHA256
  }).toString(CryptoJS.enc.Base64);
  return `pbkdf2_sha256$${iterations}$${salt}$${hash}`;
}

export function mysqlNativePassword(password: string) {
  const first = CryptoJS.SHA1(password);
  return `*${CryptoJS.SHA1(first).toString().toUpperCase()}`;
}

export function randomSalt(length = 12) {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const values = new Uint8Array(length);
  crypto.getRandomValues(values);
  return Array.from(values, (value) => alphabet[value % alphabet.length]).join("");
}

function guessPasswordField(value: string) {
  const input = value.trim();
  if (!input) return "--";
  const findings: string[] = [];
  const hashType = detectHashType(input);
  if (hashType) findings.push(hashType);
  if (/^\*[A-F0-9]{40}$/.test(input)) findings.push("MySQL native password");
  if (/^[A-F0-9]{16}$/i.test(input)) findings.push("MySQL OLD_PASSWORD / LM-like 16 hex");
  if (/^\$argon2(?:i|id)\$/.test(input)) findings.push("Argon2");
  if (/^\$scrypt\$/.test(input)) findings.push("scrypt");
  if (/^\$apr1\$/.test(input)) findings.push("Apache htpasswd MD5");
  if (/^\$1\$/.test(input)) findings.push("Unix md5crypt");
  if (/^\$5\$/.test(input)) findings.push("Unix sha256crypt");
  if (/^\$6\$/.test(input)) findings.push("Unix sha512crypt");
  if (/^\{SHA\}[A-Za-z0-9+/=]+$/.test(input)) findings.push("LDAP {SHA}");
  if (/^\{SSHA\}[A-Za-z0-9+/=]+$/.test(input)) findings.push("LDAP salted SHA");
  if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(input) && !findings.length) findings.push("Base64-like encoded hash/secret");
  if (/^[^$:\s]+:[^$:\s]+/.test(input)) findings.push("username:hash pair");
  return findings.length ? Array.from(new Set(findings)).join("\n") : "Unknown / plain text / custom salted hash";
}

export function passwordRowsToCsv(rows: PasswordVerifyRow[]) {
  const escape = (value: string | boolean) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["candidate", "hash_type", "matched", "risk", "detail"].join(","),
    ...rows.map((row) => [row.candidate, row.hashType, row.matched, row.risk.join("; "), row.detail].map(escape).join(","))
  ].join("\n");
}

function passwordCandidateRisk(candidate: string, matched = false) {
  const lower = candidate.toLowerCase();
  return [
    matched ? "MATCHED" : "",
    /^(123456|password|admin|root|qwerty|letmein|welcome|forensicspp)$/i.test(candidate) ? "common password" : "",
    candidate.length < 8 ? "short password" : "",
    /^[a-z]+$/.test(lower) || /^\d+$/.test(candidate) ? "low complexity" : "",
    /(admin|root|test|guest|user|pass|pwd)/i.test(candidate) ? "account keyword" : ""
  ].filter(Boolean);
}

function hashTypeRisk(hashType: string) {
  return [
    /MD5|SHA1|LDAP \{SHA\}|MySQL native/i.test(hashType) ? "fast/legacy hash" : "",
    /bcrypt|PBKDF2|Argon2|scrypt/i.test(hashType) ? "slow hash" : ""
  ].filter(Boolean);
}

function verifyPasswordFast(candidate: string, target: string): PasswordVerifyRow | null {
  const normalized = target.trim();
  const lower = normalized.toLowerCase();
  const checks: Array<[string, string]> = [
    ["MD5", CryptoJS.MD5(candidate).toString()],
    ["SHA1", CryptoJS.SHA1(candidate).toString()],
    ["SHA256", CryptoJS.SHA256(candidate).toString()],
    ["SHA512", CryptoJS.SHA512(candidate).toString()],
    ["SHA3-512", CryptoJS.SHA3(candidate, { outputLength: 512 }).toString()],
    ["RIPEMD-160", CryptoJS.RIPEMD160(candidate).toString()],
    ["MySQL native password", mysqlNativePassword(candidate).toLowerCase()]
  ];
  for (const [hashType, value] of checks) {
    if (lower === value.toLowerCase()) return { candidate, hashType, matched: true, detail: "exact hash match", risk: [...passwordCandidateRisk(candidate, true), ...hashTypeRisk(hashType)] };
  }
  const django = normalized.match(/^pbkdf2_sha256\$(\d+)\$([^$]+)\$([^$]+)$/);
  if (django) {
    const [, iterationText, djangoSalt] = django;
    const generated = djangoPBKDF2(candidate, djangoSalt, Number(iterationText));
    const matched = generated === normalized;
    return { candidate, hashType: "Django PBKDF2-SHA256", matched, detail: matched ? "exact hash match" : "no match", risk: [...passwordCandidateRisk(candidate, matched), ...hashTypeRisk("Django PBKDF2-SHA256")] };
  }
  const ldapSha = normalized.match(/^\{SHA\}(.+)$/i);
  if (ldapSha) {
    const generated = CryptoJS.SHA1(candidate).toString(CryptoJS.enc.Base64);
    const matched = generated === ldapSha[1];
    return { candidate, hashType: "LDAP {SHA}", matched, detail: matched ? "exact hash match" : "no match", risk: [...passwordCandidateRisk(candidate, matched), ...hashTypeRisk("LDAP {SHA}")] };
  }
  return null;
}

export async function verifyPasswordCandidates(target: string, candidates: string[]): Promise<PasswordVerifyRow[]> {
  const normalized = target.trim();
  if (!normalized || !candidates.length) return [];
  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(normalized)) {
    const bcryptModule = await import("bcryptjs");
    const bcrypt = bcryptModule.default ?? bcryptModule;
    const rows: PasswordVerifyRow[] = [];
    for (const candidate of candidates.slice(0, 200)) {
      const matched = await new Promise<boolean>((resolve, reject) => {
        bcrypt.compare(candidate, normalized, (error, same) => {
          if (error) reject(error);
          else resolve(Boolean(same));
        });
      });
      rows.push({ candidate, hashType: "bcrypt", matched, detail: matched ? "bcrypt compare matched" : "no match", risk: [...passwordCandidateRisk(candidate, matched), ...hashTypeRisk("bcrypt")] });
    }
    return rows;
  }
  return candidates.slice(0, 200).map((candidate) => {
    const hashType = guessPasswordField(normalized).split("\n")[0] || "Unknown";
    return verifyPasswordFast(candidate, normalized) ?? { candidate, hashType, matched: false, detail: "unsupported local verifier or no match", risk: [...passwordCandidateRisk(candidate, false), ...hashTypeRisk(hashType)] };
  });
}
