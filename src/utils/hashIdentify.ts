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

// Auto identification of pasted passwords / hashes so the operator can pick the
// matching backend generation path. Everything runs locally, no network calls.

export type HashConfidence = "high" | "medium" | "low";

/** Which generate action in the password tool best reproduces this hash. */
export type GenerateHint = "common" | "bcrypt" | "pbkdf2" | null;

export type HashCategory =
  | "raw"
  | "salted"
  | "application"
  | "unix"
  | "windows"
  | "network"
  | "checksum"
  | "other";

export type HashCandidate = {
  id: string;
  name: string;
  zh: string;
  descZh: string;
  descEn: string;
  confidence: HashConfidence;
  category: HashCategory;
  hashcat?: string;
  john?: string;
  generateHint: GenerateHint;
};

export type PasswordStrength = {
  score: 0 | 1 | 2 | 3 | 4;
  labelZh: string;
  labelEn: string;
  length: number;
  hasLower: boolean;
  hasUpper: boolean;
  hasDigit: boolean;
  hasSymbol: boolean;
  notesZh: string[];
  notesEn: string[];
};

export type HashInputKind = "empty" | "hash" | "plaintext" | "unknown";

export type HashIdentifyResult = {
  input: string;
  kind: HashInputKind;
  length: number;
  charsetZh: string;
  charsetEn: string;
  candidates: HashCandidate[];
  strength?: PasswordStrength;
};

const HEX_RE = /^[0-9a-f]+$/i;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

function isHex(value: string) {
  return HEX_RE.test(value);
}

function describeCharset(value: string): { zh: string; en: string } {
  if (!value) return { zh: "空", en: "empty" };
  if (isHex(value)) return { zh: "十六进制", en: "hexadecimal" };
  if (BASE64_RE.test(value)) return { zh: "Base64", en: "base64" };
  if (/^[!-~]+$/.test(value)) return { zh: "可见 ASCII", en: "printable ASCII" };
  return { zh: "混合字符", en: "mixed characters" };
}

// ---------------------------------------------------------------------------
// Prefixed / structured formats. Order matters — the first match wins and short
// circuits the generic hex fallbacks below.
// ---------------------------------------------------------------------------

type PrefixRule = {
  test: (value: string) => boolean;
  build: () => HashCandidate[];
};

function candidate(partial: Omit<HashCandidate, "confidence" | "category" | "generateHint"> & {
  confidence?: HashConfidence;
  category?: HashCategory;
  generateHint?: GenerateHint;
}): HashCandidate {
  return {
    confidence: partial.confidence ?? "high",
    category: partial.category ?? "other",
    generateHint: partial.generateHint ?? null,
    hashcat: partial.hashcat,
    john: partial.john,
    id: partial.id,
    name: partial.name,
    zh: partial.zh,
    descZh: partial.descZh,
    descEn: partial.descEn
  };
}

const PREFIX_RULES: PrefixRule[] = [
  {
    test: (v) => /^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$/.test(v),
    build: () => [candidate({
      id: "bcrypt", name: "bcrypt", zh: "bcrypt",
      descZh: "Blowfish 慢哈希，自带盐值与代价因子（rounds），现代后台首选。",
      descEn: "Blowfish-based slow hash with embedded salt and cost factor.",
      confidence: "high", category: "application", hashcat: "3200", john: "bcrypt", generateHint: "bcrypt"
    })]
  },
  {
    test: (v) => /^\$argon2(id|i|d)\$/.test(v),
    build: () => [candidate({
      id: "argon2", name: "Argon2", zh: "Argon2",
      descZh: "内存困难型现代慢哈希（2015 密码哈希竞赛冠军），本工具暂不提供生成。",
      descEn: "Memory-hard modern password hashing (PHC winner).",
      confidence: "high", category: "application", hashcat: "34000", john: "argon2", generateHint: null
    })]
  },
  {
    test: (v) => /^pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/=]+$/.test(v),
    build: () => [candidate({
      id: "django-pbkdf2-sha256", name: "Django PBKDF2-SHA256", zh: "Django PBKDF2-SHA256",
      descZh: "Django 默认口令存储：pbkdf2_sha256$迭代$盐$摘要。可用本工具 PBKDF2 生成。",
      descEn: "Django default password storage using PBKDF2-HMAC-SHA256.",
      confidence: "high", category: "application", hashcat: "10000", john: "django", generateHint: "pbkdf2"
    })]
  },
  {
    test: (v) => /^pbkdf2_sha1\$/.test(v),
    build: () => [candidate({
      id: "django-pbkdf2-sha1", name: "Django PBKDF2-SHA1", zh: "Django PBKDF2-SHA1",
      descZh: "Django 旧版 PBKDF2-HMAC-SHA1 口令存储。",
      descEn: "Django legacy PBKDF2-HMAC-SHA1 password storage.",
      confidence: "high", category: "application", hashcat: "10000", john: "django", generateHint: null
    })]
  },
  {
    test: (v) => /^\$P\$[./A-Za-z0-9]{31}$/.test(v) || /^\$H\$[./A-Za-z0-9]{31}$/.test(v),
    build: () => [candidate({
      id: "phpass", name: "phpass (WordPress/phpBB)", zh: "phpass（WordPress/phpBB）",
      descZh: "WordPress、phpBB3 使用的 portable phpass 加盐迭代 MD5。",
      descEn: "Portable phpass salted-iterated MD5 (WordPress, phpBB3).",
      confidence: "high", category: "application", hashcat: "400", john: "phpass", generateHint: null
    })]
  },
  {
    test: (v) => /^\$6\$/.test(v),
    build: () => [candidate({
      id: "sha512crypt", name: "sha512crypt ($6$)", zh: "sha512crypt（$6$）",
      descZh: "Linux /etc/shadow 默认格式，SHA-512 crypt，加盐多轮。",
      descEn: "Linux /etc/shadow default SHA-512 crypt with salt.",
      confidence: "high", category: "unix", hashcat: "1800", john: "sha512crypt", generateHint: null
    })]
  },
  {
    test: (v) => /^\$5\$/.test(v),
    build: () => [candidate({
      id: "sha256crypt", name: "sha256crypt ($5$)", zh: "sha256crypt（$5$）",
      descZh: "Linux crypt SHA-256 格式，加盐多轮。",
      descEn: "Linux SHA-256 crypt with salt.",
      confidence: "high", category: "unix", hashcat: "7400", john: "sha256crypt", generateHint: null
    })]
  },
  {
    test: (v) => /^\$1\$/.test(v),
    build: () => [candidate({
      id: "md5crypt", name: "md5crypt ($1$)", zh: "md5crypt（$1$）",
      descZh: "传统 Unix / Cisco IOS type 5 的加盐迭代 MD5 crypt。",
      descEn: "Legacy Unix / Cisco type 5 salted iterated MD5 crypt.",
      confidence: "high", category: "unix", hashcat: "500", john: "md5crypt", generateHint: null
    })]
  },
  {
    test: (v) => /^\$apr1\$/.test(v),
    build: () => [candidate({
      id: "apr1", name: "Apache apr1 ($apr1$)", zh: "Apache apr1（$apr1$）",
      descZh: "Apache htpasswd 使用的 apr1 加盐 MD5 变体。",
      descEn: "Apache htpasswd apr1 salted MD5 variant.",
      confidence: "high", category: "application", hashcat: "1600", john: "md5crypt", generateHint: null
    })]
  },
  {
    test: (v) => /^\{SSHA\}/i.test(v),
    build: () => [candidate({
      id: "ldap-ssha", name: "LDAP {SSHA}", zh: "LDAP {SSHA}",
      descZh: "OpenLDAP 加盐 SHA-1（Base64 编码摘要+盐）。",
      descEn: "OpenLDAP salted SHA-1 (base64 digest + salt).",
      confidence: "high", category: "application", hashcat: "111", john: "salted-sha1", generateHint: null
    })]
  },
  {
    test: (v) => /^\{SHA\}/i.test(v),
    build: () => [candidate({
      id: "ldap-sha", name: "LDAP {SHA}", zh: "LDAP {SHA}",
      descZh: "OpenLDAP 无盐 SHA-1（Base64 编码），可用本工具常用哈希生成。",
      descEn: "OpenLDAP unsalted SHA-1 (base64).",
      confidence: "high", category: "application", hashcat: "101", john: "raw-sha1", generateHint: "common"
    })]
  },
  {
    test: (v) => /^\{SMD5\}/i.test(v),
    build: () => [candidate({
      id: "ldap-smd5", name: "LDAP {SMD5}", zh: "LDAP {SMD5}",
      descZh: "OpenLDAP 加盐 MD5（Base64 编码）。",
      descEn: "OpenLDAP salted MD5 (base64).",
      confidence: "high", category: "application", hashcat: "", john: "salted-md5", generateHint: null
    })]
  },
  {
    test: (v) => /^\{MD5\}/i.test(v),
    build: () => [candidate({
      id: "ldap-md5", name: "LDAP {MD5}", zh: "LDAP {MD5}",
      descZh: "OpenLDAP 无盐 MD5（Base64 编码）。",
      descEn: "OpenLDAP unsalted MD5 (base64).",
      confidence: "high", category: "application", hashcat: "", john: "raw-md5", generateHint: "common"
    })]
  },
  {
    test: (v) => /^\*[A-F0-9]{40}$/.test(v),
    build: () => [candidate({
      id: "mysql41", name: "MySQL 4.1+ native", zh: "MySQL 4.1+ 口令",
      descZh: "MySQL native password：SHA1(SHA1(pwd)) 大写并前缀 *。可用本工具生成。",
      descEn: "MySQL native password: *SHA1(SHA1(pwd)).",
      confidence: "high", category: "application", hashcat: "300", john: "mysql-sha1", generateHint: "common"
    })]
  }
];

// ---------------------------------------------------------------------------
// Generic fixed-length hex fallbacks — ambiguous, so emit ranked candidates.
// ---------------------------------------------------------------------------

const HEX_LENGTH_RULES: Record<number, HashCandidate[]> = {
  8: [
    candidate({ id: "crc32", name: "CRC32", zh: "CRC32", descZh: "32 位循环冗余校验（非加密哈希）。", descEn: "32-bit cyclic redundancy checksum.", confidence: "medium", category: "checksum", hashcat: "11500", john: "crc32", generateHint: null }),
    candidate({ id: "adler32", name: "Adler-32", zh: "Adler-32", descZh: "zlib 使用的 32 位校验和。", descEn: "32-bit Adler checksum used by zlib.", confidence: "low", category: "checksum", generateHint: null })
  ],
  16: [
    candidate({ id: "mysql323", name: "MySQL323 (old)", zh: "MySQL323（旧版）", descZh: "MySQL ≤4.0 旧口令算法，16 位十六进制。", descEn: "Legacy MySQL <=4.0 password hash.", confidence: "medium", category: "application", hashcat: "200", john: "mysql", generateHint: null }),
    candidate({ id: "crc64", name: "CRC64", zh: "CRC64", descZh: "64 位循环冗余校验。", descEn: "64-bit CRC checksum.", confidence: "low", category: "checksum", generateHint: null })
  ],
  32: [
    candidate({ id: "md5", name: "MD5", zh: "MD5", descZh: "最常见的 128 位摘要，可能是原始口令或加盐口令。可用本工具生成。", descEn: "Ubiquitous 128-bit digest, possibly raw or salted.", confidence: "high", category: "raw", hashcat: "0", john: "raw-md5", generateHint: "common" }),
    candidate({ id: "ntlm", name: "NTLM", zh: "NTLM", descZh: "Windows NT 口令哈希（MD4 of UTF-16LE），长度同 MD5。", descEn: "Windows NTLM hash (MD4 of UTF-16LE password).", confidence: "medium", category: "windows", hashcat: "1000", john: "nt", generateHint: null }),
    candidate({ id: "lm", name: "LM", zh: "LM", descZh: "Windows LAN Manager 旧口令哈希（弱）。", descEn: "Windows LAN Manager legacy hash (weak).", confidence: "low", category: "windows", hashcat: "3000", john: "lm", generateHint: null }),
    candidate({ id: "md4", name: "MD4", zh: "MD4", descZh: "已废弃的 128 位摘要。", descEn: "Obsolete 128-bit digest.", confidence: "low", category: "raw", hashcat: "900", john: "raw-md4", generateHint: null })
  ],
  40: [
    candidate({ id: "sha1", name: "SHA-1", zh: "SHA-1", descZh: "160 位摘要，可能是原始口令或加盐口令。可用本工具生成。", descEn: "160-bit SHA-1 digest, possibly raw or salted.", confidence: "high", category: "raw", hashcat: "100", john: "raw-sha1", generateHint: "common" }),
    candidate({ id: "ripemd160", name: "RIPEMD-160", zh: "RIPEMD-160", descZh: "160 位 RIPEMD 摘要，长度同 SHA-1。", descEn: "160-bit RIPEMD digest.", confidence: "medium", category: "raw", hashcat: "6000", john: "ripemd-160", generateHint: "common" }),
    candidate({ id: "mysql41-nostar", name: "MySQL 4.1 (no prefix)", zh: "MySQL 4.1（无 * 前缀）", descZh: "去掉 * 的 MySQL native password 摘要。", descEn: "MySQL native password digest without the leading *.", confidence: "low", category: "application", hashcat: "300", generateHint: "common" })
  ],
  56: [
    candidate({ id: "sha224", name: "SHA-224", zh: "SHA-224", descZh: "SHA-2 家族 224 位摘要。", descEn: "SHA-2 family 224-bit digest.", confidence: "high", category: "raw", hashcat: "1300", john: "raw-sha224", generateHint: null }),
    candidate({ id: "sha3-224", name: "SHA3-224", zh: "SHA3-224", descZh: "Keccak/SHA3 224 位摘要。", descEn: "SHA3-224 digest.", confidence: "low", category: "raw", hashcat: "17300", generateHint: null })
  ],
  64: [
    candidate({ id: "sha256", name: "SHA-256", zh: "SHA-256", descZh: "256 位摘要，最常见的现代原始哈希。可用本工具生成。", descEn: "256-bit SHA-256, common modern raw hash.", confidence: "high", category: "raw", hashcat: "1400", john: "raw-sha256", generateHint: "common" }),
    candidate({ id: "sha3-256", name: "SHA3-256", zh: "SHA3-256", descZh: "Keccak/SHA3 256 位摘要。", descEn: "SHA3-256 digest.", confidence: "medium", category: "raw", hashcat: "17400", generateHint: null }),
    candidate({ id: "sm3", name: "SM3", zh: "国密 SM3", descZh: "中国国密 256 位摘要。", descEn: "Chinese national standard SM3 256-bit digest.", confidence: "medium", category: "raw", generateHint: null }),
    candidate({ id: "ripemd256", name: "RIPEMD-256", zh: "RIPEMD-256", descZh: "256 位 RIPEMD 摘要。", descEn: "256-bit RIPEMD digest.", confidence: "low", category: "raw", generateHint: null }),
    candidate({ id: "blake2s", name: "BLAKE2s-256", zh: "BLAKE2s-256", descZh: "BLAKE2s 256 位摘要。", descEn: "BLAKE2s 256-bit digest.", confidence: "low", category: "raw", generateHint: null })
  ],
  96: [
    candidate({ id: "sha384", name: "SHA-384", zh: "SHA-384", descZh: "SHA-2 家族 384 位摘要。", descEn: "SHA-2 family 384-bit digest.", confidence: "high", category: "raw", hashcat: "10800", john: "raw-sha384", generateHint: null }),
    candidate({ id: "sha3-384", name: "SHA3-384", zh: "SHA3-384", descZh: "SHA3-384 摘要。", descEn: "SHA3-384 digest.", confidence: "low", category: "raw", hashcat: "17500", generateHint: null })
  ],
  128: [
    candidate({ id: "sha512", name: "SHA-512", zh: "SHA-512", descZh: "512 位摘要，常见现代原始哈希。可用本工具生成。", descEn: "512-bit SHA-512, common modern raw hash.", confidence: "high", category: "raw", hashcat: "1700", john: "raw-sha512", generateHint: "common" }),
    candidate({ id: "sha3-512", name: "SHA3-512", zh: "SHA3-512", descZh: "Keccak/SHA3 512 位摘要。", descEn: "SHA3-512 digest.", confidence: "medium", category: "raw", hashcat: "17600", generateHint: "common" }),
    candidate({ id: "whirlpool", name: "Whirlpool", zh: "Whirlpool", descZh: "512 位 Whirlpool 摘要。", descEn: "512-bit Whirlpool digest.", confidence: "low", category: "raw", hashcat: "6100", generateHint: null }),
    candidate({ id: "blake2b", name: "BLAKE2b-512", zh: "BLAKE2b-512", descZh: "BLAKE2b 512 位摘要。", descEn: "BLAKE2b 512-bit digest.", confidence: "low", category: "raw", hashcat: "600", generateHint: null })
  ]
};

const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "qwerty", "abc123", "111111", "123456789",
  "letmein", "admin", "welcome", "monkey", "1234567890", "password1", "root",
  "toor", "test", "guest", "administrator", "passw0rd", "iloveyou", "000000"
]);

export function assessPasswordStrength(value: string): PasswordStrength {
  const length = value.length;
  const hasLower = /[a-z]/.test(value);
  const hasUpper = /[A-Z]/.test(value);
  const hasDigit = /[0-9]/.test(value);
  const hasSymbol = /[^A-Za-z0-9]/.test(value);
  const classes = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
  const notesZh: string[] = [];
  const notesEn: string[] = [];

  let score = 0;
  if (length >= 8) score += 1;
  if (length >= 12) score += 1;
  if (classes >= 3) score += 1;
  if (length >= 16 && classes >= 3) score += 1;

  if (COMMON_PASSWORDS.has(value.toLowerCase())) {
    score = 0;
    notesZh.push("命中常见弱口令字典");
    notesEn.push("Matches a common weak-password list");
  }
  if (length < 8) {
    notesZh.push("长度不足 8 位");
    notesEn.push("Shorter than 8 characters");
  }
  if (classes < 3) {
    notesZh.push("字符种类偏少（建议含大小写、数字、符号）");
    notesEn.push("Few character classes (mix upper/lower/digit/symbol)");
  }
  if (/^\d+$/.test(value) && length > 0) {
    notesZh.push("纯数字，极易被爆破");
    notesEn.push("Digits only — trivial to brute force");
  }

  const clamped = Math.max(0, Math.min(4, score)) as 0 | 1 | 2 | 3 | 4;
  const labelsZh = ["极弱", "弱", "中等", "强", "很强"];
  const labelsEn = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
  return {
    score: clamped,
    labelZh: labelsZh[clamped],
    labelEn: labelsEn[clamped],
    length, hasLower, hasUpper, hasDigit, hasSymbol, notesZh, notesEn
  };
}

/**
 * Heuristic: decide whether the input is more likely a plaintext password than
 * a hash. Hashes are typically pure hex/base64 of characteristic lengths or use
 * a recognised `$`/`{...}`/`*` structure.
 */
function looksLikePlaintext(value: string): boolean {
  if (/\s/.test(value)) return true;
  // Pure hex of a hash-ish length is almost certainly a digest.
  if (isHex(value) && [8, 16, 32, 40, 56, 64, 96, 128].includes(value.length)) return false;
  // Structured hash markers.
  if (/^[${*]/.test(value) || /^\{[A-Z]+\}/i.test(value)) return false;
  // Long base64 blobs are usually encoded digests, short ones are ambiguous.
  if (BASE64_RE.test(value) && value.length >= 24 && value.length % 4 === 0) return false;
  return true;
}

export function identifyHash(raw: string): HashIdentifyResult {
  const input = raw.trim();
  if (!input) {
    return { input, kind: "empty", length: 0, charsetZh: "空", charsetEn: "empty", candidates: [] };
  }

  const charset = describeCharset(input);
  const base = { input, length: input.length, charsetZh: charset.zh, charsetEn: charset.en };

  // 1) Structured / prefixed formats take priority.
  for (const rule of PREFIX_RULES) {
    if (rule.test(input)) {
      return { ...base, kind: "hash", candidates: rule.build() };
    }
  }

  // 2) Generic fixed-length hex digests.
  if (isHex(input) && HEX_LENGTH_RULES[input.length]) {
    return { ...base, kind: "hash", candidates: HEX_LENGTH_RULES[input.length] };
  }

  // 3) Otherwise treat as plaintext / unknown.
  if (looksLikePlaintext(input)) {
    return { ...base, kind: "plaintext", candidates: [], strength: assessPasswordStrength(input) };
  }

  return { ...base, kind: "unknown", candidates: [] };
}

export function confidenceLabel(confidence: HashConfidence, english: boolean) {
  if (english) return confidence === "high" ? "High" : confidence === "medium" ? "Medium" : "Low";
  return confidence === "high" ? "高" : confidence === "medium" ? "中" : "低";
}

export function generateHintLabel(hint: GenerateHint, english: boolean): string {
  if (!hint) return "";
  if (hint === "bcrypt") return english ? "Use the bcrypt generator" : "用「生成 bcrypt」";
  if (hint === "pbkdf2") return english ? "Use the PBKDF2 generator" : "用「生成 Django PBKDF2」";
  return english ? "Use the common-hash generator" : "用「生成常用哈希」";
}
