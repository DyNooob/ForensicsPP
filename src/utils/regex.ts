/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

export function classifyRegexMatch(value: string, classifyIocRisk: (type: string, value: string) => string[]) {
  const risks: string[] = [];
  let detectedType = "Text";
  if (/^https?:\/\//i.test(value)) {
    detectedType = "URL";
    risks.push(...classifyIocRisk("URL", value));
  } else if (/^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i.test(value)) {
    detectedType = "Email";
    risks.push(...classifyIocRisk("Email", value));
  } else if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(value)) {
    detectedType = "IPv4";
    risks.push(...classifyIocRisk("IPv4", value));
  } else if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(value)) {
    detectedType = "Domain";
    risks.push(...classifyIocRisk("Domain", value));
  } else if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/i.test(value)) {
    detectedType = "Hash";
    risks.push(...classifyIocRisk("Hash", value));
  } else if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?$/.test(value)) {
    detectedType = "JWT-like";
    risks.push("token-like");
  } else if (/^CVE-\d{4}-\d{4,7}$/i.test(value)) {
    detectedType = "CVE";
  } else if (/^1[3-9]\d{9}$/.test(value)) {
    detectedType = "CN mobile";
    risks.push("personal data");
  } else if (/^(?:AKIA|ASIA)[A-Z0-9]{16}$/.test(value)) {
    detectedType = "AWS access key";
    risks.push("cloud credential");
  } else if (/^gh[pousr]_[A-Za-z0-9_]{36,255}$/.test(value)) {
    detectedType = "GitHub token";
    risks.push("credential");
  } else if (/^sk-[A-Za-z0-9_-]{20,}$/.test(value)) {
    detectedType = "API key";
    risks.push("credential");
  }
  if (/(pass(word)?|token|secret|api[_-]?key|session|auth|jwt|bearer|cookie)/i.test(value)) risks.push("credential marker");
  if (/(?:\.\.\/|<script|union\s+select|select\s+.+from|cmd\.exe|powershell)/i.test(value)) risks.push("attack marker");
  if (/^[A-Za-z0-9+/=_-]{48,}$/.test(value) && detectedType === "Text") risks.push("encoded-looking");
  return { detectedType, risk: Array.from(new Set(risks)) };
}
