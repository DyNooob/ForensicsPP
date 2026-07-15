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

import { describe, expect, it } from "vitest";
import { base32Decode, base32Encode, parseEmail } from "../src/features/email/workbench";
import { limitEmailHtmlPreview, MAX_EMAIL_HTML_PREVIEW_CHARS } from "../src/tools/EmailTool";

describe("email encoding helpers", () => {
  it("round-trips UTF-8 through Base32", () => {
    const value = "Forensics++ 邮件";
    expect(base32Decode(base32Encode(value))).toBe(value);
  });
});

describe("EML parsing", () => {
  it("keeps oversized HTML previews bounded", () => {
    const oversized = "x".repeat(MAX_EMAIL_HTML_PREVIEW_CHARS + 100);
    expect(limitEmailHtmlPreview(oversized)).toHaveLength(MAX_EMAIL_HTML_PREVIEW_CHARS);
  });

  it("extracts identity, authentication and Received hops", async () => {
    const raw = [
      "From: Forensics++ Alerts <alerts@example.org>",
      "To: analyst@example.net",
      "Subject: Synthetic triage fixture",
      "Date: Sun, 12 Jul 2026 10:00:00 +0800",
      "Message-ID: <fixture@example.org>",
      "Received: from sender.example.org (sender.example.org [203.0.113.8]) by mx.example.net; Sun, 12 Jul 2026 10:00:01 +0800",
      "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org; dmarc=pass header.from=example.org",
      "DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=mail; bh=fixture; b=fixture",
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "Synthetic body for local parser verification."
    ].join("\r\n");

    const parsed = await parseEmail(raw);
    const summary = Object.fromEntries(parsed.rows);
    expect(summary.From).toContain("alerts@example.org");
    expect(summary.To).toContain("analyst@example.net");
    expect(summary.Subject).toBe("Synthetic triage fixture");
    expect(parsed.receivedHops).toHaveLength(1);
    expect(parsed.authAssessments.map((row) => [row.mechanism, row.result])).toEqual(expect.arrayContaining([
      ["SPF", "pass"],
      ["DKIM", "pass"],
      ["DMARC", "pass"]
    ]));
  });

  it("keeps text and HTML bodies and decodes attachments", async () => {
    const raw = [
      "From: sender@example.org",
      "To: analyst@example.net",
      "Subject: =?UTF-8?B?5rWL6K+V6YKu5Lu2?=",
      "MIME-Version: 1.0",
      'Content-Type: multipart/mixed; boundary="outer"',
      "",
      "--outer",
      'Content-Type: multipart/alternative; boundary="body"',
      "",
      "--body",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: base64",
      "",
      "5pys5Zyw5paH5pys5q2j5paH",
      "--body",
      "Content-Type: text/html; charset=utf-8",
      "Content-Transfer-Encoding: quoted-printable",
      "",
      "<html><body><strong>HTML body</strong></body></html>",
      "--body--",
      "--outer",
      'Content-Type: image/png; name="fixture.png"',
      'Content-Disposition: attachment; filename="fixture.png"',
      "Content-Transfer-Encoding: base64",
      "",
      "iVBORw0KGgo=",
      "--outer--"
    ].join("\r\n");

    const parsed = await parseEmail(raw);

    expect(Object.fromEntries(parsed.rows).Subject).toBe("测试邮件");
    expect(parsed.bodyText).toContain("本地文本正文");
    expect(parsed.bodyHtml).toContain("<strong>HTML body</strong>");
    expect(parsed.attachments).toHaveLength(1);
    expect(parsed.attachments[0]).toMatchObject({ filename: "fixture.png", contentType: "image/png", signature: "PNG image" });
    expect(Array.from(parsed.attachments[0].content.slice(0, 8))).toEqual([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  });
});
