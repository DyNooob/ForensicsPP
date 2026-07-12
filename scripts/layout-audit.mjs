#!/usr/bin/env node
/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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

import { spawn } from "node:child_process";
import { writeFile, mkdir, mkdtemp, readdir, rm, unlink } from "node:fs/promises";
import { request } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { deflateSync } from "node:zlib";
import { strToU8, zipSync } from "fflate";
import { Ecc, QrCode } from "@rc-component/qrcode/es/libs/qrcodegen.js";

const baseUrl = process.env.AUDIT_URL || "http://localhost:5174";
const chromePath = process.env.CHROME_PATH || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const port = Number(process.env.CDP_PORT || 9237);
const width = Number(process.env.AUDIT_WIDTH || 1366);
const height = Number(process.env.AUDIT_HEIGHT || 900);
const saveScreenshots = process.env.AUDIT_SCREENSHOTS === "1";
const defaultThemeMode = process.env.AUDIT_THEME === "dark" ? "dark" : "light";
const screenshotDir = process.env.AUDIT_SCREENSHOT_DIR || "layout-audit-screenshots";
const legalVersion = "2026-07-12";

const tools = [
  "home",
  "cyberchef",
  "image",
  "codec",
  "crypto",
  "jwt",
  "password",
  "sql",
  "sqlite",
  "registry",
  "plist",
  "browserartifacts",
  "evtx",
  "documentforensics",
  "android",
  "ioc",
  "email",
  "urltool",
  "http",
  "qr",
  "fileid",
  "png",
  "archive",
  "binary",
  "windows",
  "strings",
  "entropy",
  "hash",
  "timestamp",
  "timeline",
  "baseconvert",
  "uuid",
  "json",
  "regex",
  "pcap",
  "yara"
];

const splitEmptyStartupTools = new Set([
  "password",
  "sql",
  "sqlite",
  "timestamp",
  "yara"
]);

function getJson(pathname) {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: "127.0.0.1", port, path: pathname }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        try {
          resolve(JSON.parse(body));
        } catch (error) {
          reject(error);
        }
      });
    });
    req.on("error", reject);
    req.end();
  });
}

async function createSqliteFixture() {
  const dir = await mkdtemp(join(tmpdir(), "forensicspp-sqlite-fixture-"));
  const dbPath = join(dir, "layout-fixture.sqlite");
  const sql = `
CREATE TABLE software (
  id INTEGER PRIMARY KEY,
  slug TEXT,
  icon_image TEXT,
  zh_name TEXT,
  en_name TEXT,
  zh_summary TEXT,
  en_summary TEXT,
  zh_features TEXT,
  en_features TEXT,
  zh_specs TEXT,
  en_specs TEXT,
  created_at TEXT,
  updated_at TEXT
);
INSERT INTO software VALUES
  (1, 'transfer-evidence', 'sha256:8d33ad0e7c9b4e1f90fe9e01c2c7d7e0', '交易证据核验', 'Transaction evidence verifier', '校验交易事件表与地址关系边界，输出可复核的摘要。', 'Checks transaction event tables and address relation edges.', '哈希、时间线、字段完整性', 'Hash, timeline, field integrity', 'CSV/JSON; 可归档', 'CSV/JSON; archivable', '2026-07-01T10:00:00Z', '2026-07-08T14:00:00Z'),
  (2, 'mail-header', 'sha256:b6c5f55e3a0190db9d4216f7e41c26aa', '邮件头分析', 'Email header analyzer', '整理 Received 链、认证结果和正文链接。', 'Summarizes Received chain, authentication results, and body URLs.', 'SPF/DKIM/DMARC、附件摘要', 'SPF/DKIM/DMARC, attachment summary', 'EML; local only', 'EML; local only', '2026-07-02T08:30:00Z', '2026-07-08T16:00:00Z'),
  (3, 'sqlite-browser', 'sha256:d97ad1f5fb76be9fc6f6d6ea76f2c33c', 'SQLite 浏览器', 'SQLite browser', '浏览表、复制数据、编辑单元格并导出数据库。', 'Browse tables, copy data, edit cells, and export database.', '表格、SQL、修改记录', 'Tables, SQL, change log', 'db/sqlite/sqlite3', 'db/sqlite/sqlite3', '2026-07-03T09:00:00Z', '2026-07-08T18:00:00Z');
CREATE VIEW software_names AS SELECT id, zh_name, en_name, updated_at FROM software;
`;
  const child = spawn("sqlite3", [dbPath], { stdio: ["pipe", "ignore", "pipe"] });
  child.stdin.end(sql);
  await new Promise((resolve, reject) => {
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve() : reject(new Error(stderr)));
  });
  return { dbPath, dir };
}

async function createSqlFixture() {
  const dir = await mkdtemp(join(tmpdir(), "forensicspp-sql-fixture-"));
  const sqlPath = join(dir, "layout-fixture.sql");
  const sql = `-- ForensicsPP layout fixture
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username VARCHAR(64),
  email VARCHAR(120),
  password_hash VARCHAR(255),
  created_at DATETIME
);

CREATE TABLE events (
  id INTEGER PRIMARY KEY,
  user_id INTEGER,
  ip_address VARCHAR(64),
  user_agent TEXT,
  event_time DATETIME,
  detail TEXT
);

INSERT INTO users VALUES
  (1, 'alice', 'alice@example.org', '$2b$12$examplehashaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '2026-07-01 10:00:00'),
  (2, 'bob', 'bob@example.org', '5f4dcc3b5aa765d61d8327deb882cf99', '2026-07-02 11:30:00');

INSERT INTO events VALUES
  (11, 1, '192.0.2.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '2026-07-08 08:10:00', 'login success from desktop'),
  (12, 1, '198.51.100.24', 'curl/8.7.1', '2026-07-08 09:15:44', 'api token refresh from automation'),
  (13, 2, '203.0.113.8', 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)', '2026-07-08 10:27:00', 'password reset request sent');
`;
  await writeFile(sqlPath, sql, "utf8");
  return { sqlPath, dir };
}

async function createEmailFixture() {
  const dir = await mkdtemp(join(tmpdir(), "forensicspp-email-fixture-"));
  const emailPath = join(dir, "layout-fixture.eml");
  const eml = `From: Forensics++ Alerts <alerts@example.org>
To: analyst@example.net
Subject: Evidence triage summary
Date: Tue, 08 Jul 2026 16:25:00 +0800
Message-ID: <forensicspp-layout-fixture@example.org>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="fpp-boundary"
Received: from gateway.example.org (gateway.example.org [198.51.100.14]) by mail.example.net with ESMTPS id abc123 for <analyst@example.net>; Tue, 08 Jul 2026 16:25:03 +0800
Received: from sender.example.org (sender.example.org [203.0.113.77]) by gateway.example.org with ESMTPS id def456 for <analyst@example.net>; Tue, 08 Jul 2026 16:24:58 +0800
Authentication-Results: mail.example.net; spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org; dmarc=pass header.from=example.org

--fpp-boundary
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

This message summarizes evidence triage.
Portal: https://case.example.org/review?id=42
Attachment hash note: sha256=3D0f4c9a9bb0b9a1d90b770abfe4c313

--fpp-boundary
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

<html><body><p>Evidence triage summary</p><p><a href=3D"https://case.example.org/review?id=3D42">Open case</a></p></body></html>

--fpp-boundary
Content-Type: text/plain; name="notes.txt"
Content-Disposition: attachment; filename="notes.txt"
Content-Transfer-Encoding: base64

U29tZSBsb2NhbCBub3RlcyBmb3IgbGF5b3V0IGF1ZGl0Lgo=

--fpp-boundary--
`;
  await writeFile(emailPath, eml, "utf8");
  return { emailPath, dir };
}

function makePcapTcpFrame({ sourceIp, destinationIp, sourcePort, destinationPort, payload, sequence = 1 }) {
  const body = Buffer.from(payload, "utf8");
  const frame = Buffer.alloc(14 + 20 + 20 + body.length);
  Buffer.from("001122334455", "hex").copy(frame, 0);
  Buffer.from("66778899aabb", "hex").copy(frame, 6);
  frame.writeUInt16BE(0x0800, 12);
  const ip = 14;
  frame[ip] = 0x45;
  frame.writeUInt16BE(20 + 20 + body.length, ip + 2);
  frame.writeUInt16BE(sequence & 0xffff, ip + 4);
  frame.writeUInt16BE(0x4000, ip + 6);
  frame[ip + 8] = 64;
  frame[ip + 9] = 6;
  sourceIp.forEach((value, index) => { frame[ip + 12 + index] = value; });
  destinationIp.forEach((value, index) => { frame[ip + 16 + index] = value; });
  const tcp = ip + 20;
  frame.writeUInt16BE(sourcePort, tcp);
  frame.writeUInt16BE(destinationPort, tcp + 2);
  frame.writeUInt32BE(sequence, tcp + 4);
  frame.writeUInt32BE(1, tcp + 8);
  frame[tcp + 12] = 0x50;
  frame[tcp + 13] = 0x18;
  frame.writeUInt16BE(65535, tcp + 14);
  body.copy(frame, tcp + 20);
  return frame;
}

function makeClassicPcap(frames) {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(0, 8);
  header.writeUInt32LE(0, 12);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(1, 20);
  const records = frames.map((frame, index) => {
    const record = Buffer.alloc(16);
    record.writeUInt32LE(1783501200 + index, 0);
    record.writeUInt32LE(index * 125000, 4);
    record.writeUInt32LE(frame.length, 8);
    record.writeUInt32LE(frame.length, 12);
    return Buffer.concat([record, frame]);
  });
  return Buffer.concat([header, ...records]);
}

function pngCrc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const typeBytes = Buffer.from(type, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(pngCrc32(Buffer.concat([typeBytes, data])));
  return Buffer.concat([length, typeBytes, data, crc]);
}

function createAuditPng(width = 64, height = 48) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const row = y * (width * 4 + 1);
    raw[row] = 0;
    for (let x = 0; x < width; x += 1) {
      const pixel = row + 1 + x * 4;
      const left = x < width / 2;
      const top = y < height / 2;
      const diagonal = Math.abs(x - y * width / height) < 2 || Math.abs((width - 1 - x) - y * width / height) < 2;
      raw[pixel] = diagonal ? 24 : left ? 34 : 224;
      raw[pixel + 1] = diagonal ? 39 : top ? 111 : 174;
      raw[pixel + 2] = diagonal ? 58 : left === top ? 126 : 62;
      raw[pixel + 3] = 255;
    }
  }
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", deflateSync(raw)),
    pngChunk("IEND", Buffer.alloc(0))
  ]);
}

function createAuditPdf() {
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
    "<< /Length 0 >>\nstream\n\nendstream",
    "<< /Title (ForensicsPP layout fixture) /Author (Forensics++) >>"
  ];
  let pdf = "%PDF-1.7\n";
  const offsets = [0];
  for (let index = 0; index < objects.length; index += 1) {
    offsets.push(Buffer.byteLength(pdf));
    pdf += `${index + 1} 0 obj\n${objects[index]}\nendobj\n`;
  }
  const xref = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let index = 1; index <= objects.length; index += 1) pdf += `${String(offsets[index]).padStart(10, "0")} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R /Info 5 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(pdf, "utf8");
}

async function createFileToolFixtures() {
  const dir = await mkdtemp(join(tmpdir(), "forensicspp-file-fixtures-"));
  const pngPath = join(dir, "layout-image.png");
  const qrPath = join(dir, "layout-qr.svg");
  const archivePath = join(dir, "layout-archive.zip");
  const binaryPath = join(dir, "layout-binary.exe");
  const windowsPath = join(dir, "POWERSHELL.EXE-12345678.pf");
  const pcapPath = join(dir, "layout-traffic.pcap");
  const pdfPath = join(dir, "layout-document.pdf");
  const browserHistoryPath = join(dir, "History");

  const png = Buffer.concat([createAuditPng(), Buffer.from("\nFPP_TRAILER_TEST\n", "utf8")]);
  await writeFile(pngPath, png);

  const qr = QrCode.encodeText("https://github.com/DyNooob/ForensicsPP", Ecc.MEDIUM);
  const quietZone = 4;
  const viewSize = qr.size + quietZone * 2;
  const modules = [];
  for (let y = 0; y < qr.size; y += 1) {
    for (let x = 0; x < qr.size; x += 1) {
      if (qr.getModule(x, y)) modules.push(`M${x + quietZone} ${y + quietZone}h1v1h-1z`);
    }
  }
  const qrSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewSize} ${viewSize}" width="256" height="256" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path d="${modules.join("")}" fill="#000"/></svg>`;
  await writeFile(qrPath, qrSvg);

  const archive = zipSync({
    "case/notes.txt": strToU8("Forensics++ layout fixture\ncase=FPP-001\nsource=archive\n"),
    "case/evidence.json": strToU8(JSON.stringify({ caseId: "FPP-001", status: "review", source: "layout-audit" }, null, 2)),
    "case/logs/events.log": strToU8("2026-07-08T09:12:33Z login user=analyst ip=203.0.113.42\n")
  }, { level: 6 });
  await writeFile(archivePath, archive);

  const pe = Buffer.alloc(1024);
  pe.write("MZ", 0, "ascii");
  pe.writeUInt32LE(0x80, 0x3c);
  pe.write("PE\0\0", 0x80, "binary");
  pe.writeUInt16LE(0x8664, 0x84);
  pe.writeUInt16LE(1, 0x86);
  pe.writeUInt32LE(1783501200, 0x88);
  pe.writeUInt16LE(0xf0, 0x94);
  pe.writeUInt16LE(0x2022, 0x96);
  pe.writeUInt16LE(0x20b, 0x98);
  pe.write(".text\0\0\0", 0x188, "binary");
  pe.writeUInt32LE(0x200, 0x190);
  pe.writeUInt32LE(0x1000, 0x194);
  pe.write("ForensicsPP layout fixture https://case.example.org/review", 0x220, "ascii");
  await writeFile(binaryPath, pe);

  const prefetch = Buffer.alloc(256);
  prefetch.writeUInt32LE(30, 0);
  prefetch.write("SCCA", 4, "ascii");
  prefetch.writeUInt32LE(prefetch.length, 12);
  Buffer.from("POWERSHELL.EXE", "utf16le").copy(prefetch, 16, 0, 60);
  prefetch.writeUInt32LE(0x12345678, 76);
  const filetime = (BigInt(Date.UTC(2026, 6, 8, 9, 12, 33)) + 11644473600000n) * 10000n;
  prefetch.writeBigUInt64LE(filetime, 0x80);
  prefetch.writeUInt32LE(7, 0xd0);
  Buffer.from("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "utf16le").copy(prefetch, 0xd8);
  await writeFile(windowsPath, prefetch);

  const requestFrame = makePcapTcpFrame({
    sourceIp: [10, 0, 0, 5],
    destinationIp: [93, 184, 216, 34],
    sourcePort: 51324,
    destinationPort: 80,
    payload: "GET /evidence.txt HTTP/1.1\r\nHost: case.example.org\r\nUser-Agent: ForensicsPP\r\n\r\n",
    sequence: 1
  });
  const responseFrame = makePcapTcpFrame({
    sourceIp: [93, 184, 216, 34],
    destinationIp: [10, 0, 0, 5],
    sourcePort: 80,
    destinationPort: 51324,
    payload: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 18\r\nContent-Disposition: attachment; filename=evidence.txt\r\n\r\nForensicsPP sample",
    sequence: 2
  });
  await writeFile(pcapPath, makeClassicPcap([requestFrame, responseFrame]));
  await writeFile(pdfPath, createAuditPdf());
  const browserDb = spawn("sqlite3", [browserHistoryPath], { stdio: ["pipe", "ignore", "pipe"] });
  browserDb.stdin.end(`
    CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER);
    CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER, visit_duration INTEGER);
    CREATE TABLE downloads (id INTEGER PRIMARY KEY, start_time INTEGER, end_time INTEGER, target_path TEXT, current_path TEXT, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, mime_type TEXT, tab_url TEXT, site_url TEXT, referrer TEXT);
    CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
    INSERT INTO urls VALUES (1, 'https://case.example.org/review', 'Case review', 3, 1);
    INSERT INTO visits VALUES (7, 1, 13348638245000000, 805306368, 2500000);
    INSERT INTO downloads VALUES (9, 13348638245000000, 13348638246000000, '/Users/analyst/report.zip', '/tmp/report.zip', 128, 128, 1, 'application/zip', '', '', 'https://case.example.org/review');
    INSERT INTO downloads_url_chains VALUES (9, 0, 'https://case.example.org/report.zip');
  `);
  await new Promise((resolve, reject) => {
    let message = "";
    browserDb.stderr.on("data", (chunk) => { message += chunk.toString(); });
    browserDb.on("error", reject);
    browserDb.on("close", (code) => code === 0 ? resolve() : reject(new Error(message)));
  });

  return { dir, pngPath, qrPath, archivePath, binaryPath, windowsPath, pcapPath, pdfPath, browserHistoryPath, evtxPath: join(process.cwd(), "tests/fixtures/Application.evtx") };
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForRuntimeValue(client, expression, timeout = 8000) {
  const started = Date.now();
  while (Date.now() - started < timeout) {
    const result = await client.send("Runtime.evaluate", {
      expression,
      returnByValue: true
    });
    if (result.result.value) return true;
    await wait(180);
  }
  return false;
}

async function waitForCdp() {
  const started = Date.now();
  while (Date.now() - started < 12000) {
    try {
      const tabs = await getJson("/json");
      if (Array.isArray(tabs) && tabs.some((item) => item.type === "page" && item.webSocketDebuggerUrl)) return tabs;
    } catch {
      await wait(250);
    }
    await wait(250);
  }
  throw new Error(`Chrome DevTools did not become ready on port ${port}.`);
}

function createCdpClient(webSocketDebuggerUrl) {
  const ws = new WebSocket(webSocketDebuggerUrl);
  let id = 0;
  const pending = new Map();

  ws.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (!message.id || !pending.has(message.id)) return;
    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) reject(new Error(JSON.stringify(message.error)));
    else resolve(message.result);
  });

  const opened = new Promise((resolve) => {
    ws.addEventListener("open", resolve, { once: true });
  });

  return {
    async ready() {
      await opened;
    },
    send(method, params = {}) {
      return new Promise((resolve, reject) => {
        const nextId = ++id;
        pending.set(nextId, { resolve, reject });
        ws.send(JSON.stringify({ id: nextId, method, params }));
      });
    },
    close() {
      ws.close();
    }
  };
}

async function assertServerReachable() {
  const target = new URL(baseUrl);
  try {
    await new Promise((resolve, reject) => {
      const req = request(target, { method: "HEAD" }, (res) => {
        res.resume();
        if (res.statusCode && res.statusCode < 500) resolve();
        else reject(new Error(`${baseUrl} responded with status ${res.statusCode}`));
      });
      req.on("error", reject);
      req.end();
    });
  } catch (error) {
    const details = error instanceof AggregateError
      ? error.errors?.map((item) => item.message).join("; ")
      : error instanceof Error
        ? error.message
        : String(error);
    throw new Error(`Cannot reach ${baseUrl}. Start npm run dev/preview first, or set AUDIT_URL. ${details || ""}`.trim());
  }
}

function visiblePanelAuditExpression(tool) {
  return `(() => {
    const e = document.documentElement;
    const body = document.querySelector(".tool-body");
    const container = body?.firstElementChild;
    const rect = (node) => {
      if (!node) return null;
      const r = node.getBoundingClientRect();
      const cs = getComputedStyle(node);
      return {
        x: Math.round(r.x),
        y: Math.round(r.y),
        w: Math.round(r.width),
        h: Math.round(r.height),
        display: cs.display,
        grid: cs.gridTemplateColumns,
        cls: node.className?.toString() || node.tagName
      };
    };
    const visiblePanels = [...document.querySelectorAll(".tool-panel,.home-hero,.home-directory,.cyberchef-panel,.sqlite-selection-bar,details[class*='advanced-shell']")]
      .filter((node) => {
        const r = node.getBoundingClientRect();
        const cs = getComputedStyle(node);
        return r.width > 1 && r.height > 1 && cs.display !== "none" && cs.visibility !== "hidden";
      });
    const visibleTables = [...document.querySelectorAll(".data-table,.info-table")]
      .filter((node) => {
        const r = node.getBoundingClientRect();
        const cs = getComputedStyle(node);
        return r.width > 1 && r.height > 1 && cs.display !== "none" && cs.visibility !== "hidden";
      });
    const badWritingCells = [...document.querySelectorAll(".data-table th,.data-table td,.info-table th,.info-table td")]
      .filter((node) => {
        const r = node.getBoundingClientRect();
        const cs = getComputedStyle(node);
        return r.width > 1 && r.height > 1 && cs.display !== "none" && cs.visibility !== "hidden" && cs.writingMode !== "horizontal-tb";
      });
    const visibleControls = [...document.querySelectorAll("button,a[href],input:not([type='hidden']),select,textarea,[role='button']")]
      .filter((node) => {
        const r = node.getBoundingClientRect();
        const cs = getComputedStyle(node);
        return r.width > 1 && r.height > 1 && cs.display !== "none" && cs.visibility !== "hidden";
      });
    const controlName = (node) => {
      const labelledBy = (node.getAttribute("aria-labelledby") || "")
        .split(/\s+/)
        .filter(Boolean)
        .map((id) => document.getElementById(id)?.textContent || "")
        .join(" ");
      const labels = "labels" in node && node.labels
        ? [...node.labels].map((label) => label.textContent || "").join(" ")
        : "";
      const ownText = node.matches("button,a[href],[role='button']") ? node.textContent : "";
      return [
        node.getAttribute("aria-label"),
        labelledBy,
        labels,
        node.getAttribute("title"),
        ownText,
        node.querySelector?.("img")?.getAttribute("alt")
      ].filter(Boolean).join(" ").trim();
    };
    const unnamedControls = visibleControls.filter((node) => !controlName(node));
    const legacyControls = [...document.querySelectorAll("select,input[type='number'],input[type='checkbox']:not(.ant-checkbox-input),input[type='radio']:not(.ant-segmented-item-input)")]
      .filter((node) => {
        const r = node.getBoundingClientRect();
        const cs = getComputedStyle(node);
        return r.width > 1 && r.height > 1 && cs.display !== "none" && cs.visibility !== "hidden";
      });
    const allowSplitEmpty = ${JSON.stringify(Array.from(splitEmptyStartupTools))}.includes(${JSON.stringify(tool)});
    const emptyStateSplitRows = container?.className?.toString().includes("empty-") && !allowSplitEmpty
      ? visiblePanels.filter((panel, index) => visiblePanels.some((other, otherIndex) => {
          if (index >= otherIndex) return false;
          const a = panel.getBoundingClientRect();
          const b = other.getBoundingClientRect();
          return Math.abs(a.top - b.top) < 12 && Math.abs(a.left - b.left) > 80;
        })).length
      : 0;
    const overlaps = [];
    for (let i = 0; i < Math.min(visiblePanels.length, 10); i += 1) {
      for (let j = i + 1; j < Math.min(visiblePanels.length, 10); j += 1) {
        const a = visiblePanels[i].getBoundingClientRect();
        const b = visiblePanels[j].getBoundingClientRect();
        const overlapX = Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left));
        const overlapY = Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top));
        const sameBox = a.left === b.left && a.top === b.top && a.width === b.width && a.height === b.height;
        if (!sameBox && overlapX * overlapY > 600) overlaps.push([i, j, Math.round(overlapX * overlapY)]);
      }
    }
    const overflowers = [...document.querySelectorAll('body *')]
      .filter((node) => {
        const r = node.getBoundingClientRect();
        const styles = getComputedStyle(node);
        return styles.display !== 'none' && r.width > 0 && r.right > document.documentElement.clientWidth + 1;
      })
      .slice(0, 12)
      .map((node) => {
        const r = node.getBoundingClientRect();
        return {
          cls: node.className?.toString?.() || node.tagName,
          x: Math.round(r.x),
          w: Math.round(r.width),
          right: Math.round(r.right)
        };
      });
    return {
      tool: ${JSON.stringify(tool)},
      title: document.querySelector(".page-title")?.textContent || "",
      overflowX: e.scrollWidth - e.clientWidth,
      scrollH: e.scrollHeight,
      container: rect(container),
      visiblePanelCount: visiblePanels.length,
      visibleTableCount: visibleTables.length,
      badWritingCellCount: badWritingCells.length,
      unnamedControlCount: unnamedControls.length,
      unnamedControls: unnamedControls.slice(0, 12).map((node) => ({
        tag: node.tagName,
        type: node.getAttribute("type") || "",
        cls: node.className?.toString?.() || "",
        role: node.getAttribute("role") || ""
      })),
      legacyControlCount: legacyControls.length,
      legacyControls: legacyControls.slice(0, 12).map((node) => ({
        tag: node.tagName,
        type: node.getAttribute("type") || "",
        cls: node.className?.toString?.() || ""
      })),
      emptyStateSplitRows,
      panels: visiblePanels.slice(0, 6).map(rect),
      overlaps,
      overflowers
    };
  })()`;
}

async function resetScreenshotDir() {
  await mkdir(screenshotDir, { recursive: true });
  const entries = await readdir(screenshotDir, { withFileTypes: true });
  await Promise.all(entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".png"))
    .map((entry) => unlink(join(screenshotDir, entry.name))));
}

async function captureViewport(client, filename) {
  const shot = await client.send("Page.captureScreenshot", {
    format: "png",
    captureBeyondViewport: false
  });
  await writeFile(join(screenshotDir, filename), Buffer.from(shot.data, "base64"));
}

async function loadToolState(client, tool, options = {}) {
  const {
    lang = "zh",
    themeMode = defaultThemeMode,
    sidebarCollapsed = false,
    cleanHome = false,
    legalAccepted = true
  } = options;
  await client.send("Runtime.evaluate", {
    expression: `
      localStorage.setItem("forensicspp:app.lang", JSON.stringify(${JSON.stringify(lang)}));
      localStorage.setItem("forensicspp:app.activeTool", JSON.stringify(${JSON.stringify(tool)}));
      localStorage.setItem("forensicspp:app.themeMode", JSON.stringify(${JSON.stringify(themeMode)}));
      localStorage.setItem("forensicspp:app.sidebarCollapsed", JSON.stringify(${JSON.stringify(sidebarCollapsed)}));
      if (${JSON.stringify(legalAccepted)}) {
        localStorage.setItem("forensicspp:legal.acceptedVersion", JSON.stringify(${JSON.stringify(legalVersion)}));
      } else {
        localStorage.removeItem("forensicspp:legal.acceptedVersion");
      }
      if (${JSON.stringify(cleanHome)}) {
        localStorage.setItem("forensicspp:app.recentTools", JSON.stringify([]));
        localStorage.setItem("forensicspp:app.favoriteTools", JSON.stringify([]));
      }
      location.hash = ${JSON.stringify(tool)};
    `,
    awaitPromise: true
  });
  await client.send("Page.reload", { ignoreCache: true });
  await wait(tool === "cyberchef" ? 1800 : 500);
  await waitForRuntimeValue(
    client,
    "Boolean(document.querySelector('.tool-body')?.firstElementChild && document.querySelector('.page-title')?.textContent && !document.querySelector('.tool-loading-state'))",
    tool === "cyberchef" ? 12000 : 8000
  );
}

async function clickRuntimeButton(client, expression, readyExpression) {
  await client.send("Runtime.evaluate", {
    expression,
    awaitPromise: true
  });
  await waitForRuntimeValue(client, readyExpression, 5000);
  await wait(220);
}

async function stopChrome(chrome) {
  if (chrome.exitCode !== null || chrome.signalCode) return;
  await new Promise((resolve) => {
    const timer = setTimeout(resolve, 1500);
    chrome.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    chrome.kill("SIGTERM");
  });
  chrome.stderr?.destroy();
}

async function auditConsentBar(client) {
  await loadToolState(client, "home", { cleanHome: true, legalAccepted: false });
  const result = await client.send("Runtime.evaluate", {
    expression: `(() => {
      const panel = document.querySelector(".legal-consent-modal .ant-modal-content");
      const mask = document.querySelector(".ant-modal-mask");
      const panelRect = panel?.getBoundingClientRect();
      const actions = [...document.querySelectorAll(".legal-consent-actions a, .legal-consent-actions button")];
      const ok = Boolean(panelRect)
        && Boolean(mask && getComputedStyle(mask).display !== "none")
        && panelRect.width <= Math.min(540, innerWidth - 24)
        && panelRect.left >= 8
        && panelRect.right <= innerWidth - 8
        && panelRect.top >= 8
        && panelRect.bottom <= innerHeight - 8
        && actions.length === 2
        && !document.querySelector(".legal-consent-modal .ant-modal-close");
      return {
        id: "home-consent",
        ok,
        rect: panelRect ? {
          x: Math.round(panelRect.x),
          y: Math.round(panelRect.y),
          w: Math.round(panelRect.width),
          h: Math.round(panelRect.height)
        } : null,
        maskVisible: Boolean(mask && getComputedStyle(mask).display !== "none"),
        actionCount: actions.length,
        text: panel?.textContent?.trim().slice(0, 160) || ""
      };
    })()`,
    returnByValue: true
  });
  return result.result.value;
}

async function auditNamedControls(client) {
  const result = await client.send("Runtime.evaluate", {
    expression: `(() => {
      const controls = [...document.querySelectorAll("button,a[href],input:not([type='hidden']),select,textarea,[role='button']")]
        .filter((node) => {
          const rect = node.getBoundingClientRect();
          const styles = getComputedStyle(node);
          return rect.width > 1 && rect.height > 1 && styles.display !== "none" && styles.visibility !== "hidden";
        });
      const nameFor = (node) => {
        const labelledBy = (node.getAttribute("aria-labelledby") || "")
          .split(/\s+/)
          .filter(Boolean)
          .map((id) => document.getElementById(id)?.textContent || "")
          .join(" ");
        const labels = "labels" in node && node.labels
          ? [...node.labels].map((label) => label.textContent || "").join(" ")
          : "";
        const ownText = node.matches("button,a[href],[role='button']") ? node.textContent : "";
        return [node.getAttribute("aria-label"), labelledBy, labels, node.getAttribute("title"), ownText, node.querySelector?.("img")?.getAttribute("alt")]
          .filter(Boolean)
          .join(" ")
          .trim();
      };
      const unnamed = controls.filter((node) => !nameFor(node));
      return {
        count: unnamed.length,
        items: unnamed.slice(0, 12).map((node) => ({ tag: node.tagName, type: node.getAttribute("type") || "", cls: node.className?.toString?.() || "", role: node.getAttribute("role") || "" }))
      };
    })()`,
    returnByValue: true
  });
  return result.result.value;
}

async function auditThemeSwitch(client) {
  await loadToolState(client, "home", { cleanHome: true, themeMode: "light" });
  await clickRuntimeButton(
    client,
    `document.querySelector('button[aria-label="设置"]')?.click();`,
    "Boolean(document.querySelector('.settings-modal'))"
  );
  await clickRuntimeButton(
    client,
    `[...document.querySelectorAll('.settings-main .ant-segmented-item')].find((node) => (node.textContent || '').trim() === '黑暗')?.click();`,
    "document.documentElement.dataset.themeMode === 'dark'"
  );
  await wait(220);
  const dark = await client.send("Runtime.evaluate", {
    expression: `(() => ({
      mode: document.documentElement.dataset.themeMode,
      stored: JSON.parse(localStorage.getItem('forensicspp:app.themeMode') || 'null'),
      background: getComputedStyle(document.body).backgroundColor,
      surface: getComputedStyle(document.querySelector('.settings-modal .ant-modal-content')).backgroundColor,
      sidebar: getComputedStyle(document.querySelector('.tool-sidebar')).backgroundColor
    }))()`,
    returnByValue: true
  });
  await clickRuntimeButton(
    client,
    `[...document.querySelectorAll('.settings-main .ant-segmented-item')].find((node) => (node.textContent || '').trim() === '明亮')?.click();`,
    "document.documentElement.dataset.themeMode === 'light'"
  );
  await wait(220);
  const light = await client.send("Runtime.evaluate", {
    expression: `(() => ({
      mode: document.documentElement.dataset.themeMode,
      stored: JSON.parse(localStorage.getItem('forensicspp:app.themeMode') || 'null'),
      background: getComputedStyle(document.body).backgroundColor,
      surface: getComputedStyle(document.querySelector('.settings-modal .ant-modal-content')).backgroundColor,
      sidebar: getComputedStyle(document.querySelector('.tool-sidebar')).backgroundColor
    }))()`,
    returnByValue: true
  });
  const darkValue = dark.result.value;
  const lightValue = light.result.value;
  return {
    id: "theme-switch",
    ok: darkValue?.mode === "dark"
      && darkValue?.stored === "dark"
      && lightValue?.mode === "light"
      && lightValue?.stored === "light"
      && darkValue?.background !== lightValue?.background
      && darkValue?.surface !== lightValue?.surface
      && darkValue?.sidebar !== lightValue?.sidebar
      && lightValue?.sidebar === "rgb(248, 250, 251)",
    dark: darkValue,
    light: lightValue
  };
}

async function auditSelectPopup(client) {
  const modes = ["light", "dark"];
  const states = [];

  for (const mode of modes) {
    await loadToolState(client, "codec", { themeMode: mode });
    await clickRuntimeButton(
      client,
      `document.querySelector('.codec-simple-controls .app-select .ant-select-selector')?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, button: 0 }));`,
      "Boolean(document.querySelector('.ant-select-dropdown:not(.ant-select-dropdown-hidden)'))"
    );
    const result = await client.send("Runtime.evaluate", {
      expression: `(() => {
        const popup = document.querySelector('.ant-select-dropdown:not(.ant-select-dropdown-hidden)');
        const rect = popup?.getBoundingClientRect();
        const background = popup ? getComputedStyle(popup).backgroundColor : '';
        const transparent = !background
          || background === 'transparent'
          || /rgba\\([^)]*,\\s*0(?:\\.0+)?\\)$/.test(background);
        return {
          mode: document.documentElement.dataset.themeMode,
          background,
          transparent,
          itemCount: popup?.querySelectorAll('.ant-select-item-option').length || 0,
          rect: rect ? {
            x: Math.round(rect.x),
            y: Math.round(rect.y),
            w: Math.round(rect.width),
            h: Math.round(rect.height)
          } : null
        };
      })()`,
      returnByValue: true
    });
    states.push(result.result.value);
  }

  return {
    id: "select-popup",
    ok: states.every((state) => state
      && state.mode
      && !state.transparent
      && state.itemCount >= 6
      && state.rect?.w >= 180
      && state.rect?.h >= 120),
    states
  };
}

async function auditPasswordFilled(client) {
  await loadToolState(client, "password");
  await client.send("Runtime.evaluate", {
    expression: `
      localStorage.removeItem("forensicspp:password.password.v2");
      localStorage.removeItem("forensicspp:password.salt.v2");
      const input = document.querySelector('.password-simple-main-panel input[type="password"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
      if (input && setter) {
        setter.call(input, "12345");
        input.dispatchEvent(new Event("input", { bubbles: true }));
      }
    `,
    awaitPromise: true
  });
  const automaticRows = await client.send("Runtime.evaluate", {
    expression: "document.querySelectorAll('.password-simple-hash-table tr').length",
    returnByValue: true
  });
  await clickRuntimeButton(
    client,
    `[...document.querySelectorAll('button')].find((node) => (node.textContent || '').trim() === '生成常用哈希')?.click();`,
    "document.querySelectorAll('.password-simple-hash-table tr').length >= 10"
  );
  await waitForRuntimeValue(client, "document.querySelectorAll('.password-simple-hash-table tr').length >= 4", 8000);
  await wait(260);
  const result = await client.send("Runtime.evaluate", {
    expression: `(() => {
      const panel = document.querySelector(".password-simple-output");
      const panelRect = panel?.getBoundingClientRect();
      const items = [...document.querySelectorAll(".password-simple-hash-table tr")].map((node) => {
        const rect = node.getBoundingClientRect();
        const styles = getComputedStyle(node);
        return {
          display: styles.display,
          grid: styles.gridTemplateColumns,
          x: Math.round(rect.x),
          y: Math.round(rect.y),
          w: Math.round(rect.width),
          h: Math.round(rect.height),
          text: (node.textContent || "").trim().slice(0, 80)
        };
      });
      const tooSmall = items.filter((item) => item.w < 420 || item.h < 34);
      const sensitiveStored = localStorage.getItem("forensicspp:password.password.v2") !== null
        || localStorage.getItem("forensicspp:password.salt.v2") !== null;
      const ok = Boolean(panelRect)
        && ${automaticRows.result.value} === 0
        && items.length >= 4
        && tooSmall.length === 0
        && !sensitiveStored
        && document.documentElement.scrollWidth === document.documentElement.clientWidth;
      return {
        id: "password-filled",
        ok,
        panel: panelRect ? {
          x: Math.round(panelRect.x),
          y: Math.round(panelRect.y),
          w: Math.round(panelRect.width),
          h: Math.round(panelRect.height)
        } : null,
        automaticRows: ${automaticRows.result.value},
        itemCount: items.length,
        narrowCount: tooSmall.length,
        sensitiveStored,
        items: items.slice(0, 8),
        overflowX: document.documentElement.scrollWidth - document.documentElement.clientWidth
      };
    })()`,
    returnByValue: true
  });
  return result.result.value;
}

async function auditCollapsedToolCenter(client) {
  await loadToolState(client, "hash", { sidebarCollapsed: true });
  const result = await client.send("Runtime.evaluate", {
    expression: `(() => {
      const main = document.querySelector(".tool-main");
      const body = document.querySelector(".tool-body");
      const container = body?.firstElementChild;
      const mainRect = main?.getBoundingClientRect();
      const containerRect = container?.getBoundingClientRect();
      const delta = mainRect && containerRect
        ? Math.abs((containerRect.left + containerRect.width / 2) - (mainRect.left + mainRect.width / 2))
        : 9999;
      return {
        id: "collapsed-tool-center",
        ok: Boolean(mainRect && containerRect) && delta <= 8 && containerRect.width <= mainRect.width,
        delta: Math.round(delta),
        main: mainRect ? {
          x: Math.round(mainRect.x),
          y: Math.round(mainRect.y),
          w: Math.round(mainRect.width),
          h: Math.round(mainRect.height)
        } : null,
        container: containerRect ? {
          x: Math.round(containerRect.x),
          y: Math.round(containerRect.y),
          w: Math.round(containerRect.width),
          h: Math.round(containerRect.height),
          cls: container?.className?.toString() || ""
        } : null
      };
    })()`,
    returnByValue: true
  });
  return result.result.value;
}

async function auditLoadedSqlite(client) {
  const fixture = await createSqliteFixture();
  try {
    await loadToolState(client, "sqlite");
    const document = await client.send("DOM.getDocument", { depth: 1 });
    const input = await client.send("DOM.querySelector", {
      nodeId: document.root.nodeId,
      selector: '.sqlite-source-panel input[type="file"]'
    });
    if (!input.nodeId) {
      return { id: "sqlite-loaded", ok: false, error: "SQLite file input not found" };
    }
    await client.send("DOM.setFileInputFiles", {
      nodeId: input.nodeId,
      files: [fixture.dbPath]
    });
    await waitForRuntimeValue(
      client,
      "document.querySelectorAll('.sqlite-data-table tbody tr').length >= 3 && document.querySelectorAll('.sqlite-data-table thead th').length >= 6",
      10000
    );
    await client.send("Runtime.evaluate", {
      expression: `document.querySelector('.sqlite-browse-table tbody tr')?.querySelectorAll('td')?.[4]?.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }))`,
      awaitPromise: true
    });
    const editModePrompted = await waitForRuntimeValue(client, "document.body.textContent.includes('请先开启编辑模式')", 3000);
    await client.send("Runtime.evaluate", {
      expression: `document.querySelector('.sqlite-edit-mode .ant-switch')?.click()`,
      awaitPromise: true
    });
    await waitForRuntimeValue(client, "document.querySelector('.sqlite-edit-mode .ant-switch')?.getAttribute('aria-checked') === 'true'", 3000);
    await client.send("Runtime.evaluate", {
      expression: `document.querySelector('.sqlite-browse-table tbody tr')?.querySelectorAll('td')?.[4]?.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }))`,
      awaitPromise: true
    });
    const cellSelected = await waitForRuntimeValue(client, "Boolean(document.querySelector('.sqlite-simple-cell-panel'))", 5000);
    const cellEditorReady = await waitForRuntimeValue(client, "Boolean(document.querySelector('.sqlite-inline-cell-editor'))", 5000);
    await client.send("Runtime.evaluate", {
      expression: `(() => {
        const input = document.querySelector('.sqlite-inline-cell-editor');
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        if (input && setter) {
          setter.call(input, '已更新名称');
          input.dispatchEvent(new Event('input', { bubbles: true }));
        }
      })()`,
      awaitPromise: true
    });
    await waitForRuntimeValue(client, "document.querySelector('.sqlite-inline-cell-editor')?.value === '已更新名称'", 5000);
    await client.send("Runtime.evaluate", {
      expression: `document.querySelector('.sqlite-inline-cell-editor')?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))`,
      awaitPromise: true
    });
    const cellEditSaved = await waitForRuntimeValue(client, "document.querySelector('.sqlite-browse-table tbody')?.textContent.includes('已更新名称')", 5000);
    await client.send("Runtime.evaluate", { expression: `location.hash = 'hash'`, awaitPromise: true });
    await waitForRuntimeValue(client, "document.querySelector('.page-title')?.textContent.includes('哈希')", 5000);
    await client.send("Runtime.evaluate", { expression: `location.hash = 'sqlite'`, awaitPromise: true });
    const toolStateRetained = await waitForRuntimeValue(client, "document.querySelector('.sqlite-browse-table tbody')?.textContent.includes('已更新名称')", 5000);
    const resizeBefore = await client.send("Runtime.evaluate", {
      expression: `Math.round(document.querySelectorAll('.sqlite-browse-table thead th')[2]?.getBoundingClientRect().width || 0)`,
      returnByValue: true
    });
    await client.send("Runtime.evaluate", {
      expression: `document.querySelectorAll('.sqlite-column-resizer')[1]?.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }))`,
      awaitPromise: true
    });
    const columnResizePassed = await waitForRuntimeValue(client, `Math.round(document.querySelectorAll('.sqlite-browse-table thead th')[2]?.getBoundingClientRect().width || 0) >= ${Number(resizeBefore.result.value) + 10}`, 3000);
    await client.send("Runtime.evaluate", {
      expression: `[...document.querySelectorAll('.sqlite-page-tabs button')].find((button) => (button.textContent || '').trim() === 'SQL')?.click()`,
      awaitPromise: true
    });
    const sqlPageReady = await waitForRuntimeValue(client, "Boolean(document.querySelector('.sqlite-query-input'))", 5000);
    await client.send("Runtime.evaluate", {
      expression: `(() => {
        const input = document.querySelector('.sqlite-query-input');
        const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set;
        if (input && setter) {
          setter.call(input, 'SELECT COUNT(*) AS count FROM software;');
          input.dispatchEvent(new Event('input', { bubbles: true }));
        }
      })()`,
      awaitPromise: true
    });
    await waitForRuntimeValue(client, "document.querySelector('.sqlite-query-input')?.value === 'SELECT COUNT(*) AS count FROM software;'", 5000);
    await client.send("Runtime.evaluate", {
      expression: `[...document.querySelectorAll('.sqlite-simple-sql-panel button')].find((button) => (button.textContent || '').includes('运行 SQL'))?.click()`,
      awaitPromise: true
    });
    const sqlQueryPassed = await waitForRuntimeValue(client, "document.querySelector('.sqlite-query-table tbody')?.textContent.trim() === '3'", 5000);
    await client.send("Runtime.evaluate", {
      expression: `[...document.querySelectorAll('.sqlite-page-tabs button')].find((button) => (button.textContent || '').trim().startsWith('修改'))?.click()`,
      awaitPromise: true
    });
    const changeRecorded = await waitForRuntimeValue(client, "document.querySelector('.sqlite-simple-changes-panel tbody')?.textContent.includes('cell-update')", 5000);
    await client.send("Runtime.evaluate", {
      expression: `[...document.querySelectorAll('.sqlite-page-tabs button')].find((button) => (button.textContent || '').trim() === '浏览')?.click()`,
      awaitPromise: true
    });
    await waitForRuntimeValue(client, "Boolean(document.querySelector('.sqlite-browse-table'))", 5000);
    await wait(400);
    const result = await client.send("Runtime.evaluate", {
      expression: `(() => {
        const container = document.querySelector(".sqlite-browser-grid.has-sqlite");
        const table = document.querySelector(".sqlite-data-table");
        const scroll = document.querySelector(".sqlite-data-scroll");
        const headers = [...document.querySelectorAll(".sqlite-data-table th")].map((node) => {
          const rect = node.getBoundingClientRect();
          const styles = getComputedStyle(node);
          return { w: Math.round(rect.width), h: Math.round(rect.height), writing: styles.writingMode, text: node.textContent.trim().slice(0, 80) };
        });
        const cells = [...document.querySelectorAll(".sqlite-data-table td")].slice(0, 80).map((node) => {
          const rect = node.getBoundingClientRect();
          const styles = getComputedStyle(node);
          return { w: Math.round(rect.width), h: Math.round(rect.height), writing: styles.writingMode, text: node.textContent.trim().slice(0, 80) };
        });
        const badWriting = [...headers, ...cells].filter((item) => item.writing !== "horizontal-tb");
        const pinched = [...headers, ...cells].filter((item) => item.w < 88 && item.h > 56);
        const containerRect = container?.getBoundingClientRect();
        const tableRect = table?.getBoundingClientRect();
        const scrollRect = scroll?.getBoundingClientRect();
        return {
          id: "sqlite-loaded",
          ok: Boolean(containerRect && tableRect && scrollRect)
            && ${JSON.stringify(cellSelected)}
            && ${JSON.stringify(editModePrompted)}
            && ${JSON.stringify(cellEditorReady)}
            && ${JSON.stringify(cellEditSaved)}
            && ${JSON.stringify(toolStateRetained)}
            && ${JSON.stringify(columnResizePassed)}
            && ${JSON.stringify(sqlPageReady)}
            && ${JSON.stringify(sqlQueryPassed)}
            && ${JSON.stringify(changeRecorded)}
            && badWriting.length === 0
            && pinched.length === 0
            && document.documentElement.scrollWidth === document.documentElement.clientWidth
            && tableRect.width >= scrollRect.width,
          container: containerRect ? { x: Math.round(containerRect.x), y: Math.round(containerRect.y), w: Math.round(containerRect.width), h: Math.round(containerRect.height) } : null,
          table: tableRect ? { w: Math.round(tableRect.width), h: Math.round(tableRect.height) } : null,
          scroll: scrollRect ? { w: Math.round(scrollRect.width), h: Math.round(scrollRect.height), scrollWidth: Math.round(scroll.scrollWidth) } : null,
          badWritingCount: badWriting.length,
          pinchedCount: pinched.length,
          cellSelected: ${JSON.stringify(cellSelected)},
          editModePrompted: ${JSON.stringify(editModePrompted)},
          cellEditorReady: ${JSON.stringify(cellEditorReady)},
          cellEditSaved: ${JSON.stringify(cellEditSaved)},
          toolStateRetained: ${JSON.stringify(toolStateRetained)},
          columnResizePassed: ${JSON.stringify(columnResizePassed)},
          sqlPageReady: ${JSON.stringify(sqlPageReady)},
          sqlQueryPassed: ${JSON.stringify(sqlQueryPassed)},
          changeRecorded: ${JSON.stringify(changeRecorded)},
          headerSample: headers.slice(0, 8),
          cellSample: cells.slice(0, 8),
          overflowX: document.documentElement.scrollWidth - document.documentElement.clientWidth
        };
      })()`,
      returnByValue: true
    });
    return result.result.value;
  } finally {
    await rm(fixture.dir, { recursive: true, force: true });
  }
}

async function auditLoadedEmail(client) {
  const fixture = await createEmailFixture();
  try {
    await loadToolState(client, "email");
    const document = await client.send("DOM.getDocument", { depth: 1 });
    const input = await client.send("DOM.querySelector", {
      nodeId: document.root.nodeId,
      selector: '.email-workbench input[type="file"]'
    });
    if (!input.nodeId) {
      return { id: "email-loaded", ok: false, error: "Email file input not found" };
    }
    await client.send("DOM.setFileInputFiles", {
      nodeId: input.nodeId,
      files: [fixture.emailPath]
    });
    await waitForRuntimeValue(
      client,
      "Boolean(document.querySelector('.email-workbench.has-email .email-summary-panel') && document.querySelector('.email-auth-panel') && document.querySelector('.email-route-panel'))",
      12000
    );
    await client.send("Runtime.evaluate", {
      expression: `(() => {
        const htmlButton = [...document.querySelectorAll('.email-body-panel button')]
          .find((button) => button.textContent?.trim() === 'HTML');
        htmlButton?.click();
      })()`
    });
    await waitForRuntimeValue(
      client,
      "Boolean(document.querySelector('.email-html-preview')?.getAttribute('srcdoc')?.includes('Evidence triage summary'))",
      5000
    );
    await client.send("Runtime.evaluate", {
      expression: `(() => {
        const details = document.querySelector('.email-advanced-shell');
        if (details instanceof HTMLDetailsElement) details.open = true;
      })()`
    });
    await wait(400);
    const result = await client.send("Runtime.evaluate", {
      expression: `(() => {
        const container = document.querySelector(".email-workbench.has-email");
        const source = document.querySelector(".email-source-panel");
        const summary = document.querySelector(".email-summary-panel");
        const auth = document.querySelector(".email-auth-panel");
        const route = document.querySelector(".email-route-panel");
        const htmlPreview = document.querySelector(".email-html-preview");
        const rawSource = document.querySelector(".email-raw-source");
        const containerRect = container?.getBoundingClientRect();
        const summaryRect = summary?.getBoundingClientRect();
        const htmlPreviewReady = Boolean(
          htmlPreview?.getAttribute("srcdoc")?.includes("Evidence triage summary")
        );
        const rawSourceReady = Boolean(
          rawSource?.textContent?.includes("From:")
          && rawSource.textContent.includes("Subject:")
        );
        return {
          id: "email-loaded",
          ok: Boolean(containerRect && source && summary && auth && route)
            && htmlPreviewReady
            && rawSourceReady
            && document.documentElement.scrollWidth === document.documentElement.clientWidth
            && summaryRect.width >= containerRect.width * 0.9,
          container: containerRect ? { w: Math.round(containerRect.width), h: Math.round(containerRect.height) } : null,
          summary: summaryRect ? { w: Math.round(summaryRect.width), h: Math.round(summaryRect.height) } : null,
          authRows: document.querySelectorAll('.email-auth-panel tbody tr').length,
          routeRows: document.querySelectorAll('.email-route-panel tbody tr').length,
          htmlPreviewReady,
          rawSourceReady,
          overflowX: document.documentElement.scrollWidth - document.documentElement.clientWidth
        };
      })()`,
      returnByValue: true
    });
    return result.result.value;
  } finally {
    await rm(fixture.dir, { recursive: true, force: true });
  }
}

async function auditLoadedSql(client) {
  const fixture = await createSqlFixture();
  try {
    await loadToolState(client, "sql");
    const document = await client.send("DOM.getDocument", { depth: 1 });
    const input = await client.send("DOM.querySelector", {
      nodeId: document.root.nodeId,
      selector: '.sql-upload input[type="file"]'
    });
    if (!input.nodeId) {
      return { id: "sql-loaded", ok: false, error: "SQL file input not found" };
    }
    await client.send("DOM.setFileInputFiles", {
      nodeId: input.nodeId,
      files: [fixture.sqlPath]
    });
    await waitForRuntimeValue(
      client,
      "document.querySelectorAll('.sql-facts-panel .result-copy-card').length >= 4 && document.querySelectorAll('.sql-table-list button').length >= 1",
      12000
    );
    await wait(400);
    const result = await client.send("Runtime.evaluate", {
      expression: `(() => {
        const container = document.querySelector(".sql-workbench.has-sql");
        const facts = document.querySelector(".sql-facts-panel");
        const format = document.querySelector(".sql-format-details");
        const tables = [...document.querySelectorAll(".sql-table-list button")];
        const containerRect = container?.getBoundingClientRect();
        const formatRect = format?.getBoundingClientRect();
        return {
          id: "sql-loaded",
          ok: Boolean(containerRect && facts && format)
            && tables.length >= 1
            && document.documentElement.scrollWidth === document.documentElement.clientWidth
            && formatRect.height >= 180,
          container: containerRect ? { w: Math.round(containerRect.width), h: Math.round(containerRect.height) } : null,
          format: formatRect ? { w: Math.round(formatRect.width), h: Math.round(formatRect.height) } : null,
          tableCount: tables.length,
          overflowX: document.documentElement.scrollWidth - document.documentElement.clientWidth
        };
      })()`,
      returnByValue: true
    });
    return result.result.value;
  } finally {
    await rm(fixture.dir, { recursive: true, force: true });
  }
}

const loadedFileToolStates = [
  { tool: "image", selector: ".image-workbench input[type=file]", readyClass: ".image-workbench.has-image", path: "pngPath" },
  { tool: "qr", selector: ".qr-workbench input[type=file]", readyClass: ".qr-workbench.has-qr", path: "qrPath" },
  { tool: "hash", selector: ".hash-workbench input[type=file]", readyClass: ".hash-file-browser-panel", path: "pngPath" },
  { tool: "png", selector: ".png-workbench input[type=file]", readyClass: ".png-workbench.has-png", path: "pngPath" },
  { tool: "archive", selector: ".archive-workbench input[type=file]", readyClass: ".archive-workbench.has-archive", path: "archivePath" },
  { tool: "binary", selector: ".binary-workbench input[type=file]", readyClass: ".binary-workbench.has-binary", path: "binaryPath" },
  { tool: "windows", selector: ".windows-artifact-workbench input[type=file]", readyClass: ".windows-artifact-workbench.has-windows", path: "windowsPath" },
  { tool: "fileid", selector: ".fileid-workbench input[type=file]", readyClass: ".fileid-workbench.has-fileid", path: "pngPath" },
  { tool: "pcap", selector: ".pcap-workbench input[type=file]", readyClass: ".pcap-workbench.has-pcap", path: "pcapPath" },
  { tool: "browserartifacts", selector: ".browser-artifact-workbench input[type=file]", readyClass: ".browser-artifact-results-panel", path: "browserHistoryPath", action: ["开始解析", "Parse data"] },
  { tool: "evtx", selector: ".evtx-workbench input[type=file]", readyClass: ".evtx-results-panel", path: "evtxPath", action: ["解析日志", "Parse logs"] },
  { tool: "documentforensics", selector: ".document-forensics-workbench input[type=file]", readyClass: ".document-forensics-results", path: "pdfPath", action: ["检查文档", "Inspect document"] }
];

async function auditLoadedFileTools(client) {
  const fixture = await createFileToolFixtures();
  const results = [];
  try {
    for (const state of loadedFileToolStates) {
      if (process.env.AUDIT_VERBOSE === "1") console.log(`Auditing loaded file: ${state.tool}`);
      await loadToolState(client, state.tool);
      const document = await client.send("DOM.getDocument", { depth: 1 });
      const input = await client.send("DOM.querySelector", {
        nodeId: document.root.nodeId,
        selector: state.selector
      });
      if (!input.nodeId) {
        results.push({ id: `${state.tool}-file-loaded`, tool: state.tool, ready: false, error: `File input not found: ${state.selector}` });
        continue;
      }
      await client.send("DOM.setFileInputFiles", {
        nodeId: input.nodeId,
        files: [fixture[state.path]]
      });
      if (state.tool === "hash") {
        await waitForRuntimeValue(client, "Boolean(document.querySelector('.hash-workbench.has-hash'))", 5000);
        await clickRuntimeButton(
          client,
          `[...document.querySelectorAll('.hash-workbench button')].find((node) => ['计算哈希', 'Calculate hashes'].includes((node.textContent || '').trim()))?.click();`,
          "Boolean(document.querySelector('.hash-file-browser-panel'))"
        );
      }
      if (state.action) {
        await clickRuntimeButton(
          client,
          `[...document.querySelectorAll('button')].find((node) => ${JSON.stringify(state.action)}.includes((node.textContent || '').trim()))?.click();`,
          `Boolean(document.querySelector(${JSON.stringify(state.readyClass)}))`
        );
      }
      const ready = await waitForRuntimeValue(client, `Boolean(document.querySelector(${JSON.stringify(state.readyClass)}))`, 15000);
      await wait(500);
      const result = await client.send("Runtime.evaluate", {
        expression: visiblePanelAuditExpression(state.tool),
        returnByValue: true
      });
      const value = result.result.value;
      const detail = await client.send("Runtime.evaluate", {
        expression: `(() => ({
          tableRows: document.querySelectorAll('tbody tr').length,
          resultCards: document.querySelectorAll('.result-copy-card').length,
          images: [...document.images].filter((image) => image.offsetParent !== null).map((image) => ({ width: image.naturalWidth, height: image.naturalHeight })).slice(0, 4),
          canvasCount: [...document.querySelectorAll('canvas')].filter((canvas) => canvas.offsetParent !== null).length,
          detailsCount: [...document.querySelectorAll('details')].filter((node) => node.offsetParent !== null).length,
          errorText: document.querySelector('.error-state')?.textContent?.trim() || ''
        }))()`,
        returnByValue: true
      });
      results.push({ ...value, id: `${state.tool}-file-loaded`, ready, detail: detail.result.value });
      if (saveScreenshots) await captureViewport(client, `${state.tool}-file-loaded.png`);
    }
  } finally {
    await rm(fixture.dir, { recursive: true, force: true });
  }
  return results;
}

const seededToolStates = [
  {
    tool: "codec",
    readyClass: ".codec-workbench.has-codec",
    values: {
      "codec.input": "%7B%22case%22%3A%22FPP-001%22%2C%22status%22%3A%22review%22%7D",
      "codec.output": "{\"case\":\"FPP-001\",\"status\":\"review\"}",
      "codec.operation": "urld",
      "codec.selectedFormat": "url"
    }
  },
  {
    tool: "hash",
    readyClass: ".hash-workbench.has-hash",
    values: {
      "hash.text": "Forensics++ evidence sample\ncase=FPP-001\nsource=browser-local",
      "hash.hmacKey": "case-key",
      "hash.expectedHash": ""
    }
  },
  {
    tool: "crypto",
    readyClass: ".crypto-simple-workbench.has-crypto .crypto-simple-result-panel",
    values: {
      "crypto.input": "KHOOR ZRUOG",
      "crypto.output": "HELLO WORLD",
      "crypto.operation": "caesar",
      "crypto.shift": 3
    }
  },
  {
    tool: "jwt",
    readyClass: ".jwt-simple-workbench.has-jwt .jwt-simple-output",
    values: {},
    afterLoad: `(() => {
      const input = document.querySelector('.jwt-simple-token-input');
      const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
      if (input && setter) {
        setter.call(input, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYXNlLTAwMSIsImlhdCI6MTcxOTc5NTYwMH0.signature");
        input.dispatchEvent(new Event("input", { bubbles: true }));
      }
    })()`
  },
  {
    tool: "android",
    readyClass: ".manifest-overview-panel",
    afterLoad: `(() => { const input=document.querySelector('.manifest-textarea'); const setter=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value')?.set; if(input&&setter){setter.call(input,'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example.forensics"><uses-permission android:name="android.permission.INTERNET"/><application android:debuggable="true" android:label="Evidence App"><activity android:name=".MainActivity" android:exported="true"/></application></manifest>'); input.dispatchEvent(new Event('input',{bubbles:true}));} setTimeout(()=>[...document.querySelectorAll('button')].find((node)=>/解析 Manifest|Parse Manifest/i.test(node.textContent||''))?.click(),50); })()`,
    values: {}
  },
  {
    tool: "ioc",
    readyClass: ".ioc-workbench.has-ioc",
    afterLoad: `(() => { const input=document.querySelector('.ioc-simple-input'); const setter=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value')?.set; if(input&&setter){setter.call(input,'2026-07-08T09:12:33Z src=10.0.0.5 dst=203.0.113.42 url=https://case.example.org/review?id=42 sha256=e54d7df2f5f74355fda98fac48a726f451a0f9c89d6e8786f71ab4f241b128a9'); input.dispatchEvent(new Event('input',{bubbles:true}));} setTimeout(()=>[...document.querySelectorAll('button')].find((node)=>/提取 IOC|Extract indicators/i.test(node.textContent||''))?.click(),50); })()`,
    values: {}
  },
  {
    tool: "urltool",
    readyClass: ".url-workbench.has-url",
    values: {
      "url.input.v3": "https://case.example.org/login?next=%2Freports%2F42&utm_source=mail#summary"
    }
  },
  {
    tool: "timestamp",
    readyClass: ".timestamp-workbench.has-timestamp",
    values: {
      "timestamp.input": "1719795600",
      "timestamp.batchInput.v2": "1719795600 login\n133638048000000000 FILETIME\n2026-07-08T09:12:33Z alert"
    }
  },
  {
    tool: "timeline",
    readyClass: ".timeline-simple-workbench.has-timeline .timeline-simple-results-panel",
    values: {
      "timeline.input.v2": "2026-07-08T09:12:33Z login success user=analyst ip=10.0.0.5\n1719795600000 browser history opened https://case.example.org/login\n2026-07-08 09:15:07 attachment saved invoice.pdf",
      "timeline.source": "case-001.log"
    }
  },
  {
    tool: "yara",
    readyClass: ".yara-simple-workbench.has-yara .yara-simple-results-panel",
    afterLoad: `[...document.querySelectorAll('.yara-simple-input-panel button')].find((node) => (node.textContent || '').trim() === '执行')?.click()`,
    values: {
      "yara.rules.v2": "rule EvidenceMarker { strings: $case = \"FPP-001\" ascii nocase $url = /https?:\\/\\/case\\.example\\.org/ condition: any of them }",
      "yara.sample.v2": "Case FPP-001 opened https://case.example.org/review for local triage."
    }
  },
  {
    tool: "json",
    readyClass: ".json-workbench.has-json",
    afterLoad: `(() => { const input=document.querySelector('.json-simple-textarea'); const setter=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value')?.set; if(input&&setter){setter.call(input,'{"caseId":"FPP-001","sourceIp":"203.0.113.42","url":"https://case.example.org/review","events":[{"time":"2026-07-08T09:12:33Z","action":"login"}]}'); input.dispatchEvent(new Event('input',{bubbles:true}));} setTimeout(()=>[...document.querySelectorAll('button')].find((node)=>/处理 JSON|Process JSON/i.test(node.textContent||''))?.click(),50); })()`,
    values: { "json.outputMode": "format" }
  },
  {
    tool: "regex",
    readyClass: ".regex-workbench.has-regex",
    values: {
      "regex.pattern": "\\bhttps?:\\/\\/[^\\s\\\"'<>]+|\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b",
      "regex.flags": "gi",
      "regex.text.v2": "2026-07-08T09:12:33Z user=analyst ip=203.0.113.42 visited https://case.example.org/login?token=abc123",
      "regex.replacement": "[REDACTED]"
    }
  },
  {
    tool: "http",
    readyClass: ".http-workbench.has-http",
    values: {
      "http.text.v3": "POST /api/cases/FPP-001 HTTP/1.1\nHost: case.example.org\nContent-Type: application/json\nAuthorization: Bearer review-token\nX-Forwarded-For: 203.0.113.42\n\n{\"status\":\"review\",\"artifact\":\"invoice.pdf\"}"
    }
  },
  {
    tool: "strings",
    readyClass: ".strings-workbench.has-strings",
    afterLoad: `(() => { const input=document.querySelector('.strings-simple-input'); const setter=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value')?.set; if(input&&setter){setter.call(input,'MZ....This program cannot be run in DOS mode....https://case.example.org/payload....user=analyst....token=review123....invoice.pdf'); input.dispatchEvent(new Event('input',{bubbles:true}));} setTimeout(()=>[...document.querySelectorAll('button')].find((node)=>/提取字符串|Extract strings/i.test(node.textContent||''))?.click(),50); })()`,
    values: { "strings.minLength": 4 }
  },
  {
    tool: "entropy",
    readyClass: ".entropy-workbench.has-entropy",
    values: {
      "entropy.text.v2": "ForensicsPP evidence sample 00112233445566778899abcdef".repeat(32),
      "entropy.blockSize": 128
    }
  },
  {
    tool: "baseconvert",
    readyClass: ".baseconvert-workbench.has-baseconvert",
    values: {
      "baseconvert.value.v2": "464f52454e534943532b2b",
      "baseconvert.base": 16
    }
  },
  {
    tool: "uuid",
    readyClass: ".uuid-workbench.has-uuid",
    values: {
      "uuid.value": "550e8400-e29b-41d4-a716-446655440000"
    }
  }
];

async function auditSeededToolStates(client) {
  const results = [];
  for (const fixture of seededToolStates) {
    if (process.env.AUDIT_VERBOSE === "1") console.log(`Auditing seeded tool: ${fixture.tool}`);
    await client.send("Runtime.evaluate", {
      expression: `
        for (const key of Object.keys(localStorage)) {
          if (key.startsWith("forensicspp:")) localStorage.removeItem(key);
        }
      `,
      awaitPromise: true
    });
    await client.send("Runtime.evaluate", {
      expression: `
        const values = ${JSON.stringify(Object.fromEntries(seededToolStates.map((fixture) => [fixture.tool, fixture.values])))}[${JSON.stringify(fixture.tool)}];
        for (const [key, value] of Object.entries(values)) {
          localStorage.setItem("forensicspp:" + key, JSON.stringify(value));
        }
      `,
      awaitPromise: true
    });
    await loadToolState(client, fixture.tool);
    if (fixture.afterLoad) {
      await client.send("Runtime.evaluate", { expression: fixture.afterLoad, awaitPromise: true });
    }
    const ready = await waitForRuntimeValue(client, `Boolean(document.querySelector(${JSON.stringify(fixture.readyClass)}))`, 8000);
    const result = await client.send("Runtime.evaluate", {
      expression: visiblePanelAuditExpression(fixture.tool),
      returnByValue: true
    });
    const value = result.result.value;
    results.push({ ...value, id: `${fixture.tool}-loaded`, ready });
    if (saveScreenshots) await captureViewport(client, `${fixture.tool}-loaded.png`);
  }
  return results;
}

async function main() {
  await assertServerReachable();
  const userDataDir = join(tmpdir(), `forensicspp-layout-audit-${Date.now()}`);
  const chrome = spawn(chromePath, [
    "--headless=new",
    `--remote-debugging-port=${port}`,
    "--remote-allow-origins=*",
    `--user-data-dir=${userDataDir}`,
    `--window-size=${width},${height}`,
    `${baseUrl}/#home`
  ], { stdio: ["ignore", "ignore", "pipe"] });

  let stderr = "";
  chrome.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  try {
    const tabs = await waitForCdp();
    const tab = tabs.find((item) => item.type === "page");
    if (!tab) throw new Error("No page target found in Chrome.");

    const client = createCdpClient(tab.webSocketDebuggerUrl);
    await client.ready();
    await client.send("Page.enable");
    await client.send("Runtime.enable");
    await client.send("DOM.enable");
    await client.send("Emulation.setDeviceMetricsOverride", {
      width,
      height,
      deviceScaleFactor: 1,
      mobile: false
    });

    const results = [];
    if (saveScreenshots) await resetScreenshotDir();

    for (const tool of tools) {
      if (process.env.AUDIT_VERBOSE === "1") console.log(`Auditing empty state: ${tool}`);
      await client.send("Runtime.evaluate", {
        expression: `
          for (const key of Object.keys(localStorage)) {
            if (key.startsWith("forensicspp:")) localStorage.removeItem(key);
          }
        `,
        awaitPromise: true
      });
      await loadToolState(client, tool, { cleanHome: tool === "home" });
      let result;
      for (let attempt = 0; attempt < 6; attempt += 1) {
        result = await client.send("Runtime.evaluate", {
          expression: visiblePanelAuditExpression(tool),
          returnByValue: true
        });
        const value = result.result.value;
        if (value?.container && value.title) break;
        await wait(tool === "sql" ? 900 : 500);
        if (attempt === 2) {
          await loadToolState(client, tool, { cleanHome: tool === "home" });
        }
      }
      results.push(result.result.value);

      if (saveScreenshots) {
        await captureViewport(client, `${tool}.png`);
      }
    }

    if (process.env.AUDIT_VERBOSE === "1") console.log("Auditing special states");
    if (process.env.AUDIT_VERBOSE === "1") console.log("Special: consent");
    const consentCheck = await auditConsentBar(client);
    if (saveScreenshots) {
      await captureViewport(client, "home-consent.png");
    }
    if (process.env.AUDIT_VERBOSE === "1") console.log("Special: password");
    const passwordFilledCheck = await auditPasswordFilled(client);
    if (saveScreenshots) {
      await captureViewport(client, "password-filled.png");
    }
    if (process.env.AUDIT_VERBOSE === "1") console.log("Special: collapsed center");
    const collapsedToolCenterCheck = await auditCollapsedToolCenter(client);
    if (saveScreenshots) {
      await captureViewport(client, "collapsed-tool-hash.png");
    }
    if (process.env.AUDIT_VERBOSE === "1") console.log("Special: sqlite");
    const loadedSqliteResult = await auditLoadedSqlite(client);
    const loadedSqliteAccessibility = await auditNamedControls(client);
    const loadedSqliteCheck = { ...loadedSqliteResult, accessibility: loadedSqliteAccessibility, ok: loadedSqliteResult.ok && loadedSqliteAccessibility.count === 0 };
    if (saveScreenshots) {
      await captureViewport(client, "sqlite-loaded.png");
    }
    if (process.env.AUDIT_VERBOSE === "1") console.log("Special: email");
    const loadedEmailResult = await auditLoadedEmail(client);
    const loadedEmailAccessibility = await auditNamedControls(client);
    const loadedEmailCheck = { ...loadedEmailResult, accessibility: loadedEmailAccessibility, ok: loadedEmailResult.ok && loadedEmailAccessibility.count === 0 };
    if (saveScreenshots) {
      await captureViewport(client, "email-loaded.png");
    }
    if (process.env.AUDIT_VERBOSE === "1") console.log("Special: sql");
    const loadedSqlResult = await auditLoadedSql(client);
    const loadedSqlAccessibility = await auditNamedControls(client);
    const loadedSqlCheck = { ...loadedSqlResult, accessibility: loadedSqlAccessibility, ok: loadedSqlResult.ok && loadedSqlAccessibility.count === 0 };
    if (saveScreenshots) {
      await captureViewport(client, "sql-loaded.png");
    }
    if (process.env.AUDIT_VERBOSE === "1") console.log("Auditing file-loaded states");
    const loadedFileResults = await auditLoadedFileTools(client);
    const themeSwitchCheck = await auditThemeSwitch(client);
    const selectPopupCheck = await auditSelectPopup(client);
    if (process.env.AUDIT_VERBOSE === "1") console.log("Auditing seeded states");
    const seededResults = await auditSeededToolStates(client);

    if (saveScreenshots) {
      await loadToolState(client, "home", { sidebarCollapsed: true, cleanHome: true });
      await captureViewport(client, "collapsed-home-current.png");

      await loadToolState(client, "home", { themeMode: "dark", cleanHome: true });
      await captureViewport(client, "home-dark.png");

      await loadToolState(client, "home", { cleanHome: true });
      await clickRuntimeButton(
        client,
        `document.querySelector('button[aria-label="设置"]')?.click();`,
        "Boolean(document.querySelector('.settings-modal'))"
      );
      await captureViewport(client, "modal-settings.png");

      await loadToolState(client, "home");
      await clickRuntimeButton(
        client,
        `document.querySelector('button[aria-label="命令"]')?.click();`,
        "Boolean(document.querySelector('.command-panel'))"
      );
      await captureViewport(client, "modal-command.png");
    }

    client.close();

    const abnormal = results.filter((item) => {
      const wideToolAllowed = ["home", "cyberchef"].includes(item.tool);
      const tooWide = width >= 1500 && !wideToolAllowed && item.container?.w > 1320;
      return item.overflowX !== 0 ||
        item.overlaps.length ||
        item.badWritingCellCount ||
        item.unnamedControlCount ||
        item.legacyControlCount ||
        item.emptyStateSplitRows ||
        !item.container ||
        item.container.w > width + 1 ||
        tooWide ||
        (width >= 900 && item.container.w < 700) ||
        item.visiblePanelCount === 0;
    });
    const specialChecks = [consentCheck, passwordFilledCheck, collapsedToolCenterCheck, loadedSqliteCheck, loadedEmailCheck, loadedSqlCheck, themeSwitchCheck, selectPopupCheck];
    const specialAbnormal = specialChecks.filter((item) => !item.ok);
    const seededAbnormal = seededResults.filter((item) => !item.ready || item.overflowX !== 0 || item.overlaps.length || item.badWritingCellCount || item.unnamedControlCount || item.legacyControlCount || !item.container || item.visiblePanelCount === 0);
    const fileAbnormal = loadedFileResults.filter((item) => !item.ready || item.overflowX !== 0 || item.overlaps?.length || item.badWritingCellCount || item.unnamedControlCount || item.legacyControlCount || !item.container || item.visiblePanelCount === 0);

    await writeFile("layout-audit-report.json", JSON.stringify({ baseUrl, width, height, themeMode: defaultThemeMode, screenshotDir, results, seededResults, loadedFileResults, specialChecks, abnormal, seededAbnormal, fileAbnormal, specialAbnormal }, null, 2));

    if (abnormal.length || seededAbnormal.length || fileAbnormal.length || specialAbnormal.length) {
      console.error(JSON.stringify({ count: results.length, abnormal, seededAbnormal, fileAbnormal, specialAbnormal }, null, 2));
      process.exitCode = 1;
      return;
    }

    console.log(`Layout audit passed: ${results.length} tools, ${seededResults.length} seeded states, and ${loadedFileResults.length} file-loaded states at ${width}x${height}.`);
  } finally {
    await stopChrome(chrome);
    if (stderr && process.env.AUDIT_VERBOSE === "1") {
      console.error(stderr);
    }
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
