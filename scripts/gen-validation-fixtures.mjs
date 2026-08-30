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

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import initSqlJs from "sql.js";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(here, "../tests/fixtures");
mkdirSync(outDir, { recursive: true });

// --- SQLite deleted-record fixture -------------------------------------------
const SQL = await initSqlJs();
const db = new SQL.Database();
db.run("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, email TEXT);");
db.run(
  "INSERT INTO users(id, username, email) VALUES (1,'alice','alice@example.com'),(2,'bob','bob@example.com'),(3,'carol','carol@example.com');"
);
db.run("DELETE FROM users WHERE id = 2;"); // deleted row -> recoverable
const sqliteBytes = Buffer.from(db.export());
db.close();
writeFileSync(resolve(outDir, "sqlite-deleted-record.sqlite"), sqliteBytes);

// --- Binary embedded-signature fixture ---------------------------------------
// Deterministic filler (no magic alignment) + three real signatures at known offsets.
const size = 4096;
const bytes = new Uint8Array(size);
for (let i = 0; i < size; i += 1) bytes[i] = (i * 31 + 7) & 0xff;
const embedded = [
  { label: "PNG", magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], offset: 64 },
  { label: "ZIP", magic: [0x50, 0x4b, 0x03, 0x04], offset: 768 },
  { label: "ELF", magic: [0x7f, 0x45, 0x4c, 0x46], offset: 2048 }
];
for (const item of embedded) bytes.set(item.magic, item.offset);
writeFileSync(resolve(outDir, "embedded-signatures.bin"), Buffer.from(bytes));

// --- Expected-output manifest (committed for inspectability) -----------------
const manifest = {
  sqliteDeletedRecord: {
    fixture: "sqlite-deleted-record.sqlite",
    parser: "inspectSqliteDatabase",
    expected: {
      recoveredRecordsAtLeast: 1,
      deletedUsernameRecovered: "bob",
      envelopeFindingCategory: "sqlite-recovery",
      limitationCode: "SQLITE_RECOVERY_HEURISTIC"
    }
  },
  binaryCarving: {
    fixture: "embedded-signatures.bin",
    parser: "scanCarvableObjects",
    expected: embedded.map((item) => ({ label: item.label, offset: item.offset }))
  }
};
writeFileSync(resolve(outDir, "expected.json"), `${JSON.stringify(manifest, null, 2)}\n`);

console.log(`validation fixtures written to ${outDir}`);
console.log(`- sqlite-deleted-record.sqlite (${sqliteBytes.length} bytes)`);
console.log(`- embedded-signatures.bin (${size} bytes)`);
console.log(`- expected.json`);
