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
import initSqlJs from "sql.js";
import { inspectSqliteDatabase } from "../../src/features/sqlite/forensic";
import { buildSqliteEnvelope } from "../../src/features/sqlite/envelope";

describe("validation: sqlite deleted-record recovery", () => {
  it("recovers a deleted row from free space", async () => {
    const SQL = await initSqlJs();
    const db = new SQL.Database();
    db.run("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, email TEXT);");
    db.run(
      "INSERT INTO users(id, username, email) VALUES (1,'alice','alice@example.com'),(2,'bob','bob@example.com'),(3,'carol','carol@example.com');"
    );
    // DELETE leaves the row in unallocated/freeblock space -> recoverable by the forensic parser.
    db.run("DELETE FROM users WHERE id = 2;");
    const exported = db.export();
    db.close();
    const bytes = new Uint8Array(exported);

    const analysis = inspectSqliteDatabase(bytes);
    expect(analysis.header.pageSize).toBeGreaterThan(0);
    expect(analysis.recoveredRecords.length).toBeGreaterThanOrEqual(1);

    // The deleted row surfaces either as a structured recovered record (free-space cell/payload)
    // or as an ASCII fragment carved from the freeblock/unallocated region. Assert against the full
    // recovered surface rather than only one structure, so the validation tracks real parser output.
    const recordText = analysis.recoveredRecords
      .map((record) => record.values.map((value) => value.value).join(" "))
      .join("\n");
    const fragmentText = analysis.fragments.map((fragment) => fragment.text).join("\n");
    const recoveredText = `${recordText}\n${fragmentText}`;
    expect(recoveredText.includes("bob"), "deleted row 'bob' should be recovered").toBe(true);

    const envelope = buildSqliteEnvelope(analysis, { name: "users.db", size: bytes.byteLength });
    expect(envelope.findings.some((finding) => finding.category === "sqlite-recovery")).toBe(true);
    expect(envelope.artifacts.length).toBeGreaterThanOrEqual(1);
    expect(envelope.limitations.some((item) => item.code === "SQLITE_RECOVERY_HEURISTIC")).toBe(true);
  });
});
