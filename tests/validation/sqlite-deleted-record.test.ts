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

// Deterministic, repeatable fixture. Mirrors scripts/gen-validation-fixtures.mjs:
// fixed page size, secure_delete OFF, no auto-vacuum, DELETE journal mode, a fixed
// schema, enough rows that the deleted payload survives in a freeblock, an explicit
// commit, a single DELETE, and NO VACUUM. The recovery claim is therefore fragment /
// raw residual recovery — NOT structured free-space record reconstruction.
async function buildUsersDb(secureDelete: boolean, vacuum: boolean): Promise<Uint8Array> {
  const SQL = await initSqlJs();
  const db = new SQL.Database();
  db.run("PRAGMA page_size=4096; PRAGMA secure_delete=OFF; PRAGMA auto_vacuum=NONE; PRAGMA journal_mode=DELETE;");
  if (secureDelete) db.run("PRAGMA secure_delete=ON;");
  db.run("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, email TEXT);");
  db.run(
    "INSERT INTO users(id, username, email) VALUES " +
      "(1,'alice','alice@example.com'),(2,'bob','bob@example.com'),(3,'carol','carol@example.com')," +
      "(4,'dave','dave@example.com'),(5,'erin','erin@example.com'),(6,'frank','frank@example.com');"
  );
  db.run("DELETE FROM users WHERE id = 2;"); // deleted row -> recoverable only as residual
  if (vacuum) db.run("VACUUM;");
  const bytes = new Uint8Array(db.export());
  db.close();
  return bytes;
}

describe("validation: sqlite deleted-record recovery (honest fragment-residual)", () => {
  it("recovers a deleted row as a fragment/raw residual, not a structured record", async () => {
    const bytes = await buildUsersDb(false, false);
    const analysis = inspectSqliteDatabase(bytes);
    expect(analysis.header.pageSize).toBe(4096);

    // Positive control: the live (active) table no longer contains the deleted row.
    const SQL = await initSqlJs();
    const live = new SQL.Database(bytes);
    const liveRows = live.exec("SELECT username FROM users ORDER BY id;")[0].values.map((row) => row[0]);
    live.close();
    expect(liveRows, "live table must exclude the deleted row").not.toContain("bob");
    expect(liveRows).toEqual(["alice", "carol", "dave", "erin", "frank"]);

    // Honest capability: the deleted row survives as a raw ASCII fragment in free space.
    const fragmentText = analysis.fragments.map((fragment) => fragment.text).join("\n");
    expect(fragmentText.includes("bob"), "deleted row 'bob' must be recoverable as a fragment/raw residual").toBe(true);

    // Honest limitation: structured free-space record recovery does NOT reliably recover 'bob'.
    // We must NOT broaden the assertion surface to fold fragments into records and call it
    // "deleted record recovery validated" — that would be a false structured-recovery claim.
    const recordText = analysis.recoveredRecords
      .map((record) => record.values.map((value) => value.value).join(" "))
      .join("\n");
    expect(recordText.includes("bob"), "structured recoveredRecords must not falsely claim 'bob' as a recovered record").toBe(false);

    const envelope = buildSqliteEnvelope(analysis, { name: "users.db", size: bytes.byteLength });
    expect(envelope.findings.some((finding) => finding.category === "sqlite-recovery")).toBe(true);
    // The envelope must honestly flag the recovery as heuristic/residual, not authoritative.
    expect(envelope.limitations.some((item) => item.code === "SQLITE_RECOVERY_HEURISTIC")).toBe(true);
  });

  it("negative control: secure_delete + VACUUM leaves no recoverable residual", async () => {
    const bytes = await buildUsersDb(true, true);
    const analysis = inspectSqliteDatabase(bytes);
    const surface = [
      ...analysis.recoveredRecords.map((record) => record.values.map((value) => value.value).join(" ")),
      ...analysis.fragments.map((fragment) => fragment.text)
    ].join("\n");
    expect(surface.includes("bob"), "secure_delete + VACUUM must purge the deleted row from the recoverable surface").toBe(false);
  });
});
