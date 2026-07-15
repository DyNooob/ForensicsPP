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

import initSqlJs, { type Database, type SqlJsStatic } from "sql.js";
import { beforeAll, describe, expect, it } from "vitest";
import {
  analyzeBrowserArtifacts,
  browserArtifactRecordsToCsv,
  chromiumTimeToIso,
  firefoxTimeToIso,
  persistableBrowserArtifactAnalysis,
  type BrowserArtifactInput
} from "../src/features/browserArtifacts/analyzer";

let SQL: SqlJsStatic;

beforeAll(async () => {
  SQL = await initSqlJs({
    locateFile: () => new URL("../node_modules/sql.js/dist/sql-wasm.wasm", import.meta.url).pathname
  });
});

function input(name: string, path: string, bytes: Uint8Array): BrowserArtifactInput {
  return { name, path, size: bytes.byteLength, bytes };
}

function exported(db: Database) {
  const bytes = db.export();
  db.close();
  return bytes;
}

describe("browser artifact timestamps", () => {
  it("converts Chromium and Firefox microsecond epochs", () => {
    expect(chromiumTimeToIso(13_348_638_245_000_000)).toBe("2024-01-02T03:04:05.000Z");
    expect(firefoxTimeToIso(1_704_164_645_000_000)).toBe("2024-01-02T03:04:05.000Z");
  });
});

describe("Browser Artifact Studio", () => {
  it("parses Chromium history, redirect chains and download metadata", () => {
    const db = new SQL.Database();
    db.run(`
      CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER);
      CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER, visit_duration INTEGER);
      CREATE TABLE downloads (id INTEGER PRIMARY KEY, start_time INTEGER, end_time INTEGER, target_path TEXT, current_path TEXT, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, mime_type TEXT, tab_url TEXT, site_url TEXT, referrer TEXT);
      CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
      INSERT INTO urls VALUES (1, 'https://example.test/page', 'Example page', 2, 1);
      INSERT INTO visits VALUES (7, 1, 13348638245000000, 805306368, 2500000);
      INSERT INTO downloads VALUES (9, 13348638245000000, 13348638246000000, '/Users/test/report.zip', '/tmp/report.zip', 128, 128, 1, 'application/zip', '', '', 'https://referrer.test/');
      INSERT INTO downloads_url_chains VALUES (9, 0, 'https://redirect.test/file'), (9, 1, 'https://cdn.test/report.zip');
    `);

    const result = analyzeBrowserArtifacts([
      input("History", "Chrome/User Data/Default/History", exported(db))
    ], SQL);

    expect(result.counts.visits).toBe(1);
    expect(result.counts.downloads).toBe(1);
    expect(result.firstTime).toBe("2024-01-02T03:04:05.000Z");
    expect(result.records.find((record) => record.category === "visits")).toMatchObject({
      primary: "Example page",
      url: "https://example.test/page",
      browser: "Chromium",
      profile: "Default",
      recordId: "7"
    });
    expect(result.records.find((record) => record.category === "downloads")).toMatchObject({
      primary: "report.zip",
      secondary: "https://referrer.test/",
      path: "/Users/test/report.zip",
      recordId: "9"
    });
    expect(result.records.find((record) => record.category === "downloads")?.detail).toContain("https://cdn.test/report.zip");
  });

  it("parses Firefox visits and cookies with their correct timestamp units", () => {
    const places = new SQL.Database();
    places.run(`
      CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed INTEGER);
      CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, from_visit INTEGER);
      INSERT INTO moz_places VALUES (1, 'https://mozilla.test/', 'Mozilla fixture', 3, 0);
      INSERT INTO moz_historyvisits VALUES (4, 1, 1704164645000000, 1, 0);
    `);
    const cookies = new SQL.Database();
    cookies.run(`
      CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, creationTime INTEGER, lastAccessed INTEGER, isSecure INTEGER, isHttpOnly INTEGER);
      INSERT INTO moz_cookies VALUES (5, '.mozilla.test', 'session', 'plain-value', '/', 1704168245, 1704164645000000, 1704164700000000, 1, 1);
    `);

    const result = analyzeBrowserArtifacts([
      input("places.sqlite", "Firefox/abc.default-release/places.sqlite", exported(places)),
      input("cookies.sqlite", "Firefox/abc.default-release/cookies.sqlite", exported(cookies))
    ], SQL);

    expect(result.browsers).toEqual(["Firefox"]);
    expect(result.profiles).toEqual(["abc.default-release"]);
    expect(result.counts.visits).toBe(1);
    expect(result.counts.cookies).toBe(1);
    expect(result.records.find((record) => record.category === "cookies")?.detail).toContain("plaintext present");
  });

  it("reports encrypted Chromium credentials without exposing their bytes", () => {
    const db = new SQL.Database();
    db.run(`
      CREATE TABLE logins (id INTEGER PRIMARY KEY, origin_url TEXT, username_value TEXT, password_value BLOB, date_created INTEGER, date_last_used INTEGER, date_password_modified INTEGER, times_used INTEGER, blocked_by_user INTEGER);
      INSERT INTO logins VALUES (2, 'https://account.test/', 'analyst', X'763130DEADBEEF', 13348573045000000, 13348573045000000, 13348573045000000, 4, 0);
    `);
    const result = analyzeBrowserArtifacts([
      input("Login Data", "Edge/User Data/Profile 2/Login Data", exported(db))
    ], SQL);
    const login = result.records[0];

    expect(login.browser).toBe("Edge");
    expect(login.profile).toBe("Profile 2");
    expect(login.detail).toContain("password=encrypted");
    expect(JSON.stringify(login)).not.toContain("deadbeef");
  });

  it("caps oversized artifact files and reports the limit", () => {
    const db = new SQL.Database();
    db.run("CREATE TABLE logins (id INTEGER PRIMARY KEY, origin_url TEXT, username_value TEXT, password_value BLOB, date_created INTEGER, date_last_used INTEGER, date_password_modified INTEGER, times_used INTEGER, blocked_by_user INTEGER);");
    const statement = db.prepare("INSERT INTO logins VALUES (?, ?, ?, NULL, 0, 0, 0, 0, 0)");
    for (let index = 1; index <= 50_001; index += 1) statement.run([index, "https://example.test/", `user-${index}`]);
    statement.free();
    const result = analyzeBrowserArtifacts([input("Login Data", "Chrome/User Data/Default/Login Data", exported(db))], SQL);

    expect(result.records).toHaveLength(50_000);
    expect(result.files[0].truncated).toBe(true);
    expect(result.files[0].detail).toContain("record limit");
    const persisted = persistableBrowserArtifactAnalysis(result);
    expect(persisted.snapshotLimited).toBe(true);
    expect(persisted.records.length).toBeLessThan(result.records.length);
  }, 15_000);

  it("parses bookmark and extension JSON and escapes CSV fields", () => {
    const encoder = new TextEncoder();
    const bookmarks = encoder.encode(JSON.stringify({
      roots: { bookmark_bar: { type: "folder", name: "Bar", children: [{ id: "8", type: "url", name: "A, \"quoted\" page", url: "https://bookmark.test/", date_added: "13348573045000000" }] } }
    }));
    const preferences = encoder.encode(JSON.stringify({
      extensions: { settings: { abc: { state: 1, path: "Extensions/abc", manifest: { name: "Fixture extension", version: "1.2.3" } } } }
    }));
    const result = analyzeBrowserArtifacts([
      input("Bookmarks", "Chrome/User Data/Default/Bookmarks", bookmarks),
      input("Preferences", "Chrome/User Data/Default/Preferences", preferences)
    ], SQL);

    expect(result.counts.visits).toBe(1);
    expect(result.counts.extensions).toBe(1);
    expect(browserArtifactRecordsToCsv(result.records)).toContain('"A, ""quoted"" page"');
  });
});
