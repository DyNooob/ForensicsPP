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

import type { Database, SqlJsStatic, SqlValue } from "sql.js";

export type BrowserArtifactInput = {
  name: string;
  path: string;
  size: number;
  bytes: Uint8Array;
};

export type BrowserArtifactRecord = {
  id: string;
  category: "visits" | "downloads" | "cookies" | "logins" | "autofill" | "extensions";
  browser: string;
  profile: string;
  source: string;
  time: string;
  primary: string;
  secondary: string;
  detail: string;
  url: string;
  path: string;
  recordId: string;
};

export type BrowserArtifactFileResult = {
  path: string;
  size: number;
  browser: string;
  profile: string;
  artifact: string;
  records: number;
  status: "parsed" | "ignored" | "error";
  detail: string;
};

export type BrowserArtifactAnalysis = {
  files: BrowserArtifactFileResult[];
  records: BrowserArtifactRecord[];
  counts: Record<BrowserArtifactRecord["category"], number>;
  browsers: string[];
  profiles: string[];
  firstTime: string;
  lastTime: string;
};

type Row = Record<string, SqlValue>;

const CHROME_EPOCH_OFFSET_MS = 11644473600000;

function text(value: SqlValue | undefined) {
  if (value == null) return "";
  if (value instanceof Uint8Array) return value.length ? `[encrypted/blob ${value.length} bytes]` : "";
  return String(value);
}

function number(value: SqlValue | undefined) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

export function chromiumTimeToIso(value: SqlValue | undefined) {
  const raw = number(value);
  if (!raw) return "";
  const milliseconds = raw / 1000 - CHROME_EPOCH_OFFSET_MS;
  const date = new Date(milliseconds);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

export function firefoxTimeToIso(value: SqlValue | undefined) {
  const raw = number(value);
  if (!raw) return "";
  const date = new Date(raw > 10_000_000_000 ? raw / 1000 : raw * 1000);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function unixTimeToIso(value: unknown) {
  const raw = Number(value);
  if (!Number.isFinite(raw) || !raw) return "";
  const date = new Date(raw > 10_000_000_000 ? raw : raw * 1000);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function normalizePath(value: string) {
  return value.replace(/\\/g, "/").replace(/^\.\//, "");
}

export function browserAndProfile(pathValue: string) {
  const path = normalizePath(pathValue);
  const lowered = path.toLowerCase();
  const browser = lowered.includes("firefox") || /(?:^|\/)places\.sqlite$/i.test(path)
    ? "Firefox"
    : lowered.includes("edge")
    ? "Edge"
    : lowered.includes("brave")
    ? "Brave"
    : lowered.includes("opera")
    ? "Opera"
    : "Chromium";
  const parts = path.split("/");
  const profile = parts.find((part) => /^(?:default|profile\s*\d+|profile\d+|guest profile|[^/]+\.default(?:-release)?)$/i.test(part))
    ?? (parts.length > 1 ? parts[parts.length - 2] ?? "Default" : "Default");
  return { browser, profile };
}

function rows(db: Database, query: string): Row[] {
  try {
    const result = db.exec(query)[0];
    if (!result) return [];
    return result.values.map((values) => Object.fromEntries(result.columns.map((column, index) => [column, values[index] ?? null])));
  } catch {
    return [];
  }
}

function tableNames(db: Database) {
  return new Set(rows(db, "SELECT name FROM sqlite_master WHERE type IN ('table','view')").map((row) => text(row.name).toLowerCase()));
}

function makeRecord(
  input: BrowserArtifactInput,
  category: BrowserArtifactRecord["category"],
  browser: string,
  profile: string,
  rowIndex: number,
  values: Omit<BrowserArtifactRecord, "id" | "category" | "browser" | "profile" | "source">
): BrowserArtifactRecord {
  return {
    id: `${input.path}:${category}:${values.recordId || rowIndex}`,
    category,
    browser,
    profile,
    source: input.path,
    ...values
  };
}

function parseChromiumHistory(db: Database, input: BrowserArtifactInput, browser: string, profile: string) {
  const records: BrowserArtifactRecord[] = [];
  const visits = rows(db, `
    SELECT visits.id AS record_id, urls.url, urls.title, urls.visit_count, urls.typed_count,
           visits.visit_time, visits.transition, visits.visit_duration
    FROM visits JOIN urls ON urls.id = visits.url ORDER BY visits.visit_time
  `);
  visits.forEach((row, index) => records.push(makeRecord(input, "visits", browser, profile, index, {
    time: chromiumTimeToIso(row.visit_time),
    primary: text(row.title) || text(row.url),
    secondary: text(row.url),
    detail: `visits=${text(row.visit_count) || "0"}; typed=${text(row.typed_count) || "0"}; transition=${text(row.transition) || "--"}; duration_us=${text(row.visit_duration) || "0"}`,
    url: text(row.url),
    path: "",
    recordId: text(row.record_id)
  })));

  const chains = new Map<string, string[]>();
  rows(db, "SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index").forEach((row) => {
    const id = text(row.id);
    chains.set(id, [...(chains.get(id) ?? []), text(row.url)]);
  });
  rows(db, "SELECT * FROM downloads ORDER BY start_time").forEach((row, index) => {
    const id = text(row.id);
    const urls = chains.get(id) ?? [];
    const url = text(row.tab_url) || text(row.site_url) || text(row.referrer) || urls[urls.length - 1] || "";
    const target = text(row.target_path) || text(row.current_path);
    records.push(makeRecord(input, "downloads", browser, profile, index, {
      time: chromiumTimeToIso(row.start_time),
      primary: target.split(/[\\/]/).pop() || url || `Download ${id}`,
      secondary: url,
      detail: `target=${target || "--"}; bytes=${text(row.received_bytes) || "0"}/${text(row.total_bytes) || "0"}; state=${text(row.state) || "--"}; mime=${text(row.mime_type) || "--"}; end=${chromiumTimeToIso(row.end_time) || "--"}; chain=${urls.join(" -> ") || "--"}`,
      url,
      path: target,
      recordId: id
    }));
  });
  return records;
}

function parseFirefoxPlaces(db: Database, input: BrowserArtifactInput, browser: string, profile: string) {
  const records: BrowserArtifactRecord[] = [];
  rows(db, `
    SELECT moz_historyvisits.id AS record_id, moz_places.url, moz_places.title,
           moz_places.visit_count, moz_places.typed, moz_historyvisits.visit_date,
           moz_historyvisits.visit_type, moz_historyvisits.from_visit
    FROM moz_historyvisits JOIN moz_places ON moz_places.id = moz_historyvisits.place_id
    ORDER BY moz_historyvisits.visit_date
  `).forEach((row, index) => records.push(makeRecord(input, "visits", browser, profile, index, {
    time: firefoxTimeToIso(row.visit_date),
    primary: text(row.title) || text(row.url),
    secondary: text(row.url),
    detail: `visits=${text(row.visit_count) || "0"}; typed=${text(row.typed) || "0"}; visit_type=${text(row.visit_type) || "--"}; from_visit=${text(row.from_visit) || "--"}`,
    url: text(row.url),
    path: "",
    recordId: text(row.record_id)
  })));
  return records;
}

function parseCookies(db: Database, input: BrowserArtifactInput, browser: string, profile: string, firefox: boolean) {
  const table = firefox ? "moz_cookies" : "cookies";
  return rows(db, `SELECT * FROM ${table}`).map((row, index) => {
    const host = text(row.host_key ?? row.host);
    const name = text(row.name);
    const encrypted = row.encrypted_value instanceof Uint8Array && row.encrypted_value.byteLength > 0;
    const value = text(row.value);
    const time = firefox ? firefoxTimeToIso(row.creationTime) : chromiumTimeToIso(row.creation_utc);
    const expires = firefox ? unixTimeToIso(row.expiry) : chromiumTimeToIso(row.expires_utc);
    const accessed = firefox ? firefoxTimeToIso(row.lastAccessed) : chromiumTimeToIso(row.last_access_utc);
    return makeRecord(input, "cookies", browser, profile, index, {
      time,
      primary: name || "(unnamed cookie)",
      secondary: host,
      detail: `path=${text(row.path) || "/"}; expires=${expires || "session"}; last_access=${accessed || "--"}; secure=${text(row.is_secure ?? row.isSecure) || "0"}; httponly=${text(row.is_httponly ?? row.isHttpOnly) || "0"}; value=${encrypted ? "encrypted" : value ? "plaintext present" : "empty"}`,
      url: host ? `https://${host.replace(/^\./, "")}/` : "",
      path: text(row.path),
      recordId: text(row.id) || String(index + 1)
    });
  });
}

function parseChromiumLogins(db: Database, input: BrowserArtifactInput, browser: string, profile: string) {
  return rows(db, "SELECT * FROM logins ORDER BY date_created").map((row, index) => {
    const origin = text(row.origin_url) || text(row.signon_realm) || text(row.action_url);
    const passwordState = row.password_value instanceof Uint8Array && row.password_value.byteLength ? "encrypted" : text(row.password_value) ? "stored" : "empty";
    return makeRecord(input, "logins", browser, profile, index, {
      time: chromiumTimeToIso(row.date_created),
      primary: text(row.username_value) || "(empty username)",
      secondary: origin,
      detail: `last_used=${chromiumTimeToIso(row.date_last_used) || "--"}; modified=${chromiumTimeToIso(row.date_password_modified) || "--"}; times_used=${text(row.times_used) || "0"}; password=${passwordState}; blocked=${text(row.blocked_by_user ?? row.blacklisted_by_user) || "0"}`,
      url: origin,
      path: "",
      recordId: text(row.id) || String(index + 1)
    });
  });
}

function parseChromiumAutofill(db: Database, input: BrowserArtifactInput, browser: string, profile: string) {
  return rows(db, "SELECT * FROM autofill ORDER BY date_created").map((row, index) => makeRecord(input, "autofill", browser, profile, index, {
    time: unixTimeToIso(row.date_created),
    primary: text(row.name),
    secondary: text(row.value),
    detail: `count=${text(row.count) || "0"}; last_used=${unixTimeToIso(row.date_last_used) || "--"}`,
    url: "",
    path: "",
    recordId: text(row.guid) || String(index + 1)
  }));
}

function parseJson(input: BrowserArtifactInput, browser: string, profile: string) {
  const records: BrowserArtifactRecord[] = [];
  const decoded = new TextDecoder("utf-8", { fatal: false }).decode(input.bytes);
  const value = JSON.parse(decoded) as Record<string, unknown>;
  const name = input.name.toLowerCase();
  if (name === "bookmarks") {
    const visit = (node: unknown, folder = "") => {
      if (!node || typeof node !== "object") return;
      const item = node as Record<string, unknown>;
      const nextFolder = item.type === "folder" ? [folder, String(item.name ?? "")].filter(Boolean).join("/") : folder;
      if (item.type === "url") records.push(makeRecord(input, "visits", browser, profile, records.length, {
        time: chromiumTimeToIso(String(item.date_added ?? "")),
        primary: String(item.name ?? item.url ?? "Bookmark"),
        secondary: String(item.url ?? ""),
        detail: `bookmark_folder=${folder || "root"}; date_modified=${chromiumTimeToIso(String(item.date_modified ?? "")) || "--"}`,
        url: String(item.url ?? ""),
        path: folder,
        recordId: String(item.id ?? records.length + 1)
      }));
      if (Array.isArray(item.children)) item.children.forEach((child) => visit(child, nextFolder));
    };
    Object.values((value.roots as Record<string, unknown> | undefined) ?? {}).forEach((root) => visit(root));
  } else if (name === "preferences") {
    const settings = ((value.extensions as Record<string, unknown> | undefined)?.settings as Record<string, unknown> | undefined) ?? {};
    Object.entries(settings).forEach(([id, raw], index) => {
      const extension = raw as Record<string, unknown>;
      const manifest = (extension.manifest as Record<string, unknown> | undefined) ?? {};
      records.push(makeRecord(input, "extensions", browser, profile, index, {
        time: chromiumTimeToIso(String(extension.first_install_time ?? extension.install_time ?? "")),
        primary: String(manifest.name ?? id),
        secondary: id,
        detail: `version=${String(manifest.version ?? "--")}; state=${String(extension.state ?? "--")}; location=${String(extension.location ?? "--")}; path=${String(extension.path ?? "--")}`,
        url: String(manifest.homepage_url ?? manifest.update_url ?? ""),
        path: String(extension.path ?? ""),
        recordId: id
      }));
    });
  } else if (name === "logins.json") {
    const logins = Array.isArray(value.logins) ? value.logins : [];
    logins.forEach((raw, index) => {
      const login = raw as Record<string, unknown>;
      records.push(makeRecord(input, "logins", browser, profile, index, {
        time: unixTimeToIso(login.timeCreated),
        primary: String(login.encryptedUsername ? "encrypted username" : "(empty username)"),
        secondary: String(login.hostname ?? ""),
        detail: `last_used=${unixTimeToIso(login.timeLastUsed) || "--"}; changed=${unixTimeToIso(login.timePasswordChanged) || "--"}; times_used=${String(login.timesUsed ?? "0")}; password=${login.encryptedPassword ? "encrypted" : "empty"}`,
        url: String(login.hostname ?? ""),
        path: "",
        recordId: String(login.id ?? index + 1)
      }));
    });
  }
  return records;
}

function sqliteArtifactName(tables: Set<string>) {
  if (tables.has("visits") && tables.has("urls")) return "Chromium History";
  if (tables.has("moz_historyvisits") && tables.has("moz_places")) return "Firefox Places";
  if (tables.has("cookies")) return "Chromium Cookies";
  if (tables.has("moz_cookies")) return "Firefox Cookies";
  if (tables.has("logins")) return "Chromium Login Data";
  if (tables.has("autofill")) return "Chromium Web Data";
  return "SQLite (unsupported browser schema)";
}

export function analyzeBrowserArtifacts(inputs: BrowserArtifactInput[], SQL: SqlJsStatic): BrowserArtifactAnalysis {
  const allRecords: BrowserArtifactRecord[] = [];
  const files: BrowserArtifactFileResult[] = [];

  for (const input of inputs) {
    const identity = browserAndProfile(input.path);
    let artifact = "Unsupported file";
    let records: BrowserArtifactRecord[] = [];
    try {
      const sqlite = input.bytes.length >= 16 && new TextDecoder().decode(input.bytes.slice(0, 16)) === "SQLite format 3\u0000";
      if (sqlite) {
        const db = new SQL.Database(input.bytes);
        try {
          const tables = tableNames(db);
          artifact = sqliteArtifactName(tables);
          if (tables.has("visits") && tables.has("urls")) records.push(...parseChromiumHistory(db, input, identity.browser, identity.profile));
          if (tables.has("moz_historyvisits") && tables.has("moz_places")) records.push(...parseFirefoxPlaces(db, input, "Firefox", identity.profile));
          if (tables.has("cookies")) records.push(...parseCookies(db, input, identity.browser, identity.profile, false));
          if (tables.has("moz_cookies")) records.push(...parseCookies(db, input, "Firefox", identity.profile, true));
          if (tables.has("logins")) records.push(...parseChromiumLogins(db, input, identity.browser, identity.profile));
          if (tables.has("autofill")) records.push(...parseChromiumAutofill(db, input, identity.browser, identity.profile));
        } finally {
          db.close();
        }
      } else if (["bookmarks", "preferences", "logins.json"].includes(input.name.toLowerCase())) {
        artifact = input.name;
        records = parseJson(input, input.name.toLowerCase() === "logins.json" ? "Firefox" : identity.browser, identity.profile);
      }
      allRecords.push(...records);
      files.push({ path: input.path, size: input.size, browser: identity.browser, profile: identity.profile, artifact, records: records.length, status: records.length ? "parsed" : "ignored", detail: records.length ? `${records.length} record(s)` : "No supported records found" });
    } catch (caught) {
      files.push({ path: input.path, size: input.size, browser: identity.browser, profile: identity.profile, artifact, records: 0, status: "error", detail: caught instanceof Error ? caught.message : String(caught) });
    }
  }

  allRecords.sort((left, right) => left.time.localeCompare(right.time));
  const categories: BrowserArtifactRecord["category"][] = ["visits", "downloads", "cookies", "logins", "autofill", "extensions"];
  const counts = Object.fromEntries(categories.map((category) => [category, allRecords.filter((record) => record.category === category).length])) as BrowserArtifactAnalysis["counts"];
  const timed = allRecords.filter((record) => record.time);
  return {
    files,
    records: allRecords,
    counts,
    browsers: Array.from(new Set(allRecords.map((record) => record.browser))),
    profiles: Array.from(new Set(allRecords.map((record) => record.profile))),
    firstTime: timed[0]?.time ?? "",
    lastTime: timed[timed.length - 1]?.time ?? ""
  };
}

export function browserArtifactRecordsToCsv(records: BrowserArtifactRecord[]) {
  const escape = (value: string) => /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
  return [
    ["category", "time", "browser", "profile", "primary", "secondary", "url", "path", "source", "record_id", "detail"],
    ...records.map((record) => [record.category, record.time, record.browser, record.profile, record.primary, record.secondary, record.url, record.path, record.source, record.recordId, record.detail])
  ].map((row) => row.map((value) => escape(String(value))).join(",")).join("\n");
}
