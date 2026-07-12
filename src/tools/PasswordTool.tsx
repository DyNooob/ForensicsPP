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

import React from "react";
import CryptoJS from "crypto-js";
import { AButton, AInputNumber, APasswordField, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import type { PasswordVerifyRow } from "../models";
import { downloadTextFile } from "../utils/files";
import { detectHashType } from "../utils/hash";
import { useStoredState } from "../utils/storage";

export type PasswordToolServices = {
  mysqlNativePassword: (password: string) => string;
  randomSalt: (length?: number) => string;
  verifyPasswordCandidates: (target: string, candidates: string[]) => Promise<PasswordVerifyRow[]>;
  passwordRowsToCsv: (rows: PasswordVerifyRow[]) => string;
};

function bytesToBase64(bytes: Uint8Array) {
  return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));
}

async function djangoPbkdf2(password: string, salt: string, iterations = 390000) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations }, key, 256);
  return `pbkdf2_sha256$${iterations}$${salt}$${bytesToBase64(new Uint8Array(bits))}`;
}

export function PasswordTool({ t, services }: { t: (typeof copy)["zh"]; services: PasswordToolServices }) {
  const { mysqlNativePassword, randomSalt, verifyPasswordCandidates, passwordRowsToCsv } = services;
  const english = t.waiting === "Waiting";
  const [mode, setMode] = React.useState<"generate" | "verify" | "sql">("generate");
  const [password, setPassword] = React.useState("");
  const [salt, setSalt] = React.useState(() => randomSalt());
  const [rounds, setRounds] = useStoredState("password.rounds", 10);
  const [pbkdf2Iterations, setPbkdf2Iterations] = useStoredState("password.pbkdf2Iterations", 390000);
  const [quickGenerated, setQuickGenerated] = React.useState(false);
  const [bcryptHash, setBcryptHash] = React.useState("");
  const [pbkdf2Hash, setPbkdf2Hash] = React.useState("");
  const [generatedView, setGeneratedView] = React.useState<"common" | "bcrypt" | "pbkdf2" | "">("");
  const [targetHash, setTargetHash] = React.useState("");
  const [candidatePasswords, setCandidatePasswords] = React.useState("");
  const [verifyRows, setVerifyRows] = React.useState<PasswordVerifyRow[]>([]);
  const [loading, setLoading] = React.useState<"bcrypt" | "pbkdf2" | "verify" | "">("");
  const [error, setError] = React.useState("");
  const [username, setUsername] = React.useState("");
  const [table, setTable] = React.useState("users");
  const [column, setColumn] = React.useState("password");
  const [whereColumn, setWhereColumn] = React.useState("username");

  const fastHashes = React.useMemo<Array<[string, string]>>(() => password && quickGenerated ? [
    ["MD5", CryptoJS.MD5(password).toString()],
    ["SHA-1", CryptoJS.SHA1(password).toString()],
    ["SHA-256", CryptoJS.SHA256(password).toString()],
    ["SHA-512", CryptoJS.SHA512(password).toString()],
    ["SHA3-512", CryptoJS.SHA3(password, { outputLength: 512 }).toString()],
    ["RIPEMD-160", CryptoJS.RIPEMD160(password).toString()],
    ["MySQL 4.1", mysqlNativePassword(password)],
    ["LDAP {SHA}", `{SHA}${CryptoJS.SHA1(password).toString(CryptoJS.enc.Base64)}`],
    ...(salt ? [
      ["MD5(salt + password)", CryptoJS.MD5(`${salt}${password}`).toString()] as [string, string],
      ["MD5(password + salt)", CryptoJS.MD5(`${password}${salt}`).toString()] as [string, string],
      ["SHA-256(salt + password)", CryptoJS.SHA256(`${salt}${password}`).toString()] as [string, string],
      ["SHA-256(password + salt)", CryptoJS.SHA256(`${password}${salt}`).toString()] as [string, string]
    ] : [])
  ] : [], [mysqlNativePassword, password, quickGenerated, salt]);
  const generatedHashes = React.useMemo<Array<[string, string]>>(() => [
    ...fastHashes,
    ...(bcryptHash ? [["bcrypt", bcryptHash] as [string, string]] : []),
    ...(pbkdf2Hash ? [["Django PBKDF2-SHA256", pbkdf2Hash] as [string, string]] : [])
  ], [bcryptHash, fastHashes, pbkdf2Hash]);
  const visibleGeneratedHashes = React.useMemo<Array<[string, string]>>(() => {
    if (generatedView === "common") return fastHashes;
    if (generatedView === "bcrypt" && bcryptHash) return [["bcrypt", bcryptHash]];
    if (generatedView === "pbkdf2" && pbkdf2Hash) return [["Django PBKDF2-SHA256", pbkdf2Hash]];
    return [];
  }, [bcryptHash, fastHashes, generatedView, pbkdf2Hash]);
  const candidates = React.useMemo(() => candidatePasswords.split(/\r?\n/).map((item) => item.trim()).filter(Boolean), [candidatePasswords]);
  const matchedCount = verifyRows.filter((row) => row.matched).length;
  const targetType = detectHashType(targetHash) || verifyRows[0]?.hashType || "--";
  const md5 = fastHashes.find(([label]) => label === "MD5")?.[1] ?? "";
  const escapedPassword = password.replace(/'/g, "''");
  const escapedUsername = username.replace(/'/g, "''");
  const sqlTemplates = React.useMemo<Array<[string, string]>>(() => [
    ["WordPress MD5", password && username ? `UPDATE wp_users SET user_pass = MD5('${escapedPassword}') WHERE user_login = '${escapedUsername}';` : "--"],
    ["Generic MD5", md5 && username ? `UPDATE ${table} SET ${column} = '${md5}' WHERE ${whereColumn} = '${escapedUsername}';` : "--"],
    ["bcrypt", bcryptHash && username ? `UPDATE ${table} SET ${column} = '${bcryptHash}' WHERE ${whereColumn} = '${escapedUsername}';` : "--"],
    ["Django PBKDF2", pbkdf2Hash && username ? `UPDATE ${table} SET ${column} = '${pbkdf2Hash}' WHERE ${whereColumn} = '${escapedUsername}';` : "--"]
  ], [bcryptHash, column, escapedPassword, escapedUsername, md5, password, pbkdf2Hash, table, username, whereColumn]);
  const hasInput = Boolean(password || targetHash || candidatePasswords || generatedHashes.length || verifyRows.length || username);

  const clearGenerated = () => {
    setQuickGenerated(false);
    setBcryptHash("");
    setPbkdf2Hash("");
    setGeneratedView("");
  };

  const generateQuickHashes = () => {
    if (!password) return;
    setError("");
    setQuickGenerated(true);
    setGeneratedView("common");
  };

  const generateBcrypt = async () => {
    if (!password) return;
    setLoading("bcrypt");
    setError("");
    try {
      const bcryptModule = await import("bcryptjs");
      const bcrypt = bcryptModule.default ?? bcryptModule;
      const value = await new Promise<string>((resolve, reject) => {
        bcrypt.hash(password, rounds, (caught, encrypted) => caught || !encrypted ? reject(caught ?? new Error("bcrypt failed")) : resolve(encrypted));
      });
      setBcryptHash(value);
      setGeneratedView("bcrypt");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading("");
    }
  };

  const generatePbkdf2 = async () => {
    if (!password || !salt) return;
    setLoading("pbkdf2");
    setError("");
    try {
      setPbkdf2Hash(await djangoPbkdf2(password, salt, pbkdf2Iterations));
      setGeneratedView("pbkdf2");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading("");
    }
  };

  const verify = async () => {
    if (!targetHash.trim() || !candidates.length) return;
    setLoading("verify");
    setError("");
    try {
      setVerifyRows(await verifyPasswordCandidates(targetHash.trim(), candidates));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading("");
    }
  };

  const clear = () => {
    setPassword("");
    setSalt(randomSalt());
    setQuickGenerated(false);
    setBcryptHash("");
    setPbkdf2Hash("");
    setGeneratedView("");
    setTargetHash("");
    setCandidatePasswords("");
    setVerifyRows([]);
    setUsername("");
    setError("");
  };

  return (
    <div className={`tool-grid password-simple-workbench password-grid ${hasInput ? "has-password" : "empty-password"}`}>
      <div className="tool-panel wide-panel password-simple-main-panel">
        <ToolPanelHeader
          title={english ? "Password hash" : "密码哈希"}
          actions={<>
            <ASegmentedGroup className="password-simple-mode" value={mode} selects="single">
              <ASegmentedButton value="generate" onClick={() => setMode("generate")}>{english ? "Generate" : "生成"}</ASegmentedButton>
              <ASegmentedButton value="verify" onClick={() => setMode("verify")}>{english ? "Verify" : "验证"}</ASegmentedButton>
              <ASegmentedButton value="sql" onClick={() => setMode("sql")}>SQL</ASegmentedButton>
            </ASegmentedGroup>
            <AButton variant="text" disabled={!hasInput} onClick={clear}>{t.clear}</AButton>
          </>}
        />

        {mode === "generate" && (
          <div className="password-simple-section">
            <div className="password-simple-generate-grid">
              <label className="stack-label">{t.passwordValue}<APasswordField className="text-input full-input" value={password} onChange={(event) => { setPassword(event.currentTarget.value); clearGenerated(); }} placeholder={t.passwordValue} /></label>
              <label className="stack-label">{english ? "Salt" : "盐值"}<input className="text-input full-input" value={salt} onChange={(event) => { setSalt(event.currentTarget.value); clearGenerated(); }} /></label>
              <label className="stack-label">{english ? "bcrypt rounds" : "bcrypt 轮数"}<AInputNumber min={4} max={14} value={rounds} onChange={(value) => { setRounds(Math.min(14, Math.max(4, value ?? 10))); setBcryptHash(""); }} /></label>
              <label className="stack-label">{english ? "PBKDF2 iterations" : "PBKDF2 迭代"}<AInputNumber min={10000} max={2000000} step={10000} value={pbkdf2Iterations} onChange={(value) => { setPbkdf2Iterations(Math.min(2000000, Math.max(10000, value ?? 390000))); setPbkdf2Hash(""); }} /></label>
            </div>
            <div className="button-row">
              <AButton variant="filled" disabled={!password || Boolean(loading)} onClick={generateQuickHashes}>{english ? "Generate common hashes" : "生成常用哈希"}</AButton>
              <AButton variant="outlined" disabled={!password || Boolean(loading)} onClick={() => void generateBcrypt()}>{loading === "bcrypt" ? "bcrypt..." : t.generateBcrypt}</AButton>
              <AButton variant="outlined" disabled={!password || !salt || Boolean(loading)} onClick={() => void generatePbkdf2()}>{loading === "pbkdf2" ? "PBKDF2..." : t.generatePbkdf2}</AButton>
              <AButton variant="text" onClick={() => { setSalt(randomSalt()); clearGenerated(); }}>{english ? "New salt" : "新盐值"}</AButton>
            </div>
            {visibleGeneratedHashes.length > 0 && (
              <div className="password-simple-output">
                <ToolPanelHeader title={english ? "Generated hash" : "生成结果"} actions={<AButton variant="text" onClick={() => void navigator.clipboard.writeText(visibleGeneratedHashes.map(([label, value]) => `${label}: ${value}`).join("\n"))}>{visibleGeneratedHashes.length > 1 ? (english ? "Copy all" : "复制全部") : (english ? "Copy" : "复制")}</AButton>} />
                <div className="table-scroll"><table className="data-table password-simple-hash-table"><tbody>{visibleGeneratedHashes.map(([label, value]) => <tr key={label}><th>{label}</th><td><button type="button" className="password-simple-value" onClick={() => void navigator.clipboard.writeText(value)}>{value}</button></td></tr>)}</tbody></table></div>
              </div>
            )}
          </div>
        )}

        {mode === "verify" && (
          <div className="password-simple-section">
            <label className="stack-label">{t.hashTypeInput}<textarea className="compact-textarea password-simple-target" value={targetHash} onChange={(event) => { setTargetHash(event.currentTarget.value); setVerifyRows([]); }} placeholder={english ? "Paste the target password hash" : "粘贴目标密码哈希"} /></label>
            <label className="stack-label">{t.candidatePasswords}<textarea className="single-textarea password-simple-candidates" value={candidatePasswords} onChange={(event) => { setCandidatePasswords(event.currentTarget.value); setVerifyRows([]); }} placeholder={english ? "One candidate password per line" : "每行输入一个候选口令"} /></label>
            <div className="button-row"><AButton variant="filled" disabled={!targetHash.trim() || !candidates.length || Boolean(loading)} onClick={() => void verify()}>{loading === "verify" ? (english ? "Verifying..." : "正在验证...") : t.verifyCandidates}</AButton></div>
            {verifyRows.length > 0 && (
              <div className="password-simple-output">
                <ToolPanelHeader title={english ? "Verification results" : "验证结果"} subtitle={`${matchedCount}/${verifyRows.length} MATCH`} actions={<AButton variant="outlined" onClick={() => downloadTextFile(`password-verify-${Date.now()}.csv`, passwordRowsToCsv(verifyRows), "text/csv;charset=utf-8")}>{english ? "Export CSV" : "导出 CSV"}</AButton>} />
                <InfoTable rows={[[english ? "Detected type" : "识别类型", targetType], [english ? "Candidates" : "候选数量", String(verifyRows.length)], [english ? "Matches" : "匹配数量", String(matchedCount)]]} />
                <div className="table-scroll password-simple-verify-scroll"><table className="data-table password-simple-verify-table"><thead><tr><th>{english ? "Candidate" : "候选口令"}</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Result" : "结果"}</th><th>{english ? "Detail" : "详情"}</th></tr></thead><tbody>{verifyRows.map((row, index) => <tr className={row.matched ? "selected-row" : ""} key={`${index}-${row.candidate}`}><td>{row.candidate}</td><td>{row.hashType}</td><td>{row.matched ? "MATCH" : "NO MATCH"}</td><td>{row.detail}</td></tr>)}</tbody></table></div>
                {candidates.length > 200 && <span className="inline-note">{english ? "Only the first 200 candidates were checked." : "仅验证前 200 个候选口令。"}</span>}
              </div>
            )}
          </div>
        )}

        {mode === "sql" && (
          <div className="password-simple-section">
            <div className="password-simple-sql-grid">
              <label className="stack-label">{english ? "Username" : "用户名"}<input className="text-input" value={username} onChange={(event) => setUsername(event.currentTarget.value)} /></label>
              <label className="stack-label">{english ? "Table" : "数据表"}<input className="text-input" value={table} onChange={(event) => setTable(event.currentTarget.value)} /></label>
              <label className="stack-label">{english ? "Password column" : "密码字段"}<input className="text-input" value={column} onChange={(event) => setColumn(event.currentTarget.value)} /></label>
              <label className="stack-label">{english ? "Where column" : "条件字段"}<input className="text-input" value={whereColumn} onChange={(event) => setWhereColumn(event.currentTarget.value)} /></label>
            </div>
            {!password ? <div className="empty-state">{english ? "Generate a password hash first" : "请先在生成页输入口令"}</div> : <div className="password-simple-sql-list">{sqlTemplates.map(([label, value]) => <div className="password-simple-sql-row" key={label}><strong>{label}</strong><code>{value}</code><AButton variant="text" disabled={value === "--"} onClick={() => void navigator.clipboard.writeText(value)}>{t.copy}</AButton></div>)}</div>}
          </div>
        )}

        {error && <div className="empty-state error-state">{error}</div>}
      </div>
    </div>
  );
}
