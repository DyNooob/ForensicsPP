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

import { copyText } from "../utils/clipboard";
import React from "react";
import { AButton, APasswordField, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";

type Finding = { level: string; title: string; detail: string };
type JwtInspection = {
  rows: Array<[string, string]>;
  claimRows: Array<[string, string]>;
  findings: Finding[];
  headerText: string;
  payloadText: string;
  headerObject: Record<string, unknown> | null;
  payloadObject: Record<string, unknown> | null;
  result: string;
};

type JwtListRow = {
  token: string;
  alg: string;
  sub: string;
  iss: string;
  aud: string;
  exp: string;
  signature: string;
  inspection: JwtInspection;
};

export type JwtToolServices = {
  inspectJwtToken: (token: string, secret: string) => JwtInspection;
  extractJwtTokens: (text: string) => string[];
  jwtCryptoAlgorithm: (alg: string) => unknown;
  verifyJwtAsymmetricSignature: (token: string, keyText: string) => Promise<{ status: string; detail: string }>;
  signJwtHS256: (header: string, payload: string, secret: string) => string;
};

export function JwtTool({ t, services, active = true }: { t: (typeof copy)["zh"]; services: JwtToolServices; active?: boolean }) {
  const { inspectJwtToken, extractJwtTokens, jwtCryptoAlgorithm, verifyJwtAsymmetricSignature, signJwtHS256 } = services;
  const english = t.waiting === "Waiting";
  const [mode, setMode] = React.useState<"inspect" | "generate">("inspect");
  const [tokenInput, setTokenInput] = React.useState("");
  const [secret, setSecret] = React.useState("");
  const [verifyKey, setVerifyKey] = React.useState("");
  const [verification, setVerification] = React.useState({ status: "idle", detail: "" });
  const [selectedToken, setSelectedToken] = React.useState("");
  const [view, setView] = React.useState<"decoded" | "claims" | "tokens">("decoded");
  const [header, setHeader] = React.useState('{"alg":"HS256","typ":"JWT"}');
  const [payload, setPayload] = React.useState("{}");
  const [generatedToken, setGeneratedToken] = React.useState("");
  const [generateError, setGenerateError] = React.useState("");
  const verificationRequestRef = React.useRef(0);

  React.useEffect(() => {
    if (active) return;
    verificationRequestRef.current += 1;
    setVerification({ status: "idle", detail: "" });
  }, [active]);

  const tokens = React.useMemo(() => extractJwtTokens(tokenInput).slice(0, 200), [extractJwtTokens, tokenInput]);
  const tokenRows = React.useMemo<JwtListRow[]>(() => tokens.map((token) => {
    const inspection = inspectJwtToken(token, secret);
    const rowMap = new Map(inspection.rows);
    const claimMap = new Map(inspection.claimRows);
    return {
      token,
      alg: rowMap.get("alg") ?? "--",
      sub: rowMap.get("sub") ?? "--",
      iss: rowMap.get("iss") ?? "--",
      aud: rowMap.get("aud") ?? "--",
      exp: claimMap.get("exp") ?? "--",
      signature: rowMap.get("signature") ?? "--",
      inspection
    };
  }), [inspectJwtToken, secret, tokens]);
  const activeRow = React.useMemo(() => tokenRows.find((row) => row.token === selectedToken) ?? tokenRows[0] ?? null, [selectedToken, tokenRows]);
  const activeToken = activeRow?.token ?? "";
  const activeInspection = activeRow?.inspection ?? inspectJwtToken("", secret);
  const activeRows = React.useMemo(() => new Map(activeInspection.rows), [activeInspection.rows]);
  const activeAlg = activeRows.get("alg") ?? "--";
  const asymmetric = Boolean(jwtCryptoAlgorithm(activeAlg));
  const isHmac = /^HS(?:256|384|512)$/i.test(activeAlg);
  const multiToken = tokenRows.length > 1;
  const hasInput = Boolean(tokenInput || secret || verifyKey || generatedToken);
  const parseError = tokenInput.trim() && !tokens.length ? (activeInspection.result || (english ? "No valid JWT found" : "未找到有效 JWT")) : "";
  const summaryRows = React.useMemo<Array<[string, string]>>(() => activeRow ? [
    ["alg", activeAlg],
    ["typ", activeRows.get("typ") ?? "--"],
    ["kid", activeRows.get("kid") ?? "--"],
    [english ? "Signature" : "签名状态", asymmetric && verification.status !== "idle" ? verification.detail : activeRow.signature],
    [english ? "Token length" : "Token 长度", String(activeToken.length)]
  ] : [], [activeAlg, activeRow, activeRows, activeToken.length, asymmetric, english, verification]);

  React.useEffect(() => {
    if (selectedToken && !tokens.includes(selectedToken)) setSelectedToken("");
    if (!multiToken && view === "tokens") setView("decoded");
    setVerification({ status: "idle", detail: "" });
  }, [multiToken, selectedToken, tokens, view]);

  const verifyAsymmetric = async () => {
    if (!active || !activeToken || !verifyKey.trim()) return;
    const requestId = ++verificationRequestRef.current;
    setVerification({ status: "checking", detail: english ? "Checking..." : "正在校验..." });
    try {
      const result = await verifyJwtAsymmetricSignature(activeToken, verifyKey.trim());
      if (requestId === verificationRequestRef.current) setVerification(result);
    } catch (caught) {
      if (requestId === verificationRequestRef.current) setVerification({ status: "error", detail: caught instanceof Error ? caught.message : String(caught) });
    }
  };

  const generate = () => {
    setGenerateError("");
    try {
      const parsedHeader = JSON.parse(header) as Record<string, unknown>;
      JSON.parse(payload);
      if (parsedHeader.alg !== "HS256") throw new Error(english ? "Generator supports HS256 only" : "生成器仅支持 HS256");
      if (!secret) throw new Error(english ? "Enter a shared secret" : "请输入 shared secret");
      setGeneratedToken(signJwtHS256(header, payload, secret));
    } catch (caught) {
      setGeneratedToken("");
      setGenerateError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const clear = () => {
    setTokenInput("");
    setSecret("");
    setVerifyKey("");
    setVerification({ status: "idle", detail: "" });
    setSelectedToken("");
    setView("decoded");
    setHeader('{"alg":"HS256","typ":"JWT"}');
    setPayload("{}");
    setGeneratedToken("");
    setGenerateError("");
  };

  return (
    <div className={`tool-grid jwt-simple-workbench jwt-grid ${hasInput ? "has-jwt" : "empty-jwt"}`}>
      <div className="tool-panel wide-panel jwt-simple-main-panel">
        <ToolPanelHeader
          title={english ? "JWT workbench" : "JWT 工作台"}
          actions={<>
            <ASegmentedGroup className="jwt-simple-mode" value={mode} selects="single">
              <ASegmentedButton value="inspect" onClick={() => setMode("inspect")}>{english ? "Decode / Verify" : "解析 / 验证"}</ASegmentedButton>
              <ASegmentedButton value="generate" onClick={() => setMode("generate")}>{english ? "Generate HS256" : "生成 HS256"}</ASegmentedButton>
            </ASegmentedGroup>
            <AButton variant="text" disabled={!hasInput} onClick={clear}>{t.clear}</AButton>
          </>}
        />

        {mode === "inspect" ? (
          <div className="jwt-simple-section">
            <label className="stack-label">JWT<textarea className="single-textarea jwt-simple-token-input" value={tokenInput} onChange={(event) => { setTokenInput(event.currentTarget.value); setSelectedToken(""); }} placeholder={english ? "Paste one JWT or text containing multiple JWTs" : "粘贴单个 JWT，或包含多个 JWT 的文本"} /></label>
            {activeRow && isHmac && <label className="stack-label">{english ? "Shared secret" : "共享密钥"}<APasswordField className="text-input full-input" value={secret} onChange={(event) => setSecret(event.currentTarget.value)} placeholder={english ? "Optional: verify HMAC signature" : "可选：用于校验 HMAC 签名"} /></label>}
            {activeRow && asymmetric && (
              <div className="jwt-simple-key-section">
                <label className="stack-label">{english ? "Public key or JWK" : "公钥或 JWK"}<textarea className="compact-textarea jwt-simple-key-input" value={verifyKey} onChange={(event) => { setVerifyKey(event.currentTarget.value); setVerification({ status: "idle", detail: "" }); }} placeholder="PEM / JWK" /></label>
                <div className="button-row"><AButton variant="outlined" disabled={!verifyKey.trim() || verification.status === "checking"} onClick={() => void verifyAsymmetric()}>{english ? "Verify signature" : "校验签名"}</AButton></div>
              </div>
            )}
            {parseError && <div className="empty-state error-state">{parseError}</div>}

            {activeRow && (
              <div className="jwt-simple-output">
                <ToolPanelHeader
                  title={multiToken ? `${english ? "JWTs" : "Token"} (${tokenRows.length})` : (english ? "Decoded token" : "解码结果")}
                  subtitle={`${activeAlg} · ${activeRow.signature}`}
                  actions={<ASegmentedGroup className="jwt-simple-view" value={view} selects="single">
                    <ASegmentedButton value="decoded" onClick={() => setView("decoded")}>{english ? "Decoded" : "解码"}</ASegmentedButton>
                    <ASegmentedButton value="claims" onClick={() => setView("claims")}>{english ? "Claims" : "声明"}</ASegmentedButton>
                    {multiToken && <ASegmentedButton value="tokens" onClick={() => setView("tokens")}>{english ? "Tokens" : "Token 列表"}</ASegmentedButton>}
                  </ASegmentedGroup>}
                />

                {view === "decoded" && <>
                  <InfoTable rows={summaryRows} />
                  <label className="stack-label">Header<textarea className="compact-textarea jwt-simple-json" value={activeInspection.headerText || "--"} readOnly /></label>
                  <label className="stack-label">Payload<textarea className="single-textarea jwt-simple-json" value={activeInspection.payloadText || "--"} readOnly /></label>
                  <div className="button-row"><AButton variant="outlined" onClick={() => void copyText(activeToken)}>{english ? "Copy token" : "复制 Token"}</AButton><AButton variant="text" disabled={!activeInspection.headerText} onClick={() => void copyText(activeInspection.headerText)}>{english ? "Copy Header" : "复制 Header"}</AButton><AButton variant="text" disabled={!activeInspection.payloadText} onClick={() => void copyText(activeInspection.payloadText)}>{english ? "Copy Payload" : "复制 Payload"}</AButton></div>
                </>}

                {view === "claims" && <InfoTable rows={activeInspection.claimRows.length ? activeInspection.claimRows : [[english ? "Claims" : "声明", "--"]]} />}

                {view === "tokens" && <div className="table-scroll jwt-simple-token-scroll"><table className="data-table jwt-simple-token-table"><thead><tr><th>#</th><th>alg</th><th>sub</th><th>iss</th><th>aud</th><th>exp</th><th>{english ? "Signature" : "签名"}</th></tr></thead><tbody>{tokenRows.map((row, index) => <tr className={row.token === activeToken ? "selected-row" : ""} key={`${index}-${row.token.slice(0, 24)}`}><td><button className="jwt-simple-token-select" type="button" onClick={() => setSelectedToken(row.token)}>{index + 1}</button></td><td>{row.alg}</td><td>{row.sub}</td><td>{row.iss}</td><td>{row.aud}</td><td>{row.exp}</td><td>{row.signature}</td></tr>)}</tbody></table></div>}
              </div>
            )}
          </div>
        ) : (
          <div className="jwt-simple-section">
            <label className="stack-label">Header<textarea className="compact-textarea jwt-simple-compose" value={header} onChange={(event) => { setHeader(event.currentTarget.value); setGeneratedToken(""); }} /></label>
            <label className="stack-label">Payload<textarea className="single-textarea jwt-simple-compose" value={payload} onChange={(event) => { setPayload(event.currentTarget.value); setGeneratedToken(""); }} /></label>
            <label className="stack-label">{english ? "Shared secret" : "共享密钥"}<APasswordField className="text-input full-input" value={secret} onChange={(event) => { setSecret(event.currentTarget.value); setGeneratedToken(""); }} /></label>
            <div className="button-row"><AButton variant="filled" disabled={!secret} onClick={generate}>{english ? "Generate" : "生成 Token"}</AButton></div>
            {generateError && <div className="empty-state error-state">{generateError}</div>}
            {generatedToken && <div className="jwt-simple-output"><ToolPanelHeader title={english ? "Generated token" : "生成结果"} actions={<><AButton variant="outlined" onClick={() => void copyText(generatedToken)}>{t.copy}</AButton><AButton variant="text" onClick={() => { setTokenInput(generatedToken); setMode("inspect"); setView("decoded"); }}>{english ? "Decode" : "打开解析"}</AButton></>} /><textarea className="single-textarea jwt-simple-generated" value={generatedToken} readOnly /></div>}
          </div>
        )}
      </div>
    </div>
  );
}
