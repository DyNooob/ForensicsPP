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
import { MAX_JWT_INPUT_CHARS, MAX_JWT_TOKEN_CHARS } from "../features/jwt/analyzer";

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

  const inputTooLarge = tokenInput.length > MAX_JWT_INPUT_CHARS;
  const tokens = React.useMemo(() => active && !inputTooLarge ? extractJwtTokens(tokenInput).slice(0, 200) : [], [active, extractJwtTokens, inputTooLarge, tokenInput]);
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
  const parseError = inputTooLarge
    ? (english ? `Input exceeds ${Math.round(MAX_JWT_INPUT_CHARS / 1024 / 1024)} MiB.` : `输入超过 ${Math.round(MAX_JWT_INPUT_CHARS / 1024 / 1024)} MiB。`)
    : tokenInput.trim() && !tokens.length
      ? (activeInspection.result || (english ? `No valid JWT found (single token limit: ${Math.round(MAX_JWT_TOKEN_CHARS / 1024 / 1024)} MiB)` : `未找到有效 JWT（单个 Token 上限 ${Math.round(MAX_JWT_TOKEN_CHARS / 1024 / 1024)} MiB）`))
      : "";
  const summaryRows = React.useMemo<Array<[string, string]>>(() => activeRow ? [
    ["alg", activeAlg],
    ["typ", activeRows.get("typ") ?? "--"],
    ["kid", activeRows.get("kid") ?? "--"],
    [t.signature, asymmetric && verification.status !== "idle" ? verification.detail : activeRow.signature],
    [t.token_length, String(activeToken.length)]
  ] : [], [activeAlg, activeRow, activeRows, activeToken.length, asymmetric, english, verification]);

  React.useEffect(() => {
    if (selectedToken && !tokens.includes(selectedToken)) setSelectedToken("");
    if (!multiToken && view === "tokens") setView("decoded");
    setVerification({ status: "idle", detail: "" });
  }, [multiToken, selectedToken, tokens, view]);

  const verifyAsymmetric = async () => {
    if (!active || !activeToken || !verifyKey.trim()) return;
    const requestId = ++verificationRequestRef.current;
    setVerification({ status: "checking", detail: t.checking });
    try {
      const result = await verifyJwtAsymmetricSignature(activeToken, verifyKey.trim());
      if (active && requestId === verificationRequestRef.current) setVerification(result);
    } catch (caught) {
      if (active && requestId === verificationRequestRef.current) setVerification({ status: "error", detail: caught instanceof Error ? caught.message : String(caught) });
    }
  };

  const generate = () => {
    setGenerateError("");
    try {
      const parsedHeader = JSON.parse(header) as Record<string, unknown>;
      JSON.parse(payload);
      if (parsedHeader.alg !== "HS256") throw new Error(t.generator_supports_hs256_only);
      if (!secret) throw new Error(t.enter_a_shared_secret);
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
          title={t.jwt_workbench}
          actions={<>
            <ASegmentedGroup className="jwt-simple-mode" value={mode} selects="single">
              <ASegmentedButton value="inspect" onClick={() => setMode("inspect")}>{t.decode_verify}</ASegmentedButton>
              <ASegmentedButton value="generate" onClick={() => setMode("generate")}>{t.generate_hs256}</ASegmentedButton>
            </ASegmentedGroup>
            <AButton variant="text" disabled={!hasInput} onClick={clear}>{t.clear}</AButton>
          </>}
        />

        {mode === "inspect" ? (
          <div className="jwt-simple-section">
            <label className="stack-label">JWT<textarea className="single-textarea jwt-simple-token-input" value={tokenInput} onChange={(event) => { setTokenInput(event.currentTarget.value); setSelectedToken(""); }} placeholder={t.paste_one_jwt_or_text_containing_multiple_jwts} /></label>
            {activeRow && isHmac && <label className="stack-label">{t.shared_secret}<APasswordField className="text-input full-input" value={secret} onChange={(event) => setSecret(event.currentTarget.value)} placeholder={t.optional_verify_hmac_signature} /></label>}
            {activeRow && asymmetric && (
              <div className="jwt-simple-key-section">
                <label className="stack-label">{t.public_key_or_jwk}<textarea className="compact-textarea jwt-simple-key-input" value={verifyKey} onChange={(event) => { setVerifyKey(event.currentTarget.value); setVerification({ status: "idle", detail: "" }); }} placeholder="PEM / JWK" /></label>
                <div className="button-row"><AButton variant="outlined" disabled={!verifyKey.trim() || verification.status === "checking"} onClick={() => void verifyAsymmetric()}>{t.verify_signature}</AButton></div>
              </div>
            )}
            {parseError && <div className="empty-state error-state">{parseError}</div>}

            {activeRow && (
              <div className="jwt-simple-output">
                <ToolPanelHeader
                  title={multiToken ? `${t.jwts} (${tokenRows.length})` : (t.decoded_token)}
                  subtitle={`${activeAlg} · ${activeRow.signature}`}
                  actions={<ASegmentedGroup className="jwt-simple-view" value={view} selects="single">
                    <ASegmentedButton value="decoded" onClick={() => setView("decoded")}>{t.decodedUrl}</ASegmentedButton>
                    <ASegmentedButton value="claims" onClick={() => setView("claims")}>{t.claims}</ASegmentedButton>
                    {multiToken && <ASegmentedButton value="tokens" onClick={() => setView("tokens")}>{t.tokens}</ASegmentedButton>}
                  </ASegmentedGroup>}
                />

                {view === "decoded" && <>
                  <InfoTable rows={summaryRows} />
                  <label className="stack-label">Header<textarea className="compact-textarea jwt-simple-json" value={activeInspection.headerText || "--"} readOnly /></label>
                  <label className="stack-label">Payload<textarea className="single-textarea jwt-simple-json" value={activeInspection.payloadText || "--"} readOnly /></label>
                  <div className="button-row"><AButton variant="outlined" onClick={() => void copyText(activeToken)}>{t.copy_token}</AButton><AButton variant="text" disabled={!activeInspection.headerText} onClick={() => void copyText(activeInspection.headerText)}>{t.copy_header}</AButton><AButton variant="text" disabled={!activeInspection.payloadText} onClick={() => void copyText(activeInspection.payloadText)}>{t.copy_payload}</AButton></div>
                </>}

                {view === "claims" && <InfoTable rows={activeInspection.claimRows.length ? activeInspection.claimRows : [[t.claims, "--"]]} />}

                {view === "tokens" && <div className="table-scroll jwt-simple-token-scroll"><table className="data-table jwt-simple-token-table"><thead><tr><th>#</th><th>alg</th><th>sub</th><th>iss</th><th>aud</th><th>exp</th><th>{t.signature}</th></tr></thead><tbody>{tokenRows.map((row, index) => <tr className={row.token === activeToken ? "selected-row" : ""} key={`${index}-${row.token.slice(0, 24)}`}><td><button className="jwt-simple-token-select" type="button" onClick={() => setSelectedToken(row.token)}>{index + 1}</button></td><td>{row.alg}</td><td>{row.sub}</td><td>{row.iss}</td><td>{row.aud}</td><td>{row.exp}</td><td>{row.signature}</td></tr>)}</tbody></table></div>}
              </div>
            )}
          </div>
        ) : (
          <div className="jwt-simple-section">
            <label className="stack-label">Header<textarea className="compact-textarea jwt-simple-compose" value={header} onChange={(event) => { setHeader(event.currentTarget.value); setGeneratedToken(""); }} /></label>
            <label className="stack-label">Payload<textarea className="single-textarea jwt-simple-compose" value={payload} onChange={(event) => { setPayload(event.currentTarget.value); setGeneratedToken(""); }} /></label>
            <label className="stack-label">{t.shared_secret}<APasswordField className="text-input full-input" value={secret} onChange={(event) => { setSecret(event.currentTarget.value); setGeneratedToken(""); }} /></label>
            <div className="button-row"><AButton variant="filled" disabled={!secret} onClick={generate}>{t.generate}</AButton></div>
            {generateError && <div className="empty-state error-state">{generateError}</div>}
            {generatedToken && <div className="jwt-simple-output"><ToolPanelHeader title={t.generated_token} actions={<><AButton variant="outlined" onClick={() => void copyText(generatedToken)}>{t.copy}</AButton><AButton variant="text" onClick={() => { setTokenInput(generatedToken); setMode("inspect"); setView("decoded"); }}>{t.decodeAction}</AButton></>} /><textarea className="single-textarea jwt-simple-generated" value={generatedToken} readOnly /></div>}
          </div>
        )}
      </div>
    </div>
  );
}
