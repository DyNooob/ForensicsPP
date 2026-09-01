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
import {
  AButton,
  APasswordField,
  ASegmentedButton,
  ASegmentedGroup,
  AChip,
  ACard,
  ASelect,
  ToolFactGrid,
  ToolPanelHeader
} from "../components/ui";
import { copy } from "../i18n";
import {
  MAX_JWT_INPUT_CHARS,
  MAX_JWT_TOKEN_CHARS,
  inspectJwtToken,
  extractJwtTokens,
  jwtCryptoAlgorithm,
  jwtAlgFamily,
  verifyJwtAsymmetricSignature,
  signJwtHS256,
  signJwtHmac,
  signJwtAsymmetric,
  buildNoneToken,
  stripJwtSignature,
  jwtCveReferences,
  type JwtCveRef
} from "../features/jwt/analyzer";

type Finding = { level: string; title: string; detail: string };
type JwtInspection = ReturnType<typeof inspectJwtToken>;

export type JwtToolServices = {
  inspectJwtToken: (token: string, secret: string) => JwtInspection;
  extractJwtTokens: (text: string) => string[];
  jwtCryptoAlgorithm: (alg: string) => unknown;
  jwtAlgFamily: (alg: string) => string;
  verifyJwtAsymmetricSignature: (token: string, keyText: string) => Promise<{ status: string; detail: string }>;
  signJwtHS256: (header: string, payload: string, secret: string) => string;
  signJwtHmac: (alg: string, header: string, payload: string, secret: string) => string;
  signJwtAsymmetric: (alg: string, header: string, payload: string, keyText: string) => Promise<string>;
  buildNoneToken: (header: string, payload: string) => string;
  stripJwtSignature: (token: string) => string;
  jwtCveReferences: (alg: string, headerObject: Record<string, unknown>) => JwtCveRef[];
};

type Mode = "decode" | "sign" | "security";

const ALG_OPTIONS = [
  { label: "HS256", value: "HS256" },
  { label: "HS384", value: "HS384" },
  { label: "HS512", value: "HS512" },
  { label: "RS256", value: "RS256" },
  { label: "RS384", value: "RS384" },
  { label: "RS512", value: "RS512" },
  { label: "ES256", value: "ES256" },
  { label: "ES384", value: "ES384" },
  { label: "ES512", value: "ES512" },
  { label: "PS256", value: "PS256" },
  { label: "PS384", value: "PS384" },
  { label: "PS512", value: "PS512" },
  { label: "none (unsigned)", value: "none" }
];

function findingClass(finding: Finding) {
  const title = finding.title.toLowerCase();
  if (/invalid|unsigned|missing signature|none/.test(title) || finding.level === "risk") return "risk";
  return finding.level; // "warn" | "info"
}

function severityLabel(t: (typeof copy)["zh"], level: string) {
  if (level === "risk") return t.jwt_sev_risk;
  if (level === "warn") return t.jwt_sev_warn;
  return t.jwt_sev_info;
}

export function JwtTool({ t, services, active = true }: { t: (typeof copy)["zh"]; services: JwtToolServices; active?: boolean }) {
  const {
    inspectJwtToken: inspect,
    extractJwtTokens: extract,
    jwtCryptoAlgorithm: cryptoAlg,
    jwtAlgFamily: algFamily,
    verifyJwtAsymmetricSignature: verifyAsym,
    signJwtHmac: signHmac,
    signJwtAsymmetric: signAsym,
    buildNoneToken: buildNone,
    stripJwtSignature: stripSig,
    jwtCveReferences: cveRefs
  } = services;
  const english = t.jwt_workbench === "JWT workbench";

  const [mode, setMode] = React.useState<Mode>("decode");
  const [tokenInput, setTokenInput] = React.useState("");
  const [secret, setSecret] = React.useState("");
  const [verifyKey, setVerifyKey] = React.useState("");
  const [verification, setVerification] = React.useState<{ status: string; detail: string }>({ status: "idle", detail: "" });
  const [selectedToken, setSelectedToken] = React.useState("");
  const [decodeHeader, setDecodeHeader] = React.useState("");
  const [decodePayload, setDecodePayload] = React.useState("");
  const [decodeError, setDecodeError] = React.useState("");
  const [forgeNone, setForgeNone] = React.useState("");

  const [signAlg, setSignAlg] = React.useState("HS256");
  const [signHeader, setSignHeader] = React.useState('{\n  "alg": "HS256",\n  "typ": "JWT"\n}');
  const [signPayload, setSignPayload] = React.useState("{\n  \n}");
  const [signSecret, setSignSecret] = React.useState("");
  const [signKey, setSignKey] = React.useState("");
  const [generatedToken, setGeneratedToken] = React.useState("");
  const [signError, setSignError] = React.useState("");

  const [secPubKey, setSecPubKey] = React.useState("");
  const [secNone, setSecNone] = React.useState("");
  const [secStripped, setSecStripped] = React.useState("");
  const [secConfusion, setSecConfusion] = React.useState("");
  const [secError, setSecError] = React.useState("");

  const verificationRequestRef = React.useRef(0);

  React.useEffect(() => {
    if (active) return;
    verificationRequestRef.current += 1;
    setVerification({ status: "idle", detail: "" });
  }, [active]);

  const inputTooLarge = tokenInput.length > MAX_JWT_INPUT_CHARS;
  const tokens = React.useMemo(() => (active && !inputTooLarge ? extract(tokenInput).slice(0, 200) : []), [active, extract, inputTooLarge, tokenInput]);
  const tokenRows = React.useMemo(() => tokens.map((token) => {
    const inspection = inspect(token, secret);
    const rows = new Map(inspection.rows);
    const claims = new Map(inspection.claimRows);
    return {
      token,
      alg: rows.get("alg") ?? "--",
      sub: rows.get("sub") ?? "--",
      iss: rows.get("iss") ?? "--",
      exp: claims.get("exp") ?? "--",
      signature: rows.get("signature") ?? "--",
      inspection
    };
  }), [inspect, secret, tokens]);
  const activeRow = React.useMemo(() => tokenRows.find((row) => row.token === selectedToken) ?? tokenRows[0] ?? null, [selectedToken, tokenRows]);
  const activeToken = activeRow?.token ?? "";
  const activeInspection = activeRow?.inspection ?? inspect("", secret);
  const activeRows = React.useMemo(() => new Map(activeInspection.rows), [activeInspection.rows]);
  const activeAlg = activeRows.get("alg") ?? "--";
  const asymmetric = Boolean(cryptoAlg(activeAlg));
  const isHmac = /^HS(?:256|384|512)$/i.test(activeAlg);
  const multiToken = tokenRows.length > 1;
  const hasInput = Boolean(tokenInput || secret || verifyKey || generatedToken || decodeHeader || decodePayload);

  const parseError = inputTooLarge
    ? (english ? `Input exceeds ${Math.round(MAX_JWT_INPUT_CHARS / 1024 / 1024)} MiB.` : `输入超过 ${Math.round(MAX_JWT_INPUT_CHARS / 1024 / 1024)} MiB。`)
    : tokenInput.trim() && !tokens.length
      ? (activeInspection.result || (english ? `No valid JWT found (single token limit: ${Math.round(MAX_JWT_TOKEN_CHARS / 1024 / 1024)} MiB)` : `未找到有效 JWT（单个 Token 上限 ${Math.round(MAX_JWT_TOKEN_CHARS / 1024 / 1024)} MiB）`))
      : "";

  React.useEffect(() => {
    if (selectedToken && !tokens.includes(selectedToken)) setSelectedToken("");
    setVerification({ status: "idle", detail: "" });
  }, [multiToken, selectedToken, tokens]);

  React.useEffect(() => {
    if (activeRow) {
      setDecodeHeader(activeInspection.headerText || "{}");
      setDecodePayload(activeInspection.payloadText || "{}");
      setForgeNone("");
      setDecodeError("");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeRow?.token]);

  const verifyAsymmetric = async () => {
    if (!active || !activeToken || !verifyKey.trim()) return;
    const requestId = ++verificationRequestRef.current;
    setVerification({ status: "checking", detail: t.checking });
    try {
      const result = await verifyAsym(activeToken, verifyKey.trim());
      if (active && requestId === verificationRequestRef.current) setVerification(result);
    } catch (caught) {
      if (active && requestId === verificationRequestRef.current) setVerification({ status: "error", detail: caught instanceof Error ? caught.message : String(caught) });
    }
  };

  const forgeToSign = () => {
    try {
      JSON.parse(decodeHeader);
      JSON.parse(decodePayload);
    } catch {
      setDecodeError(t.jwt_err_invalid_json);
      return;
    }
    setSignHeader(decodeHeader);
    setSignPayload(decodePayload);
    setSignAlg(algFamily(activeAlg) === "none" ? "HS256" : activeAlg);
    setMode("sign");
  };

  const doForgeNone = () => {
    try {
      const header = JSON.parse(decodeHeader);
      header.alg = "none";
      setForgeNone(buildNone(JSON.stringify(header), decodePayload));
      setDecodeError("");
    } catch {
      setDecodeError(t.jwt_err_invalid_json);
    }
  };

  const doSign = async () => {
    setSignError("");
    try {
      JSON.parse(signHeader);
      JSON.parse(signPayload);
      const family = algFamily(signAlg);
      let token = "";
      if (family === "none") token = buildNone(signHeader, signPayload);
      else if (family === "HS") {
        if (!signSecret) throw new Error(t.enter_a_shared_secret);
        token = signHmac(signAlg, signHeader, signPayload, signSecret);
      } else {
        if (!signKey.trim()) throw new Error(t.jwt_err_private_key);
        token = await signAsym(signAlg, signHeader, signPayload, signKey);
      }
      setGeneratedToken(token);
    } catch (caught) {
      setGeneratedToken("");
      setSignError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const runSecNone = () => {
    try {
      const header = JSON.parse(activeInspection.headerText || "{}");
      header.alg = "none";
      setSecNone(buildNone(JSON.stringify(header), activeInspection.payloadText || "{}"));
      setSecError("");
    } catch (caught) {
      setSecError(caught instanceof Error ? caught.message : String(caught));
    }
  };
  const runSecStrip = () => {
    try {
      setSecStripped(stripSig(activeToken));
      setSecError("");
    } catch (caught) {
      setSecError(caught instanceof Error ? caught.message : String(caught));
    }
  };
  const runSecConfusion = () => {
    try {
      if (algFamily(activeAlg) !== "RS") throw new Error(t.jwt_err_rs_only);
      if (!secPubKey.trim()) throw new Error(t.jwt_err_public_key);
      setSecConfusion(signHmac("HS256", activeInspection.headerText || "{}", activeInspection.payloadText || "{}", secPubKey));
      setSecError("");
    } catch (caught) {
      setSecConfusion("");
      setSecError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const clear = () => {
    setTokenInput("");
    setSecret("");
    setVerifyKey("");
    setVerification({ status: "idle", detail: "" });
    setSelectedToken("");
    setDecodeHeader("");
    setDecodePayload("");
    setDecodeError("");
    setForgeNone("");
    setSignAlg("HS256");
    setSignHeader('{\n  "alg": "HS256",\n  "typ": "JWT"\n}');
    setSignPayload("{\n  \n}");
    setSignSecret("");
    setSignKey("");
    setGeneratedToken("");
    setSignError("");
    setSecPubKey("");
    setSecNone("");
    setSecStripped("");
    setSecConfusion("");
    setSecError("");
  };

  const factItems = activeRow
    ? [
        { label: t.jwt_fact_alg, value: <AChip selected>{activeAlg}</AChip>, copyValue: activeAlg },
        { label: t.jwt_fact_typ, value: activeRows.get("typ") ?? "--", copyValue: activeRows.get("typ") ?? "--" },
        { label: t.jwt_fact_kid, value: activeRows.get("kid") ?? "--", copyValue: activeRows.get("kid") ?? "--" },
        { label: t.jwt_fact_exp, value: activeRows.get("exp status") ?? "--", copyValue: activeRows.get("exp status") ?? "--" },
        { label: t.jwt_fact_nbf, value: activeRows.get("nbf status") ?? "--", copyValue: activeRows.get("nbf status") ?? "--" },
        { label: t.jwt_fact_sig, value: activeRows.get("signature") ?? "--", copyValue: activeRows.get("signature") ?? "--" },
        { label: t.jwt_fact_len, value: String(activeToken.length), copyValue: String(activeToken.length) },
        { label: t.jwt_fact_seg, value: activeRows.get("segments") ?? "--", copyValue: activeRows.get("segments") ?? "--" }
      ]
    : [];

  const cveList: JwtCveRef[] = activeRow ? cveRefs(activeAlg, activeInspection.headerObject ?? {}) : [];
  const sensitiveClaims = activeInspection.payloadObject
    ? Object.entries(activeInspection.payloadObject).filter(
        ([key, value]) =>
          /(pass(word)?|secret|api[_-]?key|token|session|cookie|private[_-]?key)/i.test(key) ||
          /(bearer\s+|AKIA[0-9A-Z]{16}|-----BEGIN)/i.test(String(value))
      )
    : [];

  return (
    <div className="tool-page-shell jwt-workbench">
      <ToolPanelHeader
        title={t.jwt_workbench}
        subtitle={mode === "decode" ? t.jwt_tab_decode : mode === "sign" ? t.jwt_tab_sign : t.jwt_tab_security}
        actions={
          <>
            <ASegmentedGroup className="jwt-mode" value={mode} selects="single">
              <ASegmentedButton value="decode" onClick={() => setMode("decode")}>{t.jwt_tab_decode}</ASegmentedButton>
              <ASegmentedButton value="sign" onClick={() => setMode("sign")}>{t.jwt_tab_sign}</ASegmentedButton>
              <ASegmentedButton value="security" onClick={() => setMode("security")}>{t.jwt_tab_security}</ASegmentedButton>
            </ASegmentedGroup>
            <AButton variant="text" disabled={!hasInput && !activeToken} onClick={clear}>{t.clear}</AButton>
          </>
        }
      />

      {mode === "decode" && (
        <div className="jwt-decode-grid">
          <ACard className="jwt-input-card">
            <label className="stack-label">
              JWT
              <textarea
                className="single-textarea jwt-token-input"
                value={tokenInput}
                onChange={(event) => {
                  setTokenInput(event.currentTarget.value);
                  setSelectedToken("");
                }}
                placeholder={t.jwt_input_placeholder}
              />
            </label>
            {parseError && <div className="empty-state error-state">{parseError}</div>}
            {!activeRow && !parseError && (
              <div className="empty-state jwt-guide">
                <p>{t.jwt_no_token}</p>
                <p className="inline-note">{t.jwt_multi_hint}</p>
              </div>
            )}
            {multiToken && (
              <div className="jwt-token-list">
                {tokenRows.map((row, index) => (
                  <button
                    type="button"
                    key={`${index}-${row.token.slice(0, 18)}`}
                    className={`jwt-token-pick ${row.token === activeToken ? "active" : ""}`}
                    onClick={() => setSelectedToken(row.token)}
                  >
                    <span className="jwt-token-pick-index">{index + 1}</span>
                    <span className="jwt-token-pick-alg"><AChip>{row.alg}</AChip></span>
                    <span className="jwt-token-pick-meta">
                      <strong>{row.sub}</strong>
                      <em>{row.iss} · {row.exp}</em>
                    </span>
                  </button>
                ))}
              </div>
            )}
          </ACard>

          {activeRow && (
            <div className="jwt-decode-result">
              <ACard className="jwt-overview-card">
                <ToolPanelHeader title={t.jwt_overview} />
                <ToolFactGrid items={factItems} />
              </ACard>

              <ACard className="jwt-editor-card">
                <ToolPanelHeader
                  title={t.decoded_token}
                  actions={
                    <>
                      <AButton variant="outlined" onClick={() => void copyText(activeToken)}>{t.copy_token}</AButton>
                      <AButton variant="text" disabled={!activeInspection.headerText} onClick={() => void copyText(decodeHeader)}>{t.copy_header}</AButton>
                      <AButton variant="text" disabled={!activeInspection.payloadText} onClick={() => void copyText(decodePayload)}>{t.copy_payload}</AButton>
                    </>
                  }
                />
                <p className="inline-note">{t.jwt_edit_hint}</p>
                <label className="stack-label">Header<textarea className="compact-textarea jwt-json" value={decodeHeader} onChange={(event) => setDecodeHeader(event.currentTarget.value)} /></label>
                <label className="stack-label">Payload<textarea className="single-textarea jwt-json" value={decodePayload} onChange={(event) => setDecodePayload(event.currentTarget.value)} /></label>
                {decodeError && <div className="empty-state error-state">{decodeError}</div>}
                <div className="button-row">
                  <AButton variant="filled" onClick={forgeToSign}>{t.jwt_forge_to_sign}</AButton>
                  <AButton variant="outlined" onClick={doForgeNone}>{t.jwt_sec_none_btn_short}</AButton>
                </div>
                {forgeNone && (
                  <div className="jwt-forge-output">
                    <ToolPanelHeader title={t.jwt_sec_none_title} actions={<AButton variant="outlined" onClick={() => void copyText(forgeNone)}>{t.copy}</AButton>} />
                    <textarea className="single-textarea jwt-generated" value={forgeNone} readOnly />
                  </div>
                )}
              </ACard>

              {(isHmac || asymmetric) && (
                <ACard className="jwt-verify-card">
                  <ToolPanelHeader title={t.jwt_verify} />
                  {isHmac && (
                    <label className="stack-label">
                      {t.shared_secret}
                      <APasswordField className="text-input full-input" value={secret} onChange={(event) => setSecret(event.currentTarget.value)} placeholder={t.optional_verify_hmac_signature} />
                    </label>
                  )}
                  {asymmetric && (
                    <label className="stack-label">
                      {t.public_key_or_jwk}
                      <textarea className="compact-textarea jwt-key-input" value={verifyKey} onChange={(event) => { setVerifyKey(event.currentTarget.value); setVerification({ status: "idle", detail: "" }); }} placeholder="PEM / JWK" />
                    </label>
                  )}
                  {asymmetric && (
                    <div className="button-row">
                      <AButton variant="outlined" disabled={!verifyKey.trim() || verification.status === "checking"} onClick={() => void verifyAsymmetric()}>{t.verify_signature}</AButton>
                      {verification.status !== "idle" && (
                        <AChip selected className={verification.status === "valid" ? "ok" : verification.status === "invalid" ? "bad" : ""}>
                          {verification.detail}
                        </AChip>
                      )}
                    </div>
                  )}
                  {isHmac && !secret && (
                    <p className="inline-note">{t.jwt_hint_verify_hmac}</p>
                  )}
                </ACard>
              )}

              {activeInspection.findings.length > 0 && (
                <ACard className="jwt-findings-card">
                  <ToolPanelHeader title={t.jwt_findings} />
                  <div className="finding-list">
                    {activeInspection.findings.map((finding, index) => (
                      <div className={`finding-item ${findingClass(finding)}`} key={`${finding.title}-${index}`}>
                        <span className="finding-sev">{severityLabel(t, findingClass(finding))}</span>
                        <div className="finding-body">
                          <strong>{finding.title}</strong>
                          <span>{finding.detail}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </ACard>
              )}
            </div>
          )}
        </div>
      )}

      {mode === "sign" && (
        <div className="jwt-sign-grid">
          <ACard className="jwt-sign-card">
            <ToolPanelHeader title={t.jwt_tab_sign} />
            <label className="stack-label">
              {t.jwt_sign_alg}
              <ASelect
                className="jwt-alg-select"
                value={signAlg}
                onChange={(value: string) => setSignAlg(value)}
                options={ALG_OPTIONS}
              />
            </label>
            {algFamily(signAlg) === "none" && <p className="inline-note jwt-none-hint">{t.jwt_sign_none_hint}</p>}
            <label className="stack-label">Header<textarea className="compact-textarea jwt-json" value={signHeader} onChange={(event) => { setSignHeader(event.currentTarget.value); setGeneratedToken(""); }} /></label>
            <label className="stack-label">Payload<textarea className="single-textarea jwt-json" value={signPayload} onChange={(event) => { setSignPayload(event.currentTarget.value); setGeneratedToken(""); }} /></label>
            {algFamily(signAlg) === "HS" && (
              <label className="stack-label">
                {t.shared_secret}
                <APasswordField className="text-input full-input" value={signSecret} onChange={(event) => { setSignSecret(event.currentTarget.value); setGeneratedToken(""); }} placeholder={t.optional_verify_hmac_signature} />
              </label>
            )}
            {["RS", "ES", "PS"].includes(algFamily(signAlg)) && (
              <label className="stack-label">
                {t.jwt_sign_key}
                <textarea className="compact-textarea jwt-key-input" value={signKey} onChange={(event) => { setSignKey(event.currentTarget.value); setGeneratedToken(""); }} placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----" />
              </label>
            )}
            <div className="button-row">
              <AButton variant="filled" disabled={algFamily(signAlg) === "HS" ? !signSecret : ["RS", "ES", "PS"].includes(algFamily(signAlg)) ? !signKey.trim() : false} onClick={() => void doSign()}>{t.generate}</AButton>
            </div>
            {signError && <div className="empty-state error-state">{signError}</div>}
            {generatedToken && (
              <div className="jwt-sign-output">
                <ToolPanelHeader title={t.generated_token} actions={<><AButton variant="outlined" onClick={() => void copyText(generatedToken)}>{t.copy}</AButton><AButton variant="text" onClick={() => { setTokenInput(generatedToken); setMode("decode"); }}>{t.jwt_open_decode}</AButton></>} />
                <textarea className="single-textarea jwt-generated" value={generatedToken} readOnly />
              </div>
            )}
          </ACard>
        </div>
      )}

      {mode === "security" && (
        <div className="jwt-security-grid">
          {!activeRow && (
            <ACard>
              <div className="empty-state jwt-guide">
                <p>{t.jwt_sec_needs_token}</p>
              </div>
            </ACard>
          )}
          {activeRow && (
            <>
              <ACard className="jwt-attack-card">
                <ToolPanelHeader title={t.jwt_sec_none_title} />
                <p className="inline-note">{t.jwt_sec_none_desc}</p>
                <div className="button-row">
                  <AButton variant="outlined" onClick={runSecNone}>{t.jwt_sec_none_btn}</AButton>
                  {secNone && <AButton variant="text" onClick={() => void copyText(secNone)}>{t.copy}</AButton>}
                </div>
                {secNone && <textarea className="single-textarea jwt-generated" value={secNone} readOnly />}
              </ACard>

              <ACard className="jwt-attack-card">
                <ToolPanelHeader title={t.jwt_sec_strip_title} />
                <p className="inline-note">{t.jwt_sec_strip_desc}</p>
                <div className="button-row">
                  <AButton variant="outlined" onClick={runSecStrip}>{t.jwt_sec_strip_btn}</AButton>
                  {secStripped && <AButton variant="text" onClick={() => void copyText(secStripped)}>{t.copy}</AButton>}
                </div>
                {secStripped && <textarea className="single-textarea jwt-generated" value={secStripped} readOnly />}
              </ACard>

              <ACard className="jwt-attack-card">
                <ToolPanelHeader title={t.jwt_sec_confusion_title} />
                <p className="inline-note">{t.jwt_sec_confusion_desc}</p>
                <label className="stack-label">
                  {t.jwt_sec_confusion_pubkey}
                  <textarea className="compact-textarea jwt-key-input" value={secPubKey} onChange={(event) => setSecPubKey(event.currentTarget.value)} placeholder="-----BEGIN PUBLIC KEY-----" />
                </label>
                <div className="button-row">
                  <AButton variant="outlined" onClick={runSecConfusion}>{t.jwt_sec_confusion_btn}</AButton>
                  {secConfusion && <AButton variant="text" onClick={() => void copyText(secConfusion)}>{t.copy}</AButton>}
                </div>
                {secConfusion && <textarea className="single-textarea jwt-generated" value={secConfusion} readOnly />}
              </ACard>

              {secError && <div className="empty-state error-state">{secError}</div>}

              <ACard className="jwt-attack-card">
                <ToolPanelHeader title={t.jwt_sec_cve} />
                {cveList.length ? (
                  <div className="cve-list">
                    {cveList.map((ref) => (
                      <div className="cve-item" key={ref.id}>
                        <strong>{ref.id}</strong>
                        <span>{ref.summary}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="inline-note">{t.jwt_sec_no_cve}</p>
                )}
              </ACard>

              <ACard className="jwt-attack-card">
                <ToolPanelHeader title={t.jwt_sec_sensitive} />
                {sensitiveClaims.length ? (
                  <div className="finding-list">
                    {sensitiveClaims.map(([key, value]) => (
                      <div className="finding-item warn" key={key}>
                        <span className="finding-sev">{t.jwt_sev_warn}</span>
                        <div className="finding-body">
                          <strong>{key}</strong>
                          <span>{String(value).slice(0, 120)}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="inline-note">{t.jwt_sec_no_sensitive}</p>
                )}
              </ACard>
            </>
          )}
        </div>
      )}
    </div>
  );
}
