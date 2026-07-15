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
import { AButton, AInputNumber, ASelect, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import { useStoredState } from "../utils/storage";

export type CryptoToolServices = {
  caesar: (text: string, shift: number) => string;
  atbash: (text: string) => string;
  rot47: (text: string) => string;
  vigenere: (text: string, key: string, decode?: boolean) => string;
  affine: (text: string, a: number, b: number, decode?: boolean) => string;
  morseEncode: (text: string) => string;
  morseDecode: (text: string) => string;
  baconEncode: (text: string) => string;
  baconDecode: (text: string) => string;
  railFence: (text: string, rails: number) => string;
  railFenceDecode: (text: string, rails: number) => string;
};

type Operation = {
  value: string;
  label: string;
  parameter?: "shift" | "key" | "rails" | "affine";
};

const operations: Operation[] = [
  { value: "caesar", label: "Caesar", parameter: "shift" },
  { value: "caesar-all", label: "Caesar Bruteforce" },
  { value: "atbash", label: "Atbash" },
  { value: "rot47", label: "ROT47" },
  { value: "vigenere-e", label: "Vigenere Encode", parameter: "key" },
  { value: "vigenere-d", label: "Vigenere Decode", parameter: "key" },
  { value: "affine-e", label: "Affine Encode", parameter: "affine" },
  { value: "affine-d", label: "Affine Decode", parameter: "affine" },
  { value: "morse-e", label: "Morse Encode" },
  { value: "morse-d", label: "Morse Decode" },
  { value: "bacon-e", label: "Bacon Encode" },
  { value: "bacon-d", label: "Bacon Decode" },
  { value: "rail-e", label: "Rail Fence Encode", parameter: "rails" },
  { value: "rail-d", label: "Rail Fence Decode", parameter: "rails" }
];

const MAX_CRYPTO_INPUT_CHARS = 2 * 1024 * 1024;
const MAX_BRUTEFORCE_INPUT_CHARS = 512 * 1024;

export function CryptoTool({ t, services, active = true }: { t: (typeof copy)["zh"]; services: CryptoToolServices; active?: boolean }) {
  const english = t.waiting === "Waiting";
  const [input, setInput] = useStoredState("crypto.input.v2", "");
  const [output, setOutput] = useStoredState("crypto.output.v2", "");
  const [operation, setOperation] = useStoredState("crypto.operation", "caesar");
  const [shift, setShift] = useStoredState("crypto.shift", 3);
  const [key, setKey] = useStoredState("crypto.key.v2", "KEY");
  const [rails, setRails] = useStoredState("crypto.rails", 3);
  const [affineA, setAffineA] = useStoredState("crypto.affineA", 5);
  const [affineB, setAffineB] = useStoredState("crypto.affineB", 8);
  const selectedOperation = operations.find((item) => item.value === operation) ?? operations[0];
  const hasInput = input.length > 0;
  const hasResult = output.length > 0;
  const inputLimit = operation === "caesar-all" ? MAX_BRUTEFORCE_INPUT_CHARS : MAX_CRYPTO_INPUT_CHARS;
  const inputTooLarge = input.length > inputLimit;

  const invalidateResult = () => setOutput("");

  const transform = React.useCallback((value: string) => {
    if (operation === "caesar") return services.caesar(value, shift);
    if (operation === "caesar-all") return Array.from({ length: 26 }, (_, index) => `${index}\t${services.caesar(value, index)}`).join("\n");
    if (operation === "atbash") return services.atbash(value);
    if (operation === "rot47") return services.rot47(value);
    if (operation === "vigenere-e") return services.vigenere(value, key, false);
    if (operation === "vigenere-d") return services.vigenere(value, key, true);
    if (operation === "affine-e") return services.affine(value, affineA, affineB, false);
    if (operation === "affine-d") return services.affine(value, affineA, affineB, true);
    if (operation === "morse-e") return services.morseEncode(value);
    if (operation === "morse-d") return services.morseDecode(value);
    if (operation === "bacon-e") return services.baconEncode(value);
    if (operation === "bacon-d") return services.baconDecode(value);
    if (operation === "rail-e") return services.railFence(value, rails);
    return services.railFenceDecode(value, rails);
  }, [affineA, affineB, key, operation, rails, services, shift]);

  const run = () => {
    if (!active || inputTooLarge) return;
    setOutput(transform(input));
  };
  const clear = () => {
    setInput("");
    setOutput("");
  };
  const useResultAsInput = () => {
    if (!active || !output) return;
    setInput(output);
    setOutput("");
  };
  const caesarRows = active && operation === "caesar-all"
    ? Array.from({ length: 26 }, (_, index) => ({ shift: index, value: services.caesar(input, index) }))
    : [];

  return (
    <div className={`tool-grid crypto-simple-workbench ${hasInput || hasResult ? "has-crypto" : "empty-crypto"}`}>
      <section className="tool-panel wide-panel crypto-simple-input-panel">
        <ToolPanelHeader
          title={english ? "Classical cipher" : "古典密码转换"}
          actions={<AButton variant="text" disabled={!hasInput && !hasResult} onClick={clear}>{t.clear}</AButton>}
        />

        <div className="crypto-simple-controls">
          <label>
            {t.operation}
            <ASelect aria-label={t.operation} value={operation} onChange={(value) => { setOperation(String(value)); invalidateResult(); }} options={operations.map((item) => ({ value: item.value, label: item.label }))} />
          </label>

          {selectedOperation.parameter === "shift" && (
            <label>{t.shift}<AInputNumber min={-25} max={25} value={shift} onChange={(value) => { setShift(value ?? 0); invalidateResult(); }} /></label>
          )}
          {selectedOperation.parameter === "key" && (
            <label>{t.key}<input className="text-input" value={key} onChange={(event) => { setKey(event.target.value); invalidateResult(); }} /></label>
          )}
          {selectedOperation.parameter === "rails" && (
            <label>{t.rails}<AInputNumber min={2} max={12} value={rails} onChange={(value) => { setRails(value ?? 2); invalidateResult(); }} /></label>
          )}
          {selectedOperation.parameter === "affine" && (
            <div className="crypto-simple-affine">
              <label>{t.affineA}<AInputNumber value={affineA} onChange={(value) => { setAffineA(value ?? 1); invalidateResult(); }} /></label>
              <label>{t.affineB}<AInputNumber value={affineB} onChange={(value) => { setAffineB(value ?? 0); invalidateResult(); }} /></label>
            </div>
          )}
        </div>

        <label className="crypto-simple-text-field">
          <span>{t.inputText}</span>
          <textarea value={input} onChange={(event) => { setInput(event.target.value); invalidateResult(); }} placeholder={t.textPlaceholder} />
        </label>
        {inputTooLarge && <div className="empty-state error-state" role="alert">{english ? `Input is limited to ${Math.round(inputLimit / 1024)} KiB for this operation.` : `此操作最多处理 ${Math.round(inputLimit / 1024)} KiB 输入。`}</div>}
        <div className="crypto-simple-primary-action">
          <AButton variant="filled" disabled={!hasInput || inputTooLarge} onClick={run}>{t.run}</AButton>
        </div>
      </section>

      {hasResult && (
        <section className="tool-panel wide-panel crypto-simple-result-panel">
          <ToolPanelHeader
            title={english ? "Result" : "转换结果"}
            subtitle={selectedOperation.label}
            actions={<>
              <AButton variant="outlined" onClick={() => void copyText(output)}>{t.copyOutput}</AButton>
              {operation !== "caesar-all" && <AButton variant="text" onClick={useResultAsInput}>{english ? "Use as input" : "作为新输入"}</AButton>}
            </>}
          />
          {operation === "caesar-all" ? (
            <div className="table-scroll crypto-simple-table-scroll">
              <table className="data-table">
                <thead><tr><th>{t.shift}</th><th>{t.outputText}</th><th /></tr></thead>
                <tbody>
                  {caesarRows.map((row) => (
                    <tr key={row.shift}>
                      <td>{row.shift}</td>
                      <td className="mono-cell">{row.value}</td>
                      <td><AButton variant="text" onClick={() => { setInput(row.value); setOutput(""); setOperation("caesar"); setShift(row.shift); }}>{english ? "Use" : "使用"}</AButton></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <textarea aria-label={english ? "Cipher result" : "密码结果"} className="single-textarea crypto-simple-output" value={output} readOnly />
          )}
        </section>
      )}
    </div>
  );
}
