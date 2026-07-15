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
import { AButton, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import type { Translation } from "../i18n";
import type { BaseConvertRow } from "../models";
import { downloadTextFile } from "../utils/files";
import { useStoredState } from "../utils/storage";

function parseBigIntBase(input: string, base: number) {
  const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
  return Array.from(input.toLowerCase()).reduce((total, character) => {
    const digit = alphabet.indexOf(character);
    if (digit < 0 || digit >= base) throw new Error(`Invalid digit: ${character}`);
    return total * BigInt(base) + BigInt(digit);
  }, 0n);
}

function detectInput(input: string, fallbackBase: number) {
  const value = input.trim();
  const negative = value.startsWith("-");
  const unsigned = negative ? value.slice(1) : value;
  if (/^0x[0-9a-f]+$/i.test(unsigned)) return { base: 16, clean: unsigned.slice(2), label: "hex prefix", negative };
  if (/^0b[01]+$/i.test(unsigned)) return { base: 2, clean: unsigned.slice(2), label: "binary prefix", negative };
  if (/^0o[0-7]+$/i.test(unsigned)) return { base: 8, clean: unsigned.slice(2), label: "octal prefix", negative };
  if (/^(?:[0-9a-f]{2}[\s:-])+[0-9a-f]{2}$/i.test(unsigned)) return { base: 16, clean: unsigned.replace(/[\s:-]/g, ""), label: "hex bytes", negative };
  if (/^[01]{8}(?:\s+[01]{8})+$/i.test(unsigned)) return { base: 2, clean: unsigned.replace(/\s+/g, ""), label: "binary bytes", negative };
  return { base: fallbackBase, clean: unsigned.replace(/\s+/g, ""), label: `base ${fallbackBase}`, negative };
}

function signedFromUnsigned(value: bigint, bits: number) {
  const modulo = 1n << BigInt(bits);
  const sign = 1n << BigInt(bits - 1);
  const masked = value & (modulo - 1n);
  return (masked >= sign ? masked - modulo : masked).toString();
}

function analyzeValue(input: string, fallbackBase: number): BaseConvertRow {
  try {
    const detected = detectInput(input, fallbackBase);
    if (!detected.clean) throw new Error("Empty value");
    const unsigned = parseBigIntBase(detected.clean, detected.base);
    const value = detected.negative ? -unsigned : unsigned;
    const hex = unsigned.toString(16).toUpperCase() || "0";
    const paddedHex = hex.length % 2 ? `0${hex}` : hex;
    const bytes = paddedHex.match(/.{2}/g)?.map((part) => parseInt(part, 16)) ?? [];
    return {
      input,
      detectedBase: detected.label,
      decimal: value.toString(10),
      hex: `${detected.negative ? "-" : ""}0x${hex}`,
      binary: `${detected.negative ? "-" : ""}0b${unsigned.toString(2)}`,
      octal: `${detected.negative ? "-" : ""}0o${unsigned.toString(8)}`,
      bytesBE: bytes.map((byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join(" "),
      bytesLE: [...bytes].reverse().map((byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join(" "),
      ascii: bytes.map((byte) => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".").join(""),
      signed8: signedFromUnsigned(value, 8),
      signed16: signedFromUnsigned(value, 16),
      signed32: signedFromUnsigned(value, 32),
      interpretation: "--",
      evidenceType: "--",
      risk: []
    };
  } catch (error) {
    return {
      input,
      detectedBase: "--",
      decimal: "--",
      hex: "--",
      binary: "--",
      octal: "--",
      bytesBE: "--",
      bytesLE: "--",
      ascii: "--",
      signed8: "--",
      signed16: "--",
      signed32: "--",
      interpretation: "--",
      evidenceType: "--",
      risk: [],
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

function rowsToCsv(items: BaseConvertRow[]) {
  const escape = (value: string) => /[",\n\r]/.test(value) ? `"${value.replace(/"/g, "\"\"")}"` : value;
  return [
    ["input", "detected_base", "decimal", "hex", "binary", "octal", "bytes_be", "bytes_le", "ascii", "signed8", "signed16", "signed32", "error"].join(","),
    ...items.map((item) => [item.input, item.detectedBase, item.decimal, item.hex, item.binary, item.octal, item.bytesBE, item.bytesLE, item.ascii, item.signed8, item.signed16, item.signed32, item.error ?? ""].map(escape).join(","))
  ].join("\n");
}

const MAX_BASE_CONVERT_INPUT_CHARS = 1_000_000;
const MAX_BASE_CONVERT_ROWS = 10_000;

export function BaseConvertTool({ t, active = true }: { t: Translation; active?: boolean }) {
  const [value, setValue] = useStoredState("baseconvert.value.v3", "");
  const [base, setBase] = useStoredState("baseconvert.base", 16);
  const english = t.waiting === "Waiting";
  const hasInput = Boolean(value.trim());
  const inputTooLarge = value.length > MAX_BASE_CONVERT_INPUT_CHARS;
  const rowCount = React.useMemo(() => {
    if (!active) return 0;
    if (inputTooLarge) return MAX_BASE_CONVERT_ROWS + 1;
    return value.split(/\r?\n|,\s*/).filter((item) => item.trim()).length;
  }, [active, inputTooLarge, value]);
  const rowsTooMany = rowCount > MAX_BASE_CONVERT_ROWS;
  const conversionError = inputTooLarge
    ? (english ? "Input is limited to 1,000,000 characters." : "输入内容不能超过 1,000,000 个字符。")
    : rowsTooMany
      ? (english ? "Batch conversion is limited to 10,000 values." : "批量转换最多支持 10,000 个数值。")
      : "";
  const items = React.useMemo(() => {
    if (!active || conversionError) return [];
    return value.split(/\r?\n|,\s*/).map((item) => item.trim()).filter(Boolean).map((item) => analyzeValue(item, base));
  }, [active, base, conversionError, value]);
  const single = items.length === 1 ? items[0] : null;
  const resultRows = React.useMemo<Array<[string, string]>>(() => single ? [
    [english ? "Detected input" : "识别输入", single.detectedBase],
    [t.decimal, single.decimal],
    [t.hexadecimal, single.hex],
    [t.binaryBase, single.binary],
    [t.octal, single.octal],
    [t.bytesBigEndian, single.bytesBE],
    [t.bytesLittleEndian, single.bytesLE],
    [t.asciiBytes, single.ascii],
    [t.signedIntegers, `i8=${single.signed8}; i16=${single.signed16}; i32=${single.signed32}`]
  ] : [], [english, single, t]);
  const clear = () => setValue("");

  return (
    <div className={`tool-grid baseconvert-workbench baseconvert-simple-workbench ${hasInput ? "has-baseconvert" : "empty-baseconvert"}`}>
      <div className="tool-panel wide-panel baseconvert-simple-input-panel">
        <ToolPanelHeader title={english ? "Base conversion" : "进制转换"} actions={<AButton variant="text" disabled={!hasInput} onClick={clear}>{t.clear}</AButton>} />
        <label className="stack-label">{t.inputText}<textarea className="single-textarea baseconvert-simple-input" value={value} onChange={(event) => setValue(event.currentTarget.value)} placeholder={english ? "Enter one value, or one value per line" : "输入一个数值，或每行输入一个数值"} /></label>
        {conversionError && <div className="empty-state error-state" role="alert">{conversionError}</div>}
        <div className="baseconvert-simple-base-row">
          <span>{english ? "Default input base" : "默认输入进制"}</span>
          <ASegmentedGroup className="baseconvert-base-switch" value={String(base)} selects="single">
            {[[2, t.binaryBase], [8, t.octal], [10, t.decimal], [16, t.hexadecimal]].map(([itemBase, label]) => <ASegmentedButton value={String(itemBase)} key={itemBase} onClick={() => setBase(Number(itemBase))}>{label}</ASegmentedButton>)}
          </ASegmentedGroup>
        </div>
      </div>

      {single && <div className="tool-panel wide-panel baseconvert-simple-result-panel">
        <ToolPanelHeader
          title={english ? "Conversion result" : "转换结果"}
          subtitle={single.error ? (english ? "Invalid value" : "数值无效") : single.detectedBase}
          actions={<>
            <AButton variant="outlined" disabled={single.decimal === "--"} onClick={() => void copyText(single.decimal)}>{t.decimal}</AButton>
            <AButton variant="outlined" disabled={single.hex === "--"} onClick={() => void copyText(single.hex)}>{t.hexadecimal}</AButton>
            <AButton variant="text" disabled={single.ascii === "--"} onClick={() => void copyText(single.ascii)}>{english ? "Copy ASCII" : "复制 ASCII"}</AButton>
          </>}
        />
        {single.error ? <div className="empty-state error-state">{single.error}</div> : <InfoTable rows={resultRows} />}
      </div>}

      {items.length > 1 && <div className="tool-panel wide-panel baseconvert-simple-batch-panel">
        <ToolPanelHeader
          title={english ? "Batch results" : "批量结果"}
          subtitle={`${items.filter((item) => !item.error).length}/${items.length} ${english ? "converted" : "已转换"}`}
          actions={<AButton variant="outlined" onClick={() => downloadTextFile(`base-convert-${Date.now()}.csv`, rowsToCsv(items), "text/csv;charset=utf-8")}>{t.exportBaseCsv}</AButton>}
        />
        <div className="table-scroll baseconvert-simple-scroll"><table className="data-table baseconvert-simple-table"><thead><tr><th>{english ? "Input" : "输入"}</th><th>{t.detectedBase}</th><th>{t.decimal}</th><th>{t.hexadecimal}</th><th>{t.binaryBase}</th><th>{t.octal}</th><th>{t.asciiBytes}</th><th>{english ? "Error" : "错误"}</th></tr></thead><tbody>{items.map((item, index) => <tr key={`${index}-${item.input}`}><td>{item.input}</td><td>{item.detectedBase}</td><td>{item.decimal}</td><td>{item.hex}</td><td>{item.binary}</td><td>{item.octal}</td><td>{item.ascii}</td><td>{item.error ?? "--"}</td></tr>)}</tbody></table></div>
      </div>}
    </div>
  );
}
