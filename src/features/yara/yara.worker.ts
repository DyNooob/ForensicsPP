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

import init, { Compiler, type Rules, type Scanner } from "@virustotal/yara-x";
import { normalizeYaraXScan, type YaraXScanOutput } from "./analyzer";

type YaraWorkerRequest = {
  ruleText: string;
  data: ArrayBuffer;
  name: string;
  timeoutMs?: number;
};

const wasmUrl = new URL("../../../node_modules/@virustotal/yara-x/pkg/yara_x_js_bg.wasm", import.meta.url);
const ready = init({ module_or_path: wasmUrl });

self.onmessage = async (event: MessageEvent<YaraWorkerRequest>) => {
  const { ruleText, data, name, timeoutMs = 10_000 } = event.data;
  let compiler: Compiler | null = null;
  let rules: Rules | null = null;
  let scanner: Scanner | null = null;
  try {
    await ready;
    compiler = new Compiler();
    compiler.addSource(ruleText);
    const compilerWarnings = compiler.warnings;
    rules = compiler.build();
    scanner = rules.scanner();
    scanner.setMaxMatchesPerPattern(200);
    scanner.setTimeoutMs(timeoutMs);
    const bytes = new Uint8Array(data);
    const output = scanner.scan(bytes) as YaraXScanOutput;
    self.postMessage({ type: "result", result: normalizeYaraXScan(ruleText, bytes, name, output, compilerWarnings) });
  } catch (error) {
    const details = compiler?.errors ?? [];
    const message = error instanceof Error ? error.message : String(error);
    self.postMessage({ type: "error", error: [...details, message].filter(Boolean).join("\n") });
  } finally {
    scanner?.free();
    rules?.free();
    compiler?.free();
  }
};
