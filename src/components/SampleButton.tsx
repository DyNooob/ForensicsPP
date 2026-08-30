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

import React from "react";
import { AButton } from "./ui";
import { toolSamples } from "../tools/samples";

export function SampleButton({ toolId, english, onLoad }: {
  toolId: string;
  english: boolean;
  onLoad: (text: string) => void;
}) {
  const sample = toolSamples[toolId];
  if (!sample) return null;
  const text = english ? sample.en : sample.zh;
  return (
    <AButton variant="text" onClick={() => onLoad(text)}>
      {english ? "Load sample" : "载入示例"}
    </AButton>
  );
}
