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

import { BinaryReader } from "@ts-evtx/core/dist/src/binary/BinaryReader.js";
import { FileHeader } from "@ts-evtx/core/dist/src/evtx/FileHeader.js";
import { eventFromXml, type EvtxEvent, type EvtxFileAnalysis } from "./analyzer";

export function parseEvtxBytes(bytes: Uint8Array, source: string, maxRecords = 250_000): EvtxFileAnalysis {
  if (bytes.byteLength < 4096) throw new Error("EVTX file is smaller than its required 4 KiB header.");
  const header = new FileHeader(new BinaryReader(bytes), 0);
  if (!header.verify()) throw new Error("Invalid EVTX header or checksum.");
  const events: EvtxEvent[] = [];
  let skippedRecords = 0;
  let truncated = false;
  outer: for (const chunk of header.chunks()) {
    try {
      for (const record of chunk.records()) {
        if (events.length >= maxRecords) {
          truncated = true;
          break outer;
        }
        try {
          const timestamp = record.timestampAsDate();
          const xml = record.renderXml();
          events.push(eventFromXml(
            xml,
            source,
            record.recordNum().toString(),
            Number.isNaN(timestamp.getTime()) ? "" : timestamp.toISOString()
          ));
        } catch {
          skippedRecords += 1;
        }
      }
    } catch {
      skippedRecords += 1;
    }
  }
  return {
    source,
    size: bytes.byteLength,
    chunkCount: header.chunkCount(),
    nextRecordNumber: header.nextRecordNumber().toString(),
    dirty: header.isDirty(),
    full: header.isFull(),
    version: `${header.majorVersion()}.${header.minorVersion()}`,
    parsedRecords: events.length,
    skippedRecords,
    truncated,
    events
  };
}
