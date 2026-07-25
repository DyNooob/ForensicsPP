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

import type { PcapInfo } from "../../models";

export function serializablePcapInfo(pcap: PcapInfo) {
  return {
    ...pcap,
    packets: pcap.packets.map(({ payloadBytes, ...packet }) => ({
      ...packet,
      payloadBytes: {
        size: payloadBytes.length
      }
    })),
    extractedFiles: pcap.extractedFiles.map(({ bytes, ...item }) => ({
      ...item,
      bytes: {
        size: bytes.length,
        sha256: item.sha256
      }
    }))
  };
}

// Packet payload previews are already represented by payloadPreview/hexPreview.
// Workspace snapshots keep a bounded amount of raw data so a large capture does
// not turn IndexedDB into a second copy of the evidence file.
const MAX_PERSISTED_STREAM_BYTES = 8 * 1024 * 1024;
const MAX_PERSISTED_EXTRACTED_BYTES = 8 * 1024 * 1024;

export function persistablePcapInfo(pcap: PcapInfo): PcapInfo {
  let retainedStreamBytes = 0;
  let streamBytesLimited = false;
  const tcpStreams = pcap.tcpStreams.map((stream) => ({
    ...stream,
    segments: stream.segments.map((segment) => {
      const remaining = MAX_PERSISTED_STREAM_BYTES - retainedStreamBytes;
      if (segment.bytes.byteLength <= remaining) {
        retainedStreamBytes += segment.bytes.byteLength;
        return { ...segment, bytes: segment.bytes.slice() };
      }
      streamBytesLimited = true;
      return { ...segment, bytes: new Uint8Array() };
    })
  }));
  let retainedExtractedBytes = 0;
  let extractedBytesLimited = false;
  const extractedFiles = pcap.extractedFiles.map((file) => {
    const remaining = MAX_PERSISTED_EXTRACTED_BYTES - retainedExtractedBytes;
    if (file.bytes.byteLength <= remaining) {
      retainedExtractedBytes += file.bytes.byteLength;
      return { ...file, bytes: file.bytes.slice() };
    }
    extractedBytesLimited = true;
    return { ...file, bytes: new Uint8Array() };
  });
  return {
    ...pcap,
    packets: pcap.packets.map((packet) => ({ ...packet, payloadBytes: new Uint8Array() })),
    tcpStreams,
    extractedFiles,
    streamBytesLimited,
    extractedBytesLimited
  };
}
