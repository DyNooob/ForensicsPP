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

export type EvidenceReadOptions = {
  signal?: AbortSignal;
};

export interface EvidenceReader {
  readonly size: number;
  read(offset: number, length: number, options?: EvidenceReadOptions): Promise<Uint8Array>;
  slice(offset: number, length?: number): EvidenceReader;
  stream(offset?: number, length?: number): ReadableStream<Uint8Array>;
}

function normalizeRange(size: number, offset: number, length?: number) {
  if (!Number.isSafeInteger(offset) || offset < 0) throw new RangeError("Evidence offset must be a non-negative safe integer.");
  if (offset > size) throw new RangeError("Evidence offset exceeds source size.");
  const remaining = size - offset;
  const normalizedLength = length == null ? remaining : Math.min(remaining, length);
  if (!Number.isSafeInteger(normalizedLength) || normalizedLength < 0) throw new RangeError("Evidence length must be a non-negative safe integer.");
  return { offset, length: normalizedLength };
}

export class BlobEvidenceReader implements EvidenceReader {
  readonly size: number;

  constructor(private readonly blob: Blob) {
    this.size = blob.size;
  }

  async read(offset: number, length: number, options: EvidenceReadOptions = {}) {
    const range = normalizeRange(this.size, offset, length);
    if (options.signal?.aborted) throw new DOMException("Evidence read cancelled", "AbortError");
    const buffer = await this.blob.slice(range.offset, range.offset + range.length).arrayBuffer();
    if (options.signal?.aborted) throw new DOMException("Evidence read cancelled", "AbortError");
    return new Uint8Array(buffer);
  }

  slice(offset: number, length?: number) {
    const range = normalizeRange(this.size, offset, length);
    return new BlobEvidenceReader(this.blob.slice(range.offset, range.offset + range.length));
  }

  stream(offset = 0, length?: number) {
    const range = normalizeRange(this.size, offset, length);
    return this.blob.slice(range.offset, range.offset + range.length).stream();
  }
}

export class MemoryEvidenceReader implements EvidenceReader {
  readonly size: number;

  constructor(private readonly bytes: Uint8Array) {
    this.size = bytes.byteLength;
  }

  async read(offset: number, length: number, options: EvidenceReadOptions = {}) {
    const range = normalizeRange(this.size, offset, length);
    if (options.signal?.aborted) throw new DOMException("Evidence read cancelled", "AbortError");
    return this.bytes.slice(range.offset, range.offset + range.length);
  }

  slice(offset: number, length?: number) {
    const range = normalizeRange(this.size, offset, length);
    return new MemoryEvidenceReader(this.bytes.subarray(range.offset, range.offset + range.length));
  }

  stream(offset = 0, length?: number) {
    const range = normalizeRange(this.size, offset, length);
    const chunk = this.bytes.slice(range.offset, range.offset + range.length);
    return new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(chunk);
        controller.close();
      }
    });
  }
}

export function evidenceReaderFromBlob(blob: Blob): EvidenceReader {
  return new BlobEvidenceReader(blob);
}

export async function readEvidenceFully(reader: EvidenceReader, options: EvidenceReadOptions = {}) {
  return reader.read(0, reader.size, options);
}
