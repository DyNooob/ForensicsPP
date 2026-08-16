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

import CryptoJS from "crypto-js";
import type { PcapTcpStream, PcapTcpStreamSegment, PcapTlsHandshake } from "../../models";
import { sha256Bytes } from "../../utils/hash";

function uint16(bytes: Uint8Array, offset: number) {
  return offset + 2 <= bytes.length ? (bytes[offset] << 8) | bytes[offset + 1] : -1;
}

function uint24(bytes: Uint8Array, offset: number) {
  return offset + 3 <= bytes.length ? (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2] : -1;
}

function versionName(value: number) {
  return ({
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3"
  } as Record<number, string>)[value] ?? `0x${value.toString(16).padStart(4, "0")}`;
}

function isGrease(value: number) {
  return (value & 0x0f0f) === 0x0a0a && (value & 0xff) === (value >>> 8);
}

function md5Text(value: string) {
  return CryptoJS.MD5(value).toString();
}

function directionSegments(stream: PcapTcpStream, direction: "a-to-b" | "b-to-a") {
  return stream.segments.filter((segment) => segment.direction === direction)
    .slice()
    .sort((left, right) => left.streamOffset - right.streamOffset || left.packetNo - right.packetNo);
}

function concatSegments(segments: PcapTcpStreamSegment[]) {
  const size = segments.reduce((sum, segment) => sum + segment.bytes.length, 0);
  const bytes = new Uint8Array(size);
  let cursor = 0;
  for (const segment of segments) {
    bytes.set(segment.bytes, cursor);
    cursor += segment.bytes.length;
  }
  return bytes;
}

function extensionList(bytes: Uint8Array, offset: number, length: number) {
  const result: Array<{ type: number; bytes: Uint8Array }> = [];
  const end = Math.min(bytes.length, offset + length);
  let cursor = offset;
  while (cursor + 4 <= end) {
    const type = uint16(bytes, cursor);
    const size = uint16(bytes, cursor + 2);
    if (type < 0 || size < 0 || cursor + 4 + size > end) break;
    result.push({ type, bytes: bytes.slice(cursor + 4, cursor + 4 + size) });
    cursor += 4 + size;
  }
  return result;
}

function parseSni(bytes: Uint8Array) {
  if (bytes.length < 5) return "";
  let cursor = 2;
  while (cursor + 3 <= bytes.length) {
    const type = bytes[cursor];
    const size = uint16(bytes, cursor + 1);
    if (size < 0 || cursor + 3 + size > bytes.length) break;
    if (type === 0) return new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(cursor + 3, cursor + 3 + size));
    cursor += 3 + size;
  }
  return "";
}

function parseAlpn(bytes: Uint8Array) {
  if (bytes.length < 3) return [];
  const values: string[] = [];
  let cursor = 2;
  while (cursor < bytes.length) {
    const size = bytes[cursor];
    if (!size || cursor + 1 + size > bytes.length) break;
    values.push(new TextDecoder("latin1").decode(bytes.slice(cursor + 1, cursor + 1 + size)));
    cursor += 1 + size;
  }
  return values;
}

function parseSupportedGroups(bytes: Uint8Array) {
  if (bytes.length < 2) return [] as number[];
  const size = uint16(bytes, 0);
  const values: number[] = [];
  for (let cursor = 2; cursor + 1 < Math.min(bytes.length, 2 + size); cursor += 2) values.push(uint16(bytes, cursor));
  return values;
}

function parsePointFormats(bytes: Uint8Array) {
  if (!bytes.length) return [] as number[];
  return Array.from(bytes.slice(1, 1 + bytes[0]));
}

function parseClientSupportedVersions(bytes: Uint8Array) {
  if (!bytes.length) return [] as number[];
  const values: number[] = [];
  for (let cursor = 1; cursor + 1 < Math.min(bytes.length, 1 + bytes[0]); cursor += 2) values.push(uint16(bytes, cursor));
  return values;
}

function clientHello(body: Uint8Array) {
  if (body.length < 34) return null;
  const legacyVersion = uint16(body, 0);
  let cursor = 34;
  const sessionLength = body[cursor] ?? 0;
  cursor += 1 + sessionLength;
  if (cursor + 2 > body.length) return null;
  const cipherLength = uint16(body, cursor);
  cursor += 2;
  if (cipherLength < 0 || cursor + cipherLength > body.length || cipherLength % 2) return null;
  const ciphers: number[] = [];
  for (let index = 0; index < cipherLength; index += 2) ciphers.push(uint16(body, cursor + index));
  cursor += cipherLength;
  if (cursor >= body.length) return { legacyVersion, ciphers, extensions: [] as Array<{ type: number; bytes: Uint8Array }> };
  const compressionLength = body[cursor] ?? 0;
  cursor += 1 + compressionLength;
  if (cursor + 2 > body.length) return { legacyVersion, ciphers, extensions: [] as Array<{ type: number; bytes: Uint8Array }> };
  const extensionsLength = uint16(body, cursor);
  cursor += 2;
  const extensions = extensionsLength >= 0 ? extensionList(body, cursor, extensionsLength) : [];
  return { legacyVersion, ciphers, extensions };
}

function serverHello(body: Uint8Array) {
  if (body.length < 38) return null;
  const legacyVersion = uint16(body, 0);
  let cursor = 34;
  const sessionLength = body[cursor] ?? 0;
  cursor += 1 + sessionLength;
  if (cursor + 3 > body.length) return null;
  const cipher = uint16(body, cursor);
  cursor += 3;
  if (cursor + 2 > body.length) return { legacyVersion, cipher, extensions: [] as Array<{ type: number; bytes: Uint8Array }> };
  const extensionsLength = uint16(body, cursor);
  cursor += 2;
  const extensions = extensionsLength >= 0 ? extensionList(body, cursor, extensionsLength) : [];
  return { legacyVersion, cipher, extensions };
}

function parseCertificates(body: Uint8Array) {
  const certificates: Array<{ size: number; sha256: string }> = [];
  const parseList = (start: number, listLength: number, tls13: boolean) => {
    let cursor = start;
    const end = Math.min(body.length, start + listLength);
    while (cursor + 3 <= end && certificates.length < 32) {
      const size = uint24(body, cursor);
      cursor += 3;
      if (size <= 0 || cursor + size > end) break;
      const der = body.slice(cursor, cursor + size);
      certificates.push({ size, sha256: sha256Bytes(der) });
      cursor += size;
      if (tls13) {
        if (cursor + 2 > end) break;
        const extLength = uint16(body, cursor);
        cursor += 2 + Math.max(0, extLength);
      }
    }
  };
  const tls12Length = uint24(body, 0);
  if (tls12Length >= 0 && tls12Length <= body.length - 3) parseList(3, tls12Length, false);
  if (!certificates.length && body.length >= 4) {
    const contextLength = body[0];
    const listOffset = 1 + contextLength;
    const listLength = uint24(body, listOffset);
    if (listLength >= 0 && listOffset + 3 + listLength <= body.length) parseList(listOffset + 3, listLength, true);
  }
  return certificates;
}

function parseHandshakeDirection(stream: PcapTcpStream, direction: "a-to-b" | "b-to-a") {
  const segments = directionSegments(stream, direction);
  if (!segments.length) return [] as PcapTlsHandshake[];
  const bytes = concatSegments(segments);
  const handshakeChunks: Uint8Array[] = [];
  const recordVersions: number[] = [];
  let cursor = 0;
  while (cursor + 5 <= bytes.length) {
    const contentType = bytes[cursor];
    const recordVersion = uint16(bytes, cursor + 1);
    const size = uint16(bytes, cursor + 3);
    const plausibleType = contentType >= 20 && contentType <= 24;
    const plausibleVersion = recordVersion >= 0x0300 && recordVersion <= 0x0304;
    const plausibleSize = size >= 0 && size <= 18_432;
    if (!plausibleType || !plausibleVersion || !plausibleSize) {
      cursor += 1;
      continue;
    }
    if (cursor + 5 + size > bytes.length) break;
    if (contentType === 22) {
      handshakeChunks.push(bytes.slice(cursor + 5, cursor + 5 + size));
      recordVersions.push(recordVersion);
    }
    cursor += 5 + size;
  }
  if (!handshakeChunks.length) return [];
  const total = handshakeChunks.reduce((sum, item) => sum + item.length, 0);
  const handshakeBytes = new Uint8Array(total);
  let target = 0;
  handshakeChunks.forEach((item) => { handshakeBytes.set(item, target); target += item.length; });
  const result: PcapTlsHandshake[] = [];
  cursor = 0;
  const source = direction === "a-to-b" ? stream.endpointA : stream.endpointB;
  const destination = direction === "a-to-b" ? stream.endpointB : stream.endpointA;
  const timestamp = segments[0].timestamp;
  while (cursor + 4 <= handshakeBytes.length && result.length < 128) {
    const type = handshakeBytes[cursor];
    const size = uint24(handshakeBytes, cursor + 1);
    if (size < 0 || cursor + 4 + size > handshakeBytes.length) break;
    const body = handshakeBytes.slice(cursor + 4, cursor + 4 + size);
    const base = {
      streamKey: stream.key,
      direction,
      timestamp,
      source,
      destination,
      recordVersion: versionName(recordVersions[0] ?? 0)
    };
    if (type === 1) {
      const parsed = clientHello(body);
      if (parsed) {
        const extensionTypes = parsed.extensions.map((item) => item.type);
        const sni = parseSni(parsed.extensions.find((item) => item.type === 0)?.bytes ?? new Uint8Array());
        const alpn = parseAlpn(parsed.extensions.find((item) => item.type === 16)?.bytes ?? new Uint8Array());
        const versions = parseClientSupportedVersions(parsed.extensions.find((item) => item.type === 43)?.bytes ?? new Uint8Array());
        const groups = parseSupportedGroups(parsed.extensions.find((item) => item.type === 10)?.bytes ?? new Uint8Array());
        const pointFormats = parsePointFormats(parsed.extensions.find((item) => item.type === 11)?.bytes ?? new Uint8Array());
        const ja3 = [
          parsed.legacyVersion,
          parsed.ciphers.filter((value) => !isGrease(value)).join("-"),
          extensionTypes.filter((value) => !isGrease(value)).join("-"),
          groups.filter((value) => !isGrease(value)).join("-"),
          pointFormats.join("-")
        ].join(",");
        result.push({
          ...base,
          type: "ClientHello",
          negotiatedVersion: versions.length ? versions.map(versionName).join(", ") : versionName(parsed.legacyVersion),
          sni,
          alpn,
          cipherSuites: parsed.ciphers.map((value) => `0x${value.toString(16).padStart(4, "0")}`),
          extensions: extensionTypes.map((value) => String(value)),
          ja3,
          ja3Hash: md5Text(ja3),
          certificates: []
        });
      }
    } else if (type === 2) {
      const parsed = serverHello(body);
      if (parsed) {
        const extensionTypes = parsed.extensions.map((item) => item.type);
        const selectedVersionBytes = parsed.extensions.find((item) => item.type === 43)?.bytes;
        const selectedVersion = selectedVersionBytes && selectedVersionBytes.length >= 2 ? uint16(selectedVersionBytes, 0) : parsed.legacyVersion;
        const alpn = parseAlpn(parsed.extensions.find((item) => item.type === 16)?.bytes ?? new Uint8Array());
        const ja3s = [parsed.legacyVersion, parsed.cipher, extensionTypes.filter((value) => !isGrease(value)).join("-")].join(",");
        result.push({
          ...base,
          type: "ServerHello",
          negotiatedVersion: versionName(selectedVersion),
          sni: "",
          alpn,
          cipherSuites: [`0x${parsed.cipher.toString(16).padStart(4, "0")}`],
          extensions: extensionTypes.map((value) => String(value)),
          ja3s,
          ja3sHash: md5Text(ja3s),
          certificates: []
        });
      }
    } else if (type === 11) {
      const certificates = parseCertificates(body);
      result.push({
        ...base,
        type: "Certificate",
        negotiatedVersion: "",
        sni: "",
        alpn: [],
        cipherSuites: [],
        extensions: [],
        certificates
      });
    }
    cursor += 4 + size;
  }
  return result;
}

export function parseTlsFromTcpStreams(streams: PcapTcpStream[]) {
  return streams.flatMap((stream) => [
    ...parseHandshakeDirection(stream, "a-to-b"),
    ...parseHandshakeDirection(stream, "b-to-a")
  ]).sort((left, right) => left.timestamp.localeCompare(right.timestamp) || left.streamKey.localeCompare(right.streamKey));
}

