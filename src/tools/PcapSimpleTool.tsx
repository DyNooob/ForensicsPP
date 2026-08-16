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
import { AButton, ALinearProgress, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import type { PcapInfo, PcapHttpItem, PcapTcpStream } from "../models";
import { persistablePcapInfo } from "../features/pcap/analyzer";
import { downloadBlob, formatBytes } from "../utils/files";
import { hashBytesInWorker } from "../features/hash/task";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { runWorkerTask } from "../utils/workerTask";
import { evidenceReaderFromBlob, readEvidenceFully } from "../core/evidence/reader";
import { clearAnalysisResult, publishAnalysisResult } from "../features/analysis/resultStore";
import { appVersion } from "../config/app";

const MAX_PCAP_BYTES = 128 * 1024 * 1024;
const MAX_STREAM_PREVIEW_BYTES = 1024 * 1024;
function endpoint(value: string, port: number | null) {
  return port == null ? value : `${value}:${port}`;
}

function endpointHost(value: string) {
  if (value.startsWith("[")) return value.slice(1, value.indexOf("]") > 0 ? value.indexOf("]") : undefined);
  return value.includes(":") && value.split(":").length > 2 ? value : value.replace(/:\d+$/, "");
}

function streamSegments(stream: PcapTcpStream, direction: "both" | "a-to-b" | "b-to-a") {
  const segments = direction === "both" ? stream.segments : stream.segments.filter((segment) => segment.direction === direction);
  return segments.slice().sort(direction === "both"
    ? (left, right) => left.packetNo - right.packetNo
    : (left, right) => left.streamOffset - right.streamOffset || left.packetNo - right.packetNo);
}

function readableStreamText(bytes: Uint8Array) {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ".");
}

function PcapTrafficChart({ timeline, english }: { timeline: PcapInfo["timeline"]; english: boolean }) {
  if (!timeline.length) return null;
  const maxBytes = Math.max(...timeline.map((b) => b.bytes), 1);
  const totalBytes = timeline.reduce((sum, b) => sum + b.bytes, 0);
  const width = 680;
  const height = 140;
  const padLeft = 44;
  const padRight = 12;
  const padTop = 10;
  const padBottom = 28;
  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;
  const barW = Math.max(2, chartW / timeline.length - 1);
  const yTicks = [0, maxBytes / 2, maxBytes];
  return (
    <div className="pcap-traffic-chart">
      <div className="pcap-chart-head">
        <strong>{english ? "Traffic over time" : "流量趋势"}</strong>
        <span>{english ? `${timeline.reduce((s, b) => s + b.packets, 0)} packets · ${formatBytes(totalBytes)}` : `${timeline.reduce((s, b) => s + b.packets, 0)} 个数据包 · ${formatBytes(totalBytes)}`}</span>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={english ? "Traffic over time" : "流量趋势图"}>
        {yTicks.map((value, index) => {
          const y = padTop + chartH - (value / maxBytes) * chartH;
          return <g key={index}><line x1={padLeft} y1={y} x2={width - padRight} y2={y} stroke="var(--app-line)" strokeDasharray="2,2" /><text x={padLeft - 6} y={y + 3} textAnchor="end" fill="var(--app-muted)" fontSize="9">{formatBytes(Math.round(value))}</text></g>;
        })}
        {timeline.map((bucket, index) => {
          const x = padLeft + index * (chartW / timeline.length);
          const barH = (bucket.bytes / maxBytes) * chartH;
          const y = padTop + chartH - barH;
          return <rect key={index} x={x} y={y} width={Math.max(1, barW)} height={barH} fill="var(--app-primary)" opacity={0.85}><title>{`${bucket.label}: ${bucket.packets} pkts, ${formatBytes(bucket.bytes)}`}</title></rect>;
        })}
        <text x={padLeft} y={height - 6} fill="var(--app-muted)" fontSize="9">{timeline[0]?.label ?? "--"}</text>
        <text x={width - padRight} y={height - 6} textAnchor="end" fill="var(--app-muted)" fontSize="9">{timeline[timeline.length - 1]?.label ?? "--"}</text>
      </svg>
    </div>
  );
}

function hexRows(bytes: Uint8Array, offset: number) {
  const rows: string[] = [];
  for (let index = 0; index < bytes.length; index += 16) {
    const row = bytes.slice(index, index + 16);
    const hex = Array.from(row, (value) => value.toString(16).padStart(2, "0").toUpperCase()).join(" ").padEnd(47);
    const ascii = Array.from(row, (value) => value >= 32 && value <= 126 ? String.fromCharCode(value) : ".").join("");
    rows.push(`${(offset + index).toString(16).padStart(8, "0").toUpperCase()}  ${hex}  ${ascii}`);
  }
  return rows.join("\n");
}

function streamTranscript(stream: PcapTcpStream, direction: "both" | "a-to-b" | "b-to-a", format: "text" | "hex") {
  const labels = { "a-to-b": `${stream.endpointA} -> ${stream.endpointB}`, "b-to-a": `${stream.endpointB} -> ${stream.endpointA}` };
  const output: string[] = [];
  let remaining = MAX_STREAM_PREVIEW_BYTES;
  for (const segment of streamSegments(stream, direction)) {
    if (remaining <= 0) break;
    output.push(`[${labels[segment.direction]} | #${segment.packetNo} | ${segment.timestamp}]`);
    if (segment.gapBefore) output.push(`[capture gap: ${segment.gapBefore} bytes]`);
    const visible = segment.bytes.slice(0, remaining);
    output.push(format === "hex" ? hexRows(visible, segment.streamOffset) : readableStreamText(visible));
    remaining -= visible.length;
  }
  if (remaining <= 0) output.push(`[preview limited to ${MAX_STREAM_PREVIEW_BYTES} bytes]`);
  return output.join("\n");
}

function joinedDirectionBytes(stream: PcapTcpStream, direction: "a-to-b" | "b-to-a") {
  const segments = streamSegments(stream, direction);
  const total = segments.reduce((sum, segment) => sum + segment.bytes.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const segment of segments) {
    output.set(segment.bytes, offset);
    offset += segment.bytes.length;
  }
  return output;
}

function extractedBytesAvailable(file: PcapInfo["extractedFiles"][number]) {
  return file.size === 0 || file.bytes.byteLength >= file.size;
}

export function PcapTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {
  const english = t.waiting === "Waiting";
  const [pcap, setPcap] = React.useState<PcapInfo | null>(null);
  const [selectedPacketNo, setSelectedPacketNo] = React.useState<number | null>(null);
  const [expandedPacketNo, setExpandedPacketNo] = React.useState<number | null>(null);
  const [packetFilter, setPacketFilter] = React.useState("");
  const [protocolFilters, setProtocolFilters] = React.useState<string[]>([]);
  const [packetSort, setPacketSort] = React.useState<"no" | "time" | "size" | "protocol">("no");
  const [conversationFilter, setConversationFilter] = React.useState("");
  const [networkFilter, setNetworkFilter] = React.useState("");
  const [streamFilter, setStreamFilter] = React.useState("");
  const [selectedStreamKey, setSelectedStreamKey] = React.useState("");
  const [streamDirection, setStreamDirection] = React.useState<"both" | "a-to-b" | "b-to-a">("both");
  const [streamFormat, setStreamFormat] = React.useState<"text" | "hex">("text");
  const [extractedHashes, setExtractedHashes] = React.useState<Record<string, string>>({});
  const [extractedHashingKey, setExtractedHashingKey] = React.useState("");
  const [extractedHashError, setExtractedHashError] = React.useState("");
  const [view, setView] = React.useState<"overview" | "conversations" | "streams" | "packets" | "network" | "files">("overview");
  const [packetPage, setPacketPage] = React.useState(0);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [httpDetail, setHttpDetail] = React.useState<PcapHttpItem | null>(null);
  const [streamSearch, setStreamSearch] = React.useState("");
  const [streamSearchIndex, setStreamSearchIndex] = React.useState(0);
  const [dropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const streamTextareaRef = React.useRef<HTMLTextAreaElement | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);
  const extractedHashAbortRef = React.useRef<AbortController | null>(null);
  const extractedHashRequestRef = React.useRef(0);
  const resetExtractedHashes = React.useCallback(() => {
    extractedHashAbortRef.current?.abort();
    extractedHashAbortRef.current = null;
    extractedHashRequestRef.current += 1;
    setExtractedHashes({});
    setExtractedHashingKey("");
    setExtractedHashError("");
  }, []);
  const workspace = useToolWorkspace<PcapInfo>({
    id: "pcap",
    version: 3,
    isValid: (value): value is PcapInfo => Boolean(value && typeof value === "object" && Array.isArray((value as PcapInfo).packets) && Array.isArray((value as PcapInfo).tcpStreams)),
    onRestore: (value) => {
      const restored = { ...value, tlsItems: value.tlsItems ?? [] };
      setPcap(restored);
      resetExtractedHashes();
      setSelectedPacketNo(restored.packets[0]?.no ?? null);
      setSelectedStreamKey(restored.tcpStreams[0]?.key ?? "");
      setError("");
    }
  });
  const storageState = workspace.state;

  const protocolOptions = React.useMemo(() => {
    const protocols = new Set<string>();
    for (const packet of pcap?.packets ?? []) protocols.add(packet.protocol);
    return Array.from(protocols).sort();
  }, [pcap?.packets]);
  const packets = React.useMemo(() => {
    const value = packetFilter.trim().toLowerCase();
    const rows = (pcap?.packets ?? []).filter((packet) => {
      if (protocolFilters.length && !protocolFilters.includes(packet.protocol)) return false;
      if (!value) return true;
      return [packet.no, packet.protocol, packet.source, packet.destination, packet.sourcePort, packet.destinationPort, packet.info].join(" ").toLowerCase().includes(value);
    });
    const sorted = [...rows].sort((a, b) => {
      switch (packetSort) {
        case "time": return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime() || a.no - b.no;
        case "size": return b.captured - a.captured || a.no - b.no;
        case "protocol": return a.protocol.localeCompare(b.protocol) || a.no - b.no;
        default: return a.no - b.no;
      }
    });
    return sorted;
  }, [packetFilter, protocolFilters, packetSort, pcap]);
  const packetPageCount = Math.max(1, Math.ceil(packets.length / 250));
  const visiblePackets = packets.slice(packetPage * 250, (packetPage + 1) * 250);
  const selectedPacket = pcap?.packets.find((packet) => packet.no === selectedPacketNo) ?? null;
  const conversations = React.useMemo(() => {
    const value = conversationFilter.trim().toLowerCase();
    return (pcap?.conversations ?? []).filter((item) => !value || `${item.protocol} ${item.endpointA} ${item.endpointB}`.toLowerCase().includes(value));
  }, [conversationFilter, pcap]);
  const visibleHttp = React.useMemo(() => {
    const value = networkFilter.trim().toLowerCase();
    return (pcap?.httpItems ?? []).filter((item) => !value || `${item.packetNo} ${item.method} ${item.host} ${item.path} ${item.contentType}`.toLowerCase().includes(value)).slice(0, 2000);
  }, [networkFilter, pcap]);
  const visibleDns = React.useMemo(() => {
    const value = networkFilter.trim().toLowerCase();
    return (pcap?.dnsItems ?? []).filter((item) => !value || `${item.packetNo} ${item.name} ${item.type} ${item.source} ${item.destination}`.toLowerCase().includes(value)).slice(0, 2000);
  }, [networkFilter, pcap]);
  const visibleTls = React.useMemo(() => {
    const value = networkFilter.trim().toLowerCase();
    return (pcap?.tlsItems ?? []).filter((item) => !value || `${item.type} ${item.source} ${item.destination} ${item.sni} ${item.negotiatedVersion} ${item.alpn.join(" ")} ${item.ja3Hash ?? ""} ${item.ja3sHash ?? ""}`.toLowerCase().includes(value)).slice(0, 2000);
  }, [networkFilter, pcap]);
  const streams = React.useMemo(() => {
    const value = streamFilter.trim().toLowerCase();
    return (pcap?.tcpStreams ?? []).filter((stream) => !value || `${stream.endpointA} ${stream.endpointB}`.toLowerCase().includes(value));
  }, [pcap, streamFilter]);
  const streamByKey = React.useMemo(() => new Map((pcap?.tcpStreams ?? []).map((stream) => [stream.key, stream])), [pcap]);
  const streamIndexByKey = React.useMemo(() => new Map((pcap?.tcpStreams ?? []).map((stream, index) => [stream.key, index])), [pcap]);
  const selectedStream = pcap?.tcpStreams.find((stream) => stream.key === selectedStreamKey) ?? pcap?.tcpStreams[0] ?? null;
  const selectedStreamTranscript = React.useMemo(
    () => selectedStream ? streamTranscript(selectedStream, streamDirection, streamFormat) : "",
    [selectedStream, streamDirection, streamFormat]
  );

  const httpGroups = React.useMemo(() => {
    const groups = new Map<string, PcapHttpItem[]>();
    for (const item of visibleHttp) {
      const key = item.streamKey || `__single-${item.packetNo}`;
      const list = groups.get(key);
      if (list) list.push(item);
      else groups.set(key, [item]);
    }
    return Array.from(groups.entries()).map(([key, items]) => ({
      key,
      stream: key.startsWith("__single-") ? null : (streamByKey.get(key) ?? null),
      items
    }));
  }, [visibleHttp, streamByKey]);

  const streamMatches = React.useMemo(() => {
    const text = selectedStreamTranscript;
    const query = streamSearch.trim().toLowerCase();
    if (!query || !text) return [] as number[];
    const lower = text.toLowerCase();
    const out: number[] = [];
    let from = 0;
    for (;;) {
      const index = lower.indexOf(query, from);
      if (index < 0) break;
      out.push(index);
      from = index + query.length;
    }
    return out;
  }, [selectedStreamTranscript, streamSearch]);

  React.useEffect(() => { setStreamSearchIndex(0); }, [streamSearch, selectedStream?.key]);

  const jumpToStreamMatch = (direction: 1 | -1) => {
    if (!streamMatches.length) return;
    setStreamSearchIndex((current) => (current + direction + streamMatches.length) % streamMatches.length);
  };

  React.useEffect(() => {
    if (!streamMatches.length || !streamTextareaRef.current) return;
    const query = streamSearch.trim();
    const start = streamMatches[streamSearchIndex] ?? 0;
    const textarea = streamTextareaRef.current;
    textarea.focus();
    textarea.setSelectionRange(start, start + query.length);
    const lineHeight = Number.parseFloat(getComputedStyle(textarea).lineHeight) || 18;
    textarea.scrollTop = Math.max(0, Math.floor(start / 80) * lineHeight - textarea.clientHeight / 2);
  }, [streamSearchIndex, streamMatches, streamSearch]);

  const loadFile = async (file?: File) => {
    if (!file || !active) return;
    workspace.clear();
    clearAnalysisResult("pcap");
    resetExtractedHashes();
    setDropActive(false);
    setError("");
    abortRef.current?.abort();
    setPcap(null);
    setSelectedPacketNo(null);
    setExpandedPacketNo(null);
    setPacketFilter("");
    setProtocolFilters([]);
    setPacketSort("no");
    setConversationFilter("");
    setNetworkFilter("");
    setStreamFilter("");
    setSelectedStreamKey("");
    setStreamDirection("both");
    setStreamFormat("text");
    setPacketPage(0);
    setView("overview");
    setLoading(false);
    setStreamSearch("");
    setStreamSearchIndex(0);
    setHttpDetail(null);
    if (file.size > MAX_PCAP_BYTES) {
      setError(english ? "The capture exceeds the 128 MiB limit." : "流量包超过 128 MiB 限制。");
      return;
    }
    if (file.size <= 0) {
      setError(english ? "The capture file is empty." : "流量包为空。");
      return;
    }
    setLoading(true);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const startedAt = new Date().toISOString();
      const bytes = await readEvidenceFully(evidenceReaderFromBlob(file), { signal: controller.signal });
      if (!active || controller.signal.aborted) return;
      const next = await runWorkerTask<{ bytes: Uint8Array; name: string; size: number }, PcapInfo>({
        createWorker: () => new Worker(new URL("../workers/pcap.worker.ts", import.meta.url), { type: "module" }),
        request: { bytes, name: file.name, size: file.size },
        transfer: [bytes.buffer],
        signal: controller.signal,
        timeoutMs: 180_000
      });
      if (!active || controller.signal.aborted) return;
      if (next.format === "Unknown") throw new Error(english ? "Unsupported or unrecognized packet capture." : "无法识别该流量包格式。");
      setPcap(next);
      const completedAt = new Date().toISOString();
      const sniValues = Array.from(new Set(next.tlsItems.map((item) => item.sni).filter(Boolean)));
      const certificateCount = next.tlsItems.reduce((sum, item) => sum + item.certificates.length, 0);
      publishAnalysisResult("pcap", {
        schemaVersion: "1",
        id: `pcap-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        analyzer: { id: "pcap", version: appVersion },
        source: [{ name: file.name, size: file.size, type: file.type || "application/vnd.tcpdump.pcap", lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : "" }],
        run: { startedAt, completedAt, parameters: { maxBytes: MAX_PCAP_BYTES, tcpReassembly: true, tlsHandshakeParsing: true } },
        summary: {
          title: english ? "Packet capture analysis" : "流量取证分析",
          text: english
            ? `${next.packets.length} packets, ${next.tcpStreams.length} TCP streams, ${next.httpItems.length} HTTP items, ${next.dnsItems.length} DNS items, ${next.tlsItems.length} TLS handshake items.`
            : `${next.packets.length} 个数据包，${next.tcpStreams.length} 条 TCP 流，${next.httpItems.length} 条 HTTP，${next.dnsItems.length} 条 DNS，${next.tlsItems.length} 条 TLS 握手记录。`,
          metrics: [
            { label: english ? "Packets" : "数据包", value: String(next.packets.length) },
            { label: "TCP streams", value: String(next.tcpStreams.length) },
            { label: "HTTP", value: String(next.httpItems.length) },
            { label: "DNS", value: String(next.dnsItems.length) },
            { label: "TLS", value: String(next.tlsItems.length) }
          ]
        },
        findings: [
          ...(sniValues.length ? [{ level: "info", title: "TLS SNI", detail: sniValues.slice(0, 100).join(", ") }] : []),
          ...(certificateCount ? [{ level: "info", title: "TLS certificates", detail: `${certificateCount} certificate object(s) fingerprinted with SHA-256.` }] : []),
          ...(next.tcpStreams.some((stream) => stream.gapBytesAtoB || stream.gapBytesBtoA) ? [{ level: "warn", title: "TCP capture gaps", detail: "One or more reassembled TCP directions contain capture gaps; application-layer decoding may be incomplete." }] : [])
        ],
        indicators: [
          ...next.dnsItems.map((item) => ({ type: "domain", value: item.name, normalized: item.name.toLowerCase(), source: `packet:${item.packetNo}` })),
          ...next.httpItems.filter((item) => item.host !== "--").map((item) => ({ type: "domain", value: item.host, normalized: item.host.toLowerCase(), source: `packet:${item.packetNo}`, context: item.path })),
          ...sniValues.map((value) => ({ type: "domain", value, normalized: value.toLowerCase(), source: "tls-sni" }))
        ].slice(0, 2000),
        artifacts: next.extractedFiles.map((item, index) => ({ id: `http-file-${index}-${item.packetNo}`, label: item.filename, kind: "http-extracted-file", size: item.size, sha256: item.sha256 || undefined, mime: item.contentType !== "--" ? item.contentType : undefined, confidence: "high" as const })),
        timeline: next.events.slice(0, 2000).map((item) => ({
          iso: item.timestamp,
          local: item.timestamp,
          raw: item.title,
          format: "PCAP",
          line: item.packetNo ?? 0,
          source: item.flow || file.name,
          context: item.detail,
          epochMs: Number.isFinite(Date.parse(item.timestamp)) ? Date.parse(item.timestamp) : undefined
        })),
        limitations: [
          { code: "PCAP_FULL_BUFFER_LIMIT", detail: english ? "The current packet parser reads captures up to 128 MiB into memory; EvidenceReader is now used at the tool boundary for later streaming migration." : "当前流量解析器仍将不超过 128 MiB 的捕获文件读入内存；工具入口已切换至 EvidenceReader，便于后续流式迁移。" },
          ...(next.tlsItems.length ? [{ code: "TLS_METADATA_ONLY", detail: english ? "TLS analysis parses handshake metadata and certificate fingerprints; encrypted application data is not decrypted." : "TLS 分析仅解析握手元数据与证书指纹，不解密加密后的应用数据。" }] : [])
        ],
        data: { format: next.format, packetCount: next.packets.length, tcpStreamCount: next.tcpStreams.length, tlsHandshakeCount: next.tlsItems.length }
      });
      setSelectedPacketNo(next.packets[0]?.no ?? null);
      setExpandedPacketNo(null);
      setPacketFilter("");
      setProtocolFilters([]);
      setPacketSort("no");
      setConversationFilter("");
      setNetworkFilter("");
      setStreamFilter("");
      setSelectedStreamKey(next.tcpStreams[0]?.key ?? "");
      setStreamDirection("both");
      setStreamFormat("text");
      setPacketPage(0);
      setView("overview");
      workspace.save(persistablePcapInfo(next));
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      setPcap(null);
      setSelectedPacketNo(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setLoading(false);
      }
    }
  };

  const cancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setLoading(false);
  };

  const clear = () => {
    workspace.clear();
    clearAnalysisResult("pcap");
    resetExtractedHashes();
    abortRef.current?.abort();
    abortRef.current = null;
    setPcap(null);
    setSelectedPacketNo(null);
    setExpandedPacketNo(null);
    setPacketFilter("");
    setProtocolFilters([]);
    setPacketSort("no");
    setConversationFilter("");
    setNetworkFilter("");
    setStreamFilter("");
    setSelectedStreamKey("");
    setStreamDirection("both");
    setStreamFormat("text");
    setPacketPage(0);
    setView("overview");
    setLoading(false);
    setStreamSearch("");
    setStreamSearchIndex(0);
    setHttpDetail(null);
    setError("");
    if (inputRef.current) inputRef.current.value = "";
  };

  const saveExtracted = (index: number) => {
    const file = pcap?.extractedFiles[index];
    if (!file || !extractedBytesAvailable(file)) return;
    const bytes = new Uint8Array(file.bytes.length);
    bytes.set(file.bytes);
    downloadBlob(file.filename || `http-payload-${index + 1}.bin`, new Blob([bytes.buffer], { type: file.contentType !== "--" ? file.contentType : "application/octet-stream" }));
  };

  const extractedFileKey = (index: number) => {
    const file = pcap?.extractedFiles[index];
    return file ? `${index}:${file.filename}:${file.size}:${file.packetNo}` : `${index}`;
  };

  const hashExtractedFile = async (index: number) => {
    const file = pcap?.extractedFiles[index];
    if (!file || !extractedBytesAvailable(file)) return;
    const key = extractedFileKey(index);
    if (extractedHashes[key] || extractedHashingKey) return;
    const requestId = ++extractedHashRequestRef.current;
    setExtractedHashingKey(key);
    setExtractedHashError("");
    const controller = new AbortController();
    extractedHashAbortRef.current?.abort();
    extractedHashAbortRef.current = controller;
    try {
      const bytes = new Uint8Array(file.bytes.length);
      bytes.set(file.bytes);
      const result = await hashBytesInWorker(bytes, ["sha256"], { signal: controller.signal });
      if (!result.sha256) throw new Error(english ? "SHA-256 calculation returned no result." : "SHA-256 计算没有返回结果。");
      if (controller.signal.aborted || requestId !== extractedHashRequestRef.current) return;
      setExtractedHashes((current) => ({ ...current, [key]: result.sha256 ?? "" }));
    } catch (caught) {
      if (requestId === extractedHashRequestRef.current && !(caught instanceof DOMException && caught.name === "AbortError")) setExtractedHashError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (extractedHashAbortRef.current === controller) extractedHashAbortRef.current = null;
      if (requestId === extractedHashRequestRef.current) setExtractedHashingKey("");
    }
  };

  const saveStreamTranscript = () => {
    if (!selectedStream || !selectedStreamTranscript || pcap?.streamBytesLimited) return;
    downloadBlob(`tcp-stream-${pcap?.tcpStreams.indexOf(selectedStream) ?? 0}-${streamDirection}-${streamFormat}.txt`, new Blob([selectedStreamTranscript], { type: "text/plain;charset=utf-8" }));
  };

  const saveStreamBytes = () => {
    if (!selectedStream || streamDirection === "both" || pcap?.streamBytesLimited) return;
    const gapBytes = streamDirection === "a-to-b" ? selectedStream.gapBytesAtoB : selectedStream.gapBytesBtoA;
    if (gapBytes) return;
    const bytes = joinedDirectionBytes(selectedStream, streamDirection);
    downloadBlob(`tcp-stream-${pcap?.tcpStreams.indexOf(selectedStream) ?? 0}-${streamDirection}.bin`, new Blob([bytes.buffer], { type: "application/octet-stream" }));
  };

  const duration = pcap?.summary?.firstTimestamp && pcap.summary.lastTimestamp
    ? Math.max(0, new Date(pcap.summary.lastTimestamp).getTime() - new Date(pcap.summary.firstTimestamp).getTime())
    : 0;

  React.useEffect(() => {
    setPacketPage(0);
  }, [packetFilter]);

  React.useEffect(() => {
    if (packetPage >= packetPageCount) setPacketPage(packetPageCount - 1);
  }, [packetPage, packetPageCount]);

  React.useEffect(() => () => {
    abortRef.current?.abort();
    extractedHashAbortRef.current?.abort();
  }, []);

  React.useEffect(() => {
    if (active) return;
    abortRef.current?.abort();
    abortRef.current = null;
    extractedHashAbortRef.current?.abort();
    extractedHashAbortRef.current = null;
    extractedHashRequestRef.current += 1;
    setLoading(false);
    setExtractedHashingKey("");
  }, [active]);

  return (
    <div className={`tool-grid pcap-workbench ${pcap ? "has-pcap" : "empty-pcap"}`}>
      <section className="tool-panel wide-panel pcap-source-panel">
        <ToolPanelHeader title={pcap ? (english ? "Packet capture" : "流量包") : (english ? "Open packet capture" : "选择流量包")} actions={<AButton variant="text" disabled={!pcap && !error} onClick={clear}>{t.clear}</AButton>} />
        <input className="hidden-file-input" ref={inputRef} type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" aria-hidden="true" tabIndex={-1} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void loadFile(file); }} />
        {pcap ? <div className="pcap-loaded-source"><div><strong>{pcap.name}</strong><span>{pcap.format} · {pcap.packets.length} {english ? "packets" : "个数据包"} · {formatBytes(pcap.size)} · {storageState === "saved" ? (english ? "saved locally" : "已保留") : storageState === "saving" ? (english ? "saving" : "正在保留") : storageState === "failed" ? (english ? "not saved" : "未保留") : ""}</span></div><AButton variant="outlined" onClick={() => inputRef.current?.click()}>{english ? "Replace" : "更换文件"}</AButton></div> : <><div className={`desktop-drop-zone ${dropActive ? "active" : ""}`} role="button" tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }}
          onDragOver={(event) => { event.preventDefault(); setDropActive(true); }} onDragLeave={() => setDropActive(false)}
          onDrop={(event) => { event.preventDefault(); setDropActive(false); void loadFile(event.dataTransfer.files?.[0]); }}>
          <strong>{t.dropFileTitle}</strong>
          <span>{t.dropFileHint}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" disabled={loading} onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          {loading && <AButton variant="outlined" onClick={cancel}>{english ? "Cancel" : "取消"}</AButton>}
        </div></>}
        {loading && <ALinearProgress />}
        {error && <div className="empty-state error-state">{error}</div>}
      </section>

      {pcap && <>
        <section className="tool-panel wide-panel pcap-workspace-panel">
          <ToolPanelHeader title={t.summary} subtitle={`${pcap.name} · ${pcap.format}`} />
          <div className="pcap-simple-summary">
            <span><small>{english ? "Packets" : "数据包"}</small><strong>{pcap.summary?.packetCount ?? pcap.packets.length}</strong></span>
            <span><small>{english ? "Captured" : "捕获字节"}</small><strong>{formatBytes(pcap.summary?.totalCaptured ?? 0)}</strong></span>
            <span><small>{english ? "Duration" : "持续时间"}</small><strong>{duration ? `${(duration / 1000).toFixed(3)} s` : "--"}</strong></span>
            <span><small>{english ? "Conversations" : "会话"}</small><strong>{pcap.conversations.length}</strong></span>
          </div>
          <ASegmentedGroup className="pcap-simple-tabs" value={view} selects="single">
            <ASegmentedButton value="overview" onClick={() => setView("overview")}>{english ? "Overview" : "概览"}</ASegmentedButton>
            <ASegmentedButton value="conversations" onClick={() => setView("conversations")}>{t.conversations} ({pcap.conversations.length})</ASegmentedButton>
            <ASegmentedButton value="streams" disabled={!pcap.tcpStreams.length} onClick={() => setView("streams")}>{english ? "TCP streams" : "TCP 流"} ({pcap.tcpStreams.length})</ASegmentedButton>
            <ASegmentedButton value="packets" onClick={() => setView("packets")}>{t.packetList} ({pcap.packets.length})</ASegmentedButton>
            <ASegmentedButton value="network" onClick={() => setView("network")}>HTTP / DNS / TLS ({pcap.httpItems.length + pcap.dnsItems.length + pcap.tlsItems.length})</ASegmentedButton>
            <ASegmentedButton value="files" disabled={!pcap.extractedFiles.length} onClick={() => setView("files")}>{english ? "Files" : "文件"} ({pcap.extractedFiles.length})</ASegmentedButton>
          </ASegmentedGroup>

          {view === "overview" && <div className="pcap-simple-overview">
            {(pcap.streamBytesLimited || pcap.extractedBytesLimited) && <div className="pcap-stream-notice" role="status">{english ? "This restored workspace keeps metadata and previews, but not all raw stream or extracted-file bytes. Re-analyze the capture before exporting." : "当前工作区只保留了元数据和预览，未保留全部流及提取文件的原始字节。导出前请重新分析流量包。"}</div>}
            <InfoTable rows={[[english ? "Format" : "格式", `${pcap.format} ${pcap.version}`.trim()], [english ? "File size" : "文件大小", formatBytes(pcap.size)], [english ? "HTTP / DNS / TLS" : "HTTP / DNS / TLS", `${pcap.httpItems.length} / ${pcap.dnsItems.length} / ${pcap.tlsItems.length}`], [english ? "Extracted files" : "提取文件", String(pcap.extractedFiles.length)], [english ? "Events" : "事件", String(pcap.events.length)]]} />
            <PcapTrafficChart timeline={pcap.timeline} english={english} />
            <div className="pcap-simple-stat-grid">
              <section><strong>{english ? "Protocols" : "协议"}</strong><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Packets" : "数据包"}</th></tr></thead><tbody>{(pcap.summary?.protocols ?? []).map(([name, count]) => <tr key={name}><td>{name}</td><td>{count}</td></tr>)}</tbody></table></div></section>
              <section><strong>{english ? "Top endpoints" : "主要端点"}</strong><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english ? "Endpoint" : "端点"}</th><th>{english ? "Traffic" : "流量"}</th></tr></thead><tbody>{pcap.endpoints.slice(0, 12).map((item) => <tr key={item.endpoint}><td>{item.endpoint}</td><td>{formatBytes(item.bytesSent + item.bytesReceived)}</td></tr>)}</tbody></table></div></section>
              <section><strong>{english ? "Top services" : "主要服务"}</strong><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english ? "Port" : "端口"}</th><th>{english ? "Traffic" : "流量"}</th></tr></thead><tbody>{pcap.portStats.slice(0, 12).map((item) => <tr key={`${item.protocol}-${item.port}`}><td>{item.protocol}/{item.port}</td><td>{formatBytes(item.bytes)}</td></tr>)}</tbody></table></div></section>
            </div>
          </div>}

          {view === "conversations" && (pcap.conversations.length ? <><div className="pcap-list-filter"><input className="text-input" value={conversationFilter} onChange={(event) => setConversationFilter(event.currentTarget.value)} placeholder={english ? "Filter protocol or endpoint" : "筛选协议或端点"} aria-label={english ? "Filter conversations" : "筛选会话"} /><span>{conversations.length}/{pcap.conversations.length}</span></div><div className="table-scroll pcap-conversation-scroll"><table className="data-table"><thead><tr><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Endpoint A" : "端点 A"}</th><th>{english ? "Endpoint B" : "端点 B"}</th><th>{english ? "Packets" : "数据包"}</th><th>{english ? "Bytes" : "字节"}</th></tr></thead><tbody>{conversations.map((item) => { const stream = streamByKey.get(item.key); const open = () => { if (stream) { setSelectedStreamKey(stream.key); setView("streams"); } else { setPacketFilter(endpointHost(item.endpointA)); setView("packets"); } }; return <tr key={item.key} tabIndex={0} onClick={open} onKeyDown={(event) => { if (event.key === "Enter") open(); }}><td>{item.protocol}</td><td>{item.endpointA}</td><td>{item.endpointB}</td><td>{item.packets}</td><td>{formatBytes(item.bytes)}</td></tr>; })}</tbody></table></div></> : <div className="empty-state">--</div>)}

          {view === "streams" && <div className="pcap-stream-workspace">
            <div className="pcap-list-filter"><input className="text-input" value={streamFilter} onChange={(event) => setStreamFilter(event.currentTarget.value)} placeholder={english ? "Filter TCP endpoints" : "筛选 TCP 端点"} aria-label={english ? "Filter TCP streams" : "筛选 TCP 流"} /><span>{streams.length}/{pcap.tcpStreams.length}</span></div>
            <div className="table-scroll pcap-stream-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english ? "Endpoint A" : "端点 A"}</th><th>{english ? "Endpoint B" : "端点 B"}</th><th>{english ? "Packets" : "数据包"}</th><th>{"A -> B"}</th><th>{"B -> A"}</th><th>{english ? "Capture gaps" : "捕获缺口"}</th></tr></thead><tbody>{streams.map((stream) => <tr className={stream.key === selectedStream?.key ? "selected-row" : ""} key={stream.key} tabIndex={0} onClick={() => setSelectedStreamKey(stream.key)} onKeyDown={(event) => { if (event.key === "Enter") setSelectedStreamKey(stream.key); }}><td>{streamIndexByKey.get(stream.key) ?? "--"}</td><td>{stream.endpointA}</td><td>{stream.endpointB}</td><td>{stream.packetCount}</td><td>{formatBytes(stream.bytesAtoB)}</td><td>{formatBytes(stream.bytesBtoA)}</td><td>{formatBytes(stream.gapBytesAtoB + stream.gapBytesBtoA)}</td></tr>)}</tbody></table></div>
            {selectedStream && <div className="pcap-stream-detail">
              <ToolPanelHeader title={english ? "Follow TCP stream" : "查看 TCP 流"} subtitle={`${selectedStream.endpointA} <-> ${selectedStream.endpointB}`} actions={<><AButton variant="text" disabled={!selectedStreamTranscript} onClick={() => void copyText(selectedStreamTranscript)}>{t.copy}</AButton><AButton variant="text" disabled={!selectedStreamTranscript || Boolean(pcap.streamBytesLimited)} onClick={saveStreamTranscript}>{english ? "Save text" : "保存文本"}</AButton><AButton variant="outlined" disabled={Boolean(pcap.streamBytesLimited) || streamDirection === "both" || (streamDirection === "a-to-b" ? selectedStream.gapBytesAtoB : selectedStream.gapBytesBtoA) > 0 || !(streamDirection === "a-to-b" ? selectedStream.bytesAtoB : selectedStream.bytesBtoA)} onClick={saveStreamBytes}>{english ? "Save raw bytes" : "保存原始字节"}</AButton></>} />
              <div className="pcap-stream-controls">
                <ASegmentedGroup value={streamDirection} selects="single"><ASegmentedButton value="both" onClick={() => setStreamDirection("both")}>{english ? "Both" : "双向"}</ASegmentedButton><ASegmentedButton value="a-to-b" onClick={() => setStreamDirection("a-to-b")}>{"A -> B"}</ASegmentedButton><ASegmentedButton value="b-to-a" onClick={() => setStreamDirection("b-to-a")}>{"B -> A"}</ASegmentedButton></ASegmentedGroup>
                <ASegmentedGroup value={streamFormat} selects="single"><ASegmentedButton value="text" onClick={() => setStreamFormat("text")}>{english ? "Text" : "文本"}</ASegmentedButton><ASegmentedButton value="hex" onClick={() => setStreamFormat("hex")}>Hex</ASegmentedButton></ASegmentedGroup>
              </div>
              <div className="pcap-stream-search">
                <input className="text-input" value={streamSearch} onChange={(event) => setStreamSearch(event.currentTarget.value)} placeholder={t.streamSearch} aria-label={t.streamSearch} />
                <span className="pcap-stream-search-count">{streamMatches.length ? `${streamSearchIndex + 1}/${streamMatches.length}` : "0"}</span>
                <AButton variant="text" disabled={!streamMatches.length} onClick={() => jumpToStreamMatch(-1)} aria-label={english ? "Previous match" : "上一个匹配"}>↑</AButton>
                <AButton variant="text" disabled={!streamMatches.length} onClick={() => jumpToStreamMatch(1)} aria-label={english ? "Next match" : "下一个匹配"}>↓</AButton>
              </div>
              <div className="pcap-stream-meta"><span>{english ? "Payload" : "载荷"}: {formatBytes(selectedStream.bytesAtoB + selectedStream.bytesBtoA)}</span><span>{english ? "Retransmitted overlap" : "重传重叠"}: {formatBytes(selectedStream.retransmittedBytes)}</span><span>{english ? "Capture gaps" : "捕获缺口"}: {formatBytes(selectedStream.gapBytesAtoB + selectedStream.gapBytesBtoA)}</span></div>
              {(selectedStream.gapBytesAtoB || selectedStream.gapBytesBtoA) ? <div className="pcap-stream-notice">{english ? "The capture has sequence gaps. Gap markers are shown in the preview; raw export is available only for a complete direction." : "该流存在序列缺口，预览中已标出；只有无缺口的单向数据可以导出原始字节。"}</div> : null}
              {pcap.streamBytesLimited ? <div className="pcap-stream-notice">{english ? "The restored workspace does not contain all stream bytes. Re-analyze the capture before exporting." : "恢复的工作区未保留全部流字节，导出前请重新分析流量包。"}</div> : null}
              <textarea ref={streamTextareaRef} className="single-textarea pcap-stream-output" value={selectedStreamTranscript || "--"} readOnly aria-label={english ? "TCP stream content" : "TCP 流内容"} />
            </div>}
          </div>}

          {view === "packets" && <div className="pcap-simple-packets">
            <div className="pcap-packet-toolbar">
              <input className="text-input pcap-filter" value={packetFilter} onChange={(event) => setPacketFilter(event.currentTarget.value)} placeholder={english ? "Filter protocol, host, port, or text" : "筛选协议、地址、端口或内容"} />
              <div className="pcap-protocol-filters">
                {protocolOptions.map((protocol) => {
                  const active = protocolFilters.includes(protocol);
                  return <button key={protocol} type="button" className={`pcap-protocol-chip ${active ? "is-active" : ""}`} onClick={() => setProtocolFilters((current) => active ? current.filter((p) => p !== protocol) : [...current, protocol])}>{protocol}</button>;
                })}
              </div>
              <div className="pcap-sort-control">
                <label>{english ? "Sort" : "排序"}</label>
                <select className="text-input" value={packetSort} onChange={(event) => setPacketSort(event.target.value as typeof packetSort)}>
                  <option value="no">{english ? "Packet #" : "包号"}</option>
                  <option value="time">{english ? "Time" : "时间"}</option>
                  <option value="size">{english ? "Size" : "大小"}</option>
                  <option value="protocol">{english ? "Protocol" : "协议"}</option>
                </select>
              </div>
              <span className="pcap-packet-count">{packets.length}/{pcap.packets.length}</span>
            </div>
            <div className="table-scroll pcap-packet-scroll"><table className="data-table pcap-packet-table"><thead><tr><th>#</th><th>{english ? "Time" : "时间"}</th><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Source" : "来源"}</th><th>{english ? "Destination" : "目标"}</th><th>{english ? "Length" : "长度"}</th><th>{english ? "Info" : "信息"}</th></tr></thead><tbody>{visiblePackets.map((packet) => {
              const expanded = expandedPacketNo === packet.no;
              const stream = packet.tcpStreamKey ? streamByKey.get(packet.tcpStreamKey) : null;
              const conversation = pcap.conversations.find((c) => c.key === `${packet.protocol}|${[endpoint(packet.source, packet.sourcePort), endpoint(packet.destination, packet.destinationPort)].sort().join("|")}`);
              return (
                <React.Fragment key={packet.no}>
                  <tr className={packet.no === selectedPacketNo ? "selected-row" : ""} onClick={() => { setSelectedPacketNo(packet.no); setExpandedPacketNo(expanded ? null : packet.no); }}>
                    <td>{packet.no}</td>
                    <td>{packet.timestamp.split("T")[1]?.replace("Z", "") ?? packet.timestamp}</td>
                    <td><span className={`pcap-proto-badge proto-${packet.protocol.toLowerCase().replace(/[^a-z0-9]/g, "_")}`}>{packet.protocol}</span></td>
                    <td>{endpoint(packet.source, packet.sourcePort)}</td>
                    <td>{endpoint(packet.destination, packet.destinationPort)}</td>
                    <td>{packet.captured}</td>
                    <td className="pcap-info-cell" title={packet.info}>{packet.info}</td>
                  </tr>
                  {expanded && (
                    <tr className="pcap-packet-detail-row">
                      <td colSpan={7}>
                        <div className="pcap-packet-detail">
                          <div className="pcap-packet-detail-head">
                            <strong>{english ? "Packet" : "数据包"} #{packet.no}</strong>
                            <div className="pcap-packet-actions">
                              {stream && <AButton variant="text" onClick={() => { setSelectedStreamKey(stream.key); setView("streams"); }}>{english ? "Follow stream" : "跟踪 TCP 流"}</AButton>}
                              {conversation && <AButton variant="text" onClick={() => { setPacketFilter(endpointHost(packet.source) === endpointHost(conversation.endpointA) ? conversation.endpointA : conversation.endpointB); }}>{english ? "Filter conversation" : "筛选会话"}</AButton>}
                              <AButton variant="text" onClick={() => void copyText(packet.flow)}>{t.copy} flow</AButton>
                            </div>
                          </div>
                          <InfoTable rows={[
                            [english ? "Flow" : "流", packet.flow],
                            [english ? "Timestamp" : "时间", packet.timestamp],
                            [english ? "Captured / Original" : "捕获 / 原始", `${packet.captured} / ${packet.original}`],
                            [english ? "Delta" : "相对时间", `${packet.deltaMs.toFixed(3)} ms`],
                            ...(packet.tcpFlags ? [["TCP flags", packet.tcpFlags] as [string, string]] : []),
                            ...(packet.tcpStreamKey ? [[english ? "TCP stream" : "TCP 流", packet.tcpStreamKey] as [string, string]] : [])
                          ]} />
                          <div className="pcap-simple-payload"><label>Payload<textarea className="single-textarea compact-textarea" value={packet.payloadPreview || "--"} readOnly /></label><label>Hex<textarea className="single-textarea compact-textarea" value={packet.hexPreview || "--"} readOnly /></label></div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}</tbody></table></div>
            {packets.length > 250 && <div className="pcap-simple-pagination"><AButton variant="outlined" disabled={packetPage === 0} onClick={() => setPacketPage((value) => Math.max(0, value - 1))}>{english ? "Previous" : "上一页"}</AButton><span>{packetPage + 1} / {packetPageCount}</span><AButton variant="outlined" disabled={packetPage + 1 >= packetPageCount} onClick={() => setPacketPage((value) => Math.min(packetPageCount - 1, value + 1))}>{english ? "Next" : "下一页"}</AButton></div>}
          </div>}

          {view === "network" && <div className="pcap-simple-network">
            <div className="pcap-list-filter"><input className="text-input" value={networkFilter} onChange={(event) => setNetworkFilter(event.currentTarget.value)} placeholder={english ? "Filter HTTP, DNS, or TLS" : "筛选 HTTP、DNS 或 TLS"} aria-label={english ? "Filter HTTP, DNS, and TLS" : "筛选 HTTP、DNS 和 TLS"} /><span>{visibleHttp.length + visibleDns.length + visibleTls.length}/{pcap.httpItems.length + pcap.dnsItems.length + pcap.tlsItems.length}</span></div>
            <section><strong>HTTP</strong>{pcap.httpItems.length ? (
              <div className="pcap-http-groups">
                {httpGroups.map((group) => (
                  <div className="pcap-http-group" key={group.key}>
                    <div className="pcap-http-group-head">
                      <span className="pcap-http-group-title">{group.stream ? `${group.stream.endpointA} <-> ${group.stream.endpointB}` : (english ? "Ungrouped HTTP" : "未分组的 HTTP")}</span>
                      {group.stream && <AButton variant="text" onClick={() => { setSelectedStreamKey(group.stream!.key); setView("streams"); }}>{t.followTcpStream}</AButton>}
                    </div>
                    <div className="pcap-http-messages">
                      {group.items.map((item, index) => {
                        const title = item.role === "request" ? `${item.method} ${item.path}` : item.line;
                        return (
                          <button type="button" className="pcap-http-message" key={`${item.packetNo}-${index}`} onClick={() => setHttpDetail(item)}>
                            <span className={`pcap-http-role role-${item.role}`}>{item.role === "request" ? (english ? "REQ" : "请求") : (english ? "RES" : "响应")}</span>
                            <span className="pcap-http-title">{title}</span>
                            <span className="pcap-http-meta">{item.host} · {item.contentType || "--"} · {formatBytes(item.bodySize)}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            ) : <div className="empty-state">--</div>}</section>
            <section><strong>DNS</strong>{pcap.dnsItems.length ? <div className="table-scroll pcap-dns-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english ? "Name" : "名称"}</th><th>{english ? "Type" : "类型"}</th></tr></thead><tbody>{visibleDns.map((item) => <tr key={`${item.packetNo}-${item.name}-${item.type}`} onClick={() => { setSelectedPacketNo(item.packetNo); setView("packets"); }}><td>{item.packetNo}</td><td>{item.name}</td><td>{item.type}</td></tr>)}</tbody></table></div> : <div className="empty-state">--</div>}</section>
            <section><strong>TLS</strong>{pcap.tlsItems.length ? <div className="table-scroll pcap-tls-scroll"><table className="data-table"><thead><tr><th>{english ? "Handshake" : "握手"}</th><th>{english ? "Source" : "来源"}</th><th>{english ? "Destination" : "目标"}</th><th>SNI</th><th>{english ? "Version" : "版本"}</th><th>ALPN</th><th>JA3 / JA3S</th><th>{english ? "Certificates" : "证书"}</th></tr></thead><tbody>{visibleTls.map((item, index) => <tr key={`${item.streamKey}-${item.direction}-${item.type}-${index}`}><td>{item.type}</td><td>{item.source}</td><td>{item.destination}</td><td>{item.sni || "--"}</td><td>{item.negotiatedVersion || item.recordVersion}</td><td>{item.alpn.join(", ") || "--"}</td><td><code>{item.ja3Hash || item.ja3sHash || "--"}</code></td><td title={item.certificates.map((cert) => cert.sha256).join("\n")}>{item.certificates.length || "--"}</td></tr>)}</tbody></table></div> : <div className="empty-state">--</div>}</section>
          </div>}

          {view === "files" && <div className="table-scroll pcap-files-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english ? "Filename" : "文件名"}</th><th>Host</th><th>{english ? "Path" : "路径"}</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Size" : "大小"}</th><th>SHA-256</th><th /></tr></thead><tbody>{pcap.extractedFiles.map((item, index) => { const key = extractedFileKey(index); const hash = extractedHashes[key]; const bytesAvailable = extractedBytesAvailable(item); return <tr key={`${item.packetNo}-${index}`}><td>{item.packetNo}</td><td>{item.filename}</td><td>{item.host}</td><td>{item.path}</td><td>{item.signature} / {item.contentType}</td><td>{formatBytes(item.size)}</td><td>{hash ? <button type="button" className="pcap-extracted-hash" title={t.copy} onClick={() => void copyText(hash)}>{hash}</button> : <AButton variant="text" disabled={!bytesAvailable || Boolean(extractedHashingKey)} onClick={() => void hashExtractedFile(index)}>{extractedHashingKey === key ? (english ? "Calculating..." : "计算中...") : bytesAvailable ? (english ? "Calculate" : "计算") : (english ? "Re-analyze" : "需重新分析")}</AButton>}</td><td><AButton variant="outlined" disabled={!bytesAvailable} title={!bytesAvailable ? (english ? "Re-analyze the capture before saving" : "请重新分析流量包后保存") : undefined} onClick={() => saveExtracted(index)}>{english ? "Save" : "保存"}</AButton></td></tr>; })}</tbody></table></div>}
          {extractedHashError && <div className="empty-state error-state">{extractedHashError}</div>}
        </section>

        {view === "packets" && selectedPacket && expandedPacketNo !== selectedPacket.no && <section className="tool-panel wide-panel pcap-simple-detail-panel">
          <ToolPanelHeader title={english ? "Selected packet" : "当前数据包"} subtitle={`#${selectedPacket.no} · ${selectedPacket.protocol}`} />
          <InfoTable rows={[["Flow", selectedPacket.flow], [english ? "Timestamp" : "时间", selectedPacket.timestamp], [english ? "Captured / Original" : "捕获 / 原始", `${selectedPacket.captured} / ${selectedPacket.original}`]]} />
          <div className="pcap-simple-payload"><label>Payload<textarea className="single-textarea compact-textarea" value={selectedPacket.payloadPreview || "--"} readOnly /></label><label>Hex<textarea className="single-textarea compact-textarea" value={selectedPacket.hexPreview || "--"} readOnly /></label></div>
        </section>}
      </>}
      {httpDetail && <HttpMessageModal item={httpDetail} t={t} english={english} onClose={() => setHttpDetail(null)} onFollow={() => { const key = httpDetail.streamKey; if (key) { setSelectedStreamKey(key); setView("streams"); } setHttpDetail(null); }} />}
    </div>
  );
}

function HttpMessageModal({ item, t, english, onClose, onFollow }: { item: PcapHttpItem; t: (typeof copy)["zh"]; english: boolean; onClose: () => void; onFollow: () => void }) {
  React.useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  const fullText = item.headers ? `${item.headers}\r\n\r\n${item.bodyPreview}` : item.bodyPreview;
  const downloadMessage = () => {
    downloadBlob(`http-${item.packetNo}-${item.role}.txt`, new Blob([fullText], { type: "text/plain;charset=utf-8" }));
  };
  const title = item.role === "request" ? `${item.method} ${item.path}` : item.line;
  return (
    <div className="image-lightbox pcap-http-modal" role="dialog" aria-modal="true" aria-label={title} onClick={onClose}>
      <div className="image-lightbox-inner pcap-http-modal-inner" onClick={(event) => event.stopPropagation()}>
        <div className="image-lightbox-head">
          <strong><span className={`pcap-http-role role-${item.role}`}>{item.role === "request" ? (english ? "Request" : "请求") : (english ? "Response" : "响应")}</span> {title}</strong>
          <div className="image-lightbox-actions">
            <AButton variant="outlined" onClick={() => void copyText(fullText)}>{t.copyMessage}</AButton>
            <AButton variant="outlined" onClick={downloadMessage}>{t.downloadMessage}</AButton>
            {item.streamKey && <AButton variant="text" onClick={onFollow}>{t.followTcpStream}</AButton>}
            <AButton variant="text" onClick={onClose}>{t.closePreview}</AButton>
          </div>
        </div>
        <div className="pcap-http-modal-meta">
          <span>{english ? "Host" : "主机"}: {item.host}</span>
          <span>{english ? "Type" : "类型"}: {item.contentType || "--"}</span>
          <span>{english ? "Body" : "正文"}: {formatBytes(item.bodySize)}</span>
          <span>#{item.packetNo}</span>
          {item.streamKey && <span>{english ? "Stream" : "流"}: {item.streamKey}</span>}
        </div>
        {item.headers ? (
          <>
            <div className="pcap-http-section-label">{t.httpHeaders}</div>
            <pre className="pcap-http-headers">{item.headers}</pre>
            <div className="pcap-http-section-label">{t.httpMessageBody}</div>
            <textarea className="single-textarea pcap-http-body" value={item.bodyPreview || "--"} readOnly aria-label={english ? "HTTP body" : "HTTP 正文"} />
          </>
        ) : (
          <div className="pcap-stream-notice">{t.noHeadersCaptured}</div>
        )}
      </div>
    </div>
  );
}
