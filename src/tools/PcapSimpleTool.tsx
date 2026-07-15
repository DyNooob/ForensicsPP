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
import type { PcapInfo, PcapTcpStream } from "../models";
import { persistablePcapInfo } from "../features/pcap/analyzer";
import { downloadBlob, formatBytes } from "../utils/files";
import { hashBytesInWorker } from "../features/hash/task";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { runWorkerTask } from "../utils/workerTask";

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
  const [packetFilter, setPacketFilter] = React.useState("");
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
  const [dropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
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
      setPcap(value);
      resetExtractedHashes();
      setSelectedPacketNo(value.packets[0]?.no ?? null);
      setSelectedStreamKey(value.tcpStreams[0]?.key ?? "");
      setError("");
    }
  });
  const storageState = workspace.state;

  const packets = React.useMemo(() => {
    const value = packetFilter.trim().toLowerCase();
    const rows = pcap?.packets ?? [];
    return rows.filter((packet) => !value || [packet.no, packet.protocol, packet.source, packet.destination, packet.sourcePort, packet.destinationPort, packet.info].join(" ").toLowerCase().includes(value));
  }, [packetFilter, pcap]);
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
  const streams = React.useMemo(() => {
    const value = streamFilter.trim().toLowerCase();
    return (pcap?.tcpStreams ?? []).filter((stream) => !value || `${stream.endpointA} ${stream.endpointB}`.toLowerCase().includes(value));
  }, [pcap, streamFilter]);
  const selectedStream = pcap?.tcpStreams.find((stream) => stream.key === selectedStreamKey) ?? pcap?.tcpStreams[0] ?? null;
  const selectedStreamTranscript = React.useMemo(
    () => selectedStream ? streamTranscript(selectedStream, streamDirection, streamFormat) : "",
    [selectedStream, streamDirection, streamFormat]
  );

  const loadFile = async (file?: File) => {
    if (!file || !active) return;
    workspace.clear();
    resetExtractedHashes();
    setDropActive(false);
    setError("");
    abortRef.current?.abort();
    setPcap(null);
    setSelectedPacketNo(null);
    setPacketFilter("");
    setConversationFilter("");
    setNetworkFilter("");
    setStreamFilter("");
    setSelectedStreamKey("");
    setStreamDirection("both");
    setStreamFormat("text");
    setPacketPage(0);
    setView("overview");
    setLoading(false);
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
      const bytes = new Uint8Array(await file.arrayBuffer());
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
      setSelectedPacketNo(next.packets[0]?.no ?? null);
      setPacketFilter("");
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
    resetExtractedHashes();
    abortRef.current?.abort();
    abortRef.current = null;
    setPcap(null);
    setSelectedPacketNo(null);
    setPacketFilter("");
    setConversationFilter("");
    setNetworkFilter("");
    setStreamFilter("");
    setSelectedStreamKey("");
    setStreamDirection("both");
    setStreamFormat("text");
    setPacketPage(0);
    setView("overview");
    setLoading(false);
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
            <ASegmentedButton value="network" onClick={() => setView("network")}>HTTP / DNS ({pcap.httpItems.length + pcap.dnsItems.length})</ASegmentedButton>
            <ASegmentedButton value="files" disabled={!pcap.extractedFiles.length} onClick={() => setView("files")}>{english ? "Files" : "文件"} ({pcap.extractedFiles.length})</ASegmentedButton>
          </ASegmentedGroup>

          {view === "overview" && <div className="pcap-simple-overview">
            {(pcap.streamBytesLimited || pcap.extractedBytesLimited) && <div className="pcap-stream-notice" role="status">{english ? "This restored workspace keeps metadata and previews, but not all raw stream or extracted-file bytes. Re-analyze the capture before exporting." : "当前工作区只保留了元数据和预览，未保留全部流及提取文件的原始字节。导出前请重新分析流量包。"}</div>}
            <InfoTable rows={[[english ? "Format" : "格式", `${pcap.format} ${pcap.version}`.trim()], [english ? "File size" : "文件大小", formatBytes(pcap.size)], [english ? "HTTP / DNS" : "HTTP / DNS", `${pcap.httpItems.length} / ${pcap.dnsItems.length}`], [english ? "Extracted files" : "提取文件", String(pcap.extractedFiles.length)]]} />
            <div className="pcap-simple-stat-grid">
              <section><strong>{english ? "Protocols" : "协议"}</strong><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Packets" : "数据包"}</th></tr></thead><tbody>{(pcap.summary?.protocols ?? []).map(([name, count]) => <tr key={name}><td>{name}</td><td>{count}</td></tr>)}</tbody></table></div></section>
              <section><strong>{english ? "Top endpoints" : "主要端点"}</strong><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english ? "Endpoint" : "端点"}</th><th>{english ? "Traffic" : "流量"}</th></tr></thead><tbody>{pcap.endpoints.slice(0, 12).map((item) => <tr key={item.endpoint}><td>{item.endpoint}</td><td>{formatBytes(item.bytesSent + item.bytesReceived)}</td></tr>)}</tbody></table></div></section>
              <section><strong>{english ? "Top services" : "主要服务"}</strong><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english ? "Port" : "端口"}</th><th>{english ? "Traffic" : "流量"}</th></tr></thead><tbody>{pcap.portStats.slice(0, 12).map((item) => <tr key={`${item.protocol}-${item.port}`}><td>{item.protocol}/{item.port}</td><td>{formatBytes(item.bytes)}</td></tr>)}</tbody></table></div></section>
            </div>
          </div>}

          {view === "conversations" && (pcap.conversations.length ? <><div className="pcap-list-filter"><input className="text-input" value={conversationFilter} onChange={(event) => setConversationFilter(event.currentTarget.value)} placeholder={english ? "Filter protocol or endpoint" : "筛选协议或端点"} aria-label={english ? "Filter conversations" : "筛选会话"} /><span>{conversations.length}/{pcap.conversations.length}</span></div><div className="table-scroll pcap-conversation-scroll"><table className="data-table"><thead><tr><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Endpoint A" : "端点 A"}</th><th>{english ? "Endpoint B" : "端点 B"}</th><th>{english ? "Packets" : "数据包"}</th><th>{english ? "Bytes" : "字节"}</th></tr></thead><tbody>{conversations.map((item) => { const stream = pcap.tcpStreams.find((candidate) => candidate.key === item.key); const open = () => { if (stream) { setSelectedStreamKey(stream.key); setView("streams"); } else { setPacketFilter(endpointHost(item.endpointA)); setView("packets"); } }; return <tr key={item.key} tabIndex={0} onClick={open} onKeyDown={(event) => { if (event.key === "Enter") open(); }}><td>{item.protocol}</td><td>{item.endpointA}</td><td>{item.endpointB}</td><td>{item.packets}</td><td>{formatBytes(item.bytes)}</td></tr>; })}</tbody></table></div></> : <div className="empty-state">--</div>)}

          {view === "streams" && <div className="pcap-stream-workspace">
            <div className="pcap-list-filter"><input className="text-input" value={streamFilter} onChange={(event) => setStreamFilter(event.currentTarget.value)} placeholder={english ? "Filter TCP endpoints" : "筛选 TCP 端点"} aria-label={english ? "Filter TCP streams" : "筛选 TCP 流"} /><span>{streams.length}/{pcap.tcpStreams.length}</span></div>
            <div className="table-scroll pcap-stream-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english ? "Endpoint A" : "端点 A"}</th><th>{english ? "Endpoint B" : "端点 B"}</th><th>{english ? "Packets" : "数据包"}</th><th>{"A -> B"}</th><th>{"B -> A"}</th><th>{english ? "Capture gaps" : "捕获缺口"}</th></tr></thead><tbody>{streams.map((stream) => <tr className={stream.key === selectedStream?.key ? "selected-row" : ""} key={stream.key} tabIndex={0} onClick={() => setSelectedStreamKey(stream.key)} onKeyDown={(event) => { if (event.key === "Enter") setSelectedStreamKey(stream.key); }}><td>{pcap.tcpStreams.indexOf(stream)}</td><td>{stream.endpointA}</td><td>{stream.endpointB}</td><td>{stream.packetCount}</td><td>{formatBytes(stream.bytesAtoB)}</td><td>{formatBytes(stream.bytesBtoA)}</td><td>{formatBytes(stream.gapBytesAtoB + stream.gapBytesBtoA)}</td></tr>)}</tbody></table></div>
            {selectedStream && <div className="pcap-stream-detail">
              <ToolPanelHeader title={english ? "Follow TCP stream" : "查看 TCP 流"} subtitle={`${selectedStream.endpointA} <-> ${selectedStream.endpointB}`} actions={<><AButton variant="text" disabled={!selectedStreamTranscript} onClick={() => void copyText(selectedStreamTranscript)}>{t.copy}</AButton><AButton variant="text" disabled={!selectedStreamTranscript || Boolean(pcap.streamBytesLimited)} onClick={saveStreamTranscript}>{english ? "Save text" : "保存文本"}</AButton><AButton variant="outlined" disabled={Boolean(pcap.streamBytesLimited) || streamDirection === "both" || (streamDirection === "a-to-b" ? selectedStream.gapBytesAtoB : selectedStream.gapBytesBtoA) > 0 || !(streamDirection === "a-to-b" ? selectedStream.bytesAtoB : selectedStream.bytesBtoA)} onClick={saveStreamBytes}>{english ? "Save raw bytes" : "保存原始字节"}</AButton></>} />
              <div className="pcap-stream-controls">
                <ASegmentedGroup value={streamDirection} selects="single"><ASegmentedButton value="both" onClick={() => setStreamDirection("both")}>{english ? "Both" : "双向"}</ASegmentedButton><ASegmentedButton value="a-to-b" onClick={() => setStreamDirection("a-to-b")}>{"A -> B"}</ASegmentedButton><ASegmentedButton value="b-to-a" onClick={() => setStreamDirection("b-to-a")}>{"B -> A"}</ASegmentedButton></ASegmentedGroup>
                <ASegmentedGroup value={streamFormat} selects="single"><ASegmentedButton value="text" onClick={() => setStreamFormat("text")}>{english ? "Text" : "文本"}</ASegmentedButton><ASegmentedButton value="hex" onClick={() => setStreamFormat("hex")}>Hex</ASegmentedButton></ASegmentedGroup>
              </div>
              <div className="pcap-stream-meta"><span>{english ? "Payload" : "载荷"}: {formatBytes(selectedStream.bytesAtoB + selectedStream.bytesBtoA)}</span><span>{english ? "Retransmitted overlap" : "重传重叠"}: {formatBytes(selectedStream.retransmittedBytes)}</span><span>{english ? "Capture gaps" : "捕获缺口"}: {formatBytes(selectedStream.gapBytesAtoB + selectedStream.gapBytesBtoA)}</span></div>
              {(selectedStream.gapBytesAtoB || selectedStream.gapBytesBtoA) ? <div className="pcap-stream-notice">{english ? "The capture has sequence gaps. Gap markers are shown in the preview; raw export is available only for a complete direction." : "该流存在序列缺口，预览中已标出；只有无缺口的单向数据可以导出原始字节。"}</div> : null}
              {pcap.streamBytesLimited ? <div className="pcap-stream-notice">{english ? "The restored workspace does not contain all stream bytes. Re-analyze the capture before exporting." : "恢复的工作区未保留全部流字节，导出前请重新分析流量包。"}</div> : null}
              <textarea className="single-textarea pcap-stream-output" value={selectedStreamTranscript || "--"} readOnly aria-label={english ? "TCP stream content" : "TCP 流内容"} />
            </div>}
          </div>}

          {view === "packets" && <div className="pcap-simple-packets">
            <input className="text-input pcap-filter" value={packetFilter} onChange={(event) => setPacketFilter(event.currentTarget.value)} placeholder={english ? "Filter protocol, host, port, or text" : "筛选协议、地址、端口或内容"} />
            <div className="table-scroll pcap-packet-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english ? "Time" : "时间"}</th><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Source" : "来源"}</th><th>{english ? "Destination" : "目标"}</th><th>{english ? "Length" : "长度"}</th><th>{english ? "Info" : "信息"}</th></tr></thead><tbody>{visiblePackets.map((packet) => <tr className={packet.no === selectedPacketNo ? "selected-row" : ""} key={packet.no} onClick={() => setSelectedPacketNo(packet.no)}><td>{packet.no}</td><td>{packet.timestamp.split("T")[1]?.replace("Z", "") ?? packet.timestamp}</td><td>{packet.protocol}</td><td>{endpoint(packet.source, packet.sourcePort)}</td><td>{endpoint(packet.destination, packet.destinationPort)}</td><td>{packet.captured}</td><td>{packet.info}</td></tr>)}</tbody></table></div>
            {packets.length > 250 && <div className="pcap-simple-pagination"><AButton variant="outlined" disabled={packetPage === 0} onClick={() => setPacketPage((value) => Math.max(0, value - 1))}>{english ? "Previous" : "上一页"}</AButton><span>{packetPage + 1} / {packetPageCount}</span><AButton variant="outlined" disabled={packetPage + 1 >= packetPageCount} onClick={() => setPacketPage((value) => Math.min(packetPageCount - 1, value + 1))}>{english ? "Next" : "下一页"}</AButton></div>}
          </div>}

          {view === "network" && <div className="pcap-simple-network">
            <div className="pcap-list-filter"><input className="text-input" value={networkFilter} onChange={(event) => setNetworkFilter(event.currentTarget.value)} placeholder={english ? "Filter HTTP or DNS" : "筛选 HTTP 或 DNS"} aria-label={english ? "Filter HTTP and DNS" : "筛选 HTTP 和 DNS"} /><span>{visibleHttp.length + visibleDns.length}/{pcap.httpItems.length + pcap.dnsItems.length}</span></div>
            <section><strong>HTTP</strong>{pcap.httpItems.length ? <div className="table-scroll pcap-http-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english ? "Method" : "方法"}</th><th>Host</th><th>{english ? "Path" : "路径"}</th><th>{english ? "Type" : "类型"}</th></tr></thead><tbody>{visibleHttp.map((item) => <tr key={`${item.packetNo}-${item.line}`} onClick={() => { setSelectedPacketNo(item.packetNo); setView("packets"); }}><td>{item.packetNo}</td><td>{item.method}</td><td>{item.host}</td><td>{item.path}</td><td>{item.contentType}</td></tr>)}</tbody></table></div> : <div className="empty-state">--</div>}</section>
            <section><strong>DNS</strong>{pcap.dnsItems.length ? <div className="table-scroll pcap-dns-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english ? "Name" : "名称"}</th><th>{english ? "Type" : "类型"}</th></tr></thead><tbody>{visibleDns.map((item) => <tr key={`${item.packetNo}-${item.name}-${item.type}`} onClick={() => { setSelectedPacketNo(item.packetNo); setView("packets"); }}><td>{item.packetNo}</td><td>{item.name}</td><td>{item.type}</td></tr>)}</tbody></table></div> : <div className="empty-state">--</div>}</section>
          </div>}

          {view === "files" && <div className="table-scroll pcap-files-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english ? "Filename" : "文件名"}</th><th>Host</th><th>{english ? "Path" : "路径"}</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Size" : "大小"}</th><th>SHA-256</th><th /></tr></thead><tbody>{pcap.extractedFiles.map((item, index) => { const key = extractedFileKey(index); const hash = extractedHashes[key]; const bytesAvailable = extractedBytesAvailable(item); return <tr key={`${item.packetNo}-${index}`}><td>{item.packetNo}</td><td>{item.filename}</td><td>{item.host}</td><td>{item.path}</td><td>{item.signature} / {item.contentType}</td><td>{formatBytes(item.size)}</td><td>{hash ? <button type="button" className="pcap-extracted-hash" title={t.copy} onClick={() => void copyText(hash)}>{hash}</button> : <AButton variant="text" disabled={!bytesAvailable || Boolean(extractedHashingKey)} onClick={() => void hashExtractedFile(index)}>{extractedHashingKey === key ? (english ? "Calculating..." : "计算中...") : bytesAvailable ? (english ? "Calculate" : "计算") : (english ? "Re-analyze" : "需重新分析")}</AButton>}</td><td><AButton variant="outlined" disabled={!bytesAvailable} title={!bytesAvailable ? (english ? "Re-analyze the capture before saving" : "请重新分析流量包后保存") : undefined} onClick={() => saveExtracted(index)}>{english ? "Save" : "保存"}</AButton></td></tr>; })}</tbody></table></div>}
          {extractedHashError && <div className="empty-state error-state">{extractedHashError}</div>}
        </section>

        {view === "packets" && selectedPacket && <section className="tool-panel wide-panel pcap-simple-detail-panel">
          <ToolPanelHeader title={english ? "Selected packet" : "当前数据包"} subtitle={`#${selectedPacket.no} · ${selectedPacket.protocol}`} />
          <InfoTable rows={[["Flow", selectedPacket.flow], [english ? "Timestamp" : "时间", selectedPacket.timestamp], [english ? "Captured / Original" : "捕获 / 原始", `${selectedPacket.captured} / ${selectedPacket.original}`]]} />
          <div className="pcap-simple-payload"><label>Payload<textarea className="single-textarea compact-textarea" value={selectedPacket.payloadPreview || "--"} readOnly /></label><label>Hex<textarea className="single-textarea compact-textarea" value={selectedPacket.hexPreview || "--"} readOnly /></label></div>
        </section>}
      </>}
    </div>
  );
}
