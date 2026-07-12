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

import React from "react";
import { parsePcap } from "../features/pcap/analyzer";
import { AButton, ALinearProgress, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import type { PcapInfo } from "../models";
import { downloadBlob, formatBytes } from "../utils/files";

const MAX_PCAP_BYTES = 128 * 1024 * 1024;

function endpoint(value: string, port: number | null) {
  return port == null ? value : `${value}:${port}`;
}

export function PcapTool({ t }: { t: (typeof copy)["zh"] }) {
  const english = t.waiting === "Waiting";
  const [pcap, setPcap] = React.useState<PcapInfo | null>(null);
  const [selectedPacketNo, setSelectedPacketNo] = React.useState<number | null>(null);
  const [packetFilter, setPacketFilter] = React.useState("");
  const [view, setView] = React.useState<"overview" | "conversations" | "packets" | "network" | "files">("overview");
  const [packetPage, setPacketPage] = React.useState(0);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [dropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);

  const packets = React.useMemo(() => {
    const value = packetFilter.trim().toLowerCase();
    const rows = pcap?.packets ?? [];
    return rows.filter((packet) => !value || [packet.no, packet.protocol, packet.source, packet.destination, packet.sourcePort, packet.destinationPort, packet.info].join(" ").toLowerCase().includes(value));
  }, [packetFilter, pcap]);
  const packetPageCount = Math.max(1, Math.ceil(packets.length / 250));
  const visiblePackets = packets.slice(packetPage * 250, (packetPage + 1) * 250);
  const selectedPacket = pcap?.packets.find((packet) => packet.no === selectedPacketNo) ?? null;

  const loadFile = async (file?: File) => {
    if (!file) return;
    setDropActive(false);
    setError("");
    if (file.size > MAX_PCAP_BYTES) {
      setError(english ? "The capture exceeds the 128 MiB limit." : "流量包超过 128 MiB 限制。");
      return;
    }
    setLoading(true);
    try {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const bytes = new Uint8Array(await file.arrayBuffer());
      const next = parsePcap(bytes, file.name, file.size, "");
      setPcap(next);
      setSelectedPacketNo(next.packets[0]?.no ?? null);
      setPacketFilter("");
      setPacketPage(0);
      setView("overview");
    } catch (caught) {
      setPcap(null);
      setSelectedPacketNo(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  };

  const clear = () => {
    setPcap(null);
    setSelectedPacketNo(null);
    setPacketFilter("");
    setPacketPage(0);
    setView("overview");
    setError("");
    if (inputRef.current) inputRef.current.value = "";
  };

  const saveExtracted = (index: number) => {
    const file = pcap?.extractedFiles[index];
    if (!file) return;
    const bytes = new Uint8Array(file.bytes.length);
    bytes.set(file.bytes);
    downloadBlob(file.filename || `http-payload-${index + 1}.bin`, new Blob([bytes.buffer], { type: file.contentType !== "--" ? file.contentType : "application/octet-stream" }));
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

  return (
    <div className={`tool-grid pcap-workbench ${pcap ? "has-pcap" : "empty-pcap"}`}>
      <section className="tool-panel wide-panel pcap-source-panel">
        <ToolPanelHeader title={english ? "Packet capture" : "流量包来源"} actions={<AButton variant="text" disabled={!pcap && !error} onClick={clear}>{t.clear}</AButton>} />
        <input ref={inputRef} type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" onChange={(event) => void loadFile(event.target.files?.[0])} />
        <div className={`desktop-drop-zone ${dropActive ? "active" : ""}`} role="button" tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }}
          onDragOver={(event) => { event.preventDefault(); setDropActive(true); }} onDragLeave={() => setDropActive(false)}
          onDrop={(event) => { event.preventDefault(); void loadFile(event.dataTransfer.files?.[0]); }}>
          <strong>{pcap?.name || t.dropFileTitle}</strong>
          <span>{pcap ? `${pcap.format} · ${pcap.packets.length} ${english ? "packets" : "个数据包"}` : t.dropFileHint}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
        </div>
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
            <ASegmentedButton value="packets" onClick={() => setView("packets")}>{t.packetList} ({pcap.packets.length})</ASegmentedButton>
            <ASegmentedButton value="network" onClick={() => setView("network")}>HTTP / DNS ({pcap.httpItems.length + pcap.dnsItems.length})</ASegmentedButton>
            <ASegmentedButton value="files" disabled={!pcap.extractedFiles.length} onClick={() => setView("files")}>{english ? "Files" : "文件"} ({pcap.extractedFiles.length})</ASegmentedButton>
          </ASegmentedGroup>

          {view === "overview" && <div className="pcap-simple-overview">
            <InfoTable rows={[[english ? "Format" : "格式", `${pcap.format} ${pcap.version}`.trim()], [english ? "File size" : "文件大小", formatBytes(pcap.size)], [english ? "HTTP / DNS" : "HTTP / DNS", `${pcap.httpItems.length} / ${pcap.dnsItems.length}`], [english ? "Extracted files" : "提取文件", String(pcap.extractedFiles.length)]]} />
            <div className="pcap-simple-stat-grid">
              <section><strong>{english ? "Protocols" : "协议"}</strong><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Packets" : "数据包"}</th></tr></thead><tbody>{(pcap.summary?.protocols ?? []).map(([name, count]) => <tr key={name}><td>{name}</td><td>{count}</td></tr>)}</tbody></table></div></section>
              <section><strong>{english ? "Top endpoints" : "主要端点"}</strong><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english ? "Endpoint" : "端点"}</th><th>{english ? "Traffic" : "流量"}</th></tr></thead><tbody>{pcap.endpoints.slice(0, 12).map((item) => <tr key={item.endpoint}><td>{item.endpoint}</td><td>{formatBytes(item.bytesSent + item.bytesReceived)}</td></tr>)}</tbody></table></div></section>
              <section><strong>{english ? "Top services" : "主要服务"}</strong><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english ? "Port" : "端口"}</th><th>{english ? "Traffic" : "流量"}</th></tr></thead><tbody>{pcap.portStats.slice(0, 12).map((item) => <tr key={`${item.protocol}-${item.port}`}><td>{item.protocol}/{item.port}</td><td>{formatBytes(item.bytes)}</td></tr>)}</tbody></table></div></section>
            </div>
          </div>}

          {view === "conversations" && (pcap.conversations.length ? <div className="table-scroll pcap-conversation-scroll"><table className="data-table"><thead><tr><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Endpoint A" : "端点 A"}</th><th>{english ? "Endpoint B" : "端点 B"}</th><th>{english ? "Packets" : "数据包"}</th><th>{english ? "Bytes" : "字节"}</th></tr></thead><tbody>{pcap.conversations.slice(0, 1000).map((item) => <tr key={item.key}><td>{item.protocol}</td><td>{item.endpointA}</td><td>{item.endpointB}</td><td>{item.packets}</td><td>{formatBytes(item.bytes)}</td></tr>)}</tbody></table></div> : <div className="empty-state">--</div>)}

          {view === "packets" && <div className="pcap-simple-packets">
            <input className="text-input pcap-filter" value={packetFilter} onChange={(event) => setPacketFilter(event.currentTarget.value)} placeholder={english ? "Filter protocol, host, port, or text" : "筛选协议、地址、端口或内容"} />
            <div className="table-scroll pcap-packet-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english ? "Time" : "时间"}</th><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Source" : "来源"}</th><th>{english ? "Destination" : "目标"}</th><th>{english ? "Length" : "长度"}</th><th>{english ? "Info" : "信息"}</th></tr></thead><tbody>{visiblePackets.map((packet) => <tr className={packet.no === selectedPacketNo ? "selected-row" : ""} key={packet.no} onClick={() => setSelectedPacketNo(packet.no)}><td>{packet.no}</td><td>{packet.timestamp.split("T")[1]?.replace("Z", "") ?? packet.timestamp}</td><td>{packet.protocol}</td><td>{endpoint(packet.source, packet.sourcePort)}</td><td>{endpoint(packet.destination, packet.destinationPort)}</td><td>{packet.captured}</td><td>{packet.info}</td></tr>)}</tbody></table></div>
            {packets.length > 250 && <div className="pcap-simple-pagination"><AButton variant="outlined" disabled={packetPage === 0} onClick={() => setPacketPage((value) => Math.max(0, value - 1))}>{english ? "Previous" : "上一页"}</AButton><span>{packetPage + 1} / {packetPageCount}</span><AButton variant="outlined" disabled={packetPage + 1 >= packetPageCount} onClick={() => setPacketPage((value) => Math.min(packetPageCount - 1, value + 1))}>{english ? "Next" : "下一页"}</AButton></div>}
          </div>}

          {view === "network" && <div className="pcap-simple-network">
            <section><strong>HTTP</strong>{pcap.httpItems.length ? <div className="table-scroll pcap-http-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english ? "Method" : "方法"}</th><th>Host</th><th>{english ? "Path" : "路径"}</th><th>{english ? "Type" : "类型"}</th></tr></thead><tbody>{pcap.httpItems.map((item) => <tr key={`${item.packetNo}-${item.line}`} onClick={() => { setSelectedPacketNo(item.packetNo); setView("packets"); }}><td>{item.packetNo}</td><td>{item.method}</td><td>{item.host}</td><td>{item.path}</td><td>{item.contentType}</td></tr>)}</tbody></table></div> : <div className="empty-state">--</div>}</section>
            <section><strong>DNS</strong>{pcap.dnsItems.length ? <div className="table-scroll pcap-dns-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english ? "Name" : "名称"}</th><th>{english ? "Type" : "类型"}</th></tr></thead><tbody>{pcap.dnsItems.map((item) => <tr key={`${item.packetNo}-${item.name}-${item.type}`} onClick={() => { setSelectedPacketNo(item.packetNo); setView("packets"); }}><td>{item.packetNo}</td><td>{item.name}</td><td>{item.type}</td></tr>)}</tbody></table></div> : <div className="empty-state">--</div>}</section>
          </div>}

          {view === "files" && <div className="table-scroll pcap-files-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english ? "Filename" : "文件名"}</th><th>Host</th><th>{english ? "Path" : "路径"}</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Size" : "大小"}</th><th /></tr></thead><tbody>{pcap.extractedFiles.map((item, index) => <tr key={`${item.packetNo}-${index}`}><td>{item.packetNo}</td><td>{item.filename}</td><td>{item.host}</td><td>{item.path}</td><td>{item.signature} / {item.contentType}</td><td>{formatBytes(item.size)}</td><td><AButton variant="outlined" onClick={() => saveExtracted(index)}>{english ? "Save" : "保存"}</AButton></td></tr>)}</tbody></table></div>}
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
