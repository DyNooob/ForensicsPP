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
import { zipSync } from "fflate";
import { AButton, ALinearProgress, InfoTable, PanelTitle } from "../components/ui";
import {
  parsePcap,
  pcapConversationPacketMatch,
  pcapConversationsToCsv,
  pcapDnsToCsv,
  pcapEndpointsToCsv,
  pcapEventsToCsv,
  pcapExtractedFilesToCsv,
  pcapExtractionManifestText,
  pcapHttpToCsv,
  pcapPacketsToCsv,
  pcapPortsToCsv,
  pcapRelatedForConversation,
  pcapShortTime,
  pcapTimelineToCsv,
  pcapTrafficShare,
  pcapTriageCards,
  pcapWorkItemRows,
  pcapWorkItemsToCsv,
  pcapWorkbenchBundle,
  serializablePcapInfo
} from "../features/pcap/analyzer";
import { copy } from "../i18n";
import type { PcapConversation, PcapDnsItem, PcapExtractedFile, PcapHttpItem, PcapInfo } from "../models";
import { hexPreview } from "../utils/binary";
import { downloadBlob, downloadTextFile, formatBytes } from "../utils/files";
import { sha256Bytes, sha256BytesAsync } from "../utils/hash";

function pcapExtractedFileKey(item: PcapExtractedFile) {
  return `${item.packetNo}|${item.sha256}|${item.filename}|${item.size}`;
}

function pcapExtractedFileManifest(item: PcapExtractedFile) {
  return [
    `packet=${item.packetNo}`,
    `timestamp=${item.timestamp}`,
    `filename=${item.filename}`,
    `host=${item.host}`,
    `path=${item.path}`,
    `content_type=${item.contentType}`,
    `signature=${item.signature}`,
    `size=${item.size}`,
    `sha256=${item.sha256}`,
    `notes=${item.risk.join(", ") || "--"}`,
    "",
    item.preview
  ].join("\n");
}

function choosePcapDefaultSelection(info: PcapInfo) {
  const fileScore = (item: PcapExtractedFile) => (
    item.risk.length * 420
    + (/Windows PE|ELF|Mach-O|APK|JAR|script|archive|PDF|OLE/i.test(`${item.signature} ${item.contentType} ${item.filename}`) ? 180 : 0)
    + Math.min(Math.log2(Math.max(item.size, 1)), 24)
  );
  const httpScore = (item: PcapHttpItem) => (
    item.risk.length * 260
    + (/POST|PUT|DELETE/i.test(item.method) ? 80 : 0)
    + (/token|session|auth|login|admin|download|upload|cmd|shell|password/i.test(`${item.host} ${item.path} ${item.userAgent} ${item.bodyPreview}`) ? 90 : 0)
    + Math.min(Math.log2(Math.max(item.bodySize, 1)), 22)
  );
  const conversationScore = (conversation: PcapConversation) => {
    const related = pcapRelatedForConversation(info, conversation);
    return (
      conversation.risk.length * 260
      + related.files.length * 180
      + related.http.filter((item) => item.risk.length).length * 120
      + related.iocs.filter((item) => item.risk.length).length * 110
      + Math.min(Math.log2(Math.max(conversation.bytes, 1)), 30)
    );
  };
  const file = [...info.extractedFiles].sort((left, right) => fileScore(right) - fileScore(left) || left.filename.localeCompare(right.filename))[0] ?? null;
  const http = !file ? [...info.httpItems].sort((left, right) => httpScore(right) - httpScore(left) || left.packetNo - right.packetNo)[0] ?? null : null;
  const conversation = file
    ? info.conversations.find((candidate) => {
        const packet = info.packets.find((item) => item.no === file.packetNo);
        return packet ? pcapConversationPacketMatch(candidate, packet) : false;
      }) ?? null
    : http
    ? info.conversations.find((candidate) => {
        const packet = info.packets.find((item) => item.no === http.packetNo);
        return packet ? pcapConversationPacketMatch(candidate, packet) : false;
      }) ?? null
    : [...info.conversations].sort((left, right) => conversationScore(right) - conversationScore(left) || right.bytes - left.bytes)[0] ?? null;
  const packet = file
    ? info.packets.find((candidate) => candidate.no === file.packetNo) ?? null
    : http
    ? info.packets.find((candidate) => candidate.no === http.packetNo) ?? null
    : conversation
    ? info.packets.find((candidate) => pcapConversationPacketMatch(conversation, candidate)) ?? info.packets[0] ?? null
    : info.packets[0] ?? null;
  return {
    packetNo: packet?.no ?? null,
    conversationKey: conversation?.key ?? "",
    extractedFileKey: file ? pcapExtractedFileKey(file) : ""
  };
}

export function PcapTool({ t }: { t: (typeof copy)["zh"] }) {
  const english = t.waiting === "Waiting";
  const pcapLabels = React.useMemo(() => ({
    captured: english ? "Captured" : "捕获大小",
    packets: english ? "packets" : "个包",
    flows: english ? "flows" : "个会话",
    files: english ? "files" : "个文件",
    topFlow: english ? "Top flow" : "最大会话",
    topEndpoint: english ? "Top endpoint" : "最大端点",
    topService: english ? "Top service" : "主要服务",
    peakWindow: english ? "Peak window" : "峰值时段",
    sent: english ? "sent" : "发送",
    received: english ? "received" : "接收",
    name: english ? "Name" : "名称",
    bundleJson: english ? "Bundle JSON" : "工作区 JSON"
  }), [english]);
  const [pcap, setPcap] = React.useState<PcapInfo | null>(null);
  const [filter, setFilter] = React.useState("");
  const [selectedPacketNo, setSelectedPacketNo] = React.useState<number | null>(null);
  const [selectedConversationKey, setSelectedConversationKey] = React.useState("");
  const [selectedExtractedFileKey, setSelectedExtractedFileKey] = React.useState("");
  const [isParsingPcap, setParsingPcap] = React.useState(false);
  const [pcapError, setPcapError] = React.useState("");
  const [isPcapDropActive, setPcapDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const filteredPackets = React.useMemo(() => {
    const value = filter.trim().toLowerCase();
    const packets = pcap?.packets ?? [];
    if (!value) return packets.slice(0, 800);
    return packets.filter((packet) => [
      packet.no,
      packet.timestamp,
      packet.protocol,
      packet.source,
      packet.destination,
      packet.sourcePort,
      packet.destinationPort,
      packet.info
    ].join(" ").toLowerCase().includes(value)).slice(0, 800);
  }, [filter, pcap]);
  const selectedPacket = selectedPacketNo == null ? null : pcap?.packets.find((packet) => packet.no === selectedPacketNo) ?? null;
  const selectedConversation = selectedConversationKey ? pcap?.conversations.find((conversation) => conversation.key === selectedConversationKey) ?? null : null;
  const selectedExtractedFile = React.useMemo(() => {
    const files = pcap?.extractedFiles ?? [];
    if (!selectedExtractedFileKey) return null;
    return files.find((item) => pcapExtractedFileKey(item) === selectedExtractedFileKey) ?? null;
  }, [pcap, selectedExtractedFileKey]);
  const relatedConversation = pcap ? pcapRelatedForConversation(pcap, selectedConversation) : null;
  const workItemRows = React.useMemo(() => pcap ? pcapWorkItemRows(pcap) : [], [pcap]);
  const pcapTriage = React.useMemo(() => pcap ? pcapTriageCards(pcap) : [], [pcap]);
  const timelineMaxBytes = Math.max(1, ...(pcap?.timeline.map((bucket) => bucket.bytes) ?? [0]));
  const topPcapFlow = pcap?.conversations[0] ?? null;
  const topPcapEndpoint = pcap?.endpoints[0] ?? null;
  const topPcapService = pcap?.portStats[0] ?? null;
  const peakPcapBucket = pcap?.timeline.slice().sort((a, b) => b.bytes - a.bytes)[0] ?? null;
  const pcapDnsPreviewItems = React.useMemo(() => {
    const seen = new Set<string>();
    const rows: PcapDnsItem[] = [];
    for (const item of pcap?.dnsItems ?? []) {
      const key = `${item.name}|${item.type}`;
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push(item);
      if (rows.length >= 6) break;
    }
    return rows;
  }, [pcap]);
  const hasPcapInput = Boolean(pcap);
  const pcapVerdict = React.useMemo(() => {
    if (!pcap) {
      return {
        level: "info",
        title: t.waiting === "Waiting" ? "Waiting for capture" : "等待流量包",
        detail: t.waiting === "Waiting" ? "Upload a PCAP or PCAPNG file to inspect flows, HTTP, DNS, and extracted payloads locally." : "上传 PCAP 或 PCAPNG 后，在本地查看会话、HTTP、DNS 和提取载荷。"
      };
    }
    const dangerCard = pcapTriage.find((card) => card.level === "danger");
    if (dangerCard) {
      return {
        level: "warn",
        title: t.waiting === "Waiting" ? "Review heavy flows and extracts" : "重点复核重流量与提取项",
        detail: `${dangerCard.label}: ${dangerCard.detail}`
      };
    }
    const warnCard = pcapTriage.find((card) => card.level === "warn");
    if (warnCard) {
      return {
        level: "warn",
        title: t.waiting === "Waiting" ? "Traffic context is ready" : "流量上下文已整理",
        detail: `${warnCard.label}: ${warnCard.detail}`
      };
    }
    return {
      level: "info",
      title: t.waiting === "Waiting" ? "Local capture loaded" : "本地流量包已载入",
      detail: topPcapFlow ? `${topPcapFlow.protocol} · ${formatBytes(topPcapFlow.bytes)}` : pcap.name
    };
  }, [pcap, pcapTriage, t.waiting, topPcapFlow]);
  const pcapDesktopRows = React.useMemo<Array<[string, string]>>(() => (
    pcap
      ? [
          [t.packetList, String(pcap.summary?.packetCount ?? pcap.packets.length)],
          [pcapLabels.captured, formatBytes(pcap.summary?.totalCaptured ?? 0)],
          [t.conversations, String(pcap.conversations.length)],
          [t.extractedPayloads, String(pcap.extractedFiles.length)]
        ]
      : []
  ), [pcap, pcapLabels.captured, t.conversations, t.extractedPayloads, t.packetList]);
  const pcapCurrentFocus = React.useMemo(() => {
    if (!pcap) return { label: t.waiting === "Waiting" ? "Current focus" : "当前重点", title: "--", detail: "--" };
    if (selectedExtractedFile) {
      return {
        label: t.extractedPayloads,
        title: selectedExtractedFile.filename,
        detail: `${selectedExtractedFile.signature} · #${selectedExtractedFile.packetNo} · ${formatBytes(selectedExtractedFile.size)}`
      };
    }
    if (selectedConversation) {
      return {
        label: t.conversations,
        title: `${selectedConversation.protocol} · ${formatBytes(selectedConversation.bytes)}`,
        detail: `${selectedConversation.endpointA} <-> ${selectedConversation.endpointB}`
      };
    }
    if (selectedPacket) {
      return {
        label: t.packetList,
        title: `#${selectedPacket.no} ${selectedPacket.protocol}`,
        detail: `${selectedPacket.source} -> ${selectedPacket.destination}`
      };
    }
    if (topPcapFlow) {
      return {
        label: t.conversations,
        title: `${topPcapFlow.protocol} · ${formatBytes(topPcapFlow.bytes)}`,
        detail: `${topPcapFlow.endpointA} <-> ${topPcapFlow.endpointB}`
      };
    }
    return {
      label: t.waiting === "Waiting" ? "Current focus" : "当前重点",
      title: pcap.name,
      detail: pcap.sha256
    };
  }, [pcap, selectedConversation, selectedExtractedFile, selectedPacket, t.conversations, t.extractedPayloads, t.packetList, t.waiting, topPcapFlow]);
  React.useEffect(() => {
    if (!pcap) return;
    const packetStillExists = selectedPacketNo == null || pcap.packets.some((packet) => packet.no === selectedPacketNo);
    const conversationStillExists = !selectedConversationKey || pcap.conversations.some((conversation) => conversation.key === selectedConversationKey);
    const fileStillExists = !selectedExtractedFileKey || pcap.extractedFiles.some((item) => pcapExtractedFileKey(item) === selectedExtractedFileKey);
    if (packetStillExists && conversationStillExists && fileStillExists && (selectedPacketNo != null || selectedConversationKey || selectedExtractedFileKey)) return;
    const defaults = choosePcapDefaultSelection(pcap);
    setSelectedPacketNo(defaults.packetNo);
    setSelectedConversationKey(defaults.conversationKey);
    setSelectedExtractedFileKey(defaults.extractedFileKey);
  }, [pcap, selectedConversationKey, selectedExtractedFileKey, selectedPacketNo]);

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    setParsingPcap(true);
    setPcapError("");
    try {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      const sha256 = await sha256BytesAsync(bytes);
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      const next = parsePcap(bytes, file.name, file.size, sha256);
      const defaults = choosePcapDefaultSelection(next);
      setPcap(next);
      setSelectedPacketNo(defaults.packetNo);
      setSelectedConversationKey(defaults.conversationKey);
      setSelectedExtractedFileKey(defaults.extractedFileKey);
      setFilter("");
    } catch (caught) {
      setPcap(null);
      setSelectedPacketNo(null);
      setSelectedConversationKey("");
      setSelectedExtractedFileKey("");
      setFilter("");
      setPcapError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setParsingPcap(false);
      setPcapDropActive(false);
    }
  };
  const downloadPcapExtractedFile = (item: PcapExtractedFile, index: number) => {
    const copy = new Uint8Array(item.bytes.byteLength);
    copy.set(item.bytes);
    downloadBlob(`pcap-http-${index + 1}-${item.filename}`, new Blob([copy.buffer], { type: item.contentType !== "--" ? item.contentType : "application/octet-stream" }));
  };
  const downloadPcapExtractedZip = () => {
    if (!pcap?.extractedFiles.length) return;
    const files: Record<string, Uint8Array> = {};
    pcap.extractedFiles.forEach((item, index) => {
      const safeName = (item.filename || `http-payload-${index + 1}.bin`).split(/[\\/]/).pop()?.replace(/[^\w.\-()[\] 一-龥]+/g, "_") || `http-payload-${index + 1}.bin`;
      const copy = new Uint8Array(item.bytes.byteLength);
      copy.set(item.bytes);
      files[`files/${String(index + 1).padStart(3, "0")}-${safeName}`] = copy;
    });
    files["manifest.json"] = new TextEncoder().encode(JSON.stringify({
      generatedAt: new Date().toISOString(),
      source: { name: pcap.name, size: pcap.size, sha256: pcap.sha256 },
      files: pcap.extractedFiles.map((item, index) => ({
        index: index + 1,
        packetNo: item.packetNo,
        timestamp: item.timestamp,
        host: item.host,
        path: item.path,
        filename: item.filename,
        contentType: item.contentType,
        size: item.size,
        sha256: item.sha256,
        signature: item.signature,
        risk: item.risk
      }))
    }, null, 2));
    files["manifest.csv"] = new TextEncoder().encode(pcapExtractedFilesToCsv(pcap.extractedFiles));
    const zipped = zipSync(files, { level: 6 });
    downloadBlob(`pcap-extracted-files-${Date.now()}.zip`, new Blob([zipped], { type: "application/zip" }));
  };
  const clearPcap = () => {
    setPcap(null);
    setPcapError("");
    setFilter("");
    setSelectedPacketNo(null);
    setSelectedConversationKey("");
    setSelectedExtractedFileKey("");
  };
  const selectPcapPacket = (packetNo: number) => {
    setSelectedPacketNo(packetNo);
    setSelectedConversationKey("");
    setSelectedExtractedFileKey("");
  };
  const selectPcapConversation = (conversation: PcapConversation) => {
    setSelectedConversationKey(conversation.key);
    setSelectedExtractedFileKey("");
    const packet = pcap?.packets.find((candidate) => pcapConversationPacketMatch(conversation, candidate));
    setSelectedPacketNo(packet?.no ?? null);
  };
  const selectPcapExtractedFile = (item: PcapExtractedFile) => {
    setSelectedExtractedFileKey(pcapExtractedFileKey(item));
    setSelectedPacketNo(item.packetNo);
    setSelectedConversationKey("");
  };
  const pcapGuideCards = React.useMemo(
    () => (
      t.waiting === "Waiting"
        ? [
            { label: "Traffic", title: "Flows / Endpoints", detail: "Start with packet count, top conversations, heavy endpoints, and port distribution." },
            { label: "Protocol", title: "HTTP / DNS", detail: "Pivot from top traffic into HTTP requests, DNS lookups, and packet-level context." },
            { label: "Extraction", title: "Files / IOC", detail: "Keep extracted payloads, URLs, hosts, and related indicators in the same workbench." }
          ]
        : [
            { label: "流量", title: "会话 / 端点", detail: "先看包数量、重点会话、重流量端点和端口分布。" },
            { label: "协议", title: "HTTP / DNS", detail: "再从重点流量切到 HTTP 请求、DNS 记录和具体数据包上下文。" },
            { label: "提取", title: "文件 / IOC", detail: "把提取文件、URL、主机和相关指标统一留在同一个工作区。" }
          ]
    ),
    [t]
  );

  return (
    <div className={`tool-grid pcap-workbench ${hasPcapInput ? "has-pcap" : "empty-pcap"}`}>
      {pcap ? (
        <>
          <div
            className={`tool-panel pcap-loaded-source-panel ${isPcapDropActive ? "active" : ""}`}
            onDragOver={(event) => {
              event.preventDefault();
              setPcapDropActive(true);
            }}
            onDragLeave={() => setPcapDropActive(false)}
            onDrop={(event) => {
              event.preventDefault();
              void handleFile(event.dataTransfer.files?.[0]);
            }}
          >
            <PanelTitle title={t.waiting === "Waiting" ? "Capture source" : "流量包来源"} />
            <input ref={inputRef} type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/octet-stream" onChange={(event) => void handleFile(event.target.files?.[0])} />
            <div className="tool-section-header">
              <strong>{t.waiting === "Waiting" ? "Capture source data" : "流量包源数据"}</strong>
              <span>{t.waiting === "Waiting" ? "Keep the original PCAP visible while you pivot into flows, HTTP, DNS, extracted files, and packet-level review." : "在进入会话、HTTP、DNS、提取文件和数据包复核时，保持原始 PCAP 始终可见。"}</span>
            </div>
            <div
              className={`desktop-drop-zone pcap-drop-zone ${isPcapDropActive ? "active" : ""}`}
              role="button"
              tabIndex={0}
              onClick={() => inputRef.current?.click()}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  inputRef.current?.click();
                }
              }}
            >
              <strong>{pcap.name}</strong>
              <span>{`${pcap.summary?.packetCount ?? pcap.packets.length} ${pcapLabels.packets} · ${pcap.conversations.length} ${pcapLabels.flows} · ${pcap.httpItems.length} HTTP · ${pcap.dnsItems.length} DNS`}</span>
              <em>{`SHA256 ${pcap.sha256.slice(0, 24)}... · ${pcap.extractedFiles.length} ${pcapLabels.files}`}</em>
            </div>
            <div className="action-row source-action-row">
              <AButton disabled={isParsingPcap} onClick={() => inputRef.current?.click()}>{isParsingPcap ? `${t.analyze}...` : t.selectFile}</AButton>
              <AButton variant="outlined" disabled={!pcap.extractedFiles.length} onClick={downloadPcapExtractedZip}>下载提取文件 ZIP</AButton>
              <AButton variant="text" onClick={clearPcap}>{t.clear}</AButton>
            </div>
            {isParsingPcap && <ALinearProgress />}
            {pcapError && <pre className="result-box">{t.parseError}: {pcapError}</pre>}
          </div>

          <div className="tool-panel pcap-loaded-context-panel">
            <PanelTitle title={t.waiting === "Waiting" ? "Quick context" : "快速上下文"} />
            <div className="pcap-loaded-side">
              <div className="pcap-side-section">
                <div className="tool-section-header">
                  <strong>{t.waiting === "Waiting" ? "Quick checks" : "快速检查"}</strong>
                  <span>{t.waiting === "Waiting" ? "Keep packet count, volume, conversations, and extracted file count together before drilling into traffic review below." : "在进入下方流量复核前，先把包数、体量、会话数和提取文件数量放在一起看清楚。"}</span>
                </div>
                <div className="pcap-context-summary">
                  <strong>{pcapVerdict.title}</strong>
                  <span>{pcapVerdict.detail}</span>
                </div>
                <div className="pcap-desktop-status">
                  {pcapDesktopRows.map(([label, value]) => (
                    <button className="result-copy-card" type="button" key={label} disabled={value === "--"} onClick={() => value !== "--" && void navigator.clipboard.writeText(value)}>
                      <span>{label}</span>
                      <strong>{value}</strong>
                    </button>
                  ))}
                </div>
              </div>

              <div className="pcap-side-section">
                <div className="tool-section-header">
                  <strong>{t.waiting === "Waiting" ? "Current focus" : "当前重点"}</strong>
                  <span>{t.waiting === "Waiting" ? "Keep the most useful conversation, packet, or extracted file in view before moving into the larger review area." : "在进入更大的复核区之前，把当前最值得看的会话、数据包或提取文件保留在视线里。"}</span>
                </div>
                <div className="pcap-context-note">
                  <span>{pcapCurrentFocus.label}</span>
                  <strong>{pcapCurrentFocus.title}</strong>
                  <em>{pcapCurrentFocus.detail}</em>
                </div>
                <div className="button-row">
                  <AButton variant="outlined" onClick={() => void navigator.clipboard.writeText(pcap.sha256)}>SHA256</AButton>
                  <AButton variant="text" disabled={!selectedExtractedFile} onClick={() => selectedExtractedFile && downloadPcapExtractedFile(selectedExtractedFile, pcap.extractedFiles.indexOf(selectedExtractedFile))}>{t.download}</AButton>
                  <AButton variant="text" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
                </div>
              </div>
            </div>
          </div>
        </>
      ) : (
        <>
          <div
            className={`tool-panel pcap-empty-intake-panel ${isPcapDropActive ? "active" : ""}`}
            onDragOver={(event) => {
              event.preventDefault();
              setPcapDropActive(true);
            }}
            onDragLeave={() => setPcapDropActive(false)}
            onDrop={(event) => {
              event.preventDefault();
              void handleFile(event.dataTransfer.files?.[0]);
            }}
          >
            <PanelTitle title={t.uploadPcap} />
            <input ref={inputRef} type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/octet-stream" onChange={(event) => void handleFile(event.target.files?.[0])} />
            <div className="tool-section-header">
              <strong>{t.waiting === "Waiting" ? "Capture intake" : "流量包输入"}</strong>
              <span>{t.waiting === "Waiting" ? "Upload a PCAP or PCAPNG file to inspect flows, endpoints, HTTP, DNS, and extracted payloads." : "上传 PCAP 或 PCAPNG，统计会话、端点、HTTP、DNS 和提取载荷。"}</span>
            </div>
            <div
              className={`desktop-drop-zone pcap-drop-zone ${isPcapDropActive ? "active" : ""}`}
              role="button"
              tabIndex={0}
              onClick={() => inputRef.current?.click()}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  inputRef.current?.click();
                }
              }}
            >
              <strong>{t.dropFileTitle}</strong>
              <span>PCAP / PCAPNG</span>
              <em>{t.dropFileHint}</em>
            </div>
            <div className="action-row">
              <AButton disabled={isParsingPcap} onClick={() => inputRef.current?.click()}>{isParsingPcap ? `${t.analyze}...` : t.selectFile}</AButton>
              <AButton variant="text" disabled={!pcapError} onClick={clearPcap}>{t.clear}</AButton>
            </div>
            {isParsingPcap && <ALinearProgress />}
            {pcapError && <pre className="result-box">{t.parseError}: {pcapError}</pre>}
          </div>

          {!pcapError && !isParsingPcap && (
            <div className="tool-panel pcap-empty-guide-panel">
              <PanelTitle title={t.waiting === "Waiting" ? "Start Here" : "起步提示"} />
              <div className="workbench-guide-grid">
                {pcapGuideCards.map((card) => (
                  <article className="workbench-guide-card" key={`${card.label}-${card.title}`}>
                    <span>{card.label}</span>
                    <strong>{card.title}</strong>
                    <em>{card.detail}</em>
                  </article>
                ))}
              </div>
            </div>
          )}
        </>
      )}
      {pcap && (
        <div className="tool-panel wide-panel pcap-facts-panel">
          <PanelTitle title={t.waiting === "Waiting" ? "Traffic Summary" : "流量摘要"} />
          <div className="pcap-fact-grid">
            <button className="result-copy-card" type="button" disabled={!topPcapFlow} onClick={() => topPcapFlow && void navigator.clipboard.writeText(`${topPcapFlow.protocol}\t${topPcapFlow.endpointA} <-> ${topPcapFlow.endpointB}\t${topPcapFlow.packets} packets\t${formatBytes(topPcapFlow.bytes)}`)}>
              <span>{pcapLabels.topFlow}</span>
              <strong>{topPcapFlow ? `${formatBytes(topPcapFlow.bytes)} · ${topPcapFlow.protocol}` : "--"}</strong>
              <em>{topPcapFlow ? `${topPcapFlow.endpointA} <-> ${topPcapFlow.endpointB}` : "--"}</em>
            </button>
            <button className="result-copy-card" type="button" disabled={!topPcapEndpoint} onClick={() => topPcapEndpoint && void navigator.clipboard.writeText(`${topPcapEndpoint.endpoint}\t${formatBytes(topPcapEndpoint.bytesSent + topPcapEndpoint.bytesReceived)}\tsent ${formatBytes(topPcapEndpoint.bytesSent)}\treceived ${formatBytes(topPcapEndpoint.bytesReceived)}`)}>
              <span>{pcapLabels.topEndpoint}</span>
              <strong>{topPcapEndpoint ? formatBytes(topPcapEndpoint.bytesSent + topPcapEndpoint.bytesReceived) : "--"}</strong>
              <em>{topPcapEndpoint ? `${topPcapEndpoint.endpoint} · ↑ ${formatBytes(topPcapEndpoint.bytesSent)} / ↓ ${formatBytes(topPcapEndpoint.bytesReceived)}` : "--"}</em>
            </button>
            <button className="result-copy-card" type="button" disabled={!topPcapService} onClick={() => topPcapService && void navigator.clipboard.writeText(`${topPcapService.protocol}/${topPcapService.port}\t${formatBytes(topPcapService.bytes)}\t${topPcapService.packets} packets`)}>
              <span>{pcapLabels.topService}</span>
              <strong>{topPcapService ? `${topPcapService.protocol}/${topPcapService.port}` : "--"}</strong>
              <em>{topPcapService ? `${formatBytes(topPcapService.bytes)} · ${topPcapService.packets} ${pcapLabels.packets}` : "--"}</em>
            </button>
            <button className="result-copy-card" type="button" disabled={!peakPcapBucket} onClick={() => peakPcapBucket && void navigator.clipboard.writeText(`${peakPcapBucket.startTimestamp} -> ${peakPcapBucket.endTimestamp}\t${formatBytes(peakPcapBucket.bytes)}\t${peakPcapBucket.packets} packets\t${peakPcapBucket.topProtocol}`)}>
              <span>{pcapLabels.peakWindow}</span>
              <strong>{peakPcapBucket ? `${formatBytes(peakPcapBucket.bytes)} · ${peakPcapBucket.topProtocol}` : "--"}</strong>
              <em>{peakPcapBucket ? `${pcapShortTime(peakPcapBucket.startTimestamp)} - ${pcapShortTime(peakPcapBucket.endTimestamp)}` : "--"}</em>
            </button>
          </div>
        </div>
      )}
      {pcap && (
        <details className="pcap-advanced-shell image-advanced-shell wide-panel pcap-file-info-shell">
          <summary>
            <strong>{t.waiting === "Waiting" ? "File Info" : "文件信息"}</strong>
            <span>{t.waiting === "Waiting" ? "capture metadata and base exports" : "采集元数据和基础导出"}</span>
          </summary>
          <div className="pcap-advanced-stack">
            <div className="tool-panel wide-panel pcap-export-panel">
              <div className="panel-heading-row">
                <PanelTitle title={t.waiting === "Waiting" ? "Capture Metadata" : "采集元数据"} />
                <div className="button-row compact-buttons">
                  <AButton variant="outlined" onClick={() => void navigator.clipboard.writeText(pcap.sha256)}>SHA256</AButton>
                  <AButton variant="outlined" onClick={() => downloadTextFile(`pcap-${Date.now()}.json`, JSON.stringify(serializablePcapInfo(pcap), null, 2), "application/json;charset=utf-8")}>JSON</AButton>
                  <AButton variant="text" onClick={() => downloadTextFile(`pcap-workbench-bundle-${Date.now()}.json`, JSON.stringify(pcapWorkbenchBundle(pcap), null, 2), "application/json;charset=utf-8")}>{pcapLabels.bundleJson}</AButton>
                </div>
              </div>
            </div>
        <div className="tool-panel wide-panel advanced-panel">
          <PanelTitle title={t.pcapInfo} />
          <InfoTable
            rows={[
              [pcapLabels.name, pcap.name],
              [t.fileSize, formatBytes(pcap.size)],
              [t.signature, pcap.signature],
              [t.format, pcap.format],
              [t.endian, pcap.endian],
              [t.version, pcap.version],
              [t.snaplen, pcap.snaplen == null ? "--" : String(pcap.snaplen)],
              [t.linkType, pcap.linkType == null ? "--" : String(pcap.linkType)],
              [t.sha256, pcap.sha256]
            ]}
          />
          {pcap.findings.length ? (
            <div className="finding-list advanced-panel">
              {pcap.findings.map((finding) => (
                <div className={`finding-item ${finding.level}`} key={`${finding.title}-${finding.detail}`}>
                  <strong>{finding.title}</strong>
                  <span>{finding.detail}</span>
                </div>
              ))}
            </div>
          ) : null}
        </div>
          </div>
        </details>
      )}
      {pcap && (
        <div className="tool-panel wide-panel pcap-firstlook-panel">
          <PanelTitle title={t.waiting === "Waiting" ? "Traffic First Look" : "流量首屏"} />
          <div className="pcap-firstlook-grid">
            <section>
              <h3>{t.conversations}</h3>
              <div className="pcap-mini-list">
                {pcap.conversations.slice(0, 6).map((item) => (
                  <button key={item.key} type="button" onClick={() => selectPcapConversation(item)}>
                    <strong>{formatBytes(item.bytes)} <span>{pcapTrafficShare(item.bytes, pcap.summary?.totalCaptured ?? 0)}</span></strong>
                    <em>{item.protocol} {item.endpointA} <br /> {item.endpointB}</em>
                  </button>
                ))}
                {!pcap.conversations.length && <div className="empty-state">--</div>}
              </div>
            </section>
            <section>
              <h3>{t.pcapEndpointStats}</h3>
              <div className="pcap-mini-list">
                {pcap.endpoints.slice(0, 6).map((item) => {
                  const total = item.bytesSent + item.bytesReceived;
                  return (
                    <button key={item.endpoint} type="button" onClick={() => setFilter(item.endpoint.replace(/:\d+$/, ""))}>
                      <strong>{formatBytes(total)} <span>{pcapTrafficShare(total, (pcap.summary?.totalCaptured ?? 0) * 2)}</span></strong>
                      <em>{item.endpoint}<br />↑ {formatBytes(item.bytesSent)} / ↓ {formatBytes(item.bytesReceived)}</em>
                    </button>
                  );
                })}
                {!pcap.endpoints.length && <div className="empty-state">--</div>}
              </div>
            </section>
            <section>
              <h3>{t.topServices}</h3>
              <div className="pcap-mini-list">
                {pcap.portStats.slice(0, 6).map((item) => (
                  <button key={`${item.protocol}-${item.port}`} type="button" onClick={() => setFilter(`:${item.port}`)}>
                    <strong>{item.protocol}/{item.port} <span>{formatBytes(item.bytes)}</span></strong>
                    <em>{item.packets} {pcapLabels.packets} / {item.endpoints.slice(0, 3).join(" / ") || "--"}</em>
                  </button>
                ))}
                {!pcap.portStats.length && <div className="empty-state">--</div>}
              </div>
            </section>
            <section>
              <h3>HTTP / {t.extractedPayloads}</h3>
              <div className="pcap-mini-list">
                {pcap.extractedFiles.slice(0, 4).map((item) => (
                  <button key={`${item.packetNo}-${item.sha256}`} type="button" onClick={() => selectPcapExtractedFile(item)}>
                    <strong>{item.filename} <span>{formatBytes(item.size)}</span></strong>
                    <em>#{item.packetNo} {item.signature} / {item.contentType}</em>
                  </button>
                ))}
                {!pcap.extractedFiles.length && pcap.httpItems.slice(0, 4).map((item) => (
                  <button key={`${item.packetNo}-${item.host}-${item.path}`} type="button" onClick={() => {
                    selectPcapPacket(item.packetNo);
                    setFilter(item.host !== "--" ? item.host : String(item.packetNo));
                  }}>
                    <strong>{item.method} <span>#{item.packetNo}</span></strong>
                    <em>{item.host}{item.path !== "--" ? item.path : ""}</em>
                  </button>
                ))}
                {!pcap.extractedFiles.length && !pcap.httpItems.length && (
                  <button type="button" disabled>
                    <strong>DNS / IOC</strong>
                    <em>{pcap.dnsItems.length} DNS / {pcap.iocs.length} IOC</em>
                  </button>
                )}
              </div>
            </section>
          </div>
        </div>
      )}
      {pcap && (
        <div className="tool-panel wide-panel pcap-extract-panel">
          <div className="panel-heading-row">
            <PanelTitle title={t.waiting === "Waiting" ? "Extracts and Names" : "提取内容与域名"} />
            <div className="button-row compact-buttons">
              <AButton variant="outlined" disabled={!pcap.extractedFiles.length} onClick={downloadPcapExtractedZip}>Files ZIP</AButton>
              <AButton variant="text" onClick={() => void navigator.clipboard.writeText([
                `source=${pcap.name}`,
                `sha256=${pcap.sha256}`,
                `http=${pcap.httpItems.length}`,
                `dns=${pcap.dnsItems.length}`,
                `files=${pcap.extractedFiles.length}`,
                `iocs=${pcap.iocs.length}`
              ].join("\n"))}>复制摘要</AButton>
            </div>
          </div>
          <div className="pcap-extract-grid">
            <section>
              <h3>HTTP</h3>
              <div className="pcap-mini-list">
                {pcap.httpItems.slice(0, 5).map((item) => (
                  <button key={`${item.packetNo}-${item.host}-${item.line}`} type="button" onClick={() => {
                    selectPcapPacket(item.packetNo);
                    setFilter(item.host !== "--" ? item.host : String(item.packetNo));
                  }}>
                    <strong>{item.method} <span>{item.bodySize ? formatBytes(item.bodySize) : `#${item.packetNo}`}</span></strong>
                    <em>{item.host}{item.path !== "--" ? item.path : ""}</em>
                  </button>
                ))}
                {!pcap.httpItems.length && <div className="empty-state">--</div>}
              </div>
            </section>
            <section>
              <h3>DNS</h3>
              <div className="pcap-mini-list">
                {pcapDnsPreviewItems.map((item) => (
                  <button key={`${item.packetNo}-${item.name}-${item.type}`} type="button" onClick={() => {
                    selectPcapPacket(item.packetNo);
                    setFilter(item.name);
                  }}>
                    <strong>{item.name} <span>{item.type}</span></strong>
                    <em>#{item.packetNo} · {item.source} {"->"} {item.destination}</em>
                  </button>
                ))}
                {!pcapDnsPreviewItems.length && <div className="empty-state">--</div>}
              </div>
            </section>
            <section>
              <h3>{t.extractedPayloads}</h3>
              <div className="pcap-mini-list">
                {pcap.extractedFiles.slice(0, 5).map((item) => (
                  <button key={`${item.packetNo}-${item.sha256}`} type="button" onClick={() => selectPcapExtractedFile(item)}>
                    <strong>{item.filename} <span>{formatBytes(item.size)}</span></strong>
                    <em>{item.signature} · {item.contentType} · #{item.packetNo}</em>
                  </button>
                ))}
                {!pcap.extractedFiles.length && <div className="empty-state">--</div>}
              </div>
            </section>
            <section>
              <h3>Network IOC</h3>
              <div className="pcap-mini-list">
                {pcap.iocs.slice(0, 5).map((item) => (
                  <button key={item.id} type="button" onClick={() => void navigator.clipboard.writeText(item.value)}>
                    <strong>{item.type} <span>{t.copy}</span></strong>
                    <em>{item.value}</em>
                  </button>
                ))}
                {!pcap.iocs.length && <div className="empty-state">--</div>}
              </div>
            </section>
          </div>
        </div>
      )}
      {pcap && (selectedPacket || selectedExtractedFile || selectedConversation) && (
        <div className="tool-panel wide-panel pcap-current-quick-panel">
          <div className="panel-heading-row">
            <PanelTitle title={t.waiting === "Waiting" ? "Current Packet / File" : "当前包 / 文件"} />
            <div className="button-row compact-buttons">
              <AButton variant="outlined" disabled={!selectedPacket} onClick={() => selectedPacket && void navigator.clipboard.writeText(`#${selectedPacket.no}\t${selectedPacket.timestamp}\t${selectedPacket.protocol}\t${selectedPacket.source} -> ${selectedPacket.destination}\t${selectedPacket.info}`)}>{t.copy}</AButton>
              <AButton variant="text" disabled={!selectedExtractedFile} onClick={() => selectedExtractedFile && downloadPcapExtractedFile(selectedExtractedFile, pcap.extractedFiles.indexOf(selectedExtractedFile))}>{t.download}</AButton>
              <AButton variant="text" disabled={!selectedExtractedFile} onClick={() => selectedExtractedFile && void navigator.clipboard.writeText(pcapExtractedFileManifest(selectedExtractedFile))}>Manifest</AButton>
            </div>
          </div>
          <div className="pcap-current-grid">
            <button className="result-copy-card" type="button" disabled={!selectedPacket} onClick={() => selectedPacket && void navigator.clipboard.writeText(String(selectedPacket.no))}>
              <span>Packet</span>
              <strong>{selectedPacket ? `#${selectedPacket.no} ${selectedPacket.protocol}` : "--"}</strong>
            </button>
            <button className="result-copy-card" type="button" disabled={!selectedPacket} onClick={() => selectedPacket && void navigator.clipboard.writeText(`${selectedPacket.source}${selectedPacket.sourcePort == null ? "" : `:${selectedPacket.sourcePort}`}`)}>
              <span>Source</span>
              <strong>{selectedPacket ? `${selectedPacket.source}${selectedPacket.sourcePort == null ? "" : `:${selectedPacket.sourcePort}`}` : "--"}</strong>
            </button>
            <button className="result-copy-card" type="button" disabled={!selectedPacket} onClick={() => selectedPacket && void navigator.clipboard.writeText(`${selectedPacket.destination}${selectedPacket.destinationPort == null ? "" : `:${selectedPacket.destinationPort}`}`)}>
              <span>Destination</span>
              <strong>{selectedPacket ? `${selectedPacket.destination}${selectedPacket.destinationPort == null ? "" : `:${selectedPacket.destinationPort}`}` : "--"}</strong>
            </button>
            <button className="result-copy-card" type="button" disabled={!selectedConversation} onClick={() => selectedConversation && void navigator.clipboard.writeText(selectedConversation.key)}>
              <span>Conversation</span>
              <strong>{selectedConversation ? `${selectedConversation.protocol} · ${formatBytes(selectedConversation.bytes)}` : "--"}</strong>
            </button>
            <button className="result-copy-card" type="button" disabled={!selectedExtractedFile} onClick={() => selectedExtractedFile && void navigator.clipboard.writeText(selectedExtractedFile.sha256)}>
              <span>File SHA256</span>
              <strong>{selectedExtractedFile ? `${selectedExtractedFile.filename} · ${formatBytes(selectedExtractedFile.size)}` : "--"}</strong>
            </button>
            <button className="result-copy-card" type="button" disabled={!selectedExtractedFile} onClick={() => selectedExtractedFile && void navigator.clipboard.writeText(`${selectedExtractedFile.host}${selectedExtractedFile.path}`)}>
              <span>HTTP File</span>
              <strong>{selectedExtractedFile ? `${selectedExtractedFile.signature} · #${selectedExtractedFile.packetNo}` : "--"}</strong>
            </button>
          </div>
          {selectedPacket && (
            <pre className="pcap-current-preview">{[
              selectedPacket.info,
              selectedExtractedFile ? `\n[Current file]\n${pcapExtractedFileManifest(selectedExtractedFile)}` : ""
            ].filter(Boolean).join("\n")}</pre>
          )}
        </div>
      )}
      {pcap && (selectedPacket || selectedExtractedFile || selectedConversation) && (
        <details className="pcap-advanced-shell image-advanced-shell wide-panel pcap-current-shell">
          <summary>
            <strong>{t.waiting === "Waiting" ? "Selected Packet" : "当前包详情"}</strong>
            <span>{t.waiting === "Waiting" ? "packet, conversation, payload and file manifest" : "包、会话、载荷和文件清单"}</span>
          </summary>
          <div className="tool-panel wide-panel pcap-current-panel">
          <div className="panel-heading-row">
            <PanelTitle title="Current Traffic Item" />
            <div className="button-row compact-buttons">
              <AButton variant="outlined" disabled={!selectedPacket} onClick={() => selectedPacket && void navigator.clipboard.writeText(`#${selectedPacket.no}\t${selectedPacket.timestamp}\t${selectedPacket.protocol}\t${selectedPacket.source} -> ${selectedPacket.destination}\t${selectedPacket.info}`)}>{t.copy}</AButton>
              <AButton variant="text" disabled={!selectedConversation} onClick={() => selectedConversation && void navigator.clipboard.writeText(`${selectedConversation.protocol}\t${selectedConversation.endpointA} <-> ${selectedConversation.endpointB}\t${selectedConversation.packets} packets\t${formatBytes(selectedConversation.bytes)}`)}>{t.conversations}</AButton>
              <AButton variant="text" disabled={!selectedExtractedFile} onClick={() => selectedExtractedFile && downloadPcapExtractedFile(selectedExtractedFile, pcap.extractedFiles.indexOf(selectedExtractedFile))}>{t.download}</AButton>
              <AButton variant="text" disabled={!selectedExtractedFile} onClick={() => selectedExtractedFile && void navigator.clipboard.writeText(pcapExtractedFileManifest(selectedExtractedFile))}>Manifest</AButton>
            </div>
          </div>
          <div className="pcap-current-grid">
            <button className="result-copy-card" type="button" disabled={!selectedPacket} onClick={() => selectedPacket && void navigator.clipboard.writeText(String(selectedPacket.no))}>
              <span>Packet</span>
              <strong>{selectedPacket ? `#${selectedPacket.no} ${selectedPacket.protocol}` : "--"}</strong>
            </button>
            <button className="result-copy-card" type="button" disabled={!selectedPacket} onClick={() => selectedPacket && void navigator.clipboard.writeText(`${selectedPacket.source}${selectedPacket.sourcePort == null ? "" : `:${selectedPacket.sourcePort}`}`)}>
              <span>Source</span>
              <strong>{selectedPacket ? `${selectedPacket.source}${selectedPacket.sourcePort == null ? "" : `:${selectedPacket.sourcePort}`}` : "--"}</strong>
            </button>
            <button className="result-copy-card" type="button" disabled={!selectedPacket} onClick={() => selectedPacket && void navigator.clipboard.writeText(`${selectedPacket.destination}${selectedPacket.destinationPort == null ? "" : `:${selectedPacket.destinationPort}`}`)}>
              <span>Destination</span>
              <strong>{selectedPacket ? `${selectedPacket.destination}${selectedPacket.destinationPort == null ? "" : `:${selectedPacket.destinationPort}`}` : "--"}</strong>
            </button>
            <button className="result-copy-card" type="button" disabled={!selectedConversation} onClick={() => selectedConversation && void navigator.clipboard.writeText(selectedConversation.key)}>
              <span>Conversation</span>
              <strong>{selectedConversation ? `${selectedConversation.protocol} · ${formatBytes(selectedConversation.bytes)}` : "--"}</strong>
            </button>
            <button className="result-copy-card" type="button" disabled={!selectedExtractedFile} onClick={() => selectedExtractedFile && void navigator.clipboard.writeText(selectedExtractedFile.sha256)}>
              <span>File SHA256</span>
              <strong>{selectedExtractedFile ? `${selectedExtractedFile.filename} · ${formatBytes(selectedExtractedFile.size)}` : "--"}</strong>
            </button>
            <button className="result-copy-card" type="button" disabled={!selectedExtractedFile} onClick={() => selectedExtractedFile && void navigator.clipboard.writeText(`${selectedExtractedFile.host}${selectedExtractedFile.path}`)}>
              <span>HTTP File</span>
              <strong>{selectedExtractedFile ? `${selectedExtractedFile.signature} · #${selectedExtractedFile.packetNo}` : "--"}</strong>
            </button>
          </div>
          {selectedPacket && <pre className="pcap-current-preview">{[
            selectedPacket.info,
            selectedExtractedFile ? `\n[Current file]\n${pcapExtractedFileManifest(selectedExtractedFile)}` : ""
          ].filter(Boolean).join("\n")}</pre>}
          </div>
        </details>
      )}
      {pcap && (
        <details className="pcap-advanced-shell image-advanced-shell wide-panel pcap-detail-shell">
          <summary>
            <strong>{t.detailedResultsMode}</strong>
            <span>{t.waiting === "Waiting" ? "packets, endpoints, HTTP/DNS, timeline, and exports" : "包列表、端点、HTTP/DNS、时间线和导出"}</span>
          </summary>
          <div className="pcap-advanced-stack">
            <div className="tool-panel wide-panel pcap-export-panel">
              <div className="panel-heading-row">
                <PanelTitle title={t.waiting === "Waiting" ? "Export" : "导出"} />
                <div className="button-row compact-buttons">
                  <AButton variant="outlined" disabled={!pcap.conversations.length} onClick={() => downloadTextFile(`pcap-conversations-${Date.now()}.csv`, pcapConversationsToCsv(pcap.conversations), "text/csv;charset=utf-8")}>Conversations CSV</AButton>
                  <AButton variant="outlined" disabled={!pcap.endpoints.length} onClick={() => downloadTextFile(`pcap-endpoints-${Date.now()}.csv`, pcapEndpointsToCsv(pcap.endpoints), "text/csv;charset=utf-8")}>Endpoints CSV</AButton>
                  <AButton variant="outlined" disabled={!pcap.portStats.length} onClick={() => downloadTextFile(`pcap-services-${Date.now()}.csv`, pcapPortsToCsv(pcap.portStats), "text/csv;charset=utf-8")}>Services CSV</AButton>
                  <AButton variant="text" disabled={!pcap.packets.length} onClick={() => downloadTextFile(`pcap-packets-${Date.now()}.csv`, pcapPacketsToCsv(pcap.packets), "text/csv;charset=utf-8")}>Packets CSV</AButton>
                  <AButton variant="text" disabled={!pcap.httpItems.length} onClick={() => downloadTextFile(`pcap-http-${Date.now()}.csv`, pcapHttpToCsv(pcap.httpItems), "text/csv;charset=utf-8")}>HTTP CSV</AButton>
                  <AButton variant="text" disabled={!pcap.dnsItems.length} onClick={() => downloadTextFile(`pcap-dns-${Date.now()}.csv`, pcapDnsToCsv(pcap.dnsItems), "text/csv;charset=utf-8")}>DNS CSV</AButton>
                  <AButton variant="text" disabled={!pcap.extractedFiles.length} onClick={() => downloadTextFile(`pcap-files-${Date.now()}.csv`, pcapExtractedFilesToCsv(pcap.extractedFiles), "text/csv;charset=utf-8")}>Files CSV</AButton>
                  <AButton variant="text" disabled={!pcap.timeline.length} onClick={() => downloadTextFile(`pcap-timeline-${Date.now()}.csv`, pcapTimelineToCsv(pcap.timeline), "text/csv;charset=utf-8")}>Timeline CSV</AButton>
                  <AButton variant="text" disabled={!pcap.events.length} onClick={() => downloadTextFile(`pcap-events-${Date.now()}.csv`, pcapEventsToCsv(pcap.events), "text/csv;charset=utf-8")}>Events CSV</AButton>
                  <AButton variant="text" disabled={!pcap.extractedFiles.length} onClick={downloadPcapExtractedZip}>Files ZIP</AButton>
                  <AButton variant="text" onClick={() => downloadTextFile(`pcap-workbench-bundle-${Date.now()}.json`, JSON.stringify(pcapWorkbenchBundle(pcap), null, 2), "application/json;charset=utf-8")}>Bundle JSON</AButton>
                  <AButton variant="text" onClick={() => void navigator.clipboard.writeText(pcapExtractionManifestText(pcap))}>复制清单</AButton>
                </div>
              </div>
            </div>
      <div className="tool-panel wide-panel pcap-matrix-panel advanced-panel">
        <div className="panel-heading-row">
          <PanelTitle title={t.waiting === "Waiting" ? "Traffic Extraction Items" : "流量提取项"} />
          <div className="button-row compact-buttons">
            <AButton variant="outlined" disabled={!pcap} onClick={() => pcap && downloadTextFile(`pcap-extraction-items-${Date.now()}.csv`, pcapWorkItemsToCsv(pcap), "text/csv;charset=utf-8")}>CSV</AButton>
            <AButton variant="outlined" disabled={!pcap} onClick={() => pcap && void navigator.clipboard.writeText(pcapExtractionManifestText(pcap))}>复制清单</AButton>
            <AButton variant="outlined" disabled={!pcap} onClick={() => pcap && downloadTextFile(`pcap-workbench-bundle-${Date.now()}.json`, JSON.stringify(pcapWorkbenchBundle(pcap), null, 2), "application/json;charset=utf-8")}>Bundle JSON</AButton>
          </div>
        </div>
        {workItemRows.length ? (
          <div className="table-scroll pcap-matrix-scroll">
            <table className="data-table">
              <thead><tr><th>{english ? "Section" : "项目"}</th><th>{english ? "Count" : "数量"}</th><th>{english ? "Primary" : "主要内容"}</th><th>{english ? "Volume" : "数据量"}</th><th>{english ? "Notes" : "记录"}</th><th>{english ? "Next Action" : "后续操作"}</th></tr></thead>
              <tbody>
                {workItemRows.map((row) => (
                  <tr className={row.risk ? "soft-selected-row" : ""} key={row.section}>
                    <td>{row.section}</td>
                    <td>{row.count}</td>
                    <td>{row.primary}</td>
                    <td>{row.volume}</td>
                    <td>{row.risk}</td>
                    <td>{row.action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="empty-state">{pcap ? "--" : t.waiting}</div>}
      </div>
      <div className="tool-panel wide-panel pcap-timeline-panel advanced-panel">
        <div className="panel-heading-row">
          <PanelTitle title="Traffic Timeline" />
          <div className="button-row compact-buttons">
            <AButton variant="outlined" disabled={!pcap?.timeline.length} onClick={() => pcap && downloadTextFile(`pcap-timeline-${Date.now()}.csv`, pcapTimelineToCsv(pcap.timeline), "text/csv;charset=utf-8")}>Timeline CSV</AButton>
            <AButton variant="outlined" disabled={!pcap?.events.length} onClick={() => pcap && downloadTextFile(`pcap-events-${Date.now()}.csv`, pcapEventsToCsv(pcap.events), "text/csv;charset=utf-8")}>Events CSV</AButton>
          </div>
        </div>
        {pcap?.timeline.length ? (
          <div className="pcap-timeline-layout">
            <div className="pcap-timeline-chart" aria-label="Traffic timeline">
              {pcap.timeline.map((bucket) => (
                <button
                  className={`pcap-timeline-bar ${bucket.bytes === timelineMaxBytes ? "peak" : ""}`}
                  key={bucket.index}
                  type="button"
                  title={`${bucket.startTimestamp} - ${bucket.endTimestamp}\n${formatBytes(bucket.bytes)} / ${bucket.packets} packets / ${bucket.topProtocol}`}
                  onClick={() => {
                    const packet = pcap.packets.find((candidate) => candidate.timestamp >= bucket.startTimestamp && candidate.timestamp <= bucket.endTimestamp);
                    if (packet) selectPcapPacket(packet.no);
                  }}
                >
                  <span style={{ height: `${Math.max(4, bucket.bytes / timelineMaxBytes * 100)}%` }} />
                  <em>{bucket.topProtocol}</em>
                </button>
              ))}
            </div>
            <div className="pcap-timeline-detail">
              <InfoTable
                rows={[
                  ["Buckets", String(pcap.timeline.length)],
                  ["Peak", pcap.timeline.slice().sort((a, b) => b.bytes - a.bytes)[0] ? `${pcap.timeline.slice().sort((a, b) => b.bytes - a.bytes)[0].label} / ${formatBytes(timelineMaxBytes)}` : "--"],
                  ["Events", String(pcap.events.length)],
                  ["Top protocols in peak", pcap.timeline.slice().sort((a, b) => b.bytes - a.bytes)[0]?.protocols.map(([name, count]) => `${name}:${count}`).join(", ") || "--"]
                ]}
              />
            </div>
            <div className="pcap-event-list">
              {pcap.events.length ? pcap.events.slice(0, 40).map((event) => (
                <button
                  className={`pcap-event-card ${event.level}`}
                  key={`${event.timestamp}-${event.title}-${event.packetNo ?? ""}-${event.detail.slice(0, 60)}`}
                  type="button"
                  onClick={() => event.packetNo && selectPcapPacket(event.packetNo)}
                >
                  <span>{pcapShortTime(event.timestamp)}{event.packetNo ? ` / #${event.packetNo}` : ""}</span>
                  <strong>{event.title}</strong>
                  <em>{event.detail}</em>
                  {event.flow ? <small>{event.flow}</small> : null}
                </button>
              )) : <div className="empty-state">No priority event</div>}
            </div>
          </div>
        ) : <div className="empty-state">{pcap ? "--" : t.waiting}</div>}
      </div>
      {pcap && (
      <div className="tool-panel wide-panel advanced-panel">
        <PanelTitle title={t.pcapStats} />
        {pcap.summary ? (
          <>
            <InfoTable
              rows={[
                ["Packets", String(pcap.summary.packetCount)],
                ["Captured bytes", formatBytes(pcap.summary.totalCaptured)],
                ["First timestamp", pcap.summary.firstTimestamp],
                ["Last timestamp", pcap.summary.lastTimestamp],
                ["Protocols", pcap.summary.protocols.map(([name, count]) => `${name}: ${count}`).join(", ") || "--"],
                ["DNS names", pcap.summary.dnsNames.join(", ") || "--"],
                ["HTTP hosts", pcap.summary.httpHosts.join(", ") || "--"]
              ]}
            />
            <PanelTitle title={t.protocolStats} />
            <div className="table-scroll compact-scroll">
              <table className="data-table">
                <thead><tr><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Packets" : "数据包"}</th><th>{english ? "Share" : "占比"}</th></tr></thead>
                <tbody>
                  {pcap.summary.protocols.map(([name, count]) => (
                    <tr key={name}>
                      <td>{name}</td>
                      <td>{count}</td>
                      <td>{pcap.summary ? `${(count / Math.max(1, pcap.summary.packetCount) * 100).toFixed(2)}%` : "--"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <PanelTitle title="Top Talkers" />
            <div className="table-scroll compact-scroll">
              <table className="data-table">
                <thead><tr><th>{english ? "Endpoint" : "通信端"}</th><th>{english ? "Bytes" : "字节"}</th><th>{english ? "Share" : "占比"}</th></tr></thead>
                <tbody>
                  {pcap.summary.topTalkers.map(([host, bytes]) => (
                    <tr key={host}>
                      <td>{host}</td>
                      <td>{formatBytes(bytes)}</td>
                      <td>{`${(bytes / Math.max(1, (pcap.summary?.totalCaptured ?? 0) * 2) * 100).toFixed(2)}%`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <PanelTitle title={t.topServices} />
            <div className="table-scroll compact-scroll">
              <table className="data-table">
                <thead><tr><th>{english ? "Service" : "服务"}</th><th>{english ? "Bytes" : "字节"}</th><th>{english ? "Share" : "占比"}</th></tr></thead>
                <tbody>
                  {pcap.summary.topServices.map(([service, bytes]) => (
                    <tr key={service}>
                      <td>{service}</td>
                      <td>{formatBytes(bytes)}</td>
                      <td>{`${(bytes / Math.max(1, pcap.summary?.totalCaptured ?? 0) * 100).toFixed(2)}%`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <div className="empty-state">{t.waiting}</div>
        )}
      </div>
      )}

      <div className="tool-panel wide-panel advanced-panel">
        <PanelTitle title={t.pcapEndpointStats} />
        {pcap?.endpoints.length ? (
          <div className="table-scroll pcap-endpoint-scroll">
            <table className="data-table">
              <thead><tr><th>{english ? "Endpoint" : "通信端"}</th><th>{english ? "Packets Sent" : "发送包"}</th><th>{english ? "Packets Received" : "接收包"}</th><th>{t.pcapSentBytes}</th><th>{t.pcapReceivedBytes}</th><th>{english ? "Total" : "总计"}</th><th>{english ? "Protocols" : "协议"}</th><th>{english ? "Ports" : "端口"}</th><th>{english ? "First" : "首次"}</th><th>{english ? "Last" : "末次"}</th><th>{t.iocRisk}</th></tr></thead>
              <tbody>
                {pcap.endpoints.slice(0, 160).map((item) => (
                  <tr className={item.risk.length ? "soft-selected-row" : ""} key={item.endpoint}>
                    <td>{item.endpoint}</td>
                    <td>{item.packetsSent}</td>
                    <td>{item.packetsReceived}</td>
                    <td>{formatBytes(item.bytesSent)}</td>
                    <td>{formatBytes(item.bytesReceived)}</td>
                    <td>{formatBytes(item.bytesSent + item.bytesReceived)}</td>
                    <td>{item.protocols.join(", ") || "--"}</td>
                    <td>{item.ports.join(", ") || "--"}</td>
                    <td>{item.firstTimestamp}</td>
                    <td>{item.lastTimestamp}</td>
                    <td>{item.risk.join(", ") || "--"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="empty-state">{pcap ? "--" : t.waiting}</div>}
      </div>

      <div className="tool-panel wide-panel advanced-panel">
        <PanelTitle title={t.pcapServiceStats} />
        {pcap?.portStats.length ? (
          <div className="table-scroll pcap-service-scroll">
            <table className="data-table">
              <thead><tr><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Port" : "端口"}</th><th>{english ? "Packets" : "数据包"}</th><th>{english ? "Bytes" : "字节"}</th><th>{english ? "Endpoints" : "通信端"}</th><th>{t.iocRisk}</th></tr></thead>
              <tbody>
                {pcap.portStats.slice(0, 160).map((item) => (
                  <tr className={item.risk.length ? "soft-selected-row" : ""} key={`${item.protocol}-${item.port}`}>
                    <td>{item.protocol}</td>
                    <td>{item.port}</td>
                    <td>{item.packets}</td>
                    <td>{formatBytes(item.bytes)}</td>
                    <td>{item.endpoints.join(", ") || "--"}</td>
                    <td>{item.risk.join(", ") || "--"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="empty-state">{pcap ? "--" : t.waiting}</div>}
      </div>

      <div className="tool-panel wide-panel pcap-packet-list-panel advanced-panel">
        <div className="panel-heading-row">
          <PanelTitle title={t.packetList} />
          <input className="text-input pcap-filter" value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder="tcp / dns / 192.168 / host" />
        </div>
        {filteredPackets.length ? (
          <div className="table-scroll pcap-packet-scroll">
            <table className="data-table pcap-packet-table">
              <thead><tr><th>{english ? "No." : "序号"}</th><th>{english ? "Time" : "时间"}</th><th>{english ? "Delta" : "间隔"}</th><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Source" : "来源"}</th><th>{english ? "Destination" : "目标"}</th><th>{english ? "Length" : "长度"}</th><th>{english ? "Info" : "信息"}</th></tr></thead>
              <tbody>
                {filteredPackets.map((packet) => (
                  <tr className={packet.no === selectedPacket?.no ? "selected-row" : ""} key={packet.no} onClick={() => selectPcapPacket(packet.no)}>
                    <td>{packet.no}</td>
                    <td>{packet.timestamp.split("T")[1]?.replace("Z", "") ?? packet.timestamp}</td>
                    <td>{packet.deltaMs.toFixed(3)} ms</td>
                    <td>{packet.protocol}</td>
                    <td>{packet.sourcePort == null ? packet.source : `${packet.source}:${packet.sourcePort}`}</td>
                    <td>{packet.destinationPort == null ? packet.destination : `${packet.destination}:${packet.destinationPort}`}</td>
                    <td>{packet.captured}</td>
                    <td>{packet.info}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="empty-state">{pcap ? "--" : t.waiting}</div>}
      </div>

      <div className="tool-panel wide-panel advanced-panel">
        <PanelTitle title={t.packetPreview} />
        {selectedPacket ? (
          <>
            <InfoTable rows={[
              ["No.", String(selectedPacket.no)],
              ["Timestamp", selectedPacket.timestamp],
              ["Delta", `${selectedPacket.deltaMs.toFixed(3)} ms`],
              ["Protocol", selectedPacket.protocol],
              ["Source", selectedPacket.sourcePort == null ? selectedPacket.source : `${selectedPacket.source}:${selectedPacket.sourcePort}`],
              ["Destination", selectedPacket.destinationPort == null ? selectedPacket.destination : `${selectedPacket.destination}:${selectedPacket.destinationPort}`],
              ["Flow", selectedPacket.flow],
              ["Captured / Original", `${selectedPacket.captured} / ${selectedPacket.original}`],
              ["Payload SHA256", selectedPacket.payloadBytes.length ? sha256Bytes(selectedPacket.payloadBytes) : "--"],
              ["Info", selectedPacket.info]
            ]} />
            <div className="text-columns">
              <label>
                ASCII / Payload
                <textarea className="single-textarea compact-textarea" value={selectedPacket.payloadPreview} readOnly />
              </label>
              <label>
                Hex
                <textarea className="single-textarea compact-textarea" value={selectedPacket.hexPreview} readOnly />
              </label>
            </div>
          </>
        ) : <div className="empty-state">{t.waiting}</div>}
      </div>

      <div className="tool-panel wide-panel advanced-panel">
        <PanelTitle title={t.conversations} />
        {pcap?.conversations.length ? (
          <div className="table-scroll compact-scroll">
            <table className="data-table">
              <thead><tr><th>{english ? "Protocol" : "协议"}</th><th>{english ? "Endpoint A" : "通信端 A"}</th><th>{english ? "Endpoint B" : "通信端 B"}</th><th>{english ? "Packets" : "数据包"}</th><th>{english ? "Bytes" : "字节"}</th><th>{english ? "First" : "首次"}</th><th>{english ? "Last" : "末次"}</th><th>{t.iocRisk}</th></tr></thead>
              <tbody>
                {pcap.conversations.map((item) => (
                  <tr
                    className={item.key === selectedConversation?.key ? "selected-row" : item.risk.length ? "soft-selected-row" : ""}
                    key={item.key}
                    onClick={() => selectPcapConversation(item)}
                  >
                    <td>{item.protocol}</td>
                    <td>{item.endpointA}</td>
                    <td>{item.endpointB}</td>
                    <td>{item.packets}</td>
                    <td>{formatBytes(item.bytes)}</td>
                    <td>{item.firstTimestamp}</td>
                    <td>{item.lastTimestamp}</td>
                    <td>{item.risk.join(", ") || "--"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="empty-state">{pcap ? "--" : t.waiting}</div>}
      </div>

      <div className="tool-panel wide-panel pcap-conversation-detail-panel advanced-panel">
        <PanelTitle title="Conversation Detail" />
        {selectedConversation && relatedConversation ? (
          <>
            <InfoTable rows={[
              ["Protocol", selectedConversation.protocol],
              ["Endpoint A", selectedConversation.endpointA],
              ["Endpoint B", selectedConversation.endpointB],
              ["Packets / Bytes", `${selectedConversation.packets} / ${formatBytes(selectedConversation.bytes)}`],
              ["First / Last", `${selectedConversation.firstTimestamp} / ${selectedConversation.lastTimestamp}`],
              [t.checks, selectedConversation.risk.join(", ") || "--"],
              ["Related HTTP / DNS / Files / IOC", `${relatedConversation.http.length} / ${relatedConversation.dns.length} / ${relatedConversation.files.length} / ${relatedConversation.iocs.length}`]
            ]} />
            <div className="pcap-related-grid">
              <div>
                <strong>Packets</strong>
                <span>{relatedConversation.packets.slice(0, 12).map((packet) => `#${packet.no} ${packet.protocol} ${formatBytes(packet.captured)} ${packet.info}`).join("\n") || "--"}</span>
              </div>
              <div>
                <strong>HTTP</strong>
                <span>{relatedConversation.http.slice(0, 8).map((item) => `#${item.packetNo} ${item.method} ${item.host}${item.path !== "--" ? item.path : ""}${item.risk.length ? ` (${item.risk.join(", ")})` : ""}`).join("\n") || "--"}</span>
              </div>
              <div>
                <strong>DNS</strong>
                <span>{relatedConversation.dns.slice(0, 10).map((item) => `#${item.packetNo} ${item.type} ${item.name}`).join("\n") || "--"}</span>
              </div>
              <div>
                <strong>Files / IOC</strong>
                <span>{[
                  ...relatedConversation.files.slice(0, 5).map((item) => `file #${item.packetNo} ${item.filename} ${item.signature} ${formatBytes(item.size)}`),
                  ...relatedConversation.iocs.slice(0, 8).map((item) => `${item.type}: ${item.value}`)
                ].join("\n") || "--"}</span>
              </div>
            </div>
          </>
        ) : <div className="empty-state">{pcap ? "--" : t.waiting}</div>}
      </div>

      <div className="tool-panel wide-panel advanced-panel">
        <PanelTitle title={t.httpExtract} />
        {pcap?.httpItems.length ? (
          <div className="table-scroll pcap-http-scroll">
            <table className="data-table">
              <thead><tr><th>{english ? "No." : "序号"}</th><th>{english ? "Method" : "方法"}</th><th>{english ? "Host" : "主机"}</th><th>{english ? "Path" : "路径"}</th><th>{english ? "Line" : "请求行"}</th><th>User-Agent</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Body" : "正文"}</th><th>{t.iocRisk}</th><th>{english ? "Source" : "来源"}</th><th>{english ? "Destination" : "目标"}</th></tr></thead>
              <tbody>
                {pcap.httpItems.map((item) => (
                  <tr className={item.risk.length ? "soft-selected-row" : ""} key={`${item.packetNo}-${item.line}`} onClick={() => selectPcapPacket(item.packetNo)}>
                    <td>{item.packetNo}</td>
                    <td>{item.method}</td>
                    <td>{item.host}</td>
                    <td><code>{item.path}</code></td>
                    <td>{item.line}</td>
                    <td>{item.userAgent}</td>
                    <td>{item.contentType}</td>
                    <td>{item.bodySize ? `${formatBytes(item.bodySize)} / ${item.bodySha256.slice(0, 12)}...` : "--"}</td>
                    <td>{item.risk.join(", ") || "--"}</td>
                    <td>{item.source}</td>
                    <td>{item.destination}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="empty-state">{pcap ? "--" : t.waiting}</div>}
      </div>

      <div className="tool-panel wide-panel advanced-panel">
        <PanelTitle title="HTTP File Candidates" />
        {pcap?.extractedFiles.length ? (
          <div className="table-scroll pcap-files-scroll">
            <table className="data-table">
              <thead><tr><th>{english ? "No." : "序号"}</th><th>{english ? "Filename" : "文件名"}</th><th>{english ? "Host" : "主机"}</th><th>{english ? "Path" : "路径"}</th><th>{english ? "Type" : "类型"}</th><th>{t.fileSize}</th><th>SHA256</th><th>{t.entryRisk}</th><th>{t.preview}</th><th>{t.download}</th></tr></thead>
              <tbody>
                {pcap.extractedFiles.map((item, index) => (
                  <tr
                    className={selectedExtractedFile && pcapExtractedFileKey(item) === pcapExtractedFileKey(selectedExtractedFile) ? "selected-row" : item.risk.length ? "soft-selected-row" : ""}
                    key={`${item.packetNo}-${item.sha256}`}
                    onClick={() => selectPcapExtractedFile(item)}
                  >
                    <td>{item.packetNo}</td>
                    <td>{item.filename}</td>
                    <td>{item.host}</td>
                    <td><code>{item.path}</code></td>
                    <td>{item.signature} / {item.contentType}</td>
                    <td>{formatBytes(item.size)}</td>
                    <td><code>{item.sha256.slice(0, 18)}...</code></td>
                    <td>{item.risk.join(", ") || "--"}</td>
                    <td><code>{item.preview.slice(0, 120)}</code></td>
                    <td><AButton variant="outlined" onClick={(event) => { event.stopPropagation(); downloadPcapExtractedFile(item, index); }}>{t.download}</AButton></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="empty-state">{pcap ? "--" : t.waiting}</div>}
      </div>

      <div className="tool-panel wide-panel advanced-panel">
        <PanelTitle title={t.dnsExtract} />
        {pcap?.dnsItems.length ? (
          <div className="table-scroll compact-scroll">
            <table className="data-table">
              <thead><tr><th>{english ? "No." : "序号"}</th><th>{english ? "Name" : "名称"}</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Source" : "来源"}</th><th>{english ? "Destination" : "目标"}</th></tr></thead>
              <tbody>
                {pcap.dnsItems.map((item) => (
                  <tr key={`${item.packetNo}-${item.name}-${item.type}`} onClick={() => selectPcapPacket(item.packetNo)}>
                    <td>{item.packetNo}</td>
                    <td>{item.name}</td>
                    <td>{item.type}</td>
                    <td>{item.source}</td>
                    <td>{item.destination}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="empty-state">{pcap ? "--" : t.waiting}</div>}
      </div>

      <div className="tool-panel wide-panel advanced-panel">
        <PanelTitle title="Network IOC" />
        {pcap?.iocs.length ? (
          <div className="table-scroll compact-scroll">
            <table className="data-table">
              <thead><tr><th>{t.detectedType}</th><th>{t.sampleValue}</th><th>{t.iocNormalized}</th><th>{t.iocRisk}</th><th>{t.copy}</th></tr></thead>
              <tbody>
                {pcap.iocs.slice(0, 300).map((item) => (
                  <tr className={item.risk.length ? "soft-selected-row" : ""} key={item.id}>
                    <td>{item.type}</td>
                    <td>{item.value}</td>
                    <td>{item.normalized}</td>
                    <td>{item.risk.join(", ") || "--"}</td>
                    <td><AButton variant="text" onClick={() => void navigator.clipboard.writeText(item.value)}>{t.copy}</AButton></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="empty-state">{pcap ? "--" : t.waiting}</div>}
      </div>
          </div>
        </details>
      )}
    </div>
  );
}
