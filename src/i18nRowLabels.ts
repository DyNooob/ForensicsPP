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

import { getUiLang } from "./uiLang";

/**
 * Common English row/column labels emitted by analyzers (left column of
 * `InfoTable`). In the Chinese locale these are translated; in English they
 * pass through unchanged. Conventional acronyms and proper nouns (MD5, SHA-256,
 * UUID, GUID, CRC, HTTP, DNS, TLS, JSON, XML, ID, MIME-only, ...) are
 * intentionally NOT listed so they stay in English.
 *
 * Lookup is exact (case-insensitive, trimmed). Unknown labels fall back to the
 * original string, so analyzer data values never get mistranslated.
 */
const ROW_LABEL_ZH: Record<string, string> = {
  name: "名称",
  type: "类型",
  size: "大小",
  "file type": "文件类型",
  "file size": "文件大小",
  "detected type": "检测类型",
  "artifact type": "工件类型",
  status: "状态",
  format: "格式",
  version: "版本",
  description: "描述",
  summary: "摘要",
  category: "类别",
  level: "级别",
  severity: "严重度",
  tool: "工具",
  input: "输入",
  output: "输出",
  result: "结果",
  value: "值",
  key: "键",
  "key type": "密钥类型",
  encoding: "编码",
  "encoding type": "编码类型",
  algorithm: "算法",
  "hash algorithm": "哈希算法",
  method: "方法",
  source: "来源",
  target: "目标",
  timestamp: "时间戳",
  created: "创建时间",
  modified: "修改时间",
  accessed: "访问时间",
  owner: "所有者",
  group: "用户组",
  permissions: "权限",
  path: "路径",
  comment: "注释",
  title: "标题",
  author: "作者",
  subject: "主题",
  keywords: "关键词",
  software: "软件",
  device: "设备",
  "device model": "设备型号",
  model: "型号",
  make: "厂商",
  serial: "序列号",
  "serial number": "序列号",
  latitude: "纬度",
  longitude: "经度",
  altitude: "海拔",
  date: "日期",
  time: "时间",
  index: "索引",
  offset: "偏移",
  length: "长度",
  count: "数量",
  total: "总计",
  "total size": "总大小",
  "total files": "文件总数",
  width: "宽度",
  height: "高度",
  channels: "通道",
  samples: "样本",
  rate: "速率",
  duration: "时长",
  start: "开始",
  end: "结束",
  flow: "流",
  magic: "魔数",
  segments: "段",
  entropy: "熵",
  signature: "签名",
  compression: "压缩方式",
  "compressed bits": "压缩比特",
  extensions: "扩展名",
  "mime type": "MIME 类型",
  confidence: "置信度",
  verdict: "判定",
  risk: "风险",
  recommendation: "建议",
  rule: "规则",
  "rule name": "规则名称",
  strings: "字符串",
  hash: "哈希",
  digest: "摘要",
  checksum: "校验和",
  "block size": "块大小",
  iterations: "迭代次数",
  salt: "盐值",
  hidden: "隐藏",
  encrypted: "已加密",
  compressed: "已压缩",
  events: "事件",
  files: "文件",
  rows: "行",
  columns: "列",
  original: "原始",
  captured: "已捕获",
  matches: "匹配",
  candidates: "候选",
  detected: "检测到",
  "sensitive fields": "敏感字段",
  statements: "语句数",
  tables: "表数量",
  "http header value": "HTTP 头值",
  "signature value": "签名值",
  component: "组件",
  "component type": "组件类型",
  "subkeys": "子键",
  values: "值数量",
  "detected_type": "检测类型",
  "matches_2": "匹配",
  "events_2": "事件",
  "timestamp_2": "时间戳",
  "captured_original": "已捕获 / 原始",
  "file_size": "文件大小",
  "extracted_files": "提取文件"
};

/** Localizes a `InfoTable` row label for the active locale; falls back to the raw label. */
export function localizeRowLabel(label: string): string {
  if (!label) return label;
  const lang = getUiLang();
  if (lang === "en") return label;
  const hit = ROW_LABEL_ZH[label.trim().toLowerCase()];
  return hit ?? label;
}
