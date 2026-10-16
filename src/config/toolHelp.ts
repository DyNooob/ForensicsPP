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

import type { ToolId } from "./app";

export const toolHelp: Partial<Record<ToolId, { zh: string; en: string }>> = {
  cyberchef: { zh: "将数据放入 Input，选择配方并查看 Output。Recipe 可组合编码、压缩和哈希操作。内置工具首次打开需载入较大的静态资源。", en: "Put data in Input, compose a Recipe and inspect Output. Recipes combine encoding, compression and hashes. The embedded tool loads a larger static bundle on first use." },
  codec: { zh: "选择输入格式后执行编码或解码；可载入示例。转换结果可复制，输入变化后需重新执行。编码不是加密。", en: "Choose a format, then encode or decode; a sample is available. Copy the output and run again after editing the input. Encoding does not provide encryption." },
  crypto: { zh: "选择凯撒、摩斯、栅栏等操作，再填写输入和对应参数并执行。载入示例可快速查看流程。这里的古典密码用于文本分析，不能用于保护现代敏感数据。", en: "Select a classical cipher operation, enter text and its parameters, then run. Load a sample to try the workflow. Classical ciphers are for text analysis and do not protect modern sensitive data." },
  jwt: { zh: "粘贴 JWT 后检查 Header、Payload 和声明；也可校验签名或本地签发测试令牌。能解码不代表签名有效。HMAC 校验需要共享密钥，非对称校验需要公钥。", en: "Paste a JWT to inspect its header, payload and claims, verify a signature or generate a test token locally. Decoding does not prove a valid signature. HMAC requires a shared secret; asymmetric verification requires a public key." },
  password: { zh: "选择生成、识别或校验模式。生成 bcrypt/PBKDF2 前确认参数；校验模式比较候选密码与给定哈希。密码保持在当前会话中，SQL 模板只生成文本，不会执行数据库修改。", en: "Choose generation, identification or verification. Confirm bcrypt/PBKDF2 parameters before generating; verification compares candidates against a supplied hash. Passwords stay in the session. SQL templates are text and never execute database changes." },
  sql: { zh: "打开 MySQL/SQL dump，解析 CREATE TABLE 与 INSERT 数据，再浏览字段摘要和记录。这里用于转储检查，不连接远程数据库；任意 SQL 查询请使用 SQLite 工作台。", en: "Open a MySQL/SQL dump to parse CREATE TABLE and INSERT data, then browse field summaries and records. This inspects dumps without connecting to remote databases; use the SQLite workbench for queries." },
  registry: { zh: "打开 NTUSER.DAT、SOFTWARE、SYSTEM 等二进制 Hive，浏览键和值。支持 Hive 结构，不接受 .reg 文本；.reg 文本请使用 Windows 文件解析。", en: "Open binary hives such as NTUSER.DAT, SOFTWARE or SYSTEM and browse keys and values. This tool expects hive structures, not .reg text; use Windows artifacts for .reg exports." },
  plist: { zh: "打开 XML 或二进制 Plist，逐层查看字典、数组、数据与日期。类型信息会保留，文本表示不替代原始文件。", en: "Open an XML or binary Plist and inspect dictionaries, arrays, data and dates. Types are preserved; the text view does not replace the original file." },
  urltool: { zh: "粘贴 URL 或 hxxp/方括号隔离表示，查看规范化地址、参数与编码表示。载入示例可查看参数解码。此工具只解析文本，不访问目标地址。", en: "Paste a URL or a defanged hxxp/bracketed form to inspect its normalized address, parameters and encodings. Load a sample to try parameter decoding. The tool parses text without visiting the target." },
  http: { zh: "粘贴或载入原始 HTTP 请求/响应，查看起始行、请求头、参数、Cookie 和正文。提供两种报文示例。此工具不发送请求，不进行 TCP 流重组；流量文件请使用 PCAP 工具。", en: "Paste or load a raw HTTP request/response to inspect the start line, headers, parameters, cookies and body. Request and response examples are available. It never sends the request or reassembles TCP; use PCAP for captures." },
  bulk: { zh: "选择文件后进行流式线索扫描，按类型和偏移检查命中结果。命中是候选线索，应结合原始字节和上下文复核；切换工具会释放重型资源。", en: "Select a file for streaming artifact scans and review hits by type and offset. Hits are leads that need verification against original bytes and context. Switching tools releases heavy resources." },
  hash: { zh: "选择文本或文件，勾选算法后点击计算。可粘贴已知摘要进行匹配，默认 SHA-256。哈希一致说明字节一致，不能单独证明来源或保管过程。", en: "Select text or files, choose algorithms and calculate. Paste known digests to compare; SHA-256 is selected by default. Matching hashes establish byte equality, not provenance or chain of custody." },
  timestamp: { zh: "输入时间戳后点击转换，检查格式候选、UTC 与本地时间。可载入示例或使用批量模式。多个候选可能同时合理，须结合来源确认单位、纪元与时区。", en: "Enter a timestamp and convert to inspect candidate formats, UTC and local time. Try a sample or batch mode. Several formats may be plausible; confirm units, epoch and timezone from the source." },
  timeline: { zh: "输入带时间的文本，或合并多个文件后构建时间线。按事件来源和行号复核，结果可导出；自动识别时间不保证所有记录都使用同一时区。", en: "Enter timestamped text or merge files and build a timeline. Verify events by source and line, then export. Automatic recognition does not establish a shared timezone for all records." },
  baseconvert: { zh: "输入数值并选择来源进制，查看转换结果。支持符号和字节表示；载入示例可从 255 开始。注意数值进制与文本字符编码是不同概念。", en: "Enter a value and choose its source base to inspect conversions. Signed values and byte representations are supported; load 255 as a sample. Numeric bases and text character encodings are different concepts." },
  uuid: { zh: "生成 UUID v4 或粘贴已有标识进行解析。只有部分版本包含可解释的时间；随机 UUID 不能据此推断创建时间。", en: "Generate UUID v4 or paste an identifier to inspect it. Only some versions contain interpretable timestamps; random UUIDs do not establish creation times." },
  json: { zh: "粘贴 JSON 后执行处理，检查格式、路径或展开结果。载入示例可快速试用。此工具处理数据，不执行 JSON 中的脚本或命令。", en: "Paste JSON and process it to inspect formatting, paths or expanded results. A sample is available. The tool handles data without executing scripts or commands contained in it." },
  regex: { zh: "输入表达式、标志和源文本，或载入示例与预设。查看匹配、分组、位置和替换结果。采用 JavaScript 正则语法，复杂表达式可能触发超时。", en: "Enter a pattern, flags and source text, or load a sample and preset. Inspect matches, groups, offsets and replacement output. This uses JavaScript regex syntax; complex patterns may time out." },
};
