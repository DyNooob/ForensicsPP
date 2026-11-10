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

import { getUiLang } from "../uiLang";
export type NoticeLevel = "danger" | "warn" | "info" | "success" | "pending";
export type PresentedFinding = { level: string; title: string; detail: string };
// UI copy only. Evidence bytes, EXIF values, filenames, claims and exported analyzer results stay intact.
const TITLES: Record<string, [string, string?]> = {
  "Invalid PNG chunk structure": ["PNG 数据块结构异常", "发现无效的宽高、长度或编码字段，或未知关键数据块。请在结构页核对具体字段；CRC 匹配不代表这些字段有效。"],
  "PNG CRC mismatch": ["PNG 校验失败", "文件内容与保存的 CRC 校验值不一致，可能被修改或损坏。若 IHDR 异常，请进入修复页恢复真实宽高。"],
  "CRC mismatch": ["CRC 校验失败", "数据与校验值不一致。先保留原文件，再检查数据块和修复候选。"],
  "PNG IHDR is not first": ["PNG 文件头顺序异常", "IHDR 应为首个数据块，顺序异常可能导致解码失败。"],
  "IHDR is not first": ["IHDR 文件头顺序异常"],
  "PNG IEND missing": ["PNG 缺少结束块", "未找到 IEND，文件可能被截断。可检查修复候选。"],
  "Missing IEND": ["缺少 IEND 结束块"],
  "Risky / private PNG chunks": ["PNG 数据块需要复核", "私有块和未知块也可能是合法扩展，请结合类型、偏移和内容判断。"],
  "PNG text metadata": ["发现 PNG 文本元数据", "已提取文本。元数据存在本身不代表异常。"],
  "Text metadata chunks": ["发现文本元数据块"],
  "Unknown/private chunks": ["发现未知或私有数据块"],
  "Chunks worth review": ["发现需要复核的数据块"],
  "Unusual critical chunk order": ["关键数据块顺序异常"],
  "Trailing data after IEND": ["PNG 结束后仍有数据", "尾部字节可能包含附加文件或其他内容，可单独提取核对。"],
  "Trailing data after image end": ["图片结束后仍有数据", "逻辑结束标记后存在额外字节，请查看隐藏数据页。"],
  "Trailing data after logical end": ["文件逻辑结束后仍有数据", "额外内容可能是附加数据，请核对偏移并按需提取。"],
  "Embedded signature in trailer": ["尾部发现文件特征", "特征命中是候选线索，需提取后验证文件是否完整。"],
  "High-entropy trailer": ["尾部数据熵较高", "高熵可能来自压缩、加密或普通二进制数据，不能单独作为加密证据。"],
  "Small IDAT ratio": ["像素压缩数据占比较低"],
  "PNG structure looks consistent": ["PNG 基础结构检查通过", "已检查 CRC、关键块顺序和尾部字节；通过不排除像素隐写。"],
  "GIF comment extension": ["发现 GIF 注释扩展"],
  "GIF application extension": ["发现 GIF 应用扩展"],
  "Data after GIF trailer": ["GIF 结束标记后仍有数据"],
  "JPEG embedded thumbnail": ["发现 JPEG 内嵌缩略图"],
  "JPEG EXIF present": ["已提取 JPEG EXIF"],
  "JPEG comment": ["发现 JPEG 注释"],
  "Animated WEBP": ["检测到动态 WEBP"],
  "WEBP EXIF present": ["已提取 WEBP EXIF"],
  "WEBP ICC profile": ["发现 WEBP 色彩配置"],
  "Indexed BMP": ["BMP 使用索引色"],
  "Compressed BMP": ["BMP 使用压缩编码"],
  "TIFF magic mismatch": ["TIFF 文件标识不匹配"],
  "TIFF IFD offset out of range": ["TIFF 目录偏移越界"],
  "No meta box": ["未找到元数据容器"],
  "High local noise anomaly": ["局部像素噪声需要复核", "这是一项启发式线索。查看噪声图中的规则轮廓，并与其他通道交叉验证。"],
  "Image end marker not found": ["未找到图片结束标记", "文件可能被截断或结构受损，仍可检查已解析的数据。"],
  "Embedded file signature": ["发现内嵌文件特征", "请验证提取项，文件特征命中不保证候选完整。"],
  "Embedded signature": ["发现内嵌文件特征"],
  "PNG structure parse failed": ["PNG 结构解析失败", "容器结构无法完整读取，修复预览不等同于恢复全部数据。"],
  "Large metadata surface": ["元数据内容较多"],
  "Pixel decode failed": ["图片像素无法解码", "已保留原始字节并继续容器检查。通道和二维码检查需要可解码的像素。"],
  "Image not decoded": ["图片像素无法解码"],
  "Image decoded": ["图片像素解码成功"],
  "Extractable payload candidate": ["发现可提取内容候选"],
  "Low-bit distribution note": ["低位像素分布线索", "像素分布特征需要结合位平面查看，不能单凭统计判断存在隐写。"],
  "Alpha channel carries data": ["透明通道包含数据"],
  "Readable LSB candidate": ["最低有效位发现可读内容候选"],
  "Printable LSB text candidate": ["最低有效位发现文本候选"],
  "No obvious hidden-data marker": ["基础扫描未发现明显隐藏标记", "仅表示已执行的扫描未命中，不代表不存在隐写。"],
  "Invalid PE header": ["PE 文件头无效", "存在 MZ 标识，但 PE 签名缺失或超出文件范围。"],
  "High entropy PE section": ["PE 节熵较高"],
  "PE overlay present": ["PE 文件存在附加数据"],
  "ASLR flag absent": ["未设置 ASLR 标志"],
  "NX compatibility flag absent": ["未设置 NX 兼容标志"],
  "Imports worth review": ["发现需要复核的导入函数"],
  "DLL file": ["检测为 DLL 文件"],
  "High entropy ELF section": ["ELF 节熵较高"],
  "Relative ELF RPATH": ["ELF RPATH 使用相对路径"],
  "Executable GNU stack": ["GNU 栈具有执行权限"],
  "Unknown file signature": ["未识别文件头特征"],
  "Extension mismatch": ["扩展名与文件头不一致", "可能是重命名、伪装或格式识别受限，需核对真实格式。"],
  "Filename review marker": ["文件名需要复核"],
  "Late embedded file signature": ["文件后部发现其他格式特征"],
  "High file entropy": ["文件熵较高", "高熵本身不能区分压缩、加密和普通二进制数据。"],
  "Side evidence sampled": ["辅助证据采用采样扫描"],
  "IOC-like side evidence": ["发现疑似 IOC 辅助线索"],
  "Timestamp-like side evidence": ["发现疑似时间戳辅助线索"],
  "Strings worth review": ["发现需要复核的字符串"],
  "Token expired": ["令牌已过期"],
  "Long validity window": ["令牌有效期较长"],
  "Missing exp claim": ["缺少过期时间声明"],
  "Token not valid yet": ["令牌尚未生效"],
  "Issued-at is in the future": ["签发时间位于未来"],
  "Unsigned JWT": ["JWT 未签名", "alg 为 none，不能通过签名确认内容来源。"],
  "HMAC secret required": ["需要 HMAC 密钥", "填入共享密钥后才能校验，当前尚未验证签名。"],
  "HMAC signature valid": ["HMAC 签名校验通过"],
  "HMAC signature invalid": ["HMAC 签名校验失败", "签名与当前密钥不匹配，请核对密钥与令牌内容。"],
  "Public key required": ["需要公钥", "填入 PEM 公钥或 JWK 后可在本地验证签名。"],
  "Signature algorithm not supported": ["暂不支持此签名算法"],
  "Missing signature segment": ["JWT 缺少签名段"],
  "kid header worth review": ["kid 密钥标识需要复核"],
  "Remote key reference": ["JWT 引用了远程密钥", "这里只展示引用，不会自动请求远程密钥。"],
  "Critical header present": ["JWT 存在关键扩展头"],
  "Sensitive-looking claim": ["声明中存在疑似敏感字段"],
  "Privileged claim": ["声明包含高权限标记"],
  "Missing issuer": ["缺少签发者声明"],
  "Missing audience": ["缺少接收方声明"],
  "Missing subject": ["缺少主体声明"],
  "Invalid claim order": ["JWT 时间声明顺序异常"],
  "Broad scope set": ["授权范围较广"],
  "JWT parse failed": ["JWT 解析失败"],
};
const TEXT: Record<string, string> = {
  "An APP0/APP1 thumbnail is present; it may diverge from the main image or carry separate metadata.": "存在 APP0 / APP1 缩略图，其内容或元数据可能与主图不同。",
  "EXIF metadata is present (parsed separately on the EXIF tab).": "存在 EXIF 元数据，已在元数据区域单独解析。",
  "Animation flag is set in VP8X; frame timing lives in ANIM/ANMF chunks not parsed here.": "VP8X 设置了动画标志；帧时序位于 ANIM / ANMF 块，当前结构视图未展开。",
  "An embedded ICC color profile is present.": "存在内嵌 ICC 色彩配置。",
  "No meta box parsed; item-derived metadata may be limited.": "未解析到 meta 容器，可提取的项目元数据可能受限。",
  "No trailer, CRC error, readable LSB text, or major alpha anomaly was detected by quick checks.": "快速检查未发现尾部附加数据、CRC 错误、可读 LSB 文本或明显透明通道异常；仍不能排除其他隐写。",
  "Trimmed at logical image end": "按图片逻辑结束位置截取的副本",
  "Appended JPEG EOI marker": "补充 JPEG 结束标记",
  "Appended GIF trailer": "补充 GIF 结束字节",
  "Appended PNG IEND chunk": "补充 PNG 结束块",
  "Added a missing JPEG EOI marker (FF D9) so decoders can attempt to display the remaining scan data.": "补充缺失的 JPEG EOI 标记（FF D9），供解码器尝试读取现有像素数据；不补回缺失的像素。",
  "Added a missing GIF trailer byte (3B) for display recovery.": "补充缺失的 GIF 结束字节（3B），供解码器尝试恢复显示。",
  "Added a fresh PNG IEND chunk so decoders can attempt to display a PNG that appears truncated before its logical end.": "补充 IEND 结束块，供解码器尝试打开缺少结束块的 PNG；不补回丢失的像素。",
  "not available; image pixels could not be decoded": "像素无法解码，尚不能执行此项检查",
  "not available; image too small": "图片尺寸过小，无法可靠计算",
  "not detected": "未检出",
  "not specified (play once)": "未指定（播放一次）",
  "infinite": "无限循环",
  "absent": "不存在",
  "present": "存在",
  "none": "无",
  "simple profile (no VP8X)": "简单配置（无 VP8X）",
  "little (II)": "小端序（II）",
  "big (MM)": "大端序（MM）",
  "CRC, critical chunk order, and trailer checks did not flag obvious issues.": "CRC、关键块顺序与尾部检查未发现明显问题。",
  "JWT must contain header.payload.signature": "JWT 必须包含 header.payload.signature 三段。",
  "PNG structure parse failed": "PNG 结构解析失败",
  "Not a PNG file": "文件没有有效的 PNG 签名。",
  "path traversal": "路径穿越",
  "absolute path": "绝对路径",
  "symlink": "符号链接",
  "encrypted": "已加密",
  "Worker task returned an invalid message": "后台分析返回了无效信息，请重试。",
  "Worker task failed": "后台分析任务失败，请检查输入后重试。",
  "Worker task returned unreadable data": "后台分析返回的数据无法读取，请重试。",
  "ZIP central directory is malformed, unsupported, or Zip64.": "ZIP 中央目录损坏或采用了当前不支持的格式（如 Zip64）。",
  "Decompressed archive exceeds the 512 MiB safety limit.": "解压数据超过 512 MiB 浏览器处理上限，已停止。",
  "VBA project": "VBA 宏项目",
  "VBA stream": "VBA 宏数据流",
  "Embedded object": "内嵌对象",
  "Embedded object stream": "内嵌对象数据流",
  "OLE stream": "OLE 数据流",
  "PDF attachment": "PDF 附件",
  "Document JavaScript actions": "文档 JavaScript 动作",
  "JavaScript": "JavaScript 脚本",
  "Open action": "打开文档时触发的动作",
  "Additional action": "附加动作",
  "Launch action": "启动外部程序的动作",
  "Embedded file": "内嵌文件",
  "XFA form": "XFA 表单",
  "Encryption dictionary": "加密字典",
  "Object stream": "对象数据流",
  "invalid PNG dimensions": "PNG 宽高字段无效（零或超出格式范围）",
  "invalid PNG encoding fields": "PNG 位深、颜色类型或编码字段无效",
  "CRC mismatch": "CRC 校验不一致", "unknown ancillary chunk": "未知辅助数据块", "unknown critical chunk": "未知关键数据块", "private-use chunk": "私有数据块", "invalid IHDR length": "IHDR 长度无效", "invalid IEND length": "IEND 长度无效", "large non-image chunk": "非像素数据块较大", "high-entropy metadata": "元数据熵较高", "metadata contains IOC/secret-like text": "元数据含疑似 IOC 或敏感文本",
  "Critical PNG chunk order is invalid; viewers may reject or recover differently.": "PNG 关键块顺序无效，不同查看器可能拒绝打开或采用不同恢复方式。",
  "The PNG logical end chunk was not parsed; the file may be truncated.": "未解析到 PNG 结束块，文件可能被截断。",
  "No explicit expiration claim was found.": "未找到明确的过期时间声明。", "Header alg is none.": "文件头 alg 为 none，令牌未签名。", "Token has no signature segment while alg is not none.": "alg 并非 none，但令牌缺少签名段。",
  "No iss claim was found.": "未找到 iss 签发者声明。", "No aud claim was found.": "未找到 aud 接收方声明。", "No sub claim was found.": "未找到 sub 主体声明。", "iat is later than exp.": "签发时间 iat 晚于过期时间 exp。", "role/scope contains admin-like text.": "role 或 scope 含有类似 admin 的权限文本。",
  "MZ header exists, but PE signature is missing or outside the file.": "存在 MZ 文件头，但 PE 签名缺失或超出文件范围。", "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is not set.": "未设置 IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE。", "IMAGE_DLLCHARACTERISTICS_NX_COMPAT is not set.": "未设置 IMAGE_DLLCHARACTERISTICS_NX_COMPAT。", "PT_GNU_STACK includes execute permission.": "PT_GNU_STACK 包含执行权限。", "PE characteristics include DLL.": "PE 特征包含 DLL 标志。",
  "A secondary file signature appears after the header region; check for appended or polyglot content.": "文件头区域之后出现其他文件特征，请检查附加内容或多格式文件。",
  "Memory triage parses Minidump metadata and performs bounded PE-header discovery; it is not a Volatility-compatible kernel object parser.": "当前检查覆盖 Minidump 元数据和有限范围内的 PE 文件头，不包含基于内核符号的对象还原。",
  "Raw-memory mode performs bounded signature triage only; OS symbol-based process/VAD/network reconstruction is outside this browser-native parser.": "原始内存模式仅在有限范围扫描特征，暂不还原基于系统符号的进程、VAD 和网络对象。",
  "Extended/logical MBR partitions are identified, but EBR chain traversal is not yet expanded in this view.": "已识别扩展或逻辑 MBR 分区，当前视图尚未展开 EBR 链。",
  "Some object boundaries are heuristic or unresolved; verify them before relying on carved bytes as evidence.": "部分对象边界来自启发式估计或尚未确定，使用提取内容前请核对范围。",
  "Rebuilt PNG critical chunks": "重建 PNG 关键数据块（不恢复宽高）",
  "Rebuilt a PNG candidate from IHDR/PLTE/IDAT and a fresh IEND chunk.": "使用 IHDR、PLTE、IDAT 和新 IEND 重建容器候选；此操作本身不恢复宽高。",
};
export function localizeAnalysisText(text: string, english = getUiLang() === "en"): string {
  if (english) return text;
  if (TEXT[text]) return TEXT[text];
  if (TITLES[text]) return TITLES[text][0];
  const rules: Array<[RegExp, (...groups: string[]) => string]> = [
    [/^(\d+) comment block\(s\); may carry annotation or hidden text\.$/, n => `${n} 个注释块，可能包含说明或隐藏文本。`],
    [/^(\d+) byte\(s\) follow the 0x3B trailer; possible appended data\.$/, n => `GIF 结束字节 0x3B 后仍有 ${n} 字节，可能是附加数据。`],
    [/^(\d+) COM segment\(s\); may carry annotation or hidden text\.$/, n => `${n} 个 JPEG COM 注释段，可能包含说明或隐藏文本。`],
    [/^(\d+)-bit indexed palette; palette entries may carry hidden data\.$/, n => `使用 ${n} 位索引色表，色表条目也可携带数据。`],
    [/^Compression is (.+); pixel recovery depends on decoder support\.$/, mode => `压缩方式为 ${mode}，像素恢复取决于解码器支持。`],
    [/^Expected 42, got (\d+)\.$/, n => `TIFF 标识预期为 42，实际为 ${n}。`],
    [/^First IFD offset (\d+) is outside the file\.$/, n => `首个 IFD 偏移 ${n} 超出文件范围。`],
    [/^(\d+) metadata fields were parsed\.$/, n => `已解析 ${n} 个元数据字段。`],
    [/^(.+) logical end marker could not be located\. The file may be truncated or structurally damaged\.$/, f => `未找到 ${f} 逻辑结束标记，文件可能被截断或结构受损。`],
    [/^The browser could not decode the image pixels after (\d+) attempt\(s\)\. Container-level evidence is still available; original pixels cannot be reliably reconstructed in-browser\.$/, n => `经 ${n} 次尝试仍未解码像素；容器证据仍然可用，像素恢复结果尚未确认。`],
    [/^(.+) after (.+) logical end; this is a common place for appended payload candidates\.(?: Signature: (.+))?$/, (n,f,signature) => `${f} 逻辑结束后仍有 ${n}，可检查附加内容。${signature ? `文件特征：${signature}` : ""}`],
    [/^(\d+) pixels have non-opaque alpha; inspect alpha preview\.$/, n => `${n} 个像素并非完全不透明，请查看透明通道预览。`],
    [/^(.+) distribution note$/, label => `${label} 像素分布线索`],
    [/^ones (.+)%, horizontal transitions (.+)%\. Inspect the bit-plane preview only when it shows readable text, QR outlines, or regular shapes\.$/, (one,transition) => `1 位比例 ${one}%，水平跳变比例 ${transition}%。请结合位平面中可读文字、二维码轮廓或规则形状判断。`],
    [/^(.+)% of interior pixels differ strongly from their immediate neighborhood; inspect the noise map for pasted blocks, hidden masks, or generated noise\.$/, ratio => `${ratio}% 的内部像素与邻域差异较大，请查看噪声图，核对粘贴区域、遮罩或规则噪声。`],
    [/^(.+)\. This is a local distribution note, not a standalone hidden-data finding\.$/, detail => `${detail.replace(/ones/g, "1 位比例")}。这是局部分布线索，不能单独确认隐写。`],
    [/^Removed (.+) after the logical (.+) end marker\.$/, (n,f) => `在副本中移除 ${f} 逻辑结束标记后的 ${n}。`],
    [/^Removed (\d+) leading byte\(s\) before (.+) signature$/, (n,f) => `移除 ${f} 文件头前的 ${n} 个字节`],
    [/^Found a (.+) signature at offset (\d+); created a display candidate by removing leading bytes before the signature\.$/, (f,n) => `在偏移 ${n} 找到 ${f} 特征，移除之前的字节生成预览候选。`],
    [/^(.+) valid with current key$/, alg => `${alg} 与当前公钥校验通过`],
    [/^(.+) did not match current key$/, alg => `${alg} 与当前公钥不匹配`],
    [/^No asymmetric verifier for alg=(.+)$/, alg => `暂不支持 alg=${alg} 的非对称签名校验`],
    [/^(\d+) non-opaque pixels$/, n => `${n} 个非完全不透明像素`],
    [/^(.+) after logical end$/, n => `逻辑结束后 ${n}`],
    [/^(\d+) entries$/, n => `${n} 个条目`],
    [/^Worker task timed out after (\d+) ms$/, n => `后台分析超过 ${Number(n) / 1000} 秒时限，已停止；可缩小输入后重试。`],
    [/^Failed to fetch dynamically imported module: (.+)$/, _url => "工具资源加载失败，请检查发布包是否完整或网站资源是否部署正确。"],
    [/^ZIP contains too many entries \((\d+); limit (\d+)\)\.$/, (n,limit) => `ZIP 包含 ${n} 个条目，超过 ${limit} 个条目的处理上限。`],
    [/^ZIP expands to (\d+) bytes; browser safety limit is (\d+) bytes\.$/, (n,limit) => `ZIP 解压后为 ${n} 字节，超过 ${limit} 字节的浏览器处理上限。`],
    [/^ZIP entry (.+) expands to (\d+) bytes; per-entry safety limit is (\d+) bytes\.$/, (name,n,limit) => `ZIP 条目 ${name} 解压后为 ${n} 字节，超过单条目 ${limit} 字节的上限。`],
    [/^ZIP entry (.+) has suspicious compression ratio (.+):1\.$/, (name,ratio) => `ZIP 条目 ${name} 的压缩比为 ${ratio}:1，已停止自动解压以避免内存耗尽。`],
    [/^Token at byte offset (\d+)$/, n => `特征位于字节偏移 ${n}`],
    [/^External (.+)$/, kind => `外部引用（${kind}）`],
    [/^Not retained for extraction: (.+)$/, name => `未保留提取副本：${name}`],
    [/^Compound streams could not be enumerated: (.+)$/, name => `无法枚举复合文档数据流：${name}`],
    [/^Outline entries: (\d+)$/, n => `目录条目：${n}`],
    [/^(\d+) bytes$/, n => `${n} 字节`],
    [/^Recomputed CRC for (\d+) chunk\(s\) with mismatched CRC\.$/, n => `已重算 ${n} 个校验异常块的 CRC。`],
    [/^Removed (\d+) ancillary\/unknown chunk\(s\), including metadata chunks if present\.$/, n => `已移除 ${n} 个辅助或未知块，包含其中的元数据。`],
    [/^Removed (.+) after IEND\.$/, n => `已移除 IEND 后的 ${n} 尾部数据。`],
    [/^Partition (\d+) starts beyond image size\.$/, n => `分区 ${n} 的起点超出镜像文件范围。`],
    [/^Partition (\d+) extends beyond image size; filesystem probe is bounded to available bytes\.$/, n => `分区 ${n} 超出镜像范围，文件系统检查仅使用现有字节。`],
    [/^Object list reached the configured limit \((\d+)\)\.$/, n => `对象列表已达到 ${n} 项上限，结果可能不完整。`],
    [/^Automatic recursive expansion reached its (\d+)-byte container-read budget; remaining objects can still be carved and sent to analyzers individually\.$/, n => `自动递归已达到 ${n} 字节读取上限；其余对象仍可单独提取并交给其他工具。`],
    [/^Per-object SHA-256 hashing stopped at the configured budget \((\d+) object\(s\), (\d+) bytes\); source SHA-256 remains complete\.$/, (n,b) => `逐对象 SHA-256 已达到计算上限（${n} 个对象、${b} 字节）；源文件 SHA-256 仍然完整。`],
    [/^(.+) did not match with the current secret\.$/, alg => `${alg} 与当前密钥不匹配。`],
    [/^(.+) matched with the current secret\.$/, alg => `${alg} 与当前密钥匹配。`],
    [/^Enter the shared secret to verify (.+)\.$/, alg => `输入共享密钥后可验证 ${alg}。`],
    [/^(.+) signatures can be verified locally after a PEM public key or JWK is provided\.$/, alg => `提供 PEM 公钥或 JWK 后，可在本地验证 ${alg} 签名。`],
    [/^No local verifier is available for alg=(.+)\.$/, alg => `暂不支持 alg=${alg} 的本地验证。`],
    [/^\.(.+) does not match (.+) \((.+)\)$/, (ext, type, expected) => `扩展名 .${ext} 与 ${type} 不符，预期扩展名：${expected}`],
  ];
  for (const [pattern, render] of rules) { const match = text.match(pattern); if (match) return render(...match.slice(1)); }
  return text;
}
export function findingPresentation(finding: PresentedFinding, english = getUiLang() === "en") {
  const entry = TITLES[finding.title];
  const level: NoticeLevel = ["HMAC signature valid", "Image decoded", "PNG structure looks consistent"].includes(finding.title) ? "success" : ["HMAC secret required", "Public key required"].includes(finding.title) ? "pending" : /^(danger|risk|error|critical)$/.test(finding.level) ? "danger" : finding.level === "warn" || finding.level === "warning" ? "warn" : finding.level === "success" ? "success" : "info";
  return {
    level, title: english ? finding.title : entry?.[0] ?? localizeAnalysisText(finding.title, false),
    detail: ["PNG text metadata", "Readable LSB candidate", "Printable LSB text candidate", "kid header worth review", "Critical header present", "Sensitive-looking claim", "Broad scope set"].includes(finding.title) ? finding.detail : localizeAnalysisText(finding.detail, english), explanation: english ? undefined : entry?.[1]
  };
}
export function severityLabel(level: NoticeLevel, english = getUiLang() === "en") {
  return ({ danger: ["异常", "Error"], warn: ["需关注", "Review"], info: ["说明", "Info"], success: ["检查通过", "Passed"], pending: ["未检查", "Not checked"] }[level])[english ? 1 : 0];
}
export function sortFindings<T extends PresentedFinding>(findings: T[]) {
  const priority = { danger: 0, warn: 1, pending: 2, info: 3, success: 4 };
  return [...findings].sort((a,b) => priority[findingPresentation(a).level] - priority[findingPresentation(b).level]);
}

/** Only status/check rows receive value translations and severity. User data columns do not. */
export function statusPresentation(label: string, value: string, english = getUiLang() === "en") {
  if (/^(?:CRC errors|CRC 错误数)$/i.test(label) && /^\d+$/.test(value)) return { value, level: Number(value) > 0 ? "danger" as const : undefined };
  const controlled = /^(?:CRC|checksum|header checksum|signature status|validation|display|state|status|decode|pixel decode|IEND|repair status|校验和|文件头校验和|签名状态|校验|显示状态|状态|像素解码|修复状态)$/i.test(label.trim());
  if (!controlled) return { value, level: undefined };
  const vocabulary: Record<string, string> = { "OK": "通过", "Passed": "通过", "Present": "存在", "Missing": "缺失", "Not decoded": "无法解码", "decoded": "解码通过", "failed": "失败", "valid": "有效", "invalid": "无效", "unsupported": "暂不支持", "not checked": "尚未检查", "unknown": "未知", "yes": "是", "no": "否" };
  const localized = english ? value : vocabulary[value] ?? (/^\d+ mismatch$/.test(value) ? `${value.split(" ")[0]} 个块校验失败` : localizeAnalysisText(value, false));
  const level: NoticeLevel | undefined = /^(?:not checked|尚未检查|未验证)$/i.test(value) ? "pending" : /(?:mismatch|invalid|failed|missing|not decoded|cannot|校验失败|无法解码|缺失|不匹配|不一致)/i.test(value) ? "danger" : /(?:unsupported|unknown|not checked|未验证|尚未|暂不支持|未知)/i.test(value) ? "warn" : /^(?:OK|Passed|valid|校验通过|通过|有效)$/i.test(value) ? "success" : undefined;
  return { value: localized, level };
}
