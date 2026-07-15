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

export type OpenSourceProject = {
  name: string;
  category: "runtime" | "embedded" | "development";
  purpose: { zh: string; en: string };
  license: string;
  repository: string;
  version?: string;
  notices?: string;
};

export const openSourceProjects: OpenSourceProject[] = [
  { name: "React", category: "runtime", purpose: { zh: "界面组件与状态管理", en: "UI components and state" }, license: "MIT", repository: "https://github.com/facebook/react", version: "19" },
  { name: "React DOM", category: "runtime", purpose: { zh: "浏览器界面渲染", en: "Browser rendering" }, license: "MIT", repository: "https://github.com/facebook/react", version: "19" },
  { name: "Ant Design", category: "runtime", purpose: { zh: "界面组件与主题系统", en: "UI components and theming" }, license: "MIT", repository: "https://github.com/ant-design/ant-design", version: "5" },
  { name: "Ant Design Icons", category: "runtime", purpose: { zh: "界面图标", en: "Interface icons" }, license: "MIT", repository: "https://github.com/ant-design/ant-design-icons", version: "5" },
  { name: "Ant Design React 19 Patch", category: "runtime", purpose: { zh: "React 19 兼容层", en: "React 19 compatibility" }, license: "MIT", repository: "https://github.com/ant-design/v5-patch-for-react-19", version: "1" },
  { name: "bcrypt.js", category: "runtime", purpose: { zh: "bcrypt 生成与本地验证", en: "bcrypt generation and local verification" }, license: "BSD-3-Clause", repository: "https://github.com/dcodeIO/bcrypt.js", version: "3" },
  { name: "CFB", category: "runtime", purpose: { zh: "OLE 复合文件与文档流解析", en: "OLE compound file and document stream parsing" }, license: "Apache-2.0", repository: "https://github.com/SheetJS/js-cfb", version: "1.2" },
  { name: "CryptoJS", category: "runtime", purpose: { zh: "常用摘要、HMAC 与对称密码", en: "Digests, HMAC, and symmetric crypto" }, license: "MIT", repository: "https://github.com/brix/crypto-js", version: "4" },
  { name: "exifr", category: "runtime", purpose: { zh: "图片 EXIF 元数据解析", en: "Image EXIF metadata parsing" }, license: "MIT", repository: "https://github.com/MikeKovarik/exifr", version: "7" },
  { name: "fflate", category: "runtime", purpose: { zh: "ZIP 与压缩数据处理", en: "ZIP and compression handling" }, license: "MIT", repository: "https://github.com/101arrowz/fflate", version: "0.8" },
  { name: "jsQR", category: "runtime", purpose: { zh: "二维码识别", en: "QR code decoding" }, license: "Apache-2.0", repository: "https://github.com/cozmo/jsQR", version: "1.4" },
  { name: "postal-mime", category: "runtime", purpose: { zh: "EML 与 MIME 邮件解析", en: "EML and MIME parsing" }, license: "MIT-0", repository: "https://github.com/postalsys/postal-mime", version: "2" },
  { name: "PDF.js", category: "runtime", purpose: { zh: "PDF 结构、元数据与附件解析", en: "PDF structure, metadata, and attachment parsing" }, license: "Apache-2.0", repository: "https://github.com/mozilla/pdf.js", version: "6" },
  { name: "sm-crypto", category: "runtime", purpose: { zh: "SM2、SM3、SM4 国密算法", en: "SM2, SM3, and SM4 algorithms" }, license: "MIT", repository: "https://github.com/JuneAndGreen/sm-crypto", version: "0.4" },
  { name: "sql-formatter", category: "runtime", purpose: { zh: "SQL 格式化", en: "SQL formatting" }, license: "MIT", repository: "https://github.com/sql-formatter-org/sql-formatter", version: "15" },
  { name: "sql.js", category: "runtime", purpose: { zh: "浏览器内 SQLite 数据库", en: "SQLite in the browser" }, license: "MIT", repository: "https://github.com/sql-js/sql.js", version: "1" },
  { name: "TS-EVTX", category: "runtime", purpose: { zh: "Windows EVTX 与 BinXML 解析", en: "Windows EVTX and BinXML parsing" }, license: "MIT", repository: "https://github.com/NickSmet/ts-evtx", version: "1.2" },
  { name: "YARA-X", category: "runtime", purpose: { zh: "在浏览器内编译并扫描 YARA 规则", en: "Compile and scan YARA rules in the browser" }, license: "BSD-3-Clause", repository: "https://github.com/VirusTotal/yara-x", version: "1.15" },
  { name: "YAML", category: "runtime", purpose: { zh: "Sigma YAML 规则读取", en: "Sigma YAML rule parsing" }, license: "ISC", repository: "https://github.com/eemeli/yaml", version: "2" },
  { name: "CyberChef", category: "embedded", purpose: { zh: "内置数据转换工作台", en: "Embedded data transformation workbench" }, license: "Apache-2.0", repository: "https://github.com/gchq/CyberChef", version: "10.19.4", notices: "./cyberchef/assets/main.js.LICENSE.txt" },
  { name: "Vite", category: "development", purpose: { zh: "开发服务器与生产构建", en: "Development server and production build" }, license: "MIT", repository: "https://github.com/vitejs/vite", version: "6" },
  { name: "Vite React Plugin", category: "development", purpose: { zh: "React 构建集成", en: "React build integration" }, license: "MIT", repository: "https://github.com/vitejs/vite-plugin-react", version: "5" },
  { name: "Vitest", category: "development", purpose: { zh: "解析器与核心逻辑自动测试", en: "Automated tests for parsers and core logic" }, license: "MIT", repository: "https://github.com/vitest-dev/vitest", version: "4" },
  { name: "TypeScript", category: "development", purpose: { zh: "类型检查与源码编译", en: "Type checking and compilation" }, license: "Apache-2.0", repository: "https://github.com/microsoft/TypeScript", version: "5" },
  { name: "DefinitelyTyped: React", category: "development", purpose: { zh: "React TypeScript 类型定义", en: "React TypeScript definitions" }, license: "MIT", repository: "https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/react" },
  { name: "DefinitelyTyped: React DOM", category: "development", purpose: { zh: "React DOM TypeScript 类型定义", en: "React DOM TypeScript definitions" }, license: "MIT", repository: "https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/react-dom" },
  { name: "DefinitelyTyped: CryptoJS", category: "development", purpose: { zh: "CryptoJS TypeScript 类型定义", en: "CryptoJS TypeScript definitions" }, license: "MIT", repository: "https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/crypto-js" },
  { name: "rc-component QRCode", category: "development", purpose: { zh: "布局审计二维码样本生成", en: "QR fixtures for layout audits" }, license: "MIT", repository: "https://github.com/react-component/qrcode" },
  { name: "SQLite", category: "development", purpose: { zh: "布局审计数据库样本生成", en: "SQLite fixtures for layout audits" }, license: "Public Domain", repository: "https://github.com/sqlite/sqlite" }
];
