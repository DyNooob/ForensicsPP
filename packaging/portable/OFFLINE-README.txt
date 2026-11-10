Forensics++ — 离线使用说明 / Offline quick start
Copyright (c) 2026 DyNooob · MIT License

1. 完整解压 ZIP 文件夹。
2. 用当前版本的 Chrome 或 Edge 双击打开 index.html，即可使用。
3. 地址栏应显示 file://。无需 Python、Node.js、命令行、本地服务器或联网。

所有 JS、CSS、分析线程、WASM、CyberChef、OpenCC 词库和查询数据库均随包提供。
分析线程使用本地 Blob 加载，WASM 和查询数据嵌入运行资源，首次使用无需联网或预热缓存。
保留完整文件夹：CyberChef 和许可证等文件与 index.html 同级分发。
外部网络请求受页面策略限制。损坏或缺失的文件请重新完整解压。
IP/手机号归属地是静态数据库记录，不是实时定位；数据版本见 lookup/SOURCES.json。
HEIC/HEIF 尽力支持；损坏、特殊编码或资源超限可能无法预览。
简繁转换在左侧“简繁转换”：Ctrl/⌘+Enter 转简体，加 Shift 转繁体。
浏览器内存限制、工具文件上限和原有分析范围仍然适用。

许可证：LICENSE.txt、THIRD_PARTY_NOTICES.txt、licenses/、cyberchef/。
HEIC 对应源码与构建说明：sources/heic-sources.tar.gz。
OFFLINE_MANIFEST.json 记录版本和本地数据校验值。ZIP 的 SHA-256 见同版本 SHA256SUMS 文件。

Extract the complete ZIP and open index.html in current Chrome or Edge.
It runs directly under file://. No Python, Node.js, terminal, local server or Internet connection is required.
Keep the complete folder, including CyberChef and third-party notices.
All runtime code, workers, WASM and lookup data are bundled locally.
