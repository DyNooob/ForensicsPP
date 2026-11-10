Forensics++ 1.0 — 离线使用说明 / Offline quick start
Copyright (c) 2026 DyNooob · MIT License

1. 完整解压整个文件夹，不要只拷贝 index.html。
2. 本机需预装 Python 3（仅使用标准库，无 pip/npm 安装、无在线下载）。
   macOS/Linux: 运行 python3 start_server.py，或打开 Start-ForensicsPP.command。
   Windows: 双击 Start-ForensicsPP.bat，或运行 py -3 start_server.py。
3. 浏览器打开 http://127.0.0.1:8765/。启动器只监听本机回环地址。
4. 保持启动窗口开启，Ctrl+C 停止。端口冲突时加 --port 8766。
   不要通过 file:// 直接双击 index.html 进行 Worker/WASM 分析；浏览器会限制它们。

所有 JS、CSS、WASM、CyberChef、OpenCC 词库、IP/手机号/行政区划数据均随包提供。
首次使用无需联网或预热缓存。离线构建不会回退到 CDN；HTML 策略禁止外部资源与网络请求。
数据包损坏/遗漏时会明确失败，请重新完整解压，不能靠联网补齐。
IP/手机号归属地是静态数据库记录，不是实时定位；数据版本见 lookup/SOURCES.json。
HEIC/HEIF 预览尽力支持；损坏、特殊编码或资源超限的文件可能无法显示，但仍尝试原始元数据解析。
简繁转换在“编码解码 → 简繁转换”，Ctrl/⌘+Enter 转简体，加 Shift 转繁体。

许可证：LICENSE.txt、THIRD_PARTY_NOTICES.txt、licenses/、cyberchef/。
HEIC 解码库对应源码与构建说明：sources/heic-sources.tar.gz。
OFFLINE_MANIFEST.json 记录随包数据版本和 SHA-256；发布 ZIP 的 SHA-256 在旁边的 SHA256SUMS 文件。

Extract the complete folder. Use preinstalled Python 3 (standard library only):
  python3 start_server.py
Open http://127.0.0.1:8765/ in a current browser. Keep the terminal open.
All runtime code and lookup dictionaries ship locally. No initial Internet connection is required.
Python itself is not bundled. Any existing local static HTTP server can also serve this folder from its root.
