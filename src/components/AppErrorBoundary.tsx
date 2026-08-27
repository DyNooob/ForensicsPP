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

import React from "react";

type AppErrorBoundaryProps = {
  children: React.ReactNode;
};

type AppErrorBoundaryState = {
  error: Error | null;
};

// Root-level boundary. Individual tools already have ToolErrorBoundary, but
// App itself, the Settings modal, and the Case Reporter are rendered outside
// any boundary; an uncaught throw there used to unmount the whole tree and
// leave a blank (white) page. This turns that into a readable error instead.
export class AppErrorBoundary extends React.Component<AppErrorBoundaryProps, AppErrorBoundaryState> {
  state: AppErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): AppErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("[Forensics++] 应用级错误已捕获:", error, info);
  }

  reload = () => {
    window.location.reload();
  };

  render() {
    if (!this.state.error) return this.props.children;

    const message = this.state.error.message || String(this.state.error);
    const isModuleLoadFailure = /(?:dynamically imported module|loading chunk|failed to fetch|importing a module script|does not provide an export)/i.test(message);

    return (
      <div
        role="alert"
        style={{
          minHeight: "100vh",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: "12px",
          padding: "32px",
          boxSizing: "border-box",
          fontFamily: "Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', 'Noto Sans SC', sans-serif",
          color: "#162130",
          background: "#f5f7fa",
          textAlign: "center"
        }}
      >
        <h1 style={{ margin: 0, fontSize: "20px" }}>页面加载出错</h1>
        <p style={{ margin: 0, maxWidth: "560px", color: "#66768a" }}>
          {isModuleLoadFailure
            ? "某个模块加载失败（常见于开发服务器依赖缓存过期）。请重新加载页面；若仍失败，请在终端重启 dev 服务器（npm run dev）。"
            : "应用遇到了一个未预期的错误。错误详情已打印到浏览器控制台，可重新加载后向我们反馈。"}
        </p>
        <pre
          style={{
            maxWidth: "680px",
            width: "100%",
            overflow: "auto",
            textAlign: "left",
            background: "#fff",
            border: "1px solid #d8e0e8",
            borderRadius: "8px",
            padding: "12px 14px",
            fontSize: "12px",
            whiteSpace: "pre-wrap",
            wordBreak: "break-word"
          }}
        >
          {message}
        </pre>
        <button
          type="button"
          onClick={this.reload}
          style={{
            height: "38px",
            padding: "0 18px",
            borderRadius: "6px",
            border: "1px solid #245F73",
            background: "#245F73",
            color: "#fff",
            fontSize: "14px",
            cursor: "pointer"
          }}
        >
          重新加载
        </button>
      </div>
    );
  }
}
