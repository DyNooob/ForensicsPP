/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import React from "react";
import { ReloadOutlined, WarningOutlined } from "@ant-design/icons";
import { AButton } from "./ui";

type ToolErrorBoundaryProps = {
  title: string;
  detail: string;
  retryLabel: string;
  children: React.ReactNode;
};

type ToolErrorBoundaryState = {
  error: Error | null;
};

export class ToolErrorBoundary extends React.Component<ToolErrorBoundaryProps, ToolErrorBoundaryState> {
  state: ToolErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ToolErrorBoundaryState {
    return { error };
  }

  retry = () => {
    const message = this.state.error?.message ?? "";
    const isModuleLoadFailure = /(?:dynamically imported module|loading chunk|failed to fetch|importing a module script)/i.test(message);
    if (isModuleLoadFailure && typeof window !== "undefined") {
      window.location.reload();
      return;
    }
    this.setState({ error: null });
  };

  render() {
    if (!this.state.error) return this.props.children;

    return (
      <div className="tool-error-state" role="alert">
        <WarningOutlined aria-hidden="true" />
        <strong>{this.props.title}</strong>
        <p>{this.props.detail}</p>
        <AButton variant="outlined" icon={<ReloadOutlined aria-hidden="true" />} onClick={this.retry}>
          {this.props.retryLabel}
        </AButton>
      </div>
    );
  }
}
