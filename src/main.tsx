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
import { createRoot } from "react-dom/client";
import "@ant-design/v5-patch-for-react-19";
import "antd/dist/reset.css";
import "./styles.css";
import { App } from "./App";
import { AppErrorBoundary } from "./components/AppErrorBoundary";

function printConsoleBrand() {
  const key = "__forensicspp_console_brand__";
  if ((window as unknown as Record<string, boolean>)[key]) return;
  (window as unknown as Record<string, boolean>)[key] = true;

  const badge = "color:#07111f;background:#9bcaff;font-size:16px;font-weight:900;padding:5px 8px;border-radius:5px 0 0 5px";
  const banner = "color:#dbeafe;background:#0b1624;font-size:16px;font-weight:900;padding:5px 10px;border-radius:0 5px 5px 0";
  const label = "color:#9ca3af;font-weight:800";
  const value = "color:#bfdbfe;font-weight:800";
  const muted = "color:#cbd5e1;font-weight:700";

  console.info("%cF++%c Forensics++  |  ForensicsPP.com ", badge, banner);
  console.groupCollapsed("%cForensics++ project information", "color:#93c5fd;font-weight:900");
  console.log("%cProject   %cForensics++ (ForensicsPP.com)", label, value);
  console.log("%cAuthor    %cDyNooob", label, value);
  console.log("%cRepository%c https://github.com/DyNooob/ForensicsPP", label, value);
  console.log("%cLicense   %cMIT. Full source code is available in the repository.", label, muted);
  console.groupEnd();
}

printConsoleBrand();
const rootElement = document.getElementById("root");
if (rootElement) {
  const rootHost = rootElement as HTMLElement & { __forensicspp_root__?: ReturnType<typeof createRoot> };
  const root = rootHost.__forensicspp_root__ ?? createRoot(rootElement);
  rootHost.__forensicspp_root__ = root;
  root.render(
    <AppErrorBoundary>
      <App />
    </AppErrorBoundary>
  );
}
