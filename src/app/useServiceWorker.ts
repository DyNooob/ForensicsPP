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

export function useServiceWorker() {
  React.useEffect(() => {
    if (!window.isSecureContext || !("serviceWorker" in navigator)) return;
    // The dev server is a secure context on localhost, so an unguarded
    // registration would install a Service Worker whose cache name never changes
    // between rebuilds. A stale cached shell then keeps booting a build that no
    // longer exists. Only production bundles (`vite build`, therefore also
    // `vite preview`) register; dev actively drops any leftover registration.
    if (!import.meta.env.PROD) {
      navigator.serviceWorker
        .getRegistrations()
        .then((registrations) => Promise.all(registrations.map((registration) => registration.unregister())))
        .catch(() => undefined);
      return;
    }
    navigator.serviceWorker.register(new URL("./sw.js", document.baseURI).href).catch(() => undefined);
  }, []);
}
