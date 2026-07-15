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

import { GithubOutlined } from "@ant-design/icons";
import { projectLinks } from "../config/app";

export function GithubIconButton({ label }: { label: string }) {
  return (
    <a className="github-icon-button" href={projectLinks.repo} target="_blank" rel="noreferrer" aria-label={label} title={label}>
      <GithubOutlined aria-hidden="true" />
    </a>
  );
}
