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

import { describe, expect, it } from "vitest";
import { analyzerForArtifact } from "../src/core/analyzerRouting";

describe("central analyzer routing", () => {
  it("routes carved forensic artifacts without tool-local if/else chains", () => {
    expect(analyzerForArtifact({ label: "SQLite", extension: "db" })).toBe("sqlite");
    expect(analyzerForArtifact({ label: "EXT filesystem", extension: "img" })).toBe("disk");
    expect(analyzerForArtifact({ label: "ELF", extension: "elf" })).toBe("binary");
    expect(analyzerForArtifact({ label: "APK / ZIP archive", extension: "apk" })).toBe("android");
  });

  it("routes common evidence files opened from the home workbench", () => {
    expect(analyzerForArtifact({ label: "Security.evtx", extension: "evtx" })).toBe("evtx");
    expect(analyzerForArtifact({ label: "com.apple.finder.plist", extension: "plist" })).toBe("plist");
    expect(analyzerForArtifact({ label: "message.eml", extension: "eml", mime: "message/rfc822" })).toBe("email");
    expect(analyzerForArtifact({ label: "NTUSER.DAT", extension: "dat" })).toBe("registry");
    expect(analyzerForArtifact({ label: "History" })).toBe("browserartifacts");
    expect(analyzerForArtifact({ label: "memory.dmp", extension: "dmp" })).toBe("memory");
  });
});
