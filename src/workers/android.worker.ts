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

/**
 * Forensics++ - MIT License
 * Copyright (c) 2026 DyNooob. All rights reserved.
 */

import { decodeAndroidManifestBytes, inspectAndroidArchive, inspectAndroidBinaryXml } from "../features/android/analyzer";
import { verifyApkSignatures } from "../features/android/signingVerify";

self.onmessage = async (event: MessageEvent<{ bytes: Uint8Array; name: string; size: number }>) => {
  const { bytes, name, size } = event.data;
  try {
    const archive = bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04 ? inspectAndroidArchive(bytes) : undefined;
    const manifestBytes = archive?.manifest ?? bytes;
    const axml = inspectAndroidBinaryXml(manifestBytes);
    const xml = decodeAndroidManifestBytes(manifestBytes);
    let archiveInfo;
    if (archive) {
      const signing = await verifyApkSignatures(archive.verificationBytes, archive.signing);
      const { verificationBytes: _verificationBytes, ...publicArchive } = archive;
      archiveInfo = { ...publicArchive, signing, axmlRows: axml.rows, axmlFindings: axml.findings };
    } else {
      archiveInfo = { rows: [], findings: [], axmlRows: axml.rows, axmlFindings: axml.findings };
    }
    self.postMessage({ type: "result", result: { xml, archiveInfo } });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};
