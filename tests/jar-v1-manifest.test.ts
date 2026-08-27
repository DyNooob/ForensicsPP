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
import { verifyJarV1ManifestAndSf } from "../src/features/android/v1Verify";

async function digestBase64(name: "SHA-1" | "SHA-256", bytes: Uint8Array) {
  const d = new Uint8Array(await crypto.subtle.digest(name, bytes.slice().buffer));
  return btoa(String.fromCharCode(...d));
}

async function makeManifest(entries: Array<[string, Uint8Array]>) {
  const lines = ["Manifest-Version: 1.0", ""];
  for (const [name, bytes] of entries) {
    const d = await digestBase64("SHA-256", bytes);
    lines.push(`Name: ${name}`, `SHA-256-Digest: ${d}`, "");
  }
  return new TextEncoder().encode(lines.join("\n"));
}

async function makeSfWholeManifest(manifest: Uint8Array) {
  const d = await digestBase64("SHA-256", manifest);
  return new TextEncoder().encode(["Signature-Version: 1.0", `SHA-256-Digest-Manifest: ${d}`, "", ""].join("\n"));
}

async function makeSfPerSection(entries: Array<[string, Uint8Array]>) {
  const lines = ["Signature-Version: 1.0", ""];
  for (const [name, bytes] of entries) {
    const d = await digestBase64("SHA-256", bytes);
    lines.push(`Name: ${name}`, `SHA-256-Digest: ${d}`, "");
  }
  return new TextEncoder().encode(lines.join("\n"));
}

function filesWith(entries: Array<[string, Uint8Array]>, manifest: Uint8Array, sf: Uint8Array) {
  const files: Record<string, Uint8Array> = { "META-INF/MANIFEST.MF": manifest, "META-INF/CERT.SF": sf };
  for (const [name, bytes] of entries) files[name] = bytes;
  return files;
}

describe("APK v1 (JAR) MANIFEST.MF / .SF verification", () => {
  const f1 = Uint8Array.from([1, 2, 3]);
  const f2 = Uint8Array.from([4, 5, 6, 7]);
  const entries: Array<[string, Uint8Array]> = [["classes.dex", f1], ["AndroidManifest.xml", f2]];

  it("accepts a .SF that carries a valid whole-manifest digest", async () => {
    const manifest = await makeManifest(entries);
    const sf = await makeSfWholeManifest(manifest);
    const r = await verifyJarV1ManifestAndSf(filesWith(entries, manifest, sf), manifest, sf);
    expect(r.manifestEntries).toBe(2);
    expect(r.verifiedEntries).toBe(2);
    expect(r.sfManifestDigestVerified).toBe(true);
    expect(r.perSectionTotal).toBe(0);
    expect(r.errors).toHaveLength(0);
  });

  it("accepts per-section .SF digests that cover every MANIFEST.MF entry (no whole-manifest needed)", async () => {
    const manifest = await makeManifest(entries);
    const sf = await makeSfPerSection(entries);
    const r = await verifyJarV1ManifestAndSf(filesWith(entries, manifest, sf), manifest, sf);
    expect(r.sfManifestDigestVerified).toBe(false);
    expect(r.perSectionTotal).toBe(2);
    expect(r.perSectionVerified).toBe(2);
    expect(r.errors).toHaveLength(0);
  });

  it("flags a tampered per-section .SF digest as a mismatch error", async () => {
    const manifest = await makeManifest(entries);
    const sfText = new TextDecoder().decode(await makeSfPerSection(entries)).replace(/SHA-256-Digest: \S+/, "SHA-256-Digest: AAAAAAAA");
    const sf = new TextEncoder().encode(sfText);
    const r = await verifyJarV1ManifestAndSf(filesWith(entries, manifest, sf), manifest, sf);
    expect(r.perSectionTotal).toBe(2);
    expect(r.perSectionVerified).toBe(1);
    expect(r.errors.some((e) => /per-section digest does not match/.test(e))).toBe(true);
  });

  it("does not fully attest when per-section digests cover only part of MANIFEST.MF", async () => {
    const manifest = await makeManifest(entries);
    const sf = new TextEncoder().encode(
      ["Signature-Version: 1.0", "", `Name: classes.dex`, `SHA-256-Digest: ${await digestBase64("SHA-256", f1)}`, ""].join("\n")
    );
    const r = await verifyJarV1ManifestAndSf(filesWith(entries, manifest, sf), manifest, sf);
    expect(r.perSectionTotal).toBe(1);
    expect(r.perSectionVerified).toBe(1);
    expect(r.errors).toHaveLength(0);
    // verifyJarV1Signature treats this as not-fully-attested (attestedAll === false).
  });
});
