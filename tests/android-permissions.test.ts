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
import { PERM_CATEGORY_META, resolveAndroidPermission } from "../src/features/android/permissionCatalog";

describe("android permission catalog", () => {
  it("resolves catalogued dangerous permissions with Chinese labels", () => {
    const { shortName, info, known } = resolveAndroidPermission("android.permission.READ_SMS");
    expect(shortName).toBe("READ_SMS");
    expect(known).toBe(true);
    expect(info.category).toBe("sms");
    expect(info.severity).toBe("dangerous");
    expect(info.zh).toBe("读取短信");
    expect(info.descZh.length).toBeGreaterThan(0);
  });

  it("flags high-risk special-access permissions", () => {
    const accessibility = resolveAndroidPermission("android.permission.BIND_ACCESSIBILITY_SERVICE");
    expect(accessibility.info.category).toBe("special");
    expect(accessibility.info.severity).toBe("signature");

    const overlay = resolveAndroidPermission("android.permission.SYSTEM_ALERT_WINDOW");
    expect(overlay.info.category).toBe("special");
    expect(overlay.info.severity).toBe("special");
  });

  it("categorises uncatalogued android permissions by heuristic", () => {
    const result = resolveAndroidPermission("android.permission.ACCESS_LOCATION_EXTRA_COMMANDS");
    expect(result.known).toBe(false);
    expect(result.info.category).toBe("location");
    expect(result.info.severity).toBe("dangerous");
  });

  it("treats third-party permissions as custom with unknown severity", () => {
    const result = resolveAndroidPermission("com.example.app.CUSTOM_ACCESS");
    expect(result.known).toBe(false);
    expect(result.info.category).toBe("other");
    expect(result.info.severity).toBe("unknown");
    expect(result.info.zh).toContain("自定义");
  });

  it("humanises the short name for unknown permissions", () => {
    const result = resolveAndroidPermission("android.permission.FOO_BAR_BAZ");
    expect(result.info.en).toBe("Foo Bar Baz");
  });

  it("keeps every catalogued category present in the metadata map", () => {
    const categories = new Set(Object.values(PERM_CATEGORY_META).map((meta) => meta.en));
    expect(categories.size).toBeGreaterThan(10);
    expect(PERM_CATEGORY_META.sms.zh).toBe("短信 / 彩信");
  });
});
