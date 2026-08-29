/**
 * Forensics++ (ForensicsPP.com)
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 *
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import { describe, expect, it } from "vitest";
import { createManagedTask } from "../src/core/runtime/managedTask";

describe("managed task (beta.6 P1 worker lifecycle)", () => {
  it("aborts all registered controllers on dispose and tracks count", () => {
    const managed = createManagedTask();
    const a = managed.register();
    const b = managed.register();
    expect(managed.activeCount).toBe(2);
    managed.dispose();
    expect(a.signal.aborted).toBe(true);
    expect(b.signal.aborted).toBe(true);
    expect(managed.disposed).toBe(true);
    expect(managed.activeCount).toBe(0);
  });

  it("releases individual controllers without aborting others", () => {
    const managed = createManagedTask();
    const a = managed.register();
    const b = managed.register();
    managed.release(a);
    expect(a.signal.aborted).toBe(false);
    expect(b.signal.aborted).toBe(false);
    managed.abortAll();
    expect(b.signal.aborted).toBe(true);
  });

  it("dispose is idempotent", () => {
    const managed = createManagedTask();
    managed.register();
    managed.dispose();
    managed.dispose();
    expect(managed.disposed).toBe(true);
  });
});
