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
import {
  describeToolError,
  isResolvedStatus,
  isTerminalPhase,
  nextLifecyclePhase
} from "../src/core/runtime/toolLifecycle";

describe("tool lifecycle state machine (beta.6 P0-1)", () => {
  it("advances create -> initialize -> ready -> running -> completed", () => {
    expect(nextLifecyclePhase("create", "initialize")).toBe("initialize");
    expect(nextLifecyclePhase("initialize", "ready")).toBe("ready");
    expect(nextLifecyclePhase("ready", "run")).toBe("running");
    expect(nextLifecyclePhase("running", "complete")).toBe("completed");
  });

  it("supports reset and re-run from completed", () => {
    expect(nextLifecyclePhase("completed", "run")).toBe("running");
    expect(nextLifecyclePhase("completed", "reset")).toBe("ready");
    expect(nextLifecyclePhase("ready", "dispose")).toBe("disposed");
    expect(nextLifecyclePhase("completed", "dispose")).toBe("disposed");
  });

  it("rejects illegal transitions", () => {
    expect(nextLifecyclePhase("create", "run")).toBeNull();
    expect(nextLifecyclePhase("running", "ready")).toBeNull();
    expect(nextLifecyclePhase("disposed", "run")).toBeNull();
  });

  it("reports terminal and analysis phases", () => {
    expect(isTerminalPhase("disposed")).toBe(true);
    expect(isTerminalPhase("running")).toBe(false);
  });
});

describe("describeToolError (beta.6 P1 error handling)", () => {
  it("extracts message from Error and defaults recovery to retry", () => {
    const info = describeToolError("firmware", "database initialization", new Error("boom"));
    expect(info).toEqual({
      tool: "firmware",
      stage: "database initialization",
      error: "boom",
      recovery: "retry"
    });
  });

  it("stringifies plain string errors", () => {
    const info = describeToolError("sqlite", "open", "file locked");
    expect(info.error).toBe("file locked");
  });

  it("honors explicit recovery", () => {
    const info = describeToolError("memory", "scan", new Error("oom"), "reset");
    expect(info.recovery).toBe("reset");
  });
});

describe("isResolvedStatus", () => {
  it("is true only for success/warning/error", () => {
    expect(isResolvedStatus("success")).toBe(true);
    expect(isResolvedStatus("warning")).toBe(true);
    expect(isResolvedStatus("error")).toBe(true);
    expect(isResolvedStatus("idle")).toBe(false);
    expect(isResolvedStatus("loading")).toBe(false);
    expect(isResolvedStatus("running")).toBe(false);
  });
});
