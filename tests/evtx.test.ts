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

import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { eventFromXml, evtxEventsToCsv, persistableEvtxResults } from "../src/features/evtx/analyzer";
import { parseEvtxBytes } from "../src/features/evtx/parser";
import { parseSigmaRules, runSigmaRules } from "../src/features/evtx/sigma";

const XML = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{fixture}"/>
    <EventID>1</EventID><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-12T01:02:03.000Z"/><EventRecordID>42</EventRecordID>
    <Execution ProcessID="100" ThreadID="200"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>host.test</Computer><Security UserID="S-1-5-18"/>
  </System>
  <EventData><Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c whoami</Data><Data Name="User">TEST\\analyst</Data></EventData>
</Event>`;

describe("EVTX parsing", () => {
  it("extracts structured fields from rendered event XML", () => {
    const event = eventFromXml(XML, "Sysmon.evtx");
    expect(event).toMatchObject({
      recordId: "42",
      eventId: 1,
      levelName: "Information",
      provider: "Microsoft-Windows-Sysmon",
      channel: "Microsoft-Windows-Sysmon/Operational",
      processId: "100",
      userId: "S-1-5-18"
    });
    expect(event.data.CommandLine).toBe("cmd.exe /c whoami");
    expect(evtxEventsToCsv([event])).toContain("Microsoft-Windows-Sysmon");
  });

  it("parses a real EVTX fixture with the upstream BinXML engine", async () => {
    const bytes = new Uint8Array(await readFile(new URL("./fixtures/Application.evtx", import.meta.url)));
    const result = parseEvtxBytes(bytes, "Application.evtx", 100);
    expect(result.chunkCount).toBeGreaterThan(0);
    expect(result.events.length).toBe(100);
    expect(result.events.every((event) => event.recordId && event.timestamp)).toBe(true);
    expect(result.events.some((event) => event.provider && event.eventId != null)).toBe(true);
  });

  it("rejects invalid files before attempting record parsing", () => {
    expect(() => parseEvtxBytes(new Uint8Array(4096), "invalid.evtx")).toThrow(/Invalid EVTX/);
  });

  it("removes oversized raw XML from the persisted snapshot only", () => {
    const event = { ...eventFromXml(XML, "fixture.evtx"), xml: "x".repeat(9 * 1024 * 1024) };
    const results = [{ source: "fixture.evtx", size: event.xml.length, chunkCount: 1, nextRecordNumber: "1", dirty: false, full: true, version: "3.1", parsedRecords: 1, skippedRecords: 0, truncated: false, events: [event] }];
    const persisted = persistableEvtxResults(results);
    expect(persisted[0].events[0].xml).toBe("");
    expect(results[0].events[0].xml).toHaveLength(9 * 1024 * 1024);
  });
});

describe("local Sigma matching", () => {
  it("supports field modifiers, boolean conditions and logsource filtering", () => {
    const parsed = parseSigmaRules(`
title: Command Shell Test
id: 0d090eed-19e8-438e-9f1d-1a5ac4a799d2
level: medium
tags: [attack.execution]
logsource:
  product: windows
  service: sysmon
detection:
  image:
    Image|endswith: '\\cmd.exe'
  command:
    CommandLine|contains: 'whoami'
  condition: image and command
`);
    expect(parsed.errors).toEqual([]);
    const result = runSigmaRules([eventFromXml(XML, "Sysmon.evtx")], parsed.rules);
    expect(result.errors).toEqual([]);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].ruleTitle).toBe("Command Shell Test");
  });

  it("supports '1 of' selection patterns", () => {
    const parsed = parseSigmaRules(`
title: One Of Test
detection:
  selection_img:
    Image|endswith: '\\powershell.exe'
  selection_cmd:
    CommandLine|contains: 'whoami'
  condition: 1 of selection_*
`);
    expect(runSigmaRules([eventFromXml(XML, "fixture.evtx")], parsed.rules).matches).toHaveLength(1);
  });

  it("rejects unsupported correlations and field modifiers", () => {
    const correlation = parseSigmaRules("title: Correlation\ncorrelation:\n  type: event_count\n");
    const modifier = parseSigmaRules("title: Unsupported\ndetection:\n  selection:\n    Image|base64: test\n  condition: selection\n");
    expect(correlation.rules).toHaveLength(0);
    expect(correlation.errors[0]).toContain("correlation");
    expect(modifier.rules).toHaveLength(0);
    expect(modifier.errors[0]).toContain("base64");
  });
});
