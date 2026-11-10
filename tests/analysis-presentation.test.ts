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

import { describe, expect, it, afterEach } from "vitest";
import { findingPresentation, localizeAnalysisText, sortFindings, statusPresentation } from "../src/core/analysisPresentation";
import { setUiLang } from "../src/uiLang";
import { renderToStaticMarkup } from "react-dom/server";
import React from "react";
import { ErrorNotice, FindingCard } from "../src/components/AnalysisNotice";
import { buildFormatLayer } from "../src/features/image/analyzer";
import { parsePngFile, pngChunkRisks, pngChunkSeverity } from "../src/features/png/parser";
import { crc32 } from "../src/utils/binary";

afterEach(()=>setUiLang("zh"));
describe("localized analysis presentation",()=>{
  it.each(["invalid IHDR length", "invalid PNG dimensions", "unknown critical chunk"])("marks actual structural errors red even when CRC passes: %s",risk=>{
    expect(pngChunkSeverity({ok:true,risk:[risk]})).toBe("danger");
    expect(pngChunkSeverity({ok:true,risk:["private-use chunk"]})).toBe("warn");
    const header=new Uint8Array(13);header.set([8,6,0,0,0],8);
    expect(pngChunkRisks("IHDR",header,true,false,false,0)).toContain("invalid PNG dimensions");
  });
  it("uses red error severity and Chinese copy while retaining offsets and raw analyzer data",()=>{
    const finding={level:"danger",title:"PNG CRC mismatch",detail:"IHDR@8, IDAT@33"};
    const html=renderToStaticMarkup(React.createElement(FindingCard,{finding}));
    expect(html).toContain('data-severity="danger"');expect(html).toContain("PNG 校验失败");expect(html).toContain("IHDR@8, IDAT@33");
    expect(html).not.toContain("CRC mismatch");expect(finding.title).toBe("PNG CRC mismatch");
  });
  it("sorts actual errors before review items and neutral information without mutating the source",()=>{
    const info={level:"info",title:"JPEG EXIF present",detail:""},warn={level:"warn",title:"Extension mismatch",detail:""},error={level:"danger",title:"CRC mismatch",detail:""};
    const original=[info,warn,error];expect(sortFindings(original)).toEqual([error,warn,info]);expect(original[0]).toBe(info);
    expect(findingPresentation(warn).level).toBe("warn");
  });
  it("provides Chinese context for unrecognized parser errors and preserves the original technical detail",()=>{
    const html=renderToStaticMarkup(React.createElement(ErrorNotice,{message:"Unexpected parser state at 0x1234"}));
    expect(html).toContain("操作未完成");expect(html).toContain("原始错误信息");expect(html).toContain("Unexpected parser state at 0x1234");
    const known=renderToStaticMarkup(React.createElement(ErrorNotice,{message:"Worker task timed out after 120000 ms"}));
    expect(known).toContain("超过 120 秒时限");expect(known).not.toContain("Worker task timed out");
  });
  it("preserves English mode",()=>{
    setUiLang("en");const f={level:"danger",title:"PNG CRC mismatch",detail:"IHDR@8"};expect(findingPresentation(f).title).toBe(f.title);
    expect(localizeAnalysisText("unknown critical chunk")).toBe("unknown critical chunk");
  });
  it("does not translate evidence or infer severity from filenames, URLs or metadata values",()=>{
    for(const label of ["Name","Path","Author","Software","Comment"]){
      expect(statusPresentation(label,"invalid")).toEqual({value:"invalid",level:undefined});
      expect(statusPresentation(label,"CRC mismatch")).toEqual({value:"CRC mismatch",level:undefined});
    }
    expect(localizeAnalysisText("https://evidence.example/CRC%20mismatch")).toBe("https://evidence.example/CRC%20mismatch");
  });
  it("highlights failed checks and treats unsupported checks separately",()=>{
    expect(statusPresentation("CRC","2 mismatch")).toEqual({value:"2 个块校验失败",level:"danger"});
    expect(statusPresentation("状态","尚未检查").level).toBe("pending");
    expect(statusPresentation("CRC","OK")).toEqual({value:"通过",level:"success"});
  });
  it("translates controlled PNG risks and dynamic recovery warnings",()=>{
    expect(["CRC mismatch", "private-use chunk"].map(text => localizeAnalysisText(text)).join("；")).toBe("CRC 校验不一致；私有数据块");
    expect(findingPresentation({level:"info",title:"PNG text metadata",detail:"External private-use chunk; CRC mismatch"}).detail).toBe("External private-use chunk; CRC mismatch");
    expect(localizeAnalysisText("Partition 2 starts beyond image size.")).toBe("分区 2 的起点超出镜像文件范围。");
    expect(localizeAnalysisText("Removed 123 B after the logical PNG end marker.")).toBe("在副本中移除 PNG 逻辑结束标记后的 123 B。");
  });
  it("classifies real PNG CRC errors as danger without duplicating the same error as a private chunk",()=>{
    const bytes=Uint8Array.from([137,80,78,71,13,10,26,10,0,0,0,13,73,72,68,82,0,0,0,1,0,0,0,1,8,6,0,0,0,0,0,0,0,0,0,0,0,73,69,78,68,0,0,0,0]);
    new DataView(bytes.buffer).setUint32(41,crc32(bytes.subarray(37,41)));
    const parsed=parsePngFile(bytes);const layer=buildFormatLayer(bytes,"PNG",new Uint8Array(),parsed.chunks)!;
    expect(layer.findings.find(f=>f.title==="PNG CRC mismatch")?.level).toBe("danger");
    expect(layer.findings.some(f=>f.title==="Risky / private PNG chunks")).toBe(false);
  });
});
