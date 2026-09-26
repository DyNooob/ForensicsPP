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
import type { Lang } from "../models";

type ClockState = {
  status: "checking" | "ok" | "warn" | "unavailable";
  offsetMs: number;
  checkedAt: number;
};

function formatOffset(offsetMs: number, lang: Lang) {
  const seconds = Math.round(Math.abs(offsetMs) / 1000);
  if (seconds < 2) return lang === "zh" ? "小于 2 秒" : "under 2s";
  if (seconds < 60) return lang === "zh" ? `${seconds} 秒` : `${seconds}s`;
  const minutes = Math.round(seconds / 60);
  return lang === "zh" ? `${minutes} 分钟` : `${minutes}m`;
}

export function ClockHealth({ lang }: { lang: Lang }) {
  const [now, setNow] = React.useState(() => new Date());
  const [state, setState] = React.useState<ClockState>({ status: "checking", offsetMs: 0, checkedAt: 0 });
  const checkingRef = React.useRef(false);

  const check = React.useCallback(async () => {
    if (checkingRef.current || typeof window === "undefined") return;
    checkingRef.current = true;
    setState((current) => ({ ...current, status: "checking" }));
    const startedAt = Date.now();
    try {
      const response = await fetch(window.location.href, { method: "HEAD", cache: "no-store", credentials: "same-origin" });
      const endedAt = Date.now();
      const serverDate = response.headers.get("date");
      const serverTime = serverDate ? Date.parse(serverDate) : Number.NaN;
      if (!response.ok || !Number.isFinite(serverTime)) throw new Error("server date unavailable");
      const estimatedServerNow = serverTime + (endedAt - startedAt) / 2;
      const offsetMs = estimatedServerNow - endedAt;
      setState({ status: Math.abs(offsetMs) > 90_000 ? "warn" : "ok", offsetMs, checkedAt: endedAt });
    } catch {
      setState({ status: "unavailable", offsetMs: 0, checkedAt: Date.now() });
    } finally {
      checkingRef.current = false;
    }
  }, []);

  React.useEffect(() => {
    const tick = window.setInterval(() => {
      if (!document.hidden) setNow(new Date());
    }, 1000);
    const initial = window.setTimeout(() => void check(), 1600);
    const verify = window.setInterval(() => void check(), 10 * 60 * 1000);
    return () => {
      window.clearInterval(tick);
      window.clearTimeout(initial);
      window.clearInterval(verify);
    };
  }, [check]);

  const time = new Intl.DateTimeFormat(lang === "zh" ? "zh-CN" : "en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(now);
  const date = new Intl.DateTimeFormat(lang === "zh" ? "zh-CN" : "en-GB", { month: "2-digit", day: "2-digit" }).format(now);
  const title = state.status === "warn"
    ? (lang === "zh" ? `本机时间与服务器时间相差约 ${formatOffset(state.offsetMs, lang)}。浏览器无权修改系统时钟，请在操作系统设置中校时。点击重新检查。` : `Local time differs from server time by about ${formatOffset(state.offsetMs, lang)}. Browsers cannot change the system clock; use OS settings. Click to recheck.`)
    : state.status === "ok"
      ? (lang === "zh" ? `本机时间校验正常，偏差 ${formatOffset(state.offsetMs, lang)}。点击重新检查。` : `Local clock check passed; offset ${formatOffset(state.offsetMs, lang)}. Click to recheck.`)
      : state.status === "checking"
        ? (lang === "zh" ? "正在对比服务器时间" : "Comparing server time")
        : (lang === "zh" ? "无法读取服务器时间；当前仅显示本机时间。点击重试。" : "Server time unavailable; showing local time only. Click to retry.");

  return (
    <button
      type="button"
      className={`top-clock top-clock--${state.status}`}
      onClick={() => void check()}
      title={title}
      aria-label={title}
      aria-live={state.status === "warn" ? "assertive" : "off"}
    >
      <span className="top-clock__dot" aria-hidden="true" />
      <span className="top-clock__date">{date}</span>
      <strong>{time}</strong>
      {state.status === "warn" && <span className="top-clock__warning">{lang === "zh" ? "时间偏差" : "Clock skew"}</span>}
    </button>
  );
}
