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
import { message } from "antd";
import type { Lang } from "../models";

type ClockState = {
  status: "checking" | "ok" | "warn" | "unavailable";
  offsetMs: number;
  checkedAt: number;
};

function formatOffset(offsetMs: number, lang: Lang) {
  const seconds = Math.abs(offsetMs) / 1000;
  if (seconds < 2) return lang === "zh" ? "小于 2 秒" : "under 2s";
  if (seconds < 60) return lang === "zh" ? `${Math.round(seconds)} 秒` : `${Math.round(seconds)}s`;
  const minutes = Math.round(seconds / 60);
  return lang === "zh" ? `${minutes} 分钟` : `${minutes}m`;
}

function showClockMessage(type: "success" | "warning" | "error" | "info", content: string) {
  void message.open({ type, content, className: "app-clock-message", duration: 3.5 });
}

export function ClockHealth({ lang }: { lang: Lang }) {
  const [now, setNow] = React.useState(() => new Date());
  const [state, setState] = React.useState<ClockState>({ status: "checking", offsetMs: 0, checkedAt: 0 });
  const checkingRef = React.useRef(false);

  const check = React.useCallback(async (notify = false) => {
    if (typeof window === "undefined") return;
    if (checkingRef.current) {
      if (notify) showClockMessage("info", lang === "zh" ? "正在校验时间，请稍候。" : "Clock check is still running.");
      return;
    }
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
      const status = Math.abs(offsetMs) > 2_000 ? "warn" : "ok";
      setState({ status, offsetMs, checkedAt: endedAt });
      if (notify) {
        if (status === "ok") {
          showClockMessage("success", lang === "zh" ? "计算机时间正常。" : "Computer time is correct.");
        } else {
          const direction = offsetMs > 0
            ? (lang === "zh" ? "慢" : "behind")
            : (lang === "zh" ? "快" : "ahead");
          showClockMessage("warning", lang === "zh"
            ? `本机时间${direction}约 ${formatOffset(offsetMs, lang)}，请在系统设置中调整。`
            : `Computer time is about ${formatOffset(offsetMs, lang)} ${direction}; adjust it in system settings.`);
        }
      }
    } catch {
      setState({ status: "unavailable", offsetMs: 0, checkedAt: Date.now() });
      if (notify) showClockMessage("error", lang === "zh" ? "无法获取标准时间，请检查网络后重试。" : "Could not check standard time. Check the network and try again.");
    } finally {
      checkingRef.current = false;
    }
  }, [lang]);

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

  const clockNow = state.checkedAt && state.status !== "unavailable"
    ? new Date(now.getTime() + state.offsetMs)
    : now;
  const time = new Intl.DateTimeFormat(lang === "zh" ? "zh-CN" : "en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(clockNow);
  const date = new Intl.DateTimeFormat(lang === "zh" ? "zh-CN" : "en-GB", { month: "2-digit", day: "2-digit" }).format(clockNow);
  const title = state.status === "warn"
    ? (lang === "zh" ? `本机时间与标准时间相差约 ${formatOffset(state.offsetMs, lang)}。请在操作系统设置中校时。点击重新校验。` : `Computer time differs from standard time by about ${formatOffset(state.offsetMs, lang)}. Adjust it in OS settings. Click to check again.`)
    : state.status === "ok"
      ? (lang === "zh" ? `计算机时间正常，与标准时间偏差 ${formatOffset(state.offsetMs, lang)}。点击重新校验。` : `Computer time is correct; offset ${formatOffset(state.offsetMs, lang)}. Click to check again.`)
      : state.status === "checking"
        ? (lang === "zh" ? "正在校验标准时间" : "Checking standard time")
        : (lang === "zh" ? "无法读取标准时间；当前显示本机时间。点击重试。" : "Standard time unavailable; showing computer time. Click to retry.");

  return (
    <button
      type="button"
      className={`top-clock top-clock--${state.status}`}
      onClick={() => void check(true)}
      title={title}
      aria-label={title}
      aria-live={state.status === "warn" ? "assertive" : "off"}
    >
      <span className="top-clock__dot" aria-hidden="true" />
      <span className="top-clock__source">{state.checkedAt && state.status !== "unavailable" ? (lang === "zh" ? "标准" : "SYNC") : (lang === "zh" ? "本机" : "LOCAL")}</span>
      <span className="top-clock__date">{date}</span>
      <strong>{time}</strong>
      {state.status === "warn" && <span className="top-clock__warning">{lang === "zh" ? "时间偏差" : "Clock skew"}</span>}
    </button>
  );
}
