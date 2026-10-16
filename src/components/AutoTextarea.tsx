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

export type AutoTextareaProps = React.TextareaHTMLAttributes<HTMLTextAreaElement> & {
  minRows?: number;
  maxRows?: number;
};

/** A single native textarea: content grows, large documents stay scrollable,
 * and user resizing establishes a preferred height for subsequent edits. */
export const AutoTextarea = React.forwardRef<HTMLTextAreaElement, AutoTextareaProps>(function AutoTextarea(
  { minRows, maxRows = 24, className, style, onInput, ...props }, forwardedRef
) {
  const elementRef = React.useRef<HTMLTextAreaElement>(null);
  const manualHeight = React.useRef(0);
  const lastHeight = React.useRef(0);
  const lastWidth = React.useRef(0);
  const frame = React.useRef(0);
  React.useImperativeHandle(forwardedRef, () => elementRef.current!, []);
  const minimumRows = minRows ?? (className?.includes("compact-textarea") ? 4 : 6);
  const fit = React.useCallback(() => {
    const element = elementRef.current;
    if (!element || element.clientWidth === 0) return;
    const computed = getComputedStyle(element);
    const line = Number.parseFloat(computed.lineHeight) || 21;
    const padding = Number.parseFloat(computed.paddingTop) + Number.parseFloat(computed.paddingBottom);
    const border = Number.parseFloat(computed.borderTopWidth) + Number.parseFloat(computed.borderBottomWidth);
    const minimum = Math.max(3, minimumRows) * line + padding + border;
    const maximum = Math.max(minimum, Math.min(Math.max(minimumRows, maxRows) * line + padding + border, window.innerHeight * 0.64));
    const scroll = element.scrollTop;
    element.style.setProperty("--editor-min-height", `${minimum}px`);
    element.style.setProperty("--editor-max-height", `${maximum}px`);
    element.style.height = "auto";
    const height = Math.min(maximum, Math.max(minimum, element.scrollHeight + border, manualHeight.current));
    element.style.height = `${height}px`;
    element.style.overflowY = "auto";
    element.scrollTop = scroll;
    lastHeight.current = element.getBoundingClientRect().height;
    lastWidth.current = element.clientWidth;
  }, [minimumRows, maxRows]);

  React.useLayoutEffect(fit, [fit, props.value, props.defaultValue]);
  React.useEffect(() => {
    const element = elementRef.current;
    if (!element) return;
    const schedule = () => { cancelAnimationFrame(frame.current); frame.current = requestAnimationFrame(fit); };
    const observer = new ResizeObserver(() => {
      if (!element.clientWidth) return;
      const height = element.getBoundingClientRect().height;
      if (lastWidth.current === element.clientWidth && Math.abs(height - lastHeight.current) > 1) {
        manualHeight.current = height;
      }
      if (lastWidth.current !== element.clientWidth) schedule();
      lastHeight.current = height;
    });
    observer.observe(element);
    window.addEventListener("resize", schedule);
    void document.fonts?.ready.then(schedule);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", schedule);
      cancelAnimationFrame(frame.current);
    };
  }, [fit]);

  return <textarea {...props} ref={elementRef} className={className} style={style} data-auto-size="true"
    onInput={(event) => { onInput?.(event); fit(); }} />;
});
