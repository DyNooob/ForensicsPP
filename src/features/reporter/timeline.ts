/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import type { CaseTimelineEvent, TimelineEvent } from "../../models";

const timelineRegistry = new WeakMap<object, CaseTimelineEvent[]>();

export function timelineBounds(events: TimelineEvent[]) {
  const dated = events
    .filter((event) => event.epochMs != null)
    .slice()
    .sort((left, right) => (left.epochMs ?? 0) - (right.epochMs ?? 0));
  return {
    first: dated[0] ?? events[0],
    last: dated[dated.length - 1] ?? events[events.length - 1]
  };
}

export function rememberTimelineEvents(target: object | null | undefined, events: TimelineEvent[]) {
  if (!target) return;
  timelineRegistry.set(target, events.map(({ iso, local, raw, format, line, source, context, epochMs }) => ({
    iso,
    local,
    raw,
    format,
    line,
    source,
    context,
    ...(epochMs == null ? {} : { epochMs })
  })));
}

export function rememberedTimelineEvents(target: object | null | undefined) {
  return target ? timelineRegistry.get(target) ?? [] : [];
}
