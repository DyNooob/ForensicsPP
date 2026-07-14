/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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
import { readToolSession, removeToolSession, writeToolSession } from "./toolSessions";

type WorkspaceEnvelope<T> = {
  version: number;
  value: T;
};

type ToolWorkspaceOptions<T> = {
  id: string;
  version: number;
  isValid: (value: unknown) => value is T;
  onRestore: (value: T) => void;
};

export type ToolWorkspaceState = "idle" | "saving" | "saved" | "failed";

export function useToolWorkspace<T>({ id, version, isValid, onRestore }: ToolWorkspaceOptions<T>) {
  const [state, setState] = React.useState<ToolWorkspaceState>("idle");
  const generationRef = React.useRef(0);
  const queueRef = React.useRef<Promise<unknown>>(Promise.resolve());
  const mountedRef = React.useRef(true);
  const restoreStartedRef = React.useRef(false);
  const onRestoreRef = React.useRef(onRestore);
  const isValidRef = React.useRef(isValid);
  onRestoreRef.current = onRestore;
  isValidRef.current = isValid;

  const queue = React.useCallback((task: () => Promise<unknown>) => {
    const next = queueRef.current.catch(() => undefined).then(task);
    queueRef.current = next;
    return next;
  }, []);

  const clear = React.useCallback(() => {
    generationRef.current += 1;
    if (mountedRef.current) setState("idle");
    void queue(() => removeToolSession(id)).catch(() => undefined);
  }, [id, queue]);

  const save = React.useCallback((value: T) => {
    const generation = generationRef.current;
    if (mountedRef.current) setState("saving");
    void queue(async () => {
      if (generationRef.current !== generation) return;
      await writeToolSession<WorkspaceEnvelope<T>>(id, { version, value });
      if (mountedRef.current && generationRef.current === generation) setState("saved");
    }).catch(() => {
      if (mountedRef.current && generationRef.current === generation) setState("failed");
    });
  }, [id, queue, version]);

  React.useEffect(() => {
    mountedRef.current = true;
    if (restoreStartedRef.current) return () => { mountedRef.current = false; };
    restoreStartedRef.current = true;
    const generation = generationRef.current;
    void readToolSession<WorkspaceEnvelope<unknown>>(id).then((session) => {
      if (!mountedRef.current || generationRef.current !== generation || !session) return;
      if (session.version !== version || !isValidRef.current(session.value)) {
        void queue(() => removeToolSession(id)).catch(() => undefined);
        return;
      }
      onRestoreRef.current(session.value);
      setState("saved");
    });
    return () => { mountedRef.current = false; };
  }, [id, queue, version]);

  return { clear, save, state };
}
