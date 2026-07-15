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
import { readToolSessionResult, removeToolSession, writeToolSession } from "./toolSessions";

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
  const saveTimerRef = React.useRef<ReturnType<typeof window.setTimeout> | null>(null);
  const saveSequenceRef = React.useRef(0);
  const pendingSaveRef = React.useRef<{ generation: number; sequence: number; value: T } | null>(null);
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

  const persistPendingSave = React.useCallback((pending: { generation: number; sequence: number; value: T }) => {
    void queue(async () => {
      if (generationRef.current !== pending.generation) return;
      await writeToolSession<WorkspaceEnvelope<T>>(id, { version, value: pending.value });
      if (mountedRef.current && generationRef.current === pending.generation && saveSequenceRef.current === pending.sequence) setState("saved");
    }).catch(() => {
      if (mountedRef.current && generationRef.current === pending.generation && saveSequenceRef.current === pending.sequence) setState("failed");
    });
  }, [id, queue, version]);

  const flushPendingSave = React.useCallback(() => {
    if (saveTimerRef.current !== null) {
      window.clearTimeout(saveTimerRef.current);
      saveTimerRef.current = null;
    }
    const pending = pendingSaveRef.current;
    if (!pending || pending.generation !== generationRef.current) return;
    pendingSaveRef.current = null;
    persistPendingSave(pending);
  }, [persistPendingSave]);

  const clear = React.useCallback(() => {
    generationRef.current += 1;
    saveSequenceRef.current += 1;
    pendingSaveRef.current = null;
    if (saveTimerRef.current !== null) {
      window.clearTimeout(saveTimerRef.current);
      saveTimerRef.current = null;
    }
    if (mountedRef.current) setState("idle");
    void queue(() => removeToolSession(id)).catch(() => undefined);
  }, [id, queue]);

  const save = React.useCallback((value: T) => {
    const generation = generationRef.current;
    const sequence = ++saveSequenceRef.current;
    pendingSaveRef.current = { generation, sequence, value };
    if (mountedRef.current) setState("saving");
    if (saveTimerRef.current !== null) window.clearTimeout(saveTimerRef.current);
    saveTimerRef.current = window.setTimeout(() => {
      saveTimerRef.current = null;
      flushPendingSave();
    }, 160);
  }, [flushPendingSave]);

  React.useEffect(() => {
    const flushWhenHidden = () => {
      if (document.visibilityState === "hidden") flushPendingSave();
    };
    document.addEventListener("visibilitychange", flushWhenHidden);
    window.addEventListener("pagehide", flushPendingSave);
    return () => {
      // Route changes can unmount a tool before the debounce timer fires.
      // Flush the latest workspace so switching tools does not lose work.
      flushPendingSave();
      document.removeEventListener("visibilitychange", flushWhenHidden);
      window.removeEventListener("pagehide", flushPendingSave);
    };
  }, [flushPendingSave]);

  React.useEffect(() => {
    mountedRef.current = true;
    if (restoreStartedRef.current) return () => { mountedRef.current = false; };
    restoreStartedRef.current = true;
    const generation = generationRef.current;
    void readToolSessionResult<WorkspaceEnvelope<unknown>>(id).then(({ value: session, error }) => {
      if (!mountedRef.current || generationRef.current !== generation) return;
      if (error) {
        setState("failed");
        return;
      }
      if (!session) return;
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
