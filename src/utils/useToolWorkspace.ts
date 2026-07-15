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
  const removalQueuedRef = React.useRef(false);
  const removalTimerRef = React.useRef<ReturnType<typeof window.setTimeout> | null>(null);
  const mountedRef = React.useRef(true);
  const restoreStartedRef = React.useRef(false);
  const restoreCancelledRef = React.useRef(false);
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

  const removePersistedSession = React.useCallback(() => {
    if (removalQueuedRef.current) return;
    removalQueuedRef.current = true;
    void queue(() => removeToolSession(id))
      .catch(() => undefined)
      .finally(() => { removalQueuedRef.current = false; });
  }, [id, queue]);

  const flushPendingRemoval = React.useCallback(() => {
    if (removalTimerRef.current === null) return;
    window.clearTimeout(removalTimerRef.current);
    removalTimerRef.current = null;
    removePersistedSession();
  }, [removePersistedSession]);

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
    restoreCancelledRef.current = true;
    generationRef.current += 1;
    saveSequenceRef.current += 1;
    pendingSaveRef.current = null;
    if (saveTimerRef.current !== null) {
      window.clearTimeout(saveTimerRef.current);
      saveTimerRef.current = null;
    }
    if (mountedRef.current) setState("idle");
    if (removalQueuedRef.current || removalTimerRef.current !== null) return;
    // Text tools can clear on every keystroke; coalesce those deletes into one I/O operation.
    removalTimerRef.current = window.setTimeout(() => {
      removalTimerRef.current = null;
      if (removalQueuedRef.current) return;
      removePersistedSession();
    }, 120);
  }, [removePersistedSession]);

  const save = React.useCallback((value: T) => {
    restoreCancelledRef.current = true;
    if (removalTimerRef.current !== null) {
      window.clearTimeout(removalTimerRef.current);
      removalTimerRef.current = null;
    }
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
      if (document.visibilityState === "hidden") {
        flushPendingSave();
        flushPendingRemoval();
      }
    };
    const flushOnPageHide = () => {
      flushPendingSave();
      flushPendingRemoval();
    };
    document.addEventListener("visibilitychange", flushWhenHidden);
    window.addEventListener("pagehide", flushOnPageHide);
    return () => {
      // Route changes can unmount a tool before the debounce timer fires.
      // Flush the latest workspace so switching tools does not lose work.
      flushPendingSave();
      flushPendingRemoval();
      document.removeEventListener("visibilitychange", flushWhenHidden);
      window.removeEventListener("pagehide", flushOnPageHide);
    };
  }, [flushPendingRemoval, flushPendingSave]);

  React.useEffect(() => {
    mountedRef.current = true;
    if (restoreStartedRef.current) return () => { mountedRef.current = false; };
    restoreStartedRef.current = true;
    const generation = generationRef.current;
    void readToolSessionResult<WorkspaceEnvelope<unknown>>(id).then(({ value: session, error }) => {
      if (!mountedRef.current || generationRef.current !== generation || restoreCancelledRef.current) return;
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
