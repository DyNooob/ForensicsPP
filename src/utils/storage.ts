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
import { storagePrefix } from "../config/app";
import { clearToolSessions, readToolSessionResult, removeToolSession, writeToolSession } from "./toolSessions";

const INDEXED_STATE_THRESHOLD = 128 * 1024;
const indexedStateKeys = new Set<string>();
const indexedStateQueues = new Map<string, Promise<unknown>>();

type IndexedStateEnvelope<T> = {
  version: 1;
  value: T;
};

type StoredStateValidator<T> = (value: unknown) => value is T;

export function isStoredValueCompatible(value: unknown, initialValue: unknown) {
  if (Array.isArray(initialValue)) return Array.isArray(value);
  if (initialValue === null) return value === null;
  if (typeof initialValue === "object") return typeof value === "object" && value !== null && !Array.isArray(value);
  return typeof value === typeof initialValue;
}

function indexedStateId(storageKey: string) {
  return `app-state:${storageKey}`;
}

function indexedStateMarkerKey(storageKey: string) {
  return `${storageKey}:indexed`;
}

function enqueueIndexedState<T>(storageKey: string, task: () => Promise<T>) {
  const previous = indexedStateQueues.get(storageKey) ?? Promise.resolve();
  const next = previous.catch(() => undefined).then(task);
  indexedStateQueues.set(storageKey, next.then(() => undefined, () => undefined));
  return next;
}

export function shouldUseIndexedState(serialized: string) {
  return serialized.length > INDEXED_STATE_THRESHOLD;
}

export function parseStoredState<T>(serialized: string | null, isValid?: StoredStateValidator<T>): { found: boolean; value?: T } {
  if (serialized == null) return { found: false };
  try {
    const value: unknown = JSON.parse(serialized);
    return !isValid || isValid(value) ? { found: true, value: value as T } : { found: false };
  } catch {
    return { found: false };
  }
}

export function useStoredState<T>(key: string, initialValue: T, isValid?: StoredStateValidator<T>) {
  const storageKey = `${storagePrefix}${key}`;
  const initialValueRef = React.useRef(initialValue);
  const validateStoredValue = React.useCallback<StoredStateValidator<T>>((candidate): candidate is T => {
    return isValid ? isValid(candidate) : isStoredValueCompatible(candidate, initialValueRef.current);
  }, [isValid]);
  const [value, setValue] = React.useState<T>(() => {
    if (typeof window === "undefined") return initialValue;
    try {
      const stored = parseStoredState<T>(window.localStorage.getItem(storageKey), validateStoredValue);
      return stored.found ? (stored.value as T) : initialValue;
    } catch {
      return initialValue;
    }
  });
  const [hydrated, setHydrated] = React.useState(false);
  const userInteractedRef = React.useRef(false);
  const persistValueRef = React.useRef<() => void>(() => undefined);
  const storageKeyRef = React.useRef(storageKey);
  if (storageKeyRef.current !== storageKey) {
    storageKeyRef.current = storageKey;
    userInteractedRef.current = false;
  }

  React.useEffect(() => {
    let active = true;
    let hasLocalValue = false;
    try {
      hasLocalValue = parseStoredState<T>(window.localStorage.getItem(storageKey), validateStoredValue).found;
    } catch {
      // Fall through to the IndexedDB restore path.
    }
    if (hasLocalValue) {
      setHydrated(true);
      return () => { active = false; };
    }
    void enqueueIndexedState(storageKey, () => readToolSessionResult<IndexedStateEnvelope<T>>(indexedStateId(storageKey))).then(({ value: stored }) => {
      if (!active) return;
      const validStored = stored?.version === 1 && validateStoredValue(stored.value);
      if (validStored && !userInteractedRef.current) {
        setValue(stored.value);
        indexedStateKeys.add(storageKey);
      } else if (stored && !validStored) {
        // Do not keep an obsolete workspace that will fail validation on every load.
        void enqueueIndexedState(storageKey, () => removeToolSession(indexedStateId(storageKey))).catch(() => undefined);
        try {
          window.localStorage.removeItem(indexedStateMarkerKey(storageKey));
        } catch {
          // The invalid record has still been scheduled for removal.
        }
      }
      setHydrated(true);
    });
    return () => { active = false; };
  }, [storageKey, validateStoredValue]);

  const persistValue = React.useCallback(() => {
    if (!hydrated) return;
    const indexedId = indexedStateId(storageKey);
    let serialized = "";
    try {
      serialized = JSON.stringify(value);
      if (shouldUseIndexedState(serialized)) {
        window.localStorage.removeItem(storageKey);
        window.localStorage.setItem(indexedStateMarkerKey(storageKey), "1");
        indexedStateKeys.add(storageKey);
        void enqueueIndexedState(storageKey, () => writeToolSession<IndexedStateEnvelope<T>>(indexedId, { version: 1, value })).catch(() => undefined);
        return;
      }
      const hadIndexedState = indexedStateKeys.has(storageKey) || window.localStorage.getItem(indexedStateMarkerKey(storageKey)) === "1";
      window.localStorage.setItem(storageKey, serialized);
      window.localStorage.removeItem(indexedStateMarkerKey(storageKey));
      indexedStateKeys.delete(storageKey);
      if (hadIndexedState) void enqueueIndexedState(storageKey, () => removeToolSession(indexedId)).catch(() => undefined);
    } catch {
      // A quota failure can leave an older localStorage value behind. Remove it
      // before using IndexedDB, otherwise the next load will prefer stale data.
      try {
        window.localStorage.removeItem(storageKey);
        window.localStorage.removeItem(indexedStateMarkerKey(storageKey));
      } catch {
        // Continue with the IndexedDB fallback.
      }
      indexedStateKeys.add(storageKey);
      void enqueueIndexedState(storageKey, () => writeToolSession<IndexedStateEnvelope<T>>(indexedId, { version: 1, value })).catch(() => undefined);
    }
  }, [hydrated, storageKey, value]);
  persistValueRef.current = persistValue;

  React.useEffect(() => {
    if (!hydrated) return undefined;
    const timer = window.setTimeout(() => persistValueRef.current(), 180);
    return () => window.clearTimeout(timer);
  }, [hydrated, storageKey, value]);

  React.useEffect(() => {
    const flushWhenHidden = () => {
      if (document.visibilityState === "hidden") persistValueRef.current();
    };
    const flushOnPageHide = () => persistValueRef.current();
    document.addEventListener("visibilitychange", flushWhenHidden);
    window.addEventListener("pagehide", flushOnPageHide);
    return () => {
      document.removeEventListener("visibilitychange", flushWhenHidden);
      window.removeEventListener("pagehide", flushOnPageHide);
    };
  }, []);

  React.useEffect(() => () => persistValueRef.current(), []);

  const updateValue = React.useCallback<React.Dispatch<React.SetStateAction<T>>>((nextValue) => {
    userInteractedRef.current = true;
    setValue(nextValue);
  }, []);

  return [value, updateValue] as const;
}

export async function clearForensicsStorage() {
  Object.keys(window.localStorage)
    .filter((key) => key.startsWith(storagePrefix))
    .forEach((key) => window.localStorage.removeItem(key));
  await clearToolSessions();
}

const legacyEvidenceKeys = [
  "baseconvert.value.v2",
  "codec.input",
  "codec.output",
  "crypto.input",
  "crypto.output",
  "crypto.key",
  "entropy.text.v2",
  "hash.text",
  "hash.expectedHash",
  "http.text.v3",
  "regex.text.v2",
  "sqlite.queryHistory",
  "sql.formatInput",
  "sql.formatOutput",
  "timeline.input.v2",
  "timeline.source",
  "timestamp.input",
  "timestamp.batchInput.v2",
  "url.input.v3",
  "uuid.value",
  "yara.sample.v2"
];

const legacyEvidenceCleanupVersion = "2026-07-13-v1";
const legacyEvidenceCleanupKey = `${storagePrefix}storage.legacyEvidenceCleanupVersion`;

export function clearLegacyEvidenceStorage() {
  if (typeof window === "undefined") return;
  if (window.localStorage.getItem(legacyEvidenceCleanupKey) === JSON.stringify(legacyEvidenceCleanupVersion)) return;
  legacyEvidenceKeys.forEach((key) => window.localStorage.removeItem(`${storagePrefix}${key}`));
  window.localStorage.setItem(legacyEvidenceCleanupKey, JSON.stringify(legacyEvidenceCleanupVersion));
}
