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

const databaseName = "forensicspp-workspaces";
const databaseVersion = 1;
const sessionStore = "tool-sessions";

type StoredToolSession<T> = {
  id: string;
  savedAt: string;
  value: T;
};

function openSessionDatabase() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("IndexedDB is unavailable"));
      return;
    }
    const request = indexedDB.open(databaseName, databaseVersion);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(sessionStore)) database.createObjectStore(sessionStore, { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Unable to open browser storage"));
    request.onblocked = () => reject(new Error("Browser storage is blocked by another tab"));
  });
}
function runSessionRequest<T>(mode: IDBTransactionMode, operation: (store: IDBObjectStore) => IDBRequest<T>) {
  return openSessionDatabase().then((database) => new Promise<T>((resolve, reject) => {
    const transaction = database.transaction(sessionStore, mode);
    const request = operation(transaction.objectStore(sessionStore));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Browser storage request failed"));
    transaction.oncomplete = () => database.close();
    transaction.onerror = () => {
      database.close();
      reject(transaction.error ?? new Error("Browser storage transaction failed"));
    };
    transaction.onabort = () => {
      database.close();
      reject(transaction.error ?? new Error("Browser storage transaction was cancelled"));
    };
  }));
}

export async function readToolSession<T>(id: string) {
  try {
    const stored = await runSessionRequest<StoredToolSession<T> | undefined>("readonly", (store) => store.get(id));
    return stored?.value ?? null;
  } catch {
    return null;
  }
}

export async function writeToolSession<T>(id: string, value: T) {
  await runSessionRequest<IDBValidKey>("readwrite", (store) => store.put({ id, savedAt: new Date().toISOString(), value } satisfies StoredToolSession<T>));
}

export async function removeToolSession(id: string) {
  await runSessionRequest<undefined>("readwrite", (store) => store.delete(id));
}

export function clearToolSessions() {
  return new Promise<void>((resolve) => {
    if (typeof indexedDB === "undefined") {
      resolve();
      return;
    }
    const request = indexedDB.deleteDatabase(databaseName);
    request.onsuccess = () => resolve();
    request.onerror = () => resolve();
    request.onblocked = () => resolve();
  });
}
