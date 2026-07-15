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
    let requestFinished = false;
    let transactionFinished = false;
    let result!: T;
    let settled = false;
    const close = () => database.close();
    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      close();
      reject(error instanceof Error ? error : new Error("Browser storage transaction failed"));
    };
    const finish = () => {
      if (settled || !requestFinished || !transactionFinished) return;
      settled = true;
      close();
      resolve(result);
    };
    request.onsuccess = () => {
      result = request.result;
      requestFinished = true;
      finish();
    };
    request.onerror = () => fail(request.error ?? new Error("Browser storage request failed"));
    transaction.oncomplete = () => {
      transactionFinished = true;
      finish();
    };
    transaction.onerror = () => {
      fail(transaction.error ?? new Error("Browser storage transaction failed"));
    };
    transaction.onabort = () => {
      fail(transaction.error ?? new Error("Browser storage transaction was cancelled"));
    };
  }));
}

export async function readToolSession<T>(id: string) {
  return (await readToolSessionResult<T>(id)).value;
}

export async function readToolSessionResult<T>(id: string): Promise<{ value: T | null; error: Error | null }> {
  try {
    const stored = await runSessionRequest<StoredToolSession<T> | undefined>("readonly", (store) => store.get(id));
    return { value: stored?.value ?? null, error: null };
  } catch (caught) {
    return {
      value: null,
      error: caught instanceof Error ? caught : new Error("Browser storage request failed")
    };
  }
}

export async function writeToolSession<T>(id: string, value: T) {
  await runSessionRequest<IDBValidKey>("readwrite", (store) => store.put({ id, savedAt: new Date().toISOString(), value } satisfies StoredToolSession<T>));
}

export async function removeToolSession(id: string) {
  await runSessionRequest<undefined>("readwrite", (store) => store.delete(id));
}

export function clearToolSessions() {
  if (typeof indexedDB === "undefined") return Promise.resolve();
  // Clear records inside the existing store instead of deleting the database.
  // Database deletion can be blocked by another open tab and falsely report success.
  return runSessionRequest<undefined>("readwrite", (store) => store.clear()).then(() => undefined);
}
