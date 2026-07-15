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

declare module "sql.js" {
  export type SqlValue = string | number | null | Uint8Array;

  export type QueryExecResult = {
    columns: string[];
    values: SqlValue[][];
  };

  export type Statement = {
    bind(values?: SqlValue[] | Record<string, SqlValue>): boolean;
    step(): boolean;
    getAsObject(): Record<string, SqlValue>;
    free(): void;
  };

  export type Database = {
    exec(sql: string): QueryExecResult[];
    run(sql: string, params?: SqlValue[]): Database;
    prepare(sql: string): Statement;
    export(): Uint8Array;
    close(): void;
  };

  export type SqlJsStatic = {
    Database: new (data?: Uint8Array) => Database;
  };

  export default function initSqlJs(config?: { locateFile?: (file: string) => string }): Promise<SqlJsStatic>;
}

declare module "*.wasm?url" {
  const url: string;
  export default url;
}
