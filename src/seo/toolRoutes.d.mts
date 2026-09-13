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
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

// Type declarations for the authoritative tool ↔ slug registry
// (toolRoutes.mjs). This module is plain ESM consumed by both the runtime
// router (routeAdapter.ts) and the Node build scripts; the .d.mts keeps
// `allowJs: false` typechecking honest without duplicating the data.

export declare const TOOL_SLUG: Record<string, string>;
export declare const SLUG_TO_TOOL: Record<string, string>;
export declare const LEGACY_TO_TOOL: Record<string, string>;
export declare const INDEXABLE_TOOLS: Set<string>;
export declare const TOOLS_PREFIX: string;

export declare function isKnownSlug(slug: unknown): boolean;
export declare function toolIdForSlug(slug: unknown): string | null;
