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
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import type { ResourcePolicy, ToolDefinition, ToolId } from "../../config/app";
import { getToolDefinitionById } from "../../config/app";

export type ToolResourceProfile = {
  policy: ResourcePolicy;
  heavy: boolean;
  supportsEvidence: boolean;
  supportsResult: boolean;
  supportsHandoff: boolean;
  supportsPersistence: boolean;
};

function hasAccepts(definition: ToolDefinition): boolean {
  return !!definition.accepts && definition.accepts.length > 0;
}

function defaultPolicyFor(definition: ToolDefinition): ResourcePolicy {
  if (definition.category === "transform") return "retain";
  if (definition.category === "featured") return "retain";
  if (hasAccepts(definition)) return "suspendable";
  return "retain";
}

/**
 * Resolve the resource profile for a tool definition.
 * Explicit fields on {@link ToolDefinition} win; everything else is derived so the
 * 38 existing tools keep working without per-field annotation.
 */
export function resolveResourceProfile(definition: ToolDefinition | null): ToolResourceProfile {
  if (!definition) {
    return {
      policy: "retain",
      heavy: false,
      supportsEvidence: false,
      supportsResult: false,
      supportsHandoff: false,
      supportsPersistence: false
    };
  }
  const policy = definition.resourcePolicy ?? defaultPolicyFor(definition);
  const isEvidenceTool = hasAccepts(definition) || definition.category === "analysis" || definition.category === "network";
  return {
    policy,
    heavy: definition.heavy ?? (policy === "dispose-on-switch" || policy === "suspendable"),
    supportsEvidence: definition.supportsEvidence ?? isEvidenceTool,
    supportsResult: definition.supportsResult ?? (definition.category === "analysis" || definition.category === "network"),
    supportsHandoff: definition.supportsHandoff ?? hasAccepts(definition),
    supportsPersistence: definition.supportsPersistence ?? definition.category === "transform"
  };
}

export function policyOf(toolId: ToolId): ResourcePolicy {
  return resolveResourceProfile(getToolDefinitionById(toolId)).policy;
}

export function resourceProfileOf(toolId: ToolId): ToolResourceProfile {
  return resolveResourceProfile(getToolDefinitionById(toolId));
}

export function isHeavyTool(toolId: ToolId): boolean {
  return resourceProfileOf(toolId).heavy;
}

export function isDisposeOnSwitch(toolId: ToolId): boolean {
  return policyOf(toolId) === "dispose-on-switch";
}
