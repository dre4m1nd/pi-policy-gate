import { createHash } from "node:crypto";

import type { GlobalPermissionConfig, PermissionState } from "../core/types.js"

/**
 * A canonical, order-independent representation of an effective permission policy.
 *
 * Policy versioning hashes this structure so that the same set of rules always
 * yields the same version, regardless of key insertion order or formatting in
 * the underlying config files. This makes decisions traceable: an audit record
 * can state which policy version produced it, and two versions differ exactly
 * when the effective rules differ.
 */
export type CanonicalPolicy = {
  defaultPolicy: Record<string, PermissionState>;
  tools: Record<string, PermissionState>;
  bash: Record<string, PermissionState>;
  mcp: Record<string, PermissionState>;
  skills: Record<string, PermissionState>;
  special: Record<string, PermissionState>;
};

const CATEGORY_KEYS = ["defaultPolicy", "tools", "bash", "mcp", "skills", "special"] as const;

function canonicalRecord(value: unknown): Record<string, PermissionState> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  const record = value as Record<string, unknown>;
  const sorted: Record<string, PermissionState> = {};
  for (const key of Object.keys(record).sort()) {
    const candidate = record[key];
    if (candidate === "allow" || candidate === "deny" || candidate === "ask") {
      sorted[key] = candidate;
    }
  }
  return sorted;
}

/** Build the canonical form of an effective policy, sorting every rule map by key. */
export function toCanonicalPolicy(policy: GlobalPermissionConfig): CanonicalPolicy {
  const canonical: CanonicalPolicy = {
    defaultPolicy: {},
    tools: {},
    bash: {},
    mcp: {},
    skills: {},
    special: {},
  };

  for (const key of CATEGORY_KEYS) {
    Object.assign(canonical[key], canonicalRecord((policy as unknown as Record<string, unknown>)[key]));
  }

  return canonical;
}

/** Stable JSON stringify with sorted keys at every level. */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const entries = Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`);
  return `{${entries.join(",")}}`;
}

/**
 * Compute a short, stable version identifier for an effective policy.
 *
 * Uses SHA-256 over the canonical form and returns the first 16 hex chars.
 * This is a content hash: identical policies produce identical versions, and
 * any change to an effective rule changes the version.
 */
export function computePolicyVersion(policy: GlobalPermissionConfig): string {
  const canonical = toCanonicalPolicy(policy);
  const digest = createHash("sha256").update(stableStringify(canonical)).digest("hex");
  return `v1-${digest.slice(0, 16)}`;
}

/**
 * Compute the difference between two policies as a set of human-readable
 * rule changes. Used by the simulator's diff mode to explain why decisions
 * may have changed between two policy versions.
 */
export type PolicyDiff = {
  added: string[];
  removed: string[];
  changed: string[];
};

export function diffPolicies(
  base: GlobalPermissionConfig,
  next: GlobalPermissionConfig,
): PolicyDiff {
  const baseCanonical = toCanonicalPolicy(base);
  const nextCanonical = toCanonicalPolicy(next);
  const added: string[] = [];
  const removed: string[] = [];
  const changed: string[] = [];

  for (const category of CATEGORY_KEYS) {
    const baseRules = baseCanonical[category];
    const nextRules = nextCanonical[category];

    for (const rule of Object.keys(nextRules)) {
      const label = `${category}.${rule}`;
      if (!(rule in baseRules)) {
        added.push(`${label} = ${nextRules[rule]}`);
      } else if (baseRules[rule] !== nextRules[rule]) {
        changed.push(`${label}: ${baseRules[rule]} -> ${nextRules[rule]}`);
      }
    }

    for (const rule of Object.keys(baseRules)) {
      if (!(rule in nextRules)) {
        removed.push(`${category}.${rule} = ${baseRules[rule]}`);
      }
    }
  }

  return { added, removed, changed };
}
