import { computePolicyVersion } from "./policy-version.js";
import type { PermissionCheckResult, PermissionState } from "./types.js";
import type { PermissionManager } from "./permission-manager.js";
import type { AuditDecision } from "./audit-ledger.js";

/**
 * Pure evaluation pipeline.
 *
 * The permission gate is expressed as three explicit stages so that it can be
 * tested and reused without the TUI or interactive prompts:
 *
 *   1. resolve  — pick the effective policy for an agent (and its version)
 *   2. evaluate — match the tool call against the compiled rules
 *   3. decide   — map the match to a terminal decision
 *
 * This module is intentionally a thin, pure composition over
 * `PermissionManager`. It does not prompt, block, or mutate state; it returns
 * the decision so callers (the tool_call handler, the simulator, and tests)
 * can act on it.
 */

export type PipelineDecision = {
  toolName: string;
  /** The policy state that matched: allow / deny / ask. */
  state: PermissionState;
  /** The terminal decision the gate will take. */
  decision: AuditDecision;
  source: PermissionCheckResult["source"];
  matchedPattern?: string;
  target?: string;
  command?: string;
  policyVersion: string;
};

/**
 * Evaluate a single tool call against the effective policy.
 *
 * `decision` is derived from `state`: `ask` maps to the `ask` decision
 * (a human approval is required), `deny` maps to deny, and `allow` maps to
 * allow. The caller is responsible for actually prompting on `ask`.
 */
export function evaluateToolCall(
  manager: PermissionManager,
  toolName: string,
  input: unknown,
  agentName?: string,
): PipelineDecision {
  const check = manager.checkPermission(toolName, input, agentName);
  const policyVersion = computePolicyVersion(manager.getEffectivePolicy(agentName));

  return {
    toolName,
    state: check.state,
    decision: check.state,
    source: check.source,
    matchedPattern: check.matchedPattern,
    target: check.target,
    command: check.command,
    policyVersion,
  };
}

/**
 * Build a compact, redacted subject string for a tool call, suitable for the
 * audit ledger. Prefers the command (for bash) and falls back to the target
 * resource (path, skill name, etc.).
 */
export function describeSubject(decision: PipelineDecision): string | undefined {
  if (decision.command) {
    return decision.command;
  }
  if (decision.target) {
    return decision.target;
  }
  return undefined;
}
